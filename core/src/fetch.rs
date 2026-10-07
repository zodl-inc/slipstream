// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL Slipstream.
//
// ZODL Slipstream is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL Slipstream is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! Parallel block fetch: K workers claim consecutive sub-ranges ("plan chunks")
//! of the requested range and stream them via GetBlockRange, splitting each
//! stream into byte-budgeted SUB-chunks (T6.8-S) so spam-era plan chunks
//! (mainnet "sandblasting" ~1.70M–2.00M: hundreds of MB per 10k blocks) stay
//! memory-bounded and timeout-immune. A reorder stage releases sub-chunks
//! strictly in (plan_index, sub_index) order — continuity-verified — into the
//! byte-budgeted ChunkQueue. Splitting + resume-from-height retry landed in
//! run T6.8-S, 2026-06-12.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::events::Progress;

use prost::Message;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};
use tracing::{debug, info, warn};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{BlockId, BlockRange},
};

use crate::{
    chunk::{Chunk, ChunkQueueSender},
    config::{Endpoint, EngineConfig},
    connector::connect_direct_with_retry,
    error::SlipstreamError,
    grpc::{self, LwdClient},
    verify::Continuity,
};

#[derive(Clone, Debug)]
pub struct FetchPlan {
    pub start: u64,
    /// Inclusive.
    pub end: u64,
    pub chunk_blocks: u32,
    pub streams: usize,
    /// Budget of consecutive ZERO-PROGRESS attempts per plan chunk. An attempt
    /// that emitted at least one sub-chunk resets the counter (T6.8-S: resume
    /// makes retries cheap — each re-downloads at most one partial sub-chunk).
    pub retries_per_chunk: u32,
    /// Per-SUB-chunk flush interval (T6.8-S, liveness rework): when a sub-chunk
    /// has not filled within this time, the blocks received so far are emitted as
    /// a shorter sub-chunk and the stream continues — a slow stream is never
    /// failed or re-downloaded for being slow. A stream that delivers nothing
    /// dies via `grpc::STREAM_IDLE_TIMEOUT` instead.
    pub chunk_timeout: Duration,
    /// Byte budget per emitted sub-chunk (estimated wire bytes). Normal-era
    /// 10k-block chunks (~1–6 MB) stay single sub-chunks; sandblasting chunks
    /// split into many small sub-chunks automatically. Threaded from
    /// [`EngineConfig::chunk_split_bytes`] by the scheduler.
    pub split_bytes: usize,
    /// [v0.7 P2] Arm the wire-collapse detector (Some ⇔ the engine has
    /// alternates to fail over to; None = pre-v0.7 behavior verbatim).
    pub failover: Option<WireFailoverArm>,
}

/// [v0.7 P2] Detector thresholds. Defaults are the shipped policy; the
/// throttle-proxy gates (P4) exercise them deterministically.
#[derive(Clone, Copy, Debug)]
pub struct WireFailoverArm {
    /// Consecutive seconds of ZERO arrivals while the reorder stage was
    /// ready to receive (recv-blocked, NOT queue-blocked — so scan
    /// backpressure can never trip this) before a full-stall fire. Sits
    /// above the connector's transient-reconnect backoff (~5–10 s blips)
    /// and below grpc's 30 s idle kill.
    pub stall_secs: u64,
    /// Relative collapse: fire when the rolling window rate falls below
    /// this fraction of the pass's best window…
    pub collapse_fraction: f64,
    /// …AND below this absolute rate (MB/s) — a drop from 20 to 3 MB/s is
    /// not worth a switch; a drop to below this is.
    pub painful_mbps: f64,
    /// Unconditional floor (MB/s): a window below this fires regardless of
    /// history (nothing is usable at this rate on any supported device).
    pub floor_mbps: f64,
}

impl Default for WireFailoverArm {
    fn default() -> Self {
        Self {
            stall_secs: 12,
            collapse_fraction: 0.15,
            painful_mbps: 2.0,
            floor_mbps: 0.2,
        }
    }
}

impl FetchPlan {
    /// `start <= end` is required; violations are a caller bug.
    pub fn new(start: u64, end: u64, chunk_blocks: u32, streams: usize) -> Self {
        assert!(start <= end, "FetchPlan: start {start} > end {end}");
        assert!(chunk_blocks > 0, "FetchPlan: chunk_blocks must be > 0");
        Self {
            start,
            end,
            chunk_blocks,
            streams,
            retries_per_chunk: 3,
            chunk_timeout: Duration::from_secs(120),
            split_bytes: EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            failover: None,
        }
    }

    fn chunk_count(&self) -> u64 {
        let span = self.end - self.start + 1;
        span.div_ceil(self.chunk_blocks as u64)
    }

    fn chunk_range(&self, index: u64) -> (u64, u64) {
        let s = self.start + index * self.chunk_blocks as u64;
        let e = (s + self.chunk_blocks as u64 - 1).min(self.end);
        (s, e)
    }
}

#[derive(Debug, Default, Clone)]
pub struct FetchStats {
    pub blocks: u64,
    /// Sum of estimated (wire-encoded) chunk bytes.
    pub bytes: u64,
    /// Wall time of the whole pipeline INCLUDING ChunkQueue backpressure —
    /// pipeline throughput, not pure network speed. With a fast-draining
    /// consumer (the benchmark drains immediately) it approximates download speed.
    pub elapsed: Duration,
    /// [v0.7 P0] Wire arrival series: (seconds since fetch begin, cumulative
    /// bytes) recorded at every sub-chunk ARRIVAL at the reorder stage — the
    /// raw material for windowed throughput (worst-window reporting now, the
    /// P2 collapse detector later). ~1 sample per ≤ split_bytes of wire data.
    pub wire_samples: Vec<(f64, u64)>,
}

impl FetchStats {
    pub fn blocks_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            self.blocks as f64 / secs
        } else {
            0.0
        }
    }
    pub fn megabytes_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs > 0.0 {
            self.bytes as f64 / (1024.0 * 1024.0) / secs
        } else {
            0.0
        }
    }

    /// [v0.7 P0] Worst sustained wire throughput across the pass: the
    /// minimum MB/s over any ≥ `window_s` span between arrival samples (a
    /// synthetic (0, 0) sample anchors the first window; passes shorter
    /// than the window rate the whole pass). CAVEAT: ahead-gate
    /// backpressure (scan slower than wire) parks the workers and reads as
    /// wire idle here — interpret beside `recv_wait` (high recv_wait =
    /// wire-bound = this number is the server's doing, which is exactly the
    /// case the v0.7 wire work exists for).
    pub fn worst_window_mbps(&self, window_s: f64) -> f64 {
        let mut samples: Vec<(f64, u64)> = Vec::with_capacity(self.wire_samples.len() + 1);
        samples.push((0.0, 0));
        samples.extend(self.wire_samples.iter().copied());
        if samples.len() < 2 {
            return self.megabytes_per_sec();
        }
        let mut worst = f64::INFINITY;
        let mut j = 1usize;
        for i in 0..samples.len() - 1 {
            if j <= i {
                j = i + 1;
            }
            while j < samples.len() && samples[j].0 - samples[i].0 < window_s {
                j += 1;
            }
            if j == samples.len() {
                break; // no full window starting at i; later starts are shorter still
            }
            let dt = samples[j].0 - samples[i].0;
            let db = samples[j].1.saturating_sub(samples[i].1) as f64;
            worst = worst.min(db / (1024.0 * 1024.0) / dt);
        }
        if worst.is_finite() {
            worst
        } else {
            self.megabytes_per_sec()
        }
    }
}

// ── T6.8-S sub-chunk splitting ─────────────────────────────────────────────────

/// One worker's in-order slice of a plan chunk. `sub_index` starts at 0 per plan
/// chunk and SURVIVES retries (resume continues the sequence, never repeating an
/// index); `is_last` marks the plan chunk's final sub-chunk so the reorder stage
/// can advance to the next plan index.
struct SubChunk {
    plan_index: u64,
    sub_index: u64,
    is_last: bool,
    /// Estimated wire bytes (sum of prost encoded_len), as accumulated by the splitter.
    bytes: usize,
    blocks: Vec<CompactBlock>,
    /// Fetch-ahead budget permit (None when emitted by the floor plan chunk).
    /// Held while the sub-chunk waits in the reorder channel/buffer; released
    /// when the reorder stage hands the sub-chunk to the ChunkQueue (whose own
    /// byte budget takes over from there).
    permit: Option<OwnedSemaphorePermit>,
}

/// Byte-budgeted accumulator: collects streamed blocks and yields a completed
/// sub-chunk whenever adding the next block would exceed `split_bytes` (the
/// pushed block then opens the next sub-chunk). Invariants: yielded sub-chunks
/// are never empty and preserve stream order; a single block larger than the
/// budget forms its own sub-chunk (no infinite loop).
pub(crate) struct ChunkSplitter {
    split_bytes: usize,
    acc: Vec<CompactBlock>,
    acc_bytes: usize,
}

impl ChunkSplitter {
    pub(crate) fn new(split_bytes: usize) -> Self {
        Self {
            split_bytes,
            acc: Vec::new(),
            acc_bytes: 0,
        }
    }

    /// Push the next streamed block; returns `Some((blocks, bytes))` when the
    /// budget overflows and a sub-chunk completes.
    pub(crate) fn push(&mut self, block: CompactBlock) -> Option<(Vec<CompactBlock>, usize)> {
        let block_bytes = Message::encoded_len(&block);
        let completed = if !self.acc.is_empty() && self.acc_bytes + block_bytes > self.split_bytes {
            let blocks = std::mem::take(&mut self.acc);
            let bytes = std::mem::replace(&mut self.acc_bytes, 0);
            Some((blocks, bytes))
        } else {
            None
        };
        self.acc.push(block);
        self.acc_bytes += block_bytes;
        completed
    }

    /// Final flush at clean end of stream; `None` when nothing is buffered.
    pub(crate) fn finish(self) -> Option<(Vec<CompactBlock>, usize)> {
        if self.acc.is_empty() {
            None
        } else {
            Some((self.acc, self.acc_bytes))
        }
    }

    /// Flush whatever has accumulated as a (short) sub-chunk and keep splitting
    /// from empty; `None` when nothing is buffered. The pump's deadline uses it
    /// so a slow stream hands on the blocks it already received.
    pub(crate) fn take_partial(&mut self) -> Option<(Vec<CompactBlock>, usize)> {
        if self.acc.is_empty() {
            return None;
        }
        let blocks = std::mem::take(&mut self.acc);
        let bytes = std::mem::replace(&mut self.acc_bytes, 0);
        Some((blocks, bytes))
    }

    /// Height of the newest buffered block, if any.
    pub(crate) fn last_height(&self) -> Option<u64> {
        self.acc.last().map(|b| b.height)
    }
}

// ── T6.8-S fetch-ahead admission control ───────────────────────────────────────

/// How far (in bytes) NON-floor workers may run ahead of the reorder release
/// point. Bounds the reorder buffer in dense eras: without it, K−1 workers
/// each streaming a ~300–900 MB sandblasting plan chunk would park it all in
/// the reorder buffer (default 4 streams: ~1–3 GB → device jetsam). 8×
/// `split_bytes` admits ≥8 normal-era chunks in flight (zero throttling in the
/// normal era) while capping spam-era ahead-buffering at ~64 MiB (default split).
const AHEAD_BUDGET_FACTOR: usize = 8;

/// Poll cadence for floor re-checks while a worker waits on the ahead budget.
const AHEAD_POLL: Duration = Duration::from_millis(100);

/// Admission control for the reorder stage (T6.8-S): the plan chunk currently
/// being released (the "floor") streams unthrottled — its sub-chunks flow
/// straight through to the ChunkQueue — while every other plan chunk must
/// acquire ahead-budget permits, pausing its stream when the budget is spent.
/// Deadlock-free by construction: the floor never waits on the budget, a
/// blocked waiter re-checks the floor every [`AHEAD_POLL`] (so a worker that
/// BECOMES the floor mid-wait proceeds promptly), and held budget is freed
/// exactly when buffered sub-chunks become the floor and drain into the queue.
#[derive(Clone)]
struct AheadGate {
    budget: Arc<Semaphore>,
    cap: usize,
    /// Plan index currently being released by the reorder stage.
    floor: Arc<AtomicU64>,
}

impl AheadGate {
    fn new(cap: usize, floor: Arc<AtomicU64>) -> Self {
        let cap = cap.max(1);
        Self {
            budget: Arc::new(Semaphore::new(cap.min(Semaphore::MAX_PERMITS))),
            cap,
            floor,
        }
    }

    /// Returns a budget permit for one sub-chunk, or `None` when `plan_index`
    /// is (or becomes) the release floor — the floor is exempt.
    async fn admit(&self, plan_index: u64, bytes: usize) -> Option<OwnedSemaphorePermit> {
        // u32 saturation mirrors ChunkQueueSender::send; oversized sub-chunks
        // clamp to the whole budget instead of deadlocking.
        let need = u32::try_from(bytes.min(self.cap).max(1)).unwrap_or(u32::MAX);
        loop {
            if self.floor.load(Ordering::Acquire) >= plan_index {
                return None;
            }
            match tokio::time::timeout(
                AHEAD_POLL,
                Arc::clone(&self.budget).acquire_many_owned(need),
            )
            .await
            {
                Ok(Ok(permit)) => return Some(permit),
                // Semaphore closed = shutdown; the subsequent send fails anyway.
                Ok(Err(_closed)) => return None,
                Err(_elapsed) => {} // re-check the floor (acquire_many is cancel-safe)
            }
        }
    }
}

// ── T6.8-S worker-side streaming ───────────────────────────────────────────────

/// Per-plan-chunk streaming state, surviving retries (resume-from-height).
struct PlanChunkCursor {
    plan_index: u64,
    /// Plan-chunk end bound (inclusive).
    end: u64,
    /// Next height to request: (last emitted sub-chunk's end) + 1. Retries
    /// re-open the stream HERE — already-emitted heights are never re-sent, so
    /// double-release (and therefore double-scan) is structurally impossible.
    resume_from: u64,
    /// Continues across retries so (plan_index, sub_index) stays unique and dense.
    next_sub_index: u64,
    /// Set by every emitted sub-chunk; cleared at attempt start (see worker's
    /// zero-progress retry accounting).
    emitted_this_attempt: bool,
}

#[derive(Debug)]
enum PumpOutcome {
    /// Stream delivered cleanly through `cursor.end`; `is_last` was emitted.
    Completed,
    /// The reorder stage hung up (abort path) — stop quietly.
    ConsumerGone,
}

/// Sends one sub-chunk through the ahead gate into the reorder channel.
/// Returns `false` when the reorder stage is gone. Updates the cursor ONLY on
/// successful handoff (a failed send must not advance the resume point).
async fn emit_sub_chunk(
    cursor: &mut PlanChunkCursor,
    blocks: Vec<CompactBlock>,
    bytes: usize,
    is_last: bool,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> bool {
    debug_assert!(!blocks.is_empty(), "splitter never yields empty sub-chunks");
    let last_height = blocks.last().map(|b| b.height);
    let permit = gate.admit(cursor.plan_index, bytes).await;
    let sub = SubChunk {
        plan_index: cursor.plan_index,
        sub_index: cursor.next_sub_index,
        is_last,
        bytes,
        blocks,
        permit,
    };
    if out.send(sub).await.is_err() {
        return false;
    }
    debug!(
        plan_index = cursor.plan_index,
        sub_index = cursor.next_sub_index,
        kb = bytes / 1024,
        is_last,
        "sub-chunk emitted"
    );
    if let Some(h) = last_height {
        cursor.resume_from = h + 1;
    }
    cursor.next_sub_index += 1;
    cursor.emitted_this_attempt = true;
    true
}

/// Ends a failing attempt: hands the blocks it already received (`tail`, the
/// splitter's buffer) on as a partial sub-chunk (`is_last = false`), which
/// advances `resume_from` so the worker's retry resumes after them, then fails
/// with `err`. Flushes only when the tail does not end at `cursor.end`: the
/// plan chunk's final block is never emitted from an error path (only a clean
/// end carries `is_last`), so such a tail is left for the retry. Returns
/// `Ok(ConsumerGone)` when the reorder stage is gone, as the other emit sites do.
async fn flush_then_fail(
    tail: Option<(Vec<CompactBlock>, usize)>,
    cursor: &mut PlanChunkCursor,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
    err: SlipstreamError,
) -> Result<PumpOutcome, SlipstreamError> {
    if let Some((blocks, bytes)) = tail
        && blocks.last().map(|b| b.height) != Some(cursor.end)
    {
        debug!(
            plan_index = cursor.plan_index,
            blocks = blocks.len(),
            "attempt failing — handing on the blocks received so far"
        );
        if !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await {
            return Ok(PumpOutcome::ConsumerGone);
        }
    }
    Err(err)
}

/// Streams one (possibly resumed) plan-chunk request into byte-budgeted
/// sub-chunks. Generic over the message stream so hermetic tests can inject
/// synthetic/flaky streams (production passes tonic's `Streaming`).
///
/// Deadline semantics: `progress_deadline` bounds how long received blocks
/// wait before being handed on. When it elapses with blocks buffered, they are
/// emitted as a partial sub-chunk (never the plan chunk's final block, which
/// only the clean-end flush emits with `is_last`), and the timer restarts.
/// Admission/backpressure time is excluded because the timer resets when an
/// emission completes. A silent stream dies via the per-message
/// grpc::STREAM_IDLE_TIMEOUT inside `next_with_idle_timeout`.
///
/// Failure semantics: a failing attempt — a stream error, the idle timeout, or
/// a clean end BEFORE `cursor.end` (short/empty delivery) — hands on what it
/// received before returning its retryable Transport error (see
/// [`flush_then_fail`]), so the worker's retry resumes after those blocks
/// instead of downloading them again. Only a clean end that reaches
/// `cursor.end` carries `is_last`.
async fn pump_block_stream<S>(
    stream: &mut S,
    cursor: &mut PlanChunkCursor,
    split_bytes: usize,
    progress_deadline: Duration,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
    progress: Option<&Progress>,
) -> Result<PumpOutcome, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    let ctx = format!(
        "block stream {}..{} (plan chunk {})",
        cursor.resume_from, cursor.end, cursor.plan_index
    );
    let mut splitter = ChunkSplitter::new(split_bytes);
    // tokio Instant (not std) so start_paused tests drive the deadline.
    let mut last_emit = tokio::time::Instant::now();
    loop {
        let item = match grpc::next_with_idle_timeout(stream, &ctx).await {
            Ok(item) => item,
            // Idle timeout: the stream went silent.
            Err(err) => return flush_then_fail(splitter.finish(), cursor, gate, out, err).await,
        };
        let Some(item) = item else {
            // Clean end of stream: the tail carries `is_last` iff it completes the
            // plan chunk; a short delivery hands on what it got and fails.
            return match splitter.finish() {
                Some((blocks, bytes)) if blocks.last().map(|b| b.height) == Some(cursor.end) => {
                    if emit_sub_chunk(cursor, blocks, bytes, true, gate, out).await {
                        Ok(PumpOutcome::Completed)
                    } else {
                        Ok(PumpOutcome::ConsumerGone)
                    }
                }
                tail => {
                    let got = tail
                        .as_ref()
                        .and_then(|(blocks, _)| blocks.last().map(|b| b.height))
                        .unwrap_or_else(|| cursor.resume_from.saturating_sub(1));
                    let err = SlipstreamError::Transport(format!(
                        "{ctx}: stream ended short at {got}, expected {}",
                        cursor.end
                    ));
                    flush_then_fail(tail, cursor, gate, out, err).await
                }
            };
        };
        let block = match item {
            Ok(block) => block,
            Err(status) => {
                let err = SlipstreamError::Transport(format!("{ctx}: {status}"));
                return flush_then_fail(splitter.finish(), cursor, gate, out, err).await;
            }
        };
        // Liveness: data arriving is forward progress even while the
        // sub-chunk is still accumulating (the stall clock hosts watch).
        if let Some(p) = progress {
            p.touch();
        }
        if let Some((blocks, bytes)) = splitter.push(block) {
            if !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await {
                return Ok(PumpOutcome::ConsumerGone);
            }
            last_emit = tokio::time::Instant::now();
        } else if last_emit.elapsed() >= progress_deadline
            && splitter.last_height() != Some(cursor.end)
        {
            // Slow but alive: hand on what has arrived instead of failing the
            // attempt and re-downloading it. The plan chunk's final block is never
            // flushed here — the clean-end flush below carries `is_last`.
            if let Some((blocks, bytes)) = splitter.take_partial() {
                debug!(
                    plan_index = cursor.plan_index,
                    blocks = blocks.len(),
                    "sub-chunk deadline reached — handing on the blocks received so far"
                );
                if !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await {
                    return Ok(PumpOutcome::ConsumerGone);
                }
                last_emit = tokio::time::Instant::now();
            }
        }
    }
}

/// Opens the (resume-aware) GetBlockRange stream and pumps it into sub-chunks.
async fn open_and_pump(
    client: &mut LwdClient,
    cursor: &mut PlanChunkCursor,
    plan: &FetchPlan,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
    progress: Option<&Progress>,
) -> Result<PumpOutcome, SlipstreamError> {
    let req = BlockRange {
        start: Some(BlockId {
            height: cursor.resume_from,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: cursor.end,
            hash: vec![],
        }),
        ..Default::default()
    };
    // B2 (#1755): response-headers deadline. A server that accepts the request
    // but never answers must fail fast into the worker's retry+reconnect loop.
    let mut stream = tokio::time::timeout(grpc::UNARY_TIMEOUT, client.get_block_range(req))
        .await
        .map_err(|_| {
            SlipstreamError::Transport(format!(
                "get_block_range {}..{}: timed out after {}s",
                cursor.resume_from,
                cursor.end,
                grpc::UNARY_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            SlipstreamError::Transport(format!(
                "get_block_range {}..{}: {e}",
                cursor.resume_from, cursor.end
            ))
        })?
        .into_inner();
    pump_block_stream(
        &mut stream,
        cursor,
        plan.split_bytes,
        plan.chunk_timeout,
        gate,
        out,
        progress,
    )
    .await
}

async fn worker(
    worker_id: usize,
    endpoint: Endpoint,
    plan: FetchPlan,
    next: Arc<AtomicU64>,
    gate: AheadGate,
    out: mpsc::Sender<SubChunk>,
    progress: Option<Arc<Progress>>,
) -> Result<(), SlipstreamError> {
    let mut client = connect_direct_with_retry(&endpoint).await?;
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        if index >= plan.chunk_count() {
            debug!(worker_id, "no more chunks");
            return Ok(());
        }
        let (s, e) = plan.chunk_range(index);
        let mut cursor = PlanChunkCursor {
            plan_index: index,
            end: e,
            resume_from: s,
            next_sub_index: 0,
            emitted_this_attempt: false,
        };
        // Counts consecutive ZERO-PROGRESS attempts; an attempt that emitted a
        // sub-chunk resets the budget (resume makes such retries cheap and the
        // total attempt count stays bounded by sub-chunks × retries).
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            cursor.emitted_this_attempt = false;
            match open_and_pump(
                &mut client,
                &mut cursor,
                &plan,
                &gate,
                &out,
                progress.as_deref(),
            )
            .await
            {
                Ok(PumpOutcome::Completed) => break,
                Ok(PumpOutcome::ConsumerGone) => return Ok(()), // reorder stage gone (abort)
                Err(err) => {
                    let failed_attempt = attempt;
                    if cursor.emitted_this_attempt {
                        attempt = 0; // progress was made — fresh retry budget
                    }
                    if attempt > plan.retries_per_chunk {
                        return Err(SlipstreamError::Transport(format!(
                            "plan chunk {index} ({s}..{e}) failed after {attempt} zero-progress attempts: {err}"
                        )));
                    }
                    warn!(
                        worker_id,
                        index,
                        attempt = failed_attempt,
                        made_progress = cursor.emitted_this_attempt,
                        resume_from = cursor.resume_from,
                        %err,
                        "chunk fetch failed; retrying from resume height"
                    );
                    // Exponent capped: retries_per_chunk is a pub tunable; uncapped 2^n overflows u64.
                    tokio::time::sleep(Duration::from_millis(
                        250u64.saturating_mul(1 << attempt.saturating_sub(1).min(10)),
                    ))
                    .await;
                    // Reconnect: the channel may be poisoned after a stream error. Resilient to a
                    // brief server outage (bounded retry-with-backoff) so a transient connect blip
                    // resumes this chunk in place instead of failing it → restarting the whole pass.
                    client = connect_direct_with_retry(&endpoint).await?;
                }
            }
        }
    }
}

// ── v0.7 P2: wire-collapse detector ───────────────────────────────────────────

/// [v0.7 P2] The wire-collapse detector. Lives in the reorder stage because
/// that is the ONE place where wire-starve and scan-backpressure are
/// structurally distinguishable: when scan lags, the ChunkQueue fills and
/// the reorder stage blocks in `queue.send` (arrivals keep landing in the
/// rx buffer); when the WIRE starves, the stage blocks in `rx.recv` with
/// nothing arriving. Only recv-blocked time feeds this detector, so a slow
/// device can never trip a failover.
///
/// Two triggers (see [`WireFailoverArm`] for the shipped thresholds):
/// - STALL: ≥ `stall_secs` consecutive recv-blocked seconds, zero arrivals.
/// - COLLAPSE: the rolling window rate drops below `collapse_fraction` of
///   the pass's best window AND below `painful_mbps` (or below the
///   unconditional `floor_mbps`) — a healthy→sick transition that is
///   actually worth a switch, never a "20 → 3 MB/s" over-reaction and
///   never a steady-slow pass tripping against its own baseline (that
///   shape means the ACCESS network is the constraint — switching servers
///   cannot help, as the 2026-07-08 hotel day proved).
///
/// Clock-free (methods take `now_s` = seconds since fetch begin) so the
/// trigger logic unit-tests without sleeping.
struct WireDetector {
    arm: WireFailoverArm,
    /// (secs since start, cumulative bytes) — pushed per arrival.
    samples: Vec<(f64, u64)>,
    cum_bytes: u64,
    /// Consecutive recv-starve seconds (reset on any arrival).
    starve_secs: u64,
    /// Best rolling-window rate observed this pass (MB/s).
    best_window_mbps: f64,
}

/// Rolling window length for the collapse trigger.
const DETECT_WINDOW_S: f64 = 10.0;
/// No firing before this much wall + data (connect/ramp grace).
const DETECT_WARMUP_S: f64 = 15.0;
const DETECT_WARMUP_BYTES: u64 = 4 * 1024 * 1024;

impl WireDetector {
    fn new(arm: WireFailoverArm) -> Self {
        Self {
            arm,
            samples: Vec::new(),
            cum_bytes: 0,
            starve_secs: 0,
            best_window_mbps: 0.0,
        }
    }

    fn warmed_up(&self, now_s: f64) -> bool {
        now_s > DETECT_WARMUP_S && self.cum_bytes > DETECT_WARMUP_BYTES
    }

    /// Rate over the trailing [`DETECT_WINDOW_S`] seconds, MB/s (None until
    /// the pass is older than the window).
    fn window_mbps(&self, now_s: f64) -> Option<f64> {
        let cut = now_s - DETECT_WINDOW_S;
        if cut <= 0.0 {
            return None;
        }
        // Bytes at the window start = last sample at or before `cut`
        // (no sample that old ⇒ everything arrived inside the window ⇒
        // base 0 would overstate the window; use the oldest sample's base).
        let base = self
            .samples
            .iter()
            .rev()
            .find(|(t, _)| *t <= cut)
            .map_or(0, |(_, b)| *b);
        Some(self.cum_bytes.saturating_sub(base) as f64 / (1024.0 * 1024.0) / DETECT_WINDOW_S)
    }

    /// Record an arrival; may fire the COLLAPSE trigger.
    fn arrival(&mut self, bytes: u64, now_s: f64) -> Result<(), SlipstreamError> {
        self.starve_secs = 0;
        self.cum_bytes += bytes;
        self.samples.push((now_s, self.cum_bytes));
        let Some(rate) = self.window_mbps(now_s) else {
            return Ok(());
        };
        if rate > self.best_window_mbps {
            self.best_window_mbps = rate;
        }
        if !self.warmed_up(now_s) {
            return Ok(());
        }
        let relative_floor = self.arm.collapse_fraction * self.best_window_mbps;
        let collapsed =
            (rate < relative_floor && rate < self.arm.painful_mbps) || rate < self.arm.floor_mbps;
        if collapsed {
            return Err(SlipstreamError::WireCollapse {
                measured_mbps: rate,
                floor_mbps: relative_floor
                    .min(self.arm.painful_mbps)
                    .max(self.arm.floor_mbps),
            });
        }
        Ok(())
    }

    /// Record one second recv-blocked with zero arrivals; may fire STALL.
    fn starve_tick(&mut self, now_s: f64) -> Result<(), SlipstreamError> {
        self.starve_secs += 1;
        if self.warmed_up(now_s) && self.starve_secs >= self.arm.stall_secs {
            return Err(SlipstreamError::WireCollapse {
                measured_mbps: 0.0,
                floor_mbps: self.arm.floor_mbps,
            });
        }
        Ok(())
    }
}

// ── T6.8-S reorder/release stage ───────────────────────────────────────────────

#[derive(Debug, Default)]
struct ReleaseSummary {
    blocks: u64,
    bytes: u64,
    /// Plan chunks fully released (`is_last` seen) — completeness-check input.
    plans_released: u64,
    /// [v0.7 P0] (secs since fetch begin, cumulative bytes) at every
    /// sub-chunk ARRIVAL (not ordered release — a sub-chunk parked in the
    /// reorder buffer already crossed the wire).
    wire_samples: Vec<(f64, u64)>,
}

/// Reorder stage: receives sub-chunks in any cross-worker order and releases
/// them strictly in (plan_index, sub_index) order into the ChunkQueue,
/// advancing to plan chunk N+1 only after N's `is_last`. Each release also
/// advances the AheadGate floor so the worker owning the floor plan chunk
/// streams unthrottled and budget held by newly-floored sub-chunks drains.
///
/// After each release `unreleased_from` holds the lowest height not yet handed to the scanner.
async fn release_ordered(
    rx: &mut mpsc::Receiver<SubChunk>,
    queue: &ChunkQueueSender,
    progress: Option<&Arc<Progress>>,
    floor: &AtomicU64,
    unreleased_from: &AtomicU64,
    started: Instant,
    failover: Option<WireFailoverArm>,
) -> Result<ReleaseSummary, SlipstreamError> {
    let mut summary = ReleaseSummary::default();
    let mut continuity = Continuity::default();
    let mut pending: BTreeMap<(u64, u64), SubChunk> = BTreeMap::new();
    let mut next: (u64, u64) = (0, 0);
    // Dense queue-chunk counter (Chunk.index contract: consecutive from 0).
    let mut emitted_chunks: u64 = 0;
    // Per-plan-chunk split accounting for the info! summary line.
    let (mut plan_subs, mut plan_blocks, mut plan_bytes) = (0u64, 0u64, 0u64);
    // [v0.7 P0] cumulative wire bytes at arrival, for the health timeline.
    let mut wire_cum: u64 = 0;
    // [v0.7 P2] armed only when the engine has somewhere to fail over TO.
    let mut detector = failover.map(WireDetector::new);

    loop {
        // Sliced recv: every full second spent HERE is recv-blocked time —
        // wire-attributed by construction (scan backpressure blocks this
        // stage in `queue.send` below, never here).
        let sub = loop {
            match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                Ok(Some(s)) => break Some(s),
                Ok(None) => break None,
                Err(_) => {
                    if let Some(d) = detector.as_mut() {
                        d.starve_tick(started.elapsed().as_secs_f64())?;
                    }
                }
            }
        };
        let Some(sub) = sub else { break };
        wire_cum += sub.bytes as u64;
        summary
            .wire_samples
            .push((started.elapsed().as_secs_f64(), wire_cum));
        if let Some(d) = detector.as_mut() {
            d.arrival(sub.bytes as u64, started.elapsed().as_secs_f64())?;
        }
        pending.insert((sub.plan_index, sub.sub_index), sub);
        while let Some(sub) = pending.remove(&next) {
            let SubChunk {
                plan_index,
                is_last,
                bytes,
                blocks,
                permit,
                ..
            } = sub;
            continuity.verify_blocks(&blocks)?;
            // Where the download stands once this sub-chunk is released.
            let released_from = blocks.first().map(|b| b.height);
            let released_through = blocks.last().map(|b| b.height);
            let chunk = Chunk::from_blocks(emitted_chunks, blocks);
            let chunk_block_count = chunk.blocks.len() as u64;
            summary.blocks += chunk_block_count;
            summary.bytes += chunk.estimated_bytes as u64;
            plan_subs += 1;
            plan_blocks += chunk_block_count;
            plan_bytes += bytes as u64;
            // Bump the shared progress counter (poll-based; Relaxed — no ordering guarantee).
            if let Some(p) = progress {
                p.add_fetched(chunk_block_count);
            }
            queue.send(chunk).await?;
            if let Some(height) = released_through {
                unreleased_from.store(height + 1, Ordering::Release);
            }
            if let (Some(p), Some(first), Some(last)) = (progress, released_from, released_through)
            {
                p.note_blocks_released(first, last);
            }
            emitted_chunks += 1;
            // Ahead-budget permit held until the ChunkQueue takes over.
            drop(permit);
            if is_last {
                if plan_subs > 1 {
                    info!(
                        plan_index,
                        subs = plan_subs,
                        blocks = plan_blocks,
                        mb = plan_bytes / (1024 * 1024),
                        "plan chunk split into sub-chunks"
                    );
                }
                summary.plans_released += 1;
                (plan_subs, plan_blocks, plan_bytes) = (0, 0, 0);
                next = (plan_index + 1, 0);
                floor.store(plan_index + 1, Ordering::Release);
            } else {
                next.1 += 1;
            }
        }
    }
    Ok(summary)
}

/// A worker failure (error or panic) fails the fetch: the download gave up with
/// `unreleased_from` as the lowest block it had not handed to the scanner. Records nothing once
/// `unreleased_from` is past `plan_end`: every block of the plan was already handed on.
fn note_give_up(progress: Option<&Progress>, unreleased_from: &AtomicU64, plan_end: u64) {
    let at_height = unreleased_from.load(Ordering::Acquire);
    if let Some(p) = progress
        && at_height <= plan_end
    {
        p.note_download_gave_up(at_height);
    }
}

/// Drives the ordered release while supervising the fetch workers.
///
/// A worker that gives up on its plan chunk (retry budget exhausted, or its
/// reconnect failed) used to surface only after the release loop ended. But the
/// release loop waits for exactly that chunk, and the workers ahead of it block
/// on the ahead budget once it is spent — so the pass hung in `Syncing` with no
/// progress. The first worker failure now aborts every other worker and fails
/// the fetch immediately; it is a `Transport` error, so the pass-level retry
/// ladder takes over. A release error aborts the workers the same way.
///
/// When `failover` is armed (`Some`), a worker giving up is treated as the full
/// wire stall the wire-collapse detector would eventually have raised on its
/// own: the failure is remapped to `WireCollapse` (0.0 MB/s, the arm's floor)
/// so the engine's failover loop switches to an alternate endpoint at once
/// instead of retrying the same one. Worker panics and release errors are
/// unaffected by `failover` either way.
///
/// Every worker failure — an error or a panic, armed or not — is also recorded on `progress` as
/// a download give-up at `unreleased_from`, the lowest block the ordered release has not handed
/// to the scanner (see `Progress::note_download_gave_up`), as long as that block is within the
/// plan (`unreleased_from <= plan_end`). The fetch starts a worker per stream whatever its chunk
/// count, so an idle spare worker that cannot connect can fail it after every block was
/// already released; the cursor then reads `plan_end + 1`, a block no release of this plan will
/// ever cover, and nothing is recorded — the fetch still fails. A release error is not a
/// download give-up and is not recorded.
async fn supervise_fetch<R>(
    release: R,
    mut workers: JoinSet<Result<(), SlipstreamError>>,
    failover: Option<WireFailoverArm>,
    progress: Option<&Progress>,
    unreleased_from: &AtomicU64,
    plan_end: u64,
) -> Result<ReleaseSummary, SlipstreamError>
where
    R: std::future::Future<Output = Result<ReleaseSummary, SlipstreamError>>,
{
    tokio::pin!(release);
    let mut released: Option<ReleaseSummary> = None;
    loop {
        if workers.is_empty()
            && let Some(summary) = released.take()
        {
            return Ok(summary);
        }
        tokio::select! {
            biased;
            Some(joined) = workers.join_next(), if !workers.is_empty() => match joined {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    workers.abort_all();
                    note_give_up(progress, unreleased_from, plan_end);
                    if let Some(arm) = failover {
                        warn!(%err, "fetch worker gave up — failing over as a full wire stall");
                        return Err(SlipstreamError::WireCollapse {
                            measured_mbps: 0.0,
                            floor_mbps: arm.floor_mbps,
                        });
                    }
                    return Err(err);
                }
                Err(join_err) => {
                    workers.abort_all();
                    note_give_up(progress, unreleased_from, plan_end);
                    return Err(SlipstreamError::Transport(format!(
                        "worker panicked: {join_err}"
                    )));
                }
            },
            result = &mut release, if released.is_none() => match result {
                Ok(summary) => released = Some(summary),
                Err(err) => {
                    workers.abort_all();
                    return Err(err);
                }
            },
        }
    }
}

/// Fetch `plan.start..=plan.end` with `plan.streams` workers; emits ordered,
/// continuity-verified chunks into `queue`. Returns stats on success.
///
/// `progress` — if `Some`, bumps `fetched_blocks` by the block count of each
/// ordered sub-chunk as it is released (Relaxed atomic; no cross-counter guarantees).
pub async fn run_fetch(
    endpoint: &Endpoint,
    plan: FetchPlan,
    queue: ChunkQueueSender,
    progress: Option<Arc<Progress>>,
) -> Result<FetchStats, SlipstreamError> {
    let started = Instant::now();
    let chunk_count = plan.chunk_count();
    info!(
        start = plan.start,
        end = plan.end,
        chunk_count,
        streams = plan.streams,
        split_bytes = plan.split_bytes,
        "fetch begin"
    );

    let next = Arc::new(AtomicU64::new(0));
    let floor = Arc::new(AtomicU64::new(0));
    let gate = AheadGate::new(
        plan.split_bytes.saturating_mul(AHEAD_BUDGET_FACTOR),
        Arc::clone(&floor),
    );
    // Small reorder margin: each message is one sub-chunk (≤ ~split_bytes).
    let (tx, mut rx) = mpsc::channel::<SubChunk>(plan.streams.max(1));

    // The lowest block not yet handed to the scanner: where the download stands if a worker
    // gives up (see `supervise_fetch`).
    let unreleased_from = AtomicU64::new(plan.start);

    let mut workers = JoinSet::new();
    for worker_id in 0..plan.streams.max(1) {
        workers.spawn(worker(
            worker_id,
            endpoint.clone(),
            plan.clone(),
            Arc::clone(&next),
            gate.clone(),
            tx.clone(),
            progress.clone(),
        ));
    }
    drop(tx); // release loop ends when all workers finish

    // Workers are supervised WHILE the ordered release runs: one that gives up
    // fails the fetch now (see `supervise_fetch`) instead of after a release
    // that is waiting for its chunk.
    let summary = supervise_fetch(
        release_ordered(
            &mut rx,
            &queue,
            progress.as_ref(),
            &floor,
            &unreleased_from,
            started,
            plan.failover,
        ),
        workers,
        plan.failover,
        progress.as_deref(),
        &unreleased_from,
        plan.end,
    )
    .await?;

    if summary.plans_released != chunk_count {
        return Err(SlipstreamError::Transport(format!(
            "fetch incomplete: released {}/{chunk_count} plan chunks",
            summary.plans_released
        )));
    }
    let stats = FetchStats {
        blocks: summary.blocks,
        bytes: summary.bytes,
        elapsed: started.elapsed(),
        wire_samples: summary.wire_samples,
    };
    info!(
        blocks = stats.blocks,
        mb = stats.bytes / (1024 * 1024),
        elapsed_s = stats.elapsed.as_secs(),
        wire_mbps = format!("{:.1}", stats.megabytes_per_sec()).as_str(),
        wire_worst_5s_mbps = format!("{:.1}", stats.worst_window_mbps(5.0)).as_str(),
        "fetch done"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::chunk_queue;
    use futures_util::{StreamExt, stream};

    #[test]
    fn plan_chunking_covers_range_exactly() {
        let p = FetchPlan::new(1000, 1999, 300, 4);
        assert_eq!(p.chunk_count(), 4);
        assert_eq!(p.chunk_range(0), (1000, 1299));
        assert_eq!(p.chunk_range(3), (1900, 1999));
    }

    #[test]
    fn plan_single_block_range() {
        let p = FetchPlan::new(5, 5, 100, 2);
        assert_eq!(p.chunk_count(), 1);
        assert_eq!(p.chunk_range(0), (5, 5));
    }

    #[test]
    #[should_panic(expected = "FetchPlan: start")]
    fn plan_rejects_inverted_range() {
        FetchPlan::new(1000, 999, 100, 1);
    }

    // ── T6.8-S helpers ─────────────────────────────────────────────────────────

    /// Block with a controllable wire size via the `header` field; prev_hash
    /// links to height-1 so released runs pass Continuity.
    fn block_sized(height: u64, payload: usize) -> CompactBlock {
        CompactBlock {
            height,
            hash: hash_of(height),
            prev_hash: hash_of(height - 1),
            header: vec![0xAB; payload],
            ..Default::default()
        }
    }

    fn hash_of(height: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..8].copy_from_slice(&height.to_le_bytes());
        v
    }

    fn linked(from: u64, count: u64, payload: usize) -> Vec<CompactBlock> {
        (from..from + count)
            .map(|h| block_sized(h, payload))
            .collect()
    }

    fn test_cursor(plan_index: u64, start: u64, end: u64) -> PlanChunkCursor {
        PlanChunkCursor {
            plan_index,
            end,
            resume_from: start,
            next_sub_index: 0,
            emitted_this_attempt: false,
        }
    }

    /// Wide-open gate (huge budget) for pump tests that aren't about admission.
    fn open_gate() -> AheadGate {
        AheadGate::new(1 << 30, Arc::new(AtomicU64::new(0)))
    }

    fn drain_subs(rx: &mut mpsc::Receiver<SubChunk>) -> Vec<SubChunk> {
        let mut subs = Vec::new();
        while let Ok(s) = rx.try_recv() {
            subs.push(s);
        }
        subs
    }

    fn assert_heights_consecutive(subs: &[SubChunk], from: u64, to: u64) {
        let heights: Vec<u64> = subs
            .iter()
            .flat_map(|s| s.blocks.iter().map(|b| b.height))
            .collect();
        let expected: Vec<u64> = (from..=to).collect();
        assert_eq!(
            heights, expected,
            "released heights must be exactly {from}..={to}, no dups"
        );
    }

    // ── ChunkSplitter ──────────────────────────────────────────────────────────

    #[test]
    fn splitter_small_blocks_single_subchunk_fast_path() {
        let mut s = ChunkSplitter::new(1024 * 1024);
        for b in linked(100, 10, 16) {
            assert!(s.push(b).is_none(), "small blocks must not split");
        }
        let (blocks, bytes) = s.finish().expect("tail");
        assert_eq!(blocks.len(), 10);
        assert_eq!(
            blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            (100..110).collect::<Vec<_>>()
        );
        assert!(bytes > 0);
    }

    #[test]
    fn splitter_splits_at_threshold_preserving_order() {
        // ~1040-byte blocks against a 2500-byte budget → 2-block sub-chunks.
        let mut s = ChunkSplitter::new(2500);
        let mut emitted: Vec<Vec<CompactBlock>> = Vec::new();
        for b in linked(100, 7, 1000) {
            if let Some((blocks, bytes)) = s.push(b) {
                assert!(bytes <= 2500, "emitted sub-chunk must respect the budget");
                emitted.push(blocks);
            }
        }
        if let Some((blocks, _)) = s.finish() {
            emitted.push(blocks);
        }
        assert_eq!(
            emitted.len(),
            4,
            "7 blocks at 2/sub-chunk = 3 full + 1 tail"
        );
        assert_eq!(
            emitted.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![2, 2, 2, 1]
        );
        let heights: Vec<u64> = emitted.iter().flatten().map(|b| b.height).collect();
        assert_eq!(
            heights,
            (100..107).collect::<Vec<_>>(),
            "order preserved, nothing lost"
        );
    }

    #[test]
    fn splitter_oversized_block_forms_own_subchunk() {
        let mut s = ChunkSplitter::new(1000);
        assert!(
            s.push(block_sized(100, 5000)).is_none(),
            "first block always accumulates"
        );
        let (blocks, _) = s
            .push(block_sized(101, 5000))
            .expect("oversized block flushes alone");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 100);
        let (tail, _) = s.finish().expect("tail");
        assert_eq!(tail[0].height, 101);
    }

    #[test]
    fn splitter_empty_finish_is_none() {
        assert!(ChunkSplitter::new(1000).finish().is_none());
    }

    #[test]
    fn splitter_take_partial_flushes_and_resets() {
        let mut sp = ChunkSplitter::new(1 << 30);
        assert!(sp.take_partial().is_none(), "nothing buffered yet");
        for h in 100..103 {
            assert!(sp.push(block_sized(h, 1000)).is_none());
        }
        assert_eq!(sp.last_height(), Some(102));
        let (blocks, bytes) = sp.take_partial().expect("three blocks buffered");
        assert_eq!(
            blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![100, 101, 102]
        );
        assert!(bytes > 0);
        assert!(
            sp.take_partial().is_none(),
            "the flush empties the splitter"
        );
        assert_eq!(sp.last_height(), None);
        assert!(sp.push(block_sized(103, 1000)).is_none());
        let (tail, _) = sp.finish().expect("splitting continues after a flush");
        assert_eq!(tail.iter().map(|b| b.height).collect::<Vec<_>>(), vec![103]);
    }

    // ── pump_block_stream ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pump_emits_ordered_subchunks_with_final_marker() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        let mut s = stream::iter(
            linked(100, 20, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            2500,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("pump");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert!(subs.len() > 1, "split must produce multiple sub-chunks");
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense from 0"
        );
        let lasts: Vec<bool> = subs.iter().map(|s| s.is_last).collect();
        assert!(
            lasts.iter().rev().skip(1).all(|l| !*l),
            "only the final sub-chunk is last"
        );
        assert!(
            *lasts.last().expect("nonempty"),
            "final sub-chunk carries is_last"
        );
        assert_heights_consecutive(&subs, 100, 119);
        assert_eq!(
            cursor.resume_from, 120,
            "cursor advanced past the plan chunk"
        );
        assert_eq!(cursor.next_sub_index, subs.len() as u64);
    }

    #[tokio::test]
    async fn pump_small_chunk_single_subchunk_fast_path() {
        // Default-sized budget swallowing the whole plan chunk → exactly one
        // sub-chunk, is_last=true: today's behaviour, one queue chunk per plan chunk.
        let (tx, mut rx) = mpsc::channel::<SubChunk>(8);
        let gate = open_gate();
        let mut cursor = test_cursor(3, 100, 109);
        let mut s = stream::iter(
            linked(100, 10, 100)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("pump");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(
            subs.len(),
            1,
            "normal-era plan chunk = exactly one sub-chunk"
        );
        assert!(subs[0].is_last);
        assert_eq!(subs[0].sub_index, 0);
        assert_eq!(subs[0].blocks.len(), 10);
    }

    #[tokio::test]
    async fn pump_short_stream_hands_on_its_tail_then_errors() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        // Clean end at 111 — 8 blocks short.
        let mut s = stream::iter(
            linked(100, 12, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            2500,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("short stream must error");
        assert!(err.to_string().contains("ended short"), "got: {err}");
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert!(
            subs.iter().all(|s| !s.is_last),
            "no is_last on a short stream"
        );
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense from 0"
        );
        // 12 blocks at 2/sub-chunk → 5 full sub-chunks (10 blocks), then the
        // 2-block tail is handed on before the error: every block exactly once.
        assert_heights_consecutive(&subs, 100, 111);
        assert_eq!(cursor.resume_from, 112, "the retry resumes after the tail");
    }

    /// THE retry-resume contract (T6.8-S): a mid-plan-chunk failure hands on
    /// what it received and resumes from the next height; the consumer sees
    /// every height exactly once and the sub_index sequence stays dense.
    #[tokio::test]
    async fn pump_resume_after_midstream_error_no_duplicates() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 139);

        // Attempt 1: 18 blocks then a transport error.
        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(100, 18, 1000).into_iter().map(Ok).collect();
        items.push(Err(tonic::Status::unavailable("backend dropped")));
        let mut s1 = stream::iter(items);
        let err = pump_block_stream(
            &mut s1,
            &mut cursor,
            2500,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("attempt 1 must surface the stream error");
        assert!(err.to_string().contains("backend dropped"), "got: {err}");
        assert!(cursor.emitted_this_attempt, "attempt 1 made progress");
        // 18 blocks at 2/sub-chunk → 8 full sub-chunks (16 blocks), then the
        // 2-block tail is handed on before the error.
        assert_eq!(cursor.resume_from, 118, "resume = last received height + 1");
        let subs_before = cursor.next_sub_index;

        // Attempt 2 (the worker's retry): resume_from..=end, clean.
        let mut s2 = stream::iter(
            linked(cursor.resume_from, 140 - cursor.resume_from, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s2,
            &mut cursor,
            2500,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("attempt 2 completes");
        assert!(matches!(out, PumpOutcome::Completed));
        assert!(
            cursor.next_sub_index > subs_before,
            "sub_index continued, not reset"
        );

        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense across the retry boundary"
        );
        assert_eq!(
            subs.iter().filter(|s| s.is_last).count(),
            1,
            "exactly one is_last"
        );
        assert!(subs.last().expect("nonempty").is_last);
        assert_heights_consecutive(&subs, 100, 139);
    }

    /// Healthy-but-slow giant chunk: per-sub-chunk deadline RESETS on every
    /// emission, so total stream time far beyond the deadline still completes.
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_resets_on_each_emitted_subchunk() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        // One block per simulated second; 2-block sub-chunks → an emission every
        // ~2s against a 5s deadline; total 30s >> 5s.
        let mut s = Box::pin(stream::unfold(100u64, |h| async move {
            if h > 129 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, tonic::Status>(block_sized(h, 1000)), h + 1))
        }));
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            2500,
            Duration::from_secs(5),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("slow-but-progressing stream must complete");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 129);
    }

    /// Slow but alive: the budget never fills, yet the deadline no longer fails
    /// the attempt — the blocks received so far are handed on and the stream
    /// continues to a clean end. Nothing is re-downloaded.
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_emits_partial_subchunk_instead_of_failing() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = Box::pin(stream::unfold(100u64, |h| async move {
            if h > 129 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, tonic::Status>(block_sized(h, 1000)), h + 1))
        }));
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(5),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("a slow but progressing stream must complete");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert!(
            subs.len() > 1,
            "the deadline must hand on partial sub-chunks"
        );
        assert_eq!(
            subs.iter().filter(|s| s.is_last).count(),
            1,
            "exactly one final marker"
        );
        assert!(
            subs.last().expect("non-empty").is_last,
            "the final marker comes last"
        );
        assert_heights_consecutive(&subs, 100, 129);
        assert_eq!(cursor.resume_from, 130);
        assert!(cursor.emitted_this_attempt);
    }

    /// The deadline must never flush the plan chunk's LAST block as a partial:
    /// only the clean-end flush carries `is_last`, and a flushed final block
    /// would leave nothing for it ("stream ended short").
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_never_flushes_the_plan_end_as_partial() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 102);
        // Arrivals at t=1s (100), t=7s (101: deadline passed → flush [100,101]),
        // t=13s (102 = plan end: deadline passed again, but must NOT flush).
        let delays = [1u64, 6, 6];
        let mut s = Box::pin(stream::unfold(0usize, move |i| async move {
            if i >= delays.len() {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(delays[i])).await;
            Some((
                Ok::<_, tonic::Status>(block_sized(100 + i as u64, 1000)),
                i + 1,
            ))
        }));
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(5),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("must complete, not end short");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        let shape: Vec<(Vec<u64>, bool)> = subs
            .iter()
            .map(|s| (s.blocks.iter().map(|b| b.height).collect(), s.is_last))
            .collect();
        assert_eq!(shape, vec![(vec![100, 101], false), (vec![102], true)]);
    }

    /// A stream that goes silent still fails the attempt (idle timeout); the
    /// deadline change does not keep a dead stream alive.
    #[tokio::test(start_paused = true)]
    async fn pump_silent_stream_still_fails_via_idle_timeout() {
        let (tx, _rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = Box::pin(
            stream::iter(vec![Ok::<_, tonic::Status>(block_sized(100, 1000))])
                .chain(stream::pending()),
        );
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(5),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("silence must fail the attempt");
        assert!(err.to_string().contains("idle timeout"), "got: {err}");
        assert_eq!(
            cursor.resume_from, 101,
            "the block received before the silence was handed on"
        );
    }

    /// A failing attempt hands on exactly the blocks it received — as non-final
    /// sub-chunks — so the worker's retry resumes after them.
    fn assert_handed_on_before_failing(
        subs: &[SubChunk],
        cursor: &PlanChunkCursor,
        from: u64,
        to: u64,
    ) {
        assert!(
            subs.iter().all(|s| !s.is_last),
            "a failing attempt never carries is_last"
        );
        assert_heights_consecutive(subs, from, to);
        assert_eq!(
            cursor.resume_from,
            to + 1,
            "the retry resumes after the handed-on blocks"
        );
        assert!(
            cursor.emitted_this_attempt,
            "handing on counts as progress for the retry budget"
        );
    }

    /// A stream error after N blocks hands those blocks on before failing, so the
    /// retry does not download them again.
    #[tokio::test]
    async fn pump_stream_error_hands_on_received_blocks_before_failing() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(100, 5, 1000).into_iter().map(Ok).collect();
        items.push(Err(tonic::Status::unavailable("backend dropped")));
        let mut s = stream::iter(items);
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("the stream error must still fail the attempt");
        assert!(err.to_string().contains("backend dropped"), "got: {err}");
        drop(tx);
        assert_handed_on_before_failing(&drain_subs(&mut rx), &cursor, 100, 104);
    }

    /// A stream that goes silent after N blocks hands those blocks on before the
    /// idle timeout fails the attempt.
    #[tokio::test(start_paused = true)]
    async fn pump_idle_stream_hands_on_received_blocks_before_failing() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = Box::pin(
            stream::iter(
                linked(100, 5, 1000)
                    .into_iter()
                    .map(Ok::<_, tonic::Status>)
                    .collect::<Vec<_>>(),
            )
            .chain(stream::pending()),
        );
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("silence must still fail the attempt");
        assert!(err.to_string().contains("idle timeout"), "got: {err}");
        drop(tx);
        assert_handed_on_before_failing(&drain_subs(&mut rx), &cursor, 100, 104);
    }

    /// A stream that ends cleanly after N blocks, short of the plan end, hands
    /// those blocks on before failing the attempt.
    #[tokio::test]
    async fn pump_short_end_hands_on_received_blocks_before_failing() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = stream::iter(
            linked(100, 5, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("a short stream must still fail the attempt");
        assert!(
            err.to_string().contains("ended short at 104, expected 129"),
            "got: {err}"
        );
        drop(tx);
        assert_handed_on_before_failing(&drain_subs(&mut rx), &cursor, 100, 104);
    }

    /// A failing attempt never emits the plan chunk's final block: only a clean
    /// end carries `is_last`, so a buffered tail that already reaches the plan
    /// end is left for the retry.
    #[tokio::test]
    async fn pump_error_after_the_plan_end_block_hands_nothing_on() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 102);
        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(100, 3, 1000).into_iter().map(Ok).collect();
        items.push(Err(tonic::Status::unavailable("backend dropped")));
        let mut s = stream::iter(items);
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect_err("the stream error must still fail the attempt");
        assert!(err.to_string().contains("backend dropped"), "got: {err}");
        drop(tx);
        assert!(
            drain_subs(&mut rx).is_empty(),
            "the plan end is never flushed"
        );
        assert_eq!(cursor.resume_from, 100);
        assert!(!cursor.emitted_this_attempt);
    }

    /// Liveness: every block received moves the stall clock, even while the
    /// sub-chunk it belongs to is still accumulating (nothing emitted yet).
    #[tokio::test(start_paused = true)]
    async fn pump_touches_progress_on_every_received_block() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let progress = Progress::default();
        progress.last_progress_unix.store(0, Ordering::Relaxed);
        // Block 100, then silence well inside the 30 s idle timeout.
        let mut s = Box::pin(
            stream::iter(vec![Ok::<_, tonic::Status>(block_sized(100, 1000))])
                .chain(stream::pending()),
        );
        let pumped = tokio::time::timeout(
            Duration::from_secs(10),
            pump_block_stream(
                &mut s,
                &mut cursor,
                usize::MAX >> 8,
                Duration::from_secs(120),
                &gate,
                &tx,
                Some(&progress),
            ),
        )
        .await;
        assert!(pumped.is_err(), "the pump is still waiting for block 101");
        assert!(
            progress.last_progress_unix_secs() > 0,
            "receiving block 100 must stamp the stall clock"
        );
        assert!(
            drain_subs(&mut rx).is_empty(),
            "nothing was emitted — the stamp came from the receive itself"
        );
    }

    // ── AheadGate ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn gate_floor_is_exempt_even_when_budget_exhausted() {
        let floor = Arc::new(AtomicU64::new(0));
        let gate = AheadGate::new(1000, Arc::clone(&floor));
        // Ahead worker (plan 1) takes the whole budget.
        let held = gate
            .admit(1, 1000)
            .await
            .expect("ahead worker gets a permit");
        // Floor worker (plan 0) is exempt — returns None immediately.
        assert!(
            gate.admit(0, 999_999).await.is_none(),
            "floor must not consume budget"
        );
        drop(held);
    }

    #[tokio::test]
    async fn gate_blocked_ahead_worker_unblocks_when_it_becomes_floor() {
        let floor = Arc::new(AtomicU64::new(0));
        let gate = AheadGate::new(1000, Arc::clone(&floor));
        let _held = gate.admit(1, 1000).await.expect("plan 1 drains the budget");
        // Plan 2 cannot acquire (budget empty) — parks in the poll loop.
        let gate2 = gate.clone();
        let waiter = tokio::spawn(async move { gate2.admit(2, 500).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !waiter.is_finished(),
            "ahead worker must wait while budget is held"
        );
        // The release stage advances the floor to 2 → exemption kicks in.
        floor.store(2, Ordering::Release);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must unblock after floor advance")
            .expect("join");
        assert!(got.is_none(), "now-floor worker proceeds without a permit");
    }

    // ── v0.7 P2: wire-collapse detector (clock-free trigger matrix) ────────────

    /// Feed `mbps` for `secs` seconds starting at `t0` (1 arrival/second).
    fn feed(d: &mut WireDetector, mbps: f64, t0: f64, secs: u64) -> Result<(), SlipstreamError> {
        let bytes = (mbps * 1024.0 * 1024.0) as u64;
        for i in 0..secs {
            d.arrival(bytes, t0 + i as f64 + 1.0)?;
        }
        Ok(())
    }

    /// The hotel shape: steady-slow never fires — a pass at its own
    /// baseline means the ACCESS network binds; switching cannot help.
    #[test]
    fn detector_steady_slow_never_fires() {
        let mut d = WireDetector::new(WireFailoverArm::default());
        feed(&mut d, 2.3, 0.0, 120).expect("steady 2.3 MB/s must never fire");
    }

    /// Healthy → collapsed (the P4 mid-pass gate's shape) fires within
    /// roughly one detection window of the collapse.
    #[test]
    fn detector_fires_on_healthy_to_collapse() {
        let mut d = WireDetector::new(WireFailoverArm::default());
        feed(&mut d, 14.0, 0.0, 30).expect("healthy phase");
        let err = feed(&mut d, 0.5, 30.0, 30).expect_err("collapse must fire");
        assert!(matches!(err, SlipstreamError::WireCollapse { .. }), "{err}");
    }

    /// A drop that is still comfortable (20 → 3 MB/s, above painful_mbps)
    /// must NOT fire — switching for a usable rate is churn.
    #[test]
    fn detector_no_overreaction_above_painful() {
        let mut d = WireDetector::new(WireFailoverArm::default());
        feed(&mut d, 20.0, 0.0, 30).expect("healthy phase");
        feed(&mut d, 3.0, 30.0, 60).expect("3 MB/s is usable — no fire");
    }

    /// Full stall: N consecutive recv-starved seconds fire; N−1 do not.
    #[test]
    fn detector_stall_threshold_exact() {
        let arm = WireFailoverArm::default();
        let mut d = WireDetector::new(arm);
        feed(&mut d, 10.0, 0.0, 20).expect("warmup");
        for i in 0..arm.stall_secs - 1 {
            d.starve_tick(20.0 + i as f64).expect("below threshold");
        }
        let err = d
            .starve_tick(20.0 + arm.stall_secs as f64)
            .expect_err("stall fires at N");
        assert!(
            matches!(err, SlipstreamError::WireCollapse { measured_mbps, .. } if measured_mbps == 0.0)
        );
    }

    /// A healthy-sized arrival resets the starve counter — reconnect blips
    /// survive as long as the delivered rate stays usable (an arrival too
    /// SMALL to keep the window above the painful floor is itself a
    /// collapse, by design — the sibling test above proves that fires).
    #[test]
    fn detector_arrival_resets_starve() {
        let arm = WireFailoverArm::default();
        let mut d = WireDetector::new(arm);
        feed(&mut d, 10.0, 0.0, 20).expect("warmup");
        for round in 0..3u64 {
            let base = 20.0 + round as f64 * 12.0;
            for i in 0..arm.stall_secs - 1 {
                d.starve_tick(base + i as f64).expect("below threshold");
            }
            // 40 MB after the gap keeps the 10 s window comfortably usable.
            d.arrival(40 * 1024 * 1024, base + (arm.stall_secs - 1) as f64)
                .expect("healthy blip arrival");
        }
    }

    /// Nothing fires before warmup — a slow connect/ramp is not a collapse.
    #[test]
    fn detector_silent_before_warmup() {
        let mut d = WireDetector::new(WireFailoverArm::default());
        // 10 s of trickle + 11 starves, all inside the warmup horizon.
        feed(&mut d, 0.05, 0.0, 10).expect("pre-warmup trickle");
        for i in 0..11u64 {
            d.starve_tick(10.0 + i as f64).expect("pre-warmup starves");
        }
    }

    /// The unconditional floor: a pass that never had a healthy best window
    /// still fires once the rate is below floor_mbps (unusable everywhere).
    #[test]
    fn detector_absolute_floor_fires() {
        let mut d = WireDetector::new(WireFailoverArm::default());
        // 0.1 MB/s from the start: warmup needs >4 MiB, so ~45 s in.
        let err = feed(&mut d, 0.1, 0.0, 120).expect_err("sub-floor trickle must fire");
        assert!(matches!(err, SlipstreamError::WireCollapse { .. }));
    }

    // ── release_ordered ────────────────────────────────────────────────────────

    fn sub(plan_index: u64, sub_index: u64, is_last: bool, blocks: Vec<CompactBlock>) -> SubChunk {
        let bytes = blocks.iter().map(Message::encoded_len).sum();
        SubChunk {
            plan_index,
            sub_index,
            is_last,
            bytes,
            blocks,
            permit: None,
        }
    }

    /// Multi-worker out-of-order completion: the consumer must receive strictly
    /// height-ordered chunks regardless of sub-chunk arrival order.
    #[tokio::test]
    async fn release_orders_scrambled_subchunks_strictly() {
        let all = linked(100, 60, 64);
        let subs = vec![
            // plan 2: [140-149](0), [150-159](1, last)
            sub(2, 1, true, all[50..60].to_vec()),
            // plan 1: [120-139](0, last)
            sub(1, 0, true, all[20..40].to_vec()),
            // plan 0: [100-109](0), [110-119](1, last)
            sub(0, 1, true, all[10..20].to_vec()),
            sub(2, 0, false, all[40..50].to_vec()),
            sub(0, 0, false, all[0..10].to_vec()),
        ];
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        for s in subs {
            tx.send(s).await.expect("send");
        }
        drop(tx);

        let (qtx, mut qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let summary = release_ordered(
            &mut rx,
            &qtx,
            None,
            &floor,
            &AtomicU64::new(0),
            Instant::now(),
            None,
        )
        .await
        .expect("release");
        assert_eq!(summary.plans_released, 3);
        assert_eq!(summary.blocks, 60);
        drop(qtx);

        let mut released_heights = Vec::new();
        let mut indices = Vec::new();
        while let Some((chunk, permit, _boundary)) = qrx.recv().await {
            indices.push(chunk.index);
            released_heights.extend(chunk.blocks.iter().map(|b| b.height));
            drop(permit);
        }
        assert_eq!(
            released_heights,
            (100..160).collect::<Vec<_>>(),
            "strict height order"
        );
        assert_eq!(
            indices,
            (0..5).collect::<Vec<_>>(),
            "queue chunk index dense from 0"
        );
        assert_eq!(
            floor.load(Ordering::Acquire),
            3,
            "floor advanced past the last plan chunk"
        );
    }

    /// Retry-continuation shape: plan 0's tail (emitted by a resumed attempt)
    /// arrives AFTER plan 1 completed — release order must still be plan 0
    /// fully, then plan 1.
    #[tokio::test]
    async fn release_waits_for_retry_continuation_before_advancing() {
        let all = linked(100, 30, 64);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, false, all[0..10].to_vec()))
            .await
            .expect("send");
        tx.send(sub(1, 0, true, all[20..30].to_vec()))
            .await
            .expect("send");
        // ...worker 0 reconnects and resumes...
        tx.send(sub(0, 1, true, all[10..20].to_vec()))
            .await
            .expect("send");
        drop(tx);

        let (qtx, mut qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let summary = release_ordered(
            &mut rx,
            &qtx,
            None,
            &floor,
            &AtomicU64::new(0),
            Instant::now(),
            None,
        )
        .await
        .expect("release");
        assert_eq!(summary.plans_released, 2);
        drop(qtx);
        let mut released_heights = Vec::new();
        while let Some((chunk, permit, _boundary)) = qrx.recv().await {
            released_heights.extend(chunk.blocks.iter().map(|b| b.height));
            drop(permit);
        }
        assert_eq!(released_heights, (100..130).collect::<Vec<_>>());
    }

    /// Continuity is verified ACROSS sub-chunk seams: a gap between two
    /// sub-chunks of the same plan chunk must fail the fetch.
    #[tokio::test]
    async fn release_rejects_gap_between_subchunks() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, false, linked(100, 5, 64)))
            .await
            .expect("send");
        tx.send(sub(0, 1, true, linked(200, 5, 64)))
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let err = release_ordered(
            &mut rx,
            &qtx,
            None,
            &floor,
            &AtomicU64::new(0),
            Instant::now(),
            None,
        )
        .await
        .expect_err("gap must fail");
        assert!(
            matches!(err, SlipstreamError::Discontinuity { at: 200, .. }),
            "got: {err}"
        );
    }

    // ── supervise_fetch: a failed worker fails the fetch at once ──────────────

    /// Drop guard that records the task it lives in being aborted (dropped).
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn pending_worker(
        dropped: &Arc<std::sync::atomic::AtomicBool>,
    ) -> impl std::future::Future<Output = Result<(), SlipstreamError>> + Send + 'static {
        let guard = DropFlag(Arc::clone(dropped));
        async move {
            let _guard = guard;
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    /// The field hang: one worker gives up on its chunk while another waits
    /// forever (blocked on the ahead budget behind that chunk) and the release
    /// waits for the missing chunk. The supervisor must fail at once and abort
    /// the waiting worker instead of hanging.
    #[tokio::test(start_paused = true)]
    async fn supervise_returns_first_worker_error_and_aborts_the_rest() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err(SlipstreamError::Transport("plan chunk 8 gave up".into()))
        });
        workers.spawn(pending_worker(&dropped));
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();

        let outcome = tokio::time::timeout(
            Duration::from_secs(600),
            supervise_fetch(release, workers, None, None, &AtomicU64::new(0), 0),
        )
        .await
        .expect("supervisor must not hang behind the failed chunk");

        let err = outcome.expect_err("a failed worker fails the fetch");
        assert!(
            err.to_string().contains("plan chunk 8 gave up"),
            "got: {err}"
        );
        tokio::task::yield_now().await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "the still-running worker must be aborted"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_returns_release_summary_when_all_workers_succeed() {
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..3 {
            workers.spawn(async { Ok(()) });
        }
        let release = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(ReleaseSummary {
                blocks: 7,
                ..Default::default()
            })
        };
        let summary = supervise_fetch(release, workers, None, None, &AtomicU64::new(0), 0)
            .await
            .expect("all workers succeeded");
        assert_eq!(summary.blocks, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_propagates_release_error_and_aborts_workers() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(pending_worker(&dropped));
        let release = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Err::<ReleaseSummary, _>(SlipstreamError::Transport("continuity broken".into()))
        };
        let err = supervise_fetch(release, workers, None, None, &AtomicU64::new(0), 0)
            .await
            .expect_err("a release error fails the fetch");
        assert!(err.to_string().contains("continuity broken"), "got: {err}");
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::SeqCst), "workers must be aborted");
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_maps_worker_panic_to_transport_error() {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            panic!("synthetic worker panic");
        });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        let err = supervise_fetch(release, workers, None, None, &AtomicU64::new(0), 0)
            .await
            .expect_err("a panicked worker fails the fetch");
        assert!(
            matches!(err, SlipstreamError::Transport(ref m) if m.contains("worker panicked")),
            "got: {err}"
        );
    }

    /// Old semantics kept: a worker error that is only joined after the release
    /// finished still fails the fetch.
    #[tokio::test(start_paused = true)]
    async fn supervise_reports_worker_error_joined_after_release_finished() {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Err(SlipstreamError::Transport("late failure".into()))
        });
        let release = async { Ok(ReleaseSummary::default()) };
        let err = supervise_fetch(release, workers, None, None, &AtomicU64::new(0), 0)
            .await
            .expect_err("the late worker error must surface");
        assert!(err.to_string().contains("late failure"), "got: {err}");
    }

    /// When wire failover is armed, a worker giving up must be treated as the
    /// full wire stall the detector would eventually have raised on its own —
    /// so the engine's failover loop can switch endpoints immediately instead
    /// of retrying the one that just gave up.
    #[tokio::test(start_paused = true)]
    async fn supervise_fails_over_when_armed_and_a_worker_gives_up() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err(SlipstreamError::Transport("plan chunk 8 gave up".into()))
        });
        workers.spawn(pending_worker(&dropped));
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        let arm = WireFailoverArm::default();

        let outcome = tokio::time::timeout(
            Duration::from_secs(600),
            supervise_fetch(release, workers, Some(arm), None, &AtomicU64::new(0), 0),
        )
        .await
        .expect("supervisor must not hang behind the failed chunk");

        let err = outcome.expect_err("a failed worker fails the fetch");
        match err {
            SlipstreamError::WireCollapse {
                measured_mbps,
                floor_mbps,
            } => {
                assert_eq!(measured_mbps, 0.0);
                assert_eq!(floor_mbps, arm.floor_mbps);
            }
            other => panic!("expected WireCollapse, got: {other}"),
        }
        tokio::task::yield_now().await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "the still-running worker must be aborted"
        );
    }

    /// Armed failover must not swallow a genuine worker panic into a
    /// WireCollapse — a panic is a bug, not a wire-quality signal.
    #[tokio::test(start_paused = true)]
    async fn supervise_maps_worker_panic_to_transport_error_even_when_armed() {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            panic!("synthetic worker panic");
        });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        let err = supervise_fetch(
            release,
            workers,
            Some(WireFailoverArm::default()),
            None,
            &AtomicU64::new(0),
            0,
        )
        .await
        .expect_err("a panicked worker fails the fetch");
        assert!(
            matches!(err, SlipstreamError::Transport(ref m) if m.contains("worker panicked")),
            "got: {err}"
        );
    }

    // ── download-failure stall: the release cursor and give-up records ────────

    /// After each ordered release the cursor names the lowest block not yet handed to the
    /// scanner; a sub-chunk that cannot be released yet (its predecessor never came) does not
    /// move it.
    #[tokio::test]
    async fn release_advances_the_unreleased_cursor_past_each_released_subchunk() {
        let all = linked(100, 30, 64);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, false, all[0..10].to_vec()))
            .await
            .expect("send");
        // Plan 1 arrives, but plan 0's tail never does: plan 1 cannot be released.
        tx.send(sub(1, 0, true, all[20..30].to_vec()))
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        let unreleased_from = AtomicU64::new(100);
        release_ordered(
            &mut rx,
            &qtx,
            None,
            &floor,
            &unreleased_from,
            Instant::now(),
            None,
        )
        .await
        .expect("the release ends when the channel closes");
        assert_eq!(
            unreleased_from.load(Ordering::Acquire),
            110,
            "blocks 100..=109 were released; 110 is the first that was not"
        );
    }

    /// A worker that gives up is recorded as a download give-up at the release cursor — also
    /// when the cursor sits on the plan's last block, which is then still undelivered.
    #[tokio::test(start_paused = true)]
    async fn supervise_records_a_worker_give_up_at_the_release_cursor() {
        let progress = Progress::default();
        let unreleased_from = AtomicU64::new(1_234);
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async { Err(SlipstreamError::Transport("plan chunk 8 gave up".into())) });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        supervise_fetch(
            release,
            workers,
            None,
            Some(&progress),
            &unreleased_from,
            1_234,
        )
        .await
        .expect_err("a failed worker fails the fetch");
        let runs = progress.download_failures();
        assert_eq!(
            runs.iter()
                .map(|run| (run.streak, run.at_height))
                .collect::<Vec<_>>(),
            vec![(1, 1_234)],
            "the give-up is recorded at the cursor"
        );
    }

    /// Armed failover still maps the give-up to WireCollapse — and still records it.
    #[tokio::test(start_paused = true)]
    async fn supervise_records_a_worker_give_up_when_armed_too() {
        let progress = Progress::default();
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async { Err(SlipstreamError::Transport("plan chunk 8 gave up".into())) });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        let err = supervise_fetch(
            release,
            workers,
            Some(WireFailoverArm::default()),
            Some(&progress),
            &AtomicU64::new(500),
            999,
        )
        .await
        .expect_err("a failed worker fails the fetch");
        assert!(
            matches!(err, SlipstreamError::WireCollapse { .. }),
            "got: {err}"
        );
        assert_eq!(
            progress
                .download_failures()
                .iter()
                .map(|run| run.at_height)
                .collect::<Vec<_>>(),
            vec![500]
        );
    }

    /// A panicked worker also stopped the download: it is recorded like a give-up.
    #[tokio::test(start_paused = true)]
    async fn supervise_records_a_worker_panic_as_a_give_up() {
        let progress = Progress::default();
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            panic!("synthetic worker panic");
        });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        supervise_fetch(
            release,
            workers,
            None,
            Some(&progress),
            &AtomicU64::new(42),
            99,
        )
        .await
        .expect_err("a panicked worker fails the fetch");
        assert_eq!(
            progress
                .download_failures()
                .iter()
                .map(|run| run.at_height)
                .collect::<Vec<_>>(),
            vec![42]
        );
    }

    /// A release error (continuity, a gone consumer) is not a download give-up.
    #[tokio::test(start_paused = true)]
    async fn supervise_does_not_record_a_release_error_as_a_give_up() {
        let progress = Progress::default();
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(std::future::pending::<Result<(), SlipstreamError>>());
        let release = async {
            Err::<ReleaseSummary, _>(SlipstreamError::Transport("continuity broken".into()))
        };
        supervise_fetch(
            release,
            workers,
            None,
            Some(&progress),
            &AtomicU64::new(7),
            99,
        )
        .await
        .expect_err("a release error fails the fetch");
        assert_eq!(progress.download_failures(), vec![]);
    }

    /// The fetch starts a worker per stream whatever its chunk count, so an idle spare worker
    /// that cannot connect can fail it after every block was already handed to the scanner.
    /// The cursor then reads one past the plan end, a block no release of this fetch will ever
    /// cover: the fetch still fails, but no give-up is recorded.
    #[tokio::test(start_paused = true)]
    async fn supervise_records_nothing_once_every_block_was_released() {
        let progress = Progress::default();
        let plan_end = 1_999;
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            Err(SlipstreamError::Transport(
                "spare worker could not connect".into(),
            ))
        });
        let release = std::future::pending::<Result<ReleaseSummary, SlipstreamError>>();
        let err = supervise_fetch(
            release,
            workers,
            None,
            Some(&progress),
            &AtomicU64::new(plan_end + 1),
            plan_end,
        )
        .await
        .expect_err("the failed worker still fails the fetch");
        assert!(
            err.to_string().contains("spare worker could not connect"),
            "got: {err}"
        );
        assert_eq!(
            progress.download_failures(),
            vec![],
            "nothing is left to deliver, so there is no stuck block to record"
        );
    }

    // ── release_ordered: a release can end an in-progress download-failure run ────

    /// A run recorded at a block the release actually reaches ends: the download got past it.
    #[tokio::test]
    async fn release_ordered_ends_a_run_the_release_covers() {
        let progress = Arc::new(Progress::default());
        progress.note_download_gave_up_at(105, 1_000);
        progress.note_download_gave_up_at(105, 1_010);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, true, linked(100, 10, 64))) // heights 100..=109, covers 105
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        release_ordered(
            &mut rx,
            &qtx,
            Some(&progress),
            &floor,
            &AtomicU64::new(0),
            Instant::now(),
            None,
        )
        .await
        .expect("release");
        assert_eq!(
            progress.download_failures(),
            vec![],
            "the release covers block 105 and ends the run"
        );
    }

    /// A run recorded at a block the release does not reach survives, streak unchanged.
    #[tokio::test]
    async fn release_ordered_keeps_a_run_the_release_does_not_cover() {
        let progress = Arc::new(Progress::default());
        progress.note_download_gave_up_at(105, 1_000);
        progress.note_download_gave_up_at(105, 1_010);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, true, linked(100, 5, 64))) // heights 100..=104, does not reach 105
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(0);
        release_ordered(
            &mut rx,
            &qtx,
            Some(&progress),
            &floor,
            &AtomicU64::new(0),
            Instant::now(),
            None,
        )
        .await
        .expect("release");
        assert_eq!(
            progress
                .download_failures()
                .iter()
                .map(|run| run.streak)
                .collect::<Vec<_>>(),
            vec![2],
            "the release never reaches block 105 — the run must survive"
        );
    }
}
