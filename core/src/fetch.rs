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
//! stream into byte- AND block-count-budgeted SUB-chunks (T6.8-S; the
//! block-count side landed in DEV-5) so spam-era plan chunks (mainnet
//! "sandblasting" ~1.70M–2.00M: hundreds of MB per 10k blocks) stay
//! memory-bounded and timeout-immune, AND so a middle-density plan chunk that
//! stays under the byte budget (~10,000 small messages on one gRPC stream)
//! is less likely to trip h2's own per-stream small-DATA-frame guard (`GoAway
//! b"too_many_data_frames" ENHANCE_YOUR_CALM`; field-reproduced at
//! 3,355,000..3,364,999 — see `DEV-5-FRAMECAP-REPORT.md`). A reorder stage
//! releases sub-chunks strictly in (plan_index, sub_index) order —
//! continuity-verified — into the byte-budgeted ChunkQueue. Splitting +
//! resume-from-height retry landed in run T6.8-S, 2026-06-12; the
//! block-count cap landed in DEV-5.
//!
//! \[DEV-6\] DEV-5's `chunk_split_blocks` is a proactive CONSTANT — sized for
//! the one failing range that had been field-observed when it shipped, blind
//! to any budget it wasn't tuned against. `worker`'s retry path adds the
//! reactive counterpart: when a request attempt fails with SPECIFICALLY the
//! classified GoAway (`is_goaway_frame_overload`, this file) — h2's own
//! locally-raised `too_many_data_frames`/`ENHANCE_YOUR_CALM` self-protection,
//! see that function's doc for the primary-source citation of WHERE the
//! error actually originates — the worker immediately halves the failing
//! attempt's requested block span (`goaway_halved_cap`) and re-issues a
//! smaller `GetBlockRange` call from the same recorded resume height, no
//! sleep, outside the zero-progress retry-strike accounting entirely. This
//! repeats, halving again on each further classified GoAway, down to a
//! 1,000-block floor (`GOAWAY_ADAPTIVE_FLOOR_BLOCKS`); a request already at
//! the floor that still GoAways is treated as a genuine failure and falls
//! through to the pre-DEV-6 zero-progress sleep-ladder unchanged. The
//! resulting extra sub-requests are just more grist for the SAME
//! resume-from-height/sub_index machinery T6.8-S already built for
//! error-triggered retries — `PlanChunkCursor::request_end` is the only new
//! seam, threaded through `open_and_pump`/`pump_block_stream` alongside the
//! plan chunk's true end (which alone still governs `is_last`).

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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
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
    /// Per-SUB-chunk progress deadline (T6.8-S): the time budget to accumulate
    /// ONE sub-chunk (≤ `split_bytes`), reset on every emitted sub-chunk.
    /// Replaces the old whole-chunk timeout, which a healthy-but-huge
    /// sandblasting chunk could never meet (field failure 2026-06-12: 10k-block
    /// chunks of ~hundreds of MB looped `chunk fetch timed out` forever). A
    /// genuinely stalled stream dies faster via grpc::STREAM_IDLE_TIMEOUT.
    pub chunk_timeout: Duration,
    /// Byte budget per emitted sub-chunk (estimated wire bytes). Normal-era
    /// 10k-block chunks (~1–6 MB) stay single sub-chunks; sandblasting chunks
    /// split into many small sub-chunks automatically. Threaded from
    /// [`EngineConfig::chunk_split_bytes`] by the scheduler.
    pub split_bytes: usize,
    /// \[DEV-5\] Block-count budget per emitted sub-chunk, applied ALONGSIDE
    /// `split_bytes` — the splitter completes a sub-chunk whenever EITHER cap
    /// would be exceeded, whichever fires first. Defends against a
    /// middle-density plan chunk (under the byte cap, but ~10,000 messages on
    /// one gRPC stream) tripping the server's h2 per-stream frame-count
    /// protection. Threaded from [`EngineConfig::chunk_split_blocks`] by the
    /// scheduler; see that field's doc for the full mechanism + citations.
    pub split_blocks: u32,
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
            split_blocks: EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS,
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
    /// \[DEV-6\] Count of adaptive halving steps the GoAway reflex engaged
    /// across every worker during this fetch — one per classified GoAway that
    /// got a smaller-span immediate retry (not one per plan chunk; a plan
    /// chunk that halves 10,000→5,000→2,500 before succeeding counts 2).
    /// Zero in the overwhelming common case; a nonzero value means h2's
    /// `too_many_data_frames` guard fired and the reflex absorbed it without
    /// falling back to the sleep ladder.
    pub goaway_splits: u64,
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

/// Byte- AND block-count-budgeted accumulator (DEV-5 added the block-count
/// side): collects streamed blocks and yields a completed sub-chunk whenever
/// adding the next block would exceed EITHER `split_bytes` OR `split_blocks`
/// (the pushed block then opens the next sub-chunk). Invariants: yielded
/// sub-chunks are never empty and preserve stream order; a single block
/// larger than the byte budget forms its own sub-chunk (no infinite loop);
/// reaching a cap EXACTLY — without exceeding it — does not split, for
/// either dimension (matches the pre-existing byte-cap semantic: the budget
/// is a ceiling on what a sub-chunk may hold, not a target it must hit).
pub(crate) struct ChunkSplitter {
    split_bytes: usize,
    split_blocks: usize,
    acc: Vec<CompactBlock>,
    acc_bytes: usize,
}

impl ChunkSplitter {
    pub(crate) fn new(split_bytes: usize, split_blocks: usize) -> Self {
        Self {
            split_bytes,
            split_blocks,
            acc: Vec::new(),
            acc_bytes: 0,
        }
    }

    /// Push the next streamed block; returns `Some((blocks, bytes))` when
    /// either budget overflows and a sub-chunk completes.
    pub(crate) fn push(&mut self, block: CompactBlock) -> Option<(Vec<CompactBlock>, usize)> {
        let block_bytes = Message::encoded_len(&block);
        let would_exceed_bytes = self.acc_bytes + block_bytes > self.split_bytes;
        // Adding this block would make the count split_blocks + 1, i.e. the
        // count already sits AT the cap — mirrors the byte check's "adding
        // the next block would exceed" phrasing (an int-arithmetic-overflow-
        // free rewrite of `self.acc.len() + 1 > self.split_blocks`).
        let would_exceed_blocks = self.acc.len() >= self.split_blocks;
        let completed = if !self.acc.is_empty() && (would_exceed_bytes || would_exceed_blocks) {
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
    /// Plan-chunk end bound (inclusive). The plan chunk's TRUE final height —
    /// unlike `request_end()` below, never shrunk by the DEV-6 adaptive cap —
    /// this alone decides `is_last`.
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
    /// \[DEV-6\] Active GoAway-adaptive request-span cap for the REST of this
    /// plan chunk's attempts. `None` = unrestricted (request `resume_from..end`
    /// as one call — pre-DEV-6 behavior, unchanged). Set on the first
    /// classified GoAway (`goaway_halved_cap`) and halved again on every
    /// subsequent one; STICKY once engaged — persists across a successful
    /// capped sub-request too, for the rest of THIS plan chunk, rather than
    /// springing back to full size and risking an immediate repeat GoAway.
    /// Reset only by moving to a new plan chunk (a fresh `PlanChunkCursor`).
    goaway_cap: Option<u32>,
}

impl PlanChunkCursor {
    /// \[DEV-6\] End height to request on THIS attempt: the plan chunk's true
    /// end, clamped by the active adaptive cap (if any) — never below
    /// `resume_from` since `goaway_cap` is always `>= 1`.
    fn request_end(&self) -> u64 {
        match self.goaway_cap {
            Some(cap) => self.end.min(
                self.resume_from
                    .saturating_add(u64::from(cap))
                    .saturating_sub(1),
            ),
            None => self.end,
        }
    }
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

// ── DEV-6: adaptive split-on-GoAway reflex ─────────────────────────────────────

/// \[DEV-6\] Floor for the GoAway-adaptive halving reflex: the smallest
/// request span the reflex will retry immediately. A request already at (or
/// below) this floor that still GoAways is a genuine failure, not something
/// further halving could plausibly fix — it falls through to the pre-DEV-6
/// zero-progress sleep-ladder unchanged (`worker`'s retry loop).
const GOAWAY_ADAPTIVE_FLOOR_BLOCKS: u32 = 1_000;

/// \[DEV-6\] Precise classifier for the GoAway-adaptive reflex: true only for
/// h2's own locally-raised `too_many_data_frames` / `ENHANCE_YOUR_CALM`
/// self-protection — its per-stream guard against a peer delivering an
/// excessive run of small DATA frames (`h2-0.4.18` `proto/streams/streams.rs`:
/// `counts.record_data_frame(payload_len)` failing raises exactly
/// `Error::library_go_away_data(Reason::ENHANCE_YOUR_CALM,
/// "too_many_data_frames")`). Read primary sources rather than assumed: this
/// is `Initiator::Library` — h2's OWN client-side stack closing the
/// connection on itself, not a frame lightwalletd sent; the earlier
/// `h2 = "0.4.15"` pinned by this workspace's `Cargo.lock` predates this
/// specific guard (absent from that version's source; introduced by 0.4.18),
/// which independently bears on whether a live run this session can trip it
/// at all — see the DEV-6 report.
///
/// Matching happens on the fully rendered error text rather than a typed
/// downcast, because by the time a stream-read error reaches
/// `SlipstreamError::Transport` (via `format!("{ctx}: {e}")`, both call sites
/// below), it already IS just a `String` — `SlipstreamError::Transport`'s
/// only shape. That string is not lossy for this purpose: `tonic::Status`'s
/// own `Display` impl (tonic 0.14.6 `status.rs`) writes
/// `code: '...', message: "...", source: {source:?}`, and `hyper::Error` /
/// `h2::Error`'s `Debug` impls recursively chain into that `source:` slot —
/// confirmed by reading the exact impls, not assumed — so all three markers
/// below are present verbatim whenever the underlying cause truly is this
/// GoAway class. Requiring all three (not `ENHANCE_YOUR_CALM` alone, which
/// h2 also raises for unrelated self-protections like
/// `too_many_internal_resets`) is the "match precisely" this reflex needs:
/// non-matching transport errors — including other GoAway reasons — fall
/// through to today's unchanged handling.
fn is_goaway_frame_overload(err: &SlipstreamError) -> bool {
    let SlipstreamError::Transport(msg) = err else {
        return false;
    };
    msg.contains("GoAway(")
        && msg.contains("ENHANCE_YOUR_CALM")
        && msg.contains("too_many_data_frames")
}

/// \[DEV-6\] Pure halving step, independent of any network/async machinery.
/// `attempted_span` is the block count actually requested by the attempt
/// that just GoAway'd (the plan chunk's full remaining span the first time;
/// the prior cap — or less, near a plan chunk's tail — on subsequent
/// halvings). Returns the new, smaller cap to retry immediately with, or
/// `None` once `attempted_span` is already at or below `floor`: "give up the
/// adaptive path for this GoAway; fall through to the normal ladder."
fn goaway_halved_cap(attempted_span: u32, floor: u32) -> Option<u32> {
    if attempted_span <= floor {
        None
    } else {
        Some((attempted_span / 2).max(floor))
    }
}

/// \[DEV-6\] The reflex's full decision in one call: classify, then (if it
/// matches) halve. `worker`'s retry loop calls this once per failed attempt;
/// `Some(cap)` means "retry immediately at this cap, no strike, no sleep,"
/// `None` means "not this reflex's concern — run the normal ladder" (either
/// because the error isn't the classified GoAway at all, or because it is
/// but `attempted_span` was already at the floor).
fn goaway_adaptive_response(err: &SlipstreamError, attempted_span: u32, floor: u32) -> Option<u32> {
    if !is_goaway_frame_overload(err) {
        return None;
    }
    goaway_halved_cap(attempted_span, floor)
}

/// Streams one (possibly resumed) plan-chunk request into byte-budgeted
/// sub-chunks. Generic over the message stream so hermetic tests can inject
/// synthetic/flaky streams (production passes tonic's `Streaming`).
///
/// Deadline semantics (T6.8-S): `progress_deadline` bounds the accumulation of
/// any ONE sub-chunk, measured between emissions — admission/backpressure time
/// is excluded because the timer resets when an emission completes. A
/// stalled-but-open stream dies earlier via the per-message
/// grpc::STREAM_IDLE_TIMEOUT inside `next_with_idle_timeout`.
///
/// A clean stream end BEFORE `request_end` (short/empty delivery) is a
/// retryable Transport error: emitting the partial tail would either lose the
/// missing blocks silently or feed scan an empty chunk; the worker retries
/// from `resume_from` instead (the un-emitted tail is discarded by design —
/// resume re-downloads at most one sub-chunk's worth).
///
/// `request_end` (\[DEV-6\]) is the end height THIS call actually requested —
/// `cursor.end` (the plan chunk's true end) when no adaptive cap is active,
/// or something smaller when the caller is retrying a GoAway-halved span.
/// Reaching it cleanly always completes THIS call (`PumpOutcome::Completed`);
/// only reaching it AT `cursor.end` also marks the sub-chunk `is_last` and
/// therefore the whole plan chunk done — the caller (`worker`) tells the two
/// apart via `cursor.resume_from > cursor.end`.
#[allow(clippy::too_many_arguments)] // internal seam of run_fetch; bundling would obscure the borrow structure
async fn pump_block_stream<S>(
    stream: &mut S,
    cursor: &mut PlanChunkCursor,
    request_end: u64,
    split_bytes: usize,
    split_blocks: usize,
    progress_deadline: Duration,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> Result<PumpOutcome, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    let ctx = format!(
        "block stream {}..{} (plan chunk {})",
        cursor.resume_from, request_end, cursor.plan_index
    );
    let mut splitter = ChunkSplitter::new(split_bytes, split_blocks);
    // tokio Instant (not std) so start_paused tests drive the deadline.
    let mut last_progress = tokio::time::Instant::now();
    loop {
        let Some(item) = grpc::next_with_idle_timeout(stream, &ctx).await? else {
            // Clean end of stream: flush the tail iff it completes THIS request.
            return match splitter.finish() {
                Some((blocks, bytes)) if blocks.last().map(|b| b.height) == Some(request_end) => {
                    // [DEV-6] is_last only at the plan chunk's TRUE end, never
                    // at a smaller adaptively-capped request_end.
                    let is_last = request_end == cursor.end;
                    if emit_sub_chunk(cursor, blocks, bytes, is_last, gate, out).await {
                        Ok(PumpOutcome::Completed)
                    } else {
                        Ok(PumpOutcome::ConsumerGone)
                    }
                }
                tail => {
                    let got = tail
                        .and_then(|(blocks, _)| blocks.last().map(|b| b.height))
                        .unwrap_or_else(|| cursor.resume_from.saturating_sub(1));
                    Err(SlipstreamError::Transport(format!(
                        "{ctx}: stream ended short at {got}, expected {request_end}"
                    )))
                }
            };
        };
        let block = item.map_err(|e| SlipstreamError::Transport(format!("{ctx}: {e}")))?;
        if last_progress.elapsed() > progress_deadline {
            return Err(SlipstreamError::Transport(format!(
                "{ctx}: no completed sub-chunk within {}s",
                progress_deadline.as_secs()
            )));
        }
        if let Some((blocks, bytes)) = splitter.push(block) {
            if !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await {
                return Ok(PumpOutcome::ConsumerGone);
            }
            last_progress = tokio::time::Instant::now();
        }
    }
}

/// Opens the (resume-aware) GetBlockRange stream and pumps it into sub-chunks.
///
/// `request_end` (\[DEV-6\]) — see `pump_block_stream`'s doc — bounds THIS
/// call's request; pass `cursor.request_end()` (the plan chunk's true end,
/// clamped by any active GoAway-adaptive cap).
async fn open_and_pump(
    client: &mut LwdClient,
    cursor: &mut PlanChunkCursor,
    request_end: u64,
    plan: &FetchPlan,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> Result<PumpOutcome, SlipstreamError> {
    let req = BlockRange {
        start: Some(BlockId {
            height: cursor.resume_from,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: request_end,
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
                request_end,
                grpc::UNARY_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| {
            SlipstreamError::Transport(format!(
                "get_block_range {}..{}: {e}",
                cursor.resume_from, request_end
            ))
        })?
        .into_inner();
    pump_block_stream(
        &mut stream,
        cursor,
        request_end,
        plan.split_bytes,
        plan.split_blocks as usize,
        plan.chunk_timeout,
        gate,
        out,
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
    goaway_splits: Arc<AtomicU64>,
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
            goaway_cap: None,
        };
        // Counts consecutive ZERO-PROGRESS attempts; an attempt that emitted a
        // sub-chunk resets the budget (resume makes such retries cheap and the
        // total attempt count stays bounded by sub-chunks × retries). [DEV-6]
        // The adaptive GoAway reflex below never touches this counter at all —
        // it is a separate, self-bounded (halving-to-floor) budget.
        let mut attempt: u32 = 0;
        loop {
            let request_end = cursor.request_end();
            cursor.emitted_this_attempt = false;
            match open_and_pump(&mut client, &mut cursor, request_end, &plan, &gate, &out).await {
                Ok(PumpOutcome::Completed) => {
                    if cursor.resume_from > cursor.end {
                        break; // whole plan chunk released
                    }
                    // [DEV-6] Adaptively-capped partial success: more of this
                    // plan chunk remains. Continue immediately with the next
                    // (still-capped) slice — expected multi-request progress,
                    // not a retry, so `attempt` stays untouched.
                    continue;
                }
                Ok(PumpOutcome::ConsumerGone) => return Ok(()), // reorder stage gone (abort)
                Err(err) => {
                    // [DEV-6] The adaptive reflex: a precisely classified GoAway
                    // halves the request span and retries immediately, entirely
                    // outside the zero-progress strike ladder — UNLESS the span
                    // that just failed was already at (or below) the floor, in
                    // which case this falls through to the unchanged handling.
                    let attempted_span =
                        u32::try_from(request_end - cursor.resume_from + 1).unwrap_or(u32::MAX);
                    if let Some(new_cap) =
                        goaway_adaptive_response(&err, attempted_span, GOAWAY_ADAPTIVE_FLOOR_BLOCKS)
                    {
                        cursor.goaway_cap = Some(new_cap);
                        goaway_splits.fetch_add(1, Ordering::Relaxed);
                        info!(
                            worker_id,
                            index,
                            attempted_span,
                            new_cap,
                            resume_from = cursor.resume_from,
                            "GoAway (too_many_data_frames): halving request span, retrying immediately"
                        );
                        // The connection is going away (h2 GOAWAY tears down the
                        // whole connection, not just this stream) — same
                        // poisoned-channel assumption as the normal path below,
                        // just without the sleep.
                        client = connect_direct_with_retry(&endpoint).await?;
                        continue;
                    }
                    let failed_attempt = attempt + 1;
                    attempt = failed_attempt;
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
async fn release_ordered(
    rx: &mut mpsc::Receiver<SubChunk>,
    queue: &ChunkQueueSender,
    progress: Option<&Arc<Progress>>,
    floor: &AtomicU64,
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
            emitted_chunks += 1;
            // Ahead-budget permit held until the ChunkQueue takes over.
            drop(permit);
            if is_last {
                if plan_subs > 1 {
                    // DEV-5: no longer necessarily a dense/sandblasting-era
                    // split — a middle-density chunk under the byte cap can
                    // now also split purely on block count. blocks/subs and
                    // mb/subs below disambiguate after the fact: a sub-chunk
                    // averaging far under chunk_split_bytes was block-count
                    // triggered, not byte triggered.
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
    // [DEV-6] Shared across every worker; read back after they all join.
    let goaway_splits = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(plan.streams);
    for worker_id in 0..plan.streams.max(1) {
        handles.push(tokio::spawn(worker(
            worker_id,
            endpoint.clone(),
            plan.clone(),
            Arc::clone(&next),
            gate.clone(),
            tx.clone(),
            Arc::clone(&goaway_splits),
        )));
    }
    drop(tx); // release loop ends when all workers finish

    // On early error, abort workers explicitly: a dropped JoinHandle only detaches
    // the task, which would otherwise hold its socket until the next send fails.
    let abort_all = |handles: &Vec<tokio::task::JoinHandle<Result<(), SlipstreamError>>>| {
        for h in handles {
            h.abort();
        }
    };

    let summary = match release_ordered(
        &mut rx,
        &queue,
        progress.as_ref(),
        &floor,
        started,
        plan.failover,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            abort_all(&handles);
            return Err(e);
        }
    };

    for h in handles {
        h.await
            .map_err(|e| SlipstreamError::Transport(format!("worker panicked: {e}")))??;
    }
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
        goaway_splits: goaway_splits.load(Ordering::Relaxed),
    };
    info!(
        blocks = stats.blocks,
        mb = stats.bytes / (1024 * 1024),
        elapsed_s = stats.elapsed.as_secs(),
        wire_mbps = format!("{:.1}", stats.megabytes_per_sec()).as_str(),
        wire_worst_5s_mbps = format!("{:.1}", stats.worst_window_mbps(5.0)).as_str(),
        goaway_splits = stats.goaway_splits,
        "fetch done"
    );
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::chunk_queue;
    use futures_util::stream;

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

    /// DEV-5: FetchPlan::new must pick up the block-count cap's engine
    /// default, exactly like it already does for split_bytes.
    #[test]
    fn plan_default_split_blocks_matches_engine_default() {
        let p = FetchPlan::new(1000, 1999, 300, 4);
        assert_eq!(p.split_blocks, EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS);
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
            goaway_cap: None,
        }
    }

    /// Wide-open gate (huge budget) for pump tests that aren't about admission.
    fn open_gate() -> AheadGate {
        AheadGate::new(1 << 30, Arc::new(AtomicU64::new(0)))
    }

    /// DEV-5: sentinel `split_blocks` for tests that exercise ONLY the
    /// byte-cap dimension — high enough that the block-count cap never fires
    /// for any block count these tests use, isolating pre-existing byte-only
    /// splitter behavior exactly as it was before DEV-5.
    const NO_BLOCK_CAP: usize = usize::MAX;

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
        let mut s = ChunkSplitter::new(1024 * 1024, NO_BLOCK_CAP);
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
        let mut s = ChunkSplitter::new(2500, NO_BLOCK_CAP);
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
        let mut s = ChunkSplitter::new(1000, NO_BLOCK_CAP);
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
        assert!(ChunkSplitter::new(1000, NO_BLOCK_CAP).finish().is_none());
    }

    // ── DEV-5: ChunkSplitter block-count cap ──────────────────────────────────

    #[test]
    fn splitter_splits_at_block_count_cap() {
        // Tiny blocks (zero byte pressure — split_bytes is effectively
        // unbounded) against a 3-block cap → 3 + 3 + 1, the block-count
        // mirror of splitter_splits_at_threshold_preserving_order.
        let mut s = ChunkSplitter::new(usize::MAX, 3);
        let mut emitted: Vec<Vec<CompactBlock>> = Vec::new();
        for b in linked(100, 7, 16) {
            if let Some((blocks, _bytes)) = s.push(b) {
                assert!(
                    blocks.len() <= 3,
                    "emitted sub-chunk must respect the block-count budget"
                );
                emitted.push(blocks);
            }
        }
        if let Some((blocks, _)) = s.finish() {
            emitted.push(blocks);
        }
        assert_eq!(
            emitted.len(),
            3,
            "7 blocks at 3/sub-chunk = 2 full + 1 tail"
        );
        assert_eq!(
            emitted.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![3, 3, 1]
        );
        let heights: Vec<u64> = emitted.iter().flatten().map(|b| b.height).collect();
        assert_eq!(
            heights,
            (100..107).collect::<Vec<_>>(),
            "order preserved, nothing lost"
        );
    }

    /// Boundary case explicitly required by the task: landing EXACTLY on the
    /// block-count cap must not split — only EXCEEDING it does (matches the
    /// pre-existing byte-cap semantic, `splitter_small_blocks_single_subchunk_fast_path`'s
    /// sibling for the count dimension).
    #[test]
    fn splitter_exactly_at_block_cap_does_not_split() {
        let mut s = ChunkSplitter::new(usize::MAX, 5);
        for b in linked(100, 5, 16) {
            assert!(
                s.push(b).is_none(),
                "exactly-at-cap must never split mid-stream"
            );
        }
        let (blocks, _bytes) = s.finish().expect("tail");
        assert_eq!(blocks.len(), 5, "all 5 blocks land in one sub-chunk");
        assert_eq!(
            blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            (100..105).collect::<Vec<_>>()
        );
    }

    /// Boundary case explicitly required by the task: a chunk ALREADY split
    /// fine-grained by the byte cap (sandblasting-era shape) must see the
    /// block-count cap stay completely inert — identical output to the
    /// pre-DEV-5 byte-only splitter, i.e. the new cap never ADDS
    /// fragmentation on top of an already-dense split.
    #[test]
    fn splitter_dense_already_split_by_bytes_block_cap_inert() {
        // Oversized (5000-byte) blocks against a 1000-byte budget: the byte
        // cap fires on every single block (splitter_oversized_block_forms_own_subchunk's
        // shape, generalized to 6 blocks). The block-count cap is set to the
        // production default (5,000) — nowhere near tripping on a 6-block run.
        let mut s = ChunkSplitter::new(1000, EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize);
        let mut emitted: Vec<Vec<CompactBlock>> = Vec::new();
        for b in linked(100, 6, 5000) {
            if let Some((blocks, _bytes)) = s.push(b) {
                emitted.push(blocks);
            }
        }
        if let Some((blocks, _)) = s.finish() {
            emitted.push(blocks);
        }
        assert_eq!(
            emitted.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1, 1, 1, 1, 1, 1],
            "byte cap alone governs a dense stream; block cap adds nothing"
        );
    }

    /// THE DEV-5 reproduction, in unit-test form: the exact failing shape
    /// reported from the field (block stream 3,355,000..3,364,999, "plan
    /// chunk 25", h2 GoAway b\"too_many_data_frames\" ENHANCE_YOUR_CALM — see
    /// DEV-5-FRAMECAP-REPORT.md §1). A 10,000-block plan chunk at ~500-600
    /// B/block (~5-6 MB total) stays comfortably under the 8 MiB byte cap —
    /// PRE-DEV-5 (byte-only splitter) this was ONE sub-chunk, i.e. one gRPC
    /// stream of ~10,000 messages. POST-DEV-5, the shipped production
    /// defaults (8 MiB byte cap, 5,000-block cap) must split it into exactly
    /// 2 sub-chunks of 5,000 blocks each, halving the frames-per-stream count
    /// with the byte cap never once entering into it.
    #[test]
    fn splitter_sparse_many_blocks_hits_block_cap_not_bytes() {
        let mut s = ChunkSplitter::new(
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize,
        );
        let mut emitted: Vec<Vec<CompactBlock>> = Vec::new();
        let mut total_bytes = 0usize;
        for b in linked(3_355_000, 10_000, 550) {
            if let Some((blocks, bytes)) = s.push(b) {
                total_bytes += bytes;
                emitted.push(blocks);
            }
        }
        if let Some((blocks, bytes)) = s.finish() {
            total_bytes += bytes;
            emitted.push(blocks);
        }
        assert!(
            total_bytes < EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            "the whole 10,000-block range must stay under the byte cap -- this \
             is exactly what made the pre-DEV-5 byte-only splitter blind to it \
             (got {total_bytes} bytes)"
        );
        assert_eq!(
            emitted.len(),
            2,
            "10,000 blocks at a 5,000-block cap must split into exactly 2 sub-chunks"
        );
        assert_eq!(
            emitted.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![5000, 5000]
        );
        let heights: Vec<u64> = emitted.iter().flatten().map(|b| b.height).collect();
        assert_eq!(
            heights,
            (3_355_000..3_365_000).collect::<Vec<_>>(),
            "order preserved, nothing lost, exact failing range reproduced"
        );
    }

    // ── DEV-6: is_goaway_frame_overload (the error-classifier) ────────────────

    /// The exact shape cited in `DEV-5-FRAMECAP-REPORT.md` §1.4 (itself cited
    /// from `F2-ADAPTER-PARITY-REPORT.md`), reproduced here as a fabricated
    /// `SlipstreamError::Transport` — this is precisely what
    /// `format!("{ctx}: {e}")` produces from a live `tonic::Status` whose
    /// source chain is this GoAway (verified against tonic 0.14.6's own
    /// `Status::fmt`/`hyper::Error`'s/`h2::Error`'s `Debug` impls; see the
    /// classifier's doc comment).
    fn fabricated_goaway_chain() -> SlipstreamError {
        SlipstreamError::Transport(
            "block stream 3355000..3364999 (plan chunk 25): code: 'Some resource has been \
             exhausted', message: \"h2 protocol error: error reading a body from connection\", \
             source: hyper::Error(Body, Error { kind: GoAway(b\"too_many_data_frames\", \
             ENHANCE_YOUR_CALM, Library) })"
                .to_string(),
        )
    }

    #[test]
    fn goaway_classifier_matches_fabricated_chain() {
        assert!(is_goaway_frame_overload(&fabricated_goaway_chain()));
    }

    #[test]
    fn goaway_classifier_rejects_plain_connection_reset() {
        let err = SlipstreamError::Transport(
            "get_block_range 100..200: transport error: connection reset by peer".into(),
        );
        assert!(!is_goaway_frame_overload(&err));
    }

    /// "Do NOT broaden to all transport errors": h2 raises `ENHANCE_YOUR_CALM`
    /// for OTHER self-protections too (e.g. `too_many_internal_resets`,
    /// `h2-0.4.15` `proto/streams/streams.rs`) — the reason code alone is not
    /// precise enough; the debug-data string must ALSO match.
    #[test]
    fn goaway_classifier_rejects_other_enhance_your_calm_reasons() {
        let err = SlipstreamError::Transport(
            "block stream 100..200 (plan chunk 1): code: 'Some resource has been exhausted', \
             message: \"h2 protocol error\", source: hyper::Error(Body, Error { kind: \
             GoAway(b\"too_many_internal_resets\", ENHANCE_YOUR_CALM, Library) })"
                .into(),
        );
        assert!(
            !is_goaway_frame_overload(&err),
            "ENHANCE_YOUR_CALM alone (a different h2 self-protection) must not match"
        );
    }

    /// The classifier gates on the `SlipstreamError` variant, not merely on
    /// substring content anywhere in the program — a non-`Transport` error
    /// can never be this reflex's concern regardless of what text it carries.
    #[test]
    fn goaway_classifier_rejects_non_transport_variant() {
        let err = SlipstreamError::Wallet("too_many_data_frames ENHANCE_YOUR_CALM GoAway(".into());
        assert!(!is_goaway_frame_overload(&err));
    }

    // ── DEV-6: goaway_halved_cap (the halving math) ────────────────────────────

    #[test]
    fn goaway_halving_sequence_from_full_chunk_to_floor() {
        // The DEV-5-default shape: a 10,000-block plan chunk with no adaptive
        // cap yet active halves 10000 -> 5000 -> 2500 -> 1250 -> 1000(floor),
        // then gives up (constraint: the floor is where the reflex stops).
        let floor = 1_000;
        let mut span = 10_000u32;
        let mut caps = Vec::new();
        while let Some(cap) = goaway_halved_cap(span, floor) {
            caps.push(cap);
            span = cap;
        }
        assert_eq!(caps, vec![5_000, 2_500, 1_250, 1_000]);
    }

    #[test]
    fn goaway_halving_stops_once_at_or_below_floor() {
        assert_eq!(goaway_halved_cap(1_000, 1_000), None, "exactly at floor");
        assert_eq!(goaway_halved_cap(999, 1_000), None, "already below floor");
    }

    #[test]
    fn goaway_halving_never_undershoots_the_floor() {
        // Raw halving of 1250 is 625, which is BELOW the 1000 floor -- the
        // result must clamp to the floor, not fall under it.
        assert_eq!(goaway_halved_cap(1_250, 1_000), Some(1_000));
    }

    #[test]
    fn goaway_halving_small_remaining_span_gives_up_immediately() {
        // A plan-chunk TAIL already smaller than the floor (e.g. the last
        // 800 blocks of a plan chunk) never gets a "free" adaptive retry --
        // nothing left to halve meaningfully, straight to the normal ladder.
        assert_eq!(goaway_halved_cap(800, 1_000), None);
    }

    // ── DEV-6: goaway_adaptive_response (classify + halve, worker's call) ─────

    #[test]
    fn adaptive_response_engages_on_matching_goaway_above_floor() {
        assert_eq!(
            goaway_adaptive_response(&fabricated_goaway_chain(), 10_000, 1_000),
            Some(5_000)
        );
    }

    #[test]
    fn adaptive_response_none_on_matching_goaway_at_floor() {
        assert_eq!(
            goaway_adaptive_response(&fabricated_goaway_chain(), 1_000, 1_000),
            None,
            "at the floor and STILL GoAway-ing falls through to the normal ladder"
        );
    }

    #[test]
    fn adaptive_response_none_on_non_goaway_error_regardless_of_span() {
        let err = SlipstreamError::Transport("stream idle timeout (30s)".into());
        assert_eq!(goaway_adaptive_response(&err, 10_000, 1_000), None);
    }

    // ── DEV-6: PlanChunkCursor::request_end (resume-height interaction) ───────

    #[test]
    fn request_end_unrestricted_without_a_cap() {
        let cursor = test_cursor(0, 3_355_000, 3_364_999);
        assert_eq!(cursor.request_end(), 3_364_999);
    }

    #[test]
    fn request_end_clamped_by_an_active_cap() {
        let mut cursor = test_cursor(25, 3_355_000, 3_364_999);
        cursor.goaway_cap = Some(5_000);
        assert_eq!(cursor.request_end(), 3_359_999, "resume_from + cap - 1");
    }

    #[test]
    fn request_end_cap_interacts_with_an_advanced_resume_from() {
        // After some sub-chunks already emitted, the cap re-anchors on the
        // NEW resume_from -- proving the "resume-height interaction" the
        // task asked to cover explicitly.
        let mut cursor = test_cursor(25, 3_355_000, 3_364_999);
        cursor.resume_from = 3_360_000; // 5,000 blocks already emitted
        cursor.goaway_cap = Some(2_500);
        assert_eq!(cursor.request_end(), 3_362_499);
    }

    #[test]
    fn request_end_cap_never_exceeds_the_plan_chunk_true_end() {
        // Near a plan chunk's tail, a cap larger than what's left must not
        // reach past cursor.end (would ask for blocks outside this plan
        // chunk entirely).
        let mut cursor = test_cursor(25, 3_364_500, 3_364_999); // 500 blocks left
        cursor.goaway_cap = Some(1_000); // cap bigger than the remaining span
        assert_eq!(
            cursor.request_end(),
            3_364_999,
            "clamped to cursor.end, not resume_from + cap - 1"
        );
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
            119,
            2500,
            NO_BLOCK_CAP,
            Duration::from_secs(120),
            &gate,
            &tx,
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
            109,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
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
    async fn pump_short_stream_errors_without_emitting_tail() {
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
            119,
            2500,
            NO_BLOCK_CAP,
            Duration::from_secs(120),
            &gate,
            &tx,
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
        // 12 blocks at 2/sub-chunk → 5 emitted (10 blocks), 2-block tail discarded.
        let emitted_through = subs.last().and_then(|s| s.blocks.last()).map(|b| b.height);
        assert_eq!(
            cursor.resume_from,
            emitted_through.expect("subs emitted") + 1
        );
    }

    /// THE retry-resume contract (T6.8-S): a mid-plan-chunk failure after
    /// sub-chunk emission resumes from the next un-emitted height; the consumer
    /// sees every height exactly once and the sub_index sequence stays dense.
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
            139,
            2500,
            NO_BLOCK_CAP,
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect_err("attempt 1 must surface the stream error");
        assert!(err.to_string().contains("backend dropped"), "got: {err}");
        assert!(cursor.emitted_this_attempt, "attempt 1 made progress");
        // 18 blocks at 2/sub-chunk → 8 sub-chunks (16 blocks) emitted; 2 discarded.
        assert_eq!(cursor.resume_from, 116, "resume = last emitted height + 1");
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
            139,
            2500,
            NO_BLOCK_CAP,
            Duration::from_secs(120),
            &gate,
            &tx,
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
            129,
            2500,
            NO_BLOCK_CAP,
            Duration::from_secs(5),
            &gate,
            &tx,
        )
        .await
        .expect("slow-but-progressing stream must complete");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 129);
    }

    /// No emission within the deadline (budget never fills) → progress timeout.
    #[tokio::test(start_paused = true)]
    async fn pump_deadline_fires_without_subchunk_progress() {
        let (tx, _rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut s = Box::pin(stream::unfold(100u64, |h| async move {
            if h > 129 {
                return None;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((Ok::<_, tonic::Status>(block_sized(h, 1000)), h + 1))
        }));
        // Both budgets are huge → nothing ever emits → the 5s progress deadline fires.
        let err = pump_block_stream(
            &mut s,
            &mut cursor,
            129,
            usize::MAX >> 8,
            NO_BLOCK_CAP,
            Duration::from_secs(5),
            &gate,
            &tx,
        )
        .await
        .expect_err("no progress must time out");
        assert!(
            err.to_string().contains("no completed sub-chunk"),
            "got: {err}"
        );
        assert!(!cursor.emitted_this_attempt);
        assert_eq!(
            cursor.resume_from, 100,
            "no emission → resume from plan start"
        );
    }

    /// DEV-5 end-to-end: proves the block-count cap is correctly threaded all
    /// the way through `pump_block_stream` (not just the raw `ChunkSplitter`
    /// unit tests above) — a huge byte budget that would never split these
    /// tiny blocks, paired with a block-count cap of 5, must still yield 3
    /// sub-chunks (5, 5, 2) with `is_last` only on the final one.
    #[tokio::test]
    async fn pump_block_count_cap_splits_even_when_bytes_are_tiny() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(7, 100, 111);
        let mut s = stream::iter(
            linked(100, 12, 16)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            111,
            1024 * 1024, // huge byte budget -- never trips for 12×16-byte blocks
            5,           // the DEV-5 cap under test
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect("pump");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(
            subs.iter().map(|s| s.blocks.len()).collect::<Vec<_>>(),
            vec![5, 5, 2],
            "block-count cap must govern sub-chunk sizes end-to-end through the pump path"
        );
        assert_eq!(
            subs.iter().map(|s| s.is_last).collect::<Vec<_>>(),
            vec![false, false, true]
        );
        assert_heights_consecutive(&subs, 100, 111);
    }

    // ── DEV-6: adaptively-capped requests through pump_block_stream ───────────
    //
    // These exercise exactly what `worker`'s retry loop drives when the
    // GoAway reflex is engaged: `request_end` smaller than `cursor.end`.
    // `worker` itself isn't unit-testable (it owns a real `LwdClient`), so —
    // matching this file's existing altitude (`pump_resume_after_midstream_
    // error_no_duplicates` proves the error-triggered resume contract at
    // this same layer) — these prove the SUCCESS-triggered continuation
    // contract: in-order reassembly holds across a halved sub-range feeding
    // the same (plan_index, sub_index) slot sequence.

    /// A single capped request that completes cleanly at `request_end` (NOT
    /// `cursor.end`) must report `PumpOutcome::Completed` with `is_last =
    /// false` and leave `resume_from` exactly one past `request_end`, ready
    /// for a follow-up request — not `true`/plan-chunk-done, which would
    /// wrongly tell the reorder stage this plan chunk is finished.
    #[tokio::test]
    async fn pump_partial_request_end_below_plan_chunk_end_is_not_last() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(25, 3_355_000, 3_364_999); // true end far above
        let mut s = stream::iter(
            linked(3_355_000, 5_000, 550)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            3_359_999, // capped request_end -- half of the plan chunk
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect("capped request completes cleanly");
        assert!(matches!(out, PumpOutcome::Completed));
        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(subs.len(), 1);
        assert!(
            !subs[0].is_last,
            "reaching the CAPPED request_end must not be mistaken for plan-chunk completion"
        );
        assert_eq!(
            cursor.resume_from, 3_360_000,
            "resume_from lands exactly one past request_end, ready for the follow-up request"
        );
    }

    /// Two SEQUENTIAL capped requests against the SAME cursor (what `worker`
    /// does across a halving step, minus the reconnect) must reassemble in
    /// strict order with no gaps/dups: dense sub_index across the boundary,
    /// `is_last` ONLY on the second (the one that reaches the TRUE end), and
    /// every height 3,355,000..=3,364,999 exactly once.
    #[tokio::test]
    async fn pump_multiple_sequential_capped_requests_then_final_is_last() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(25, 3_355_000, 3_364_999);

        // First (capped) request: exactly the first half.
        let mut s1 = stream::iter(
            linked(3_355_000, 5_000, 550)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out1 = pump_block_stream(
            &mut s1,
            &mut cursor,
            3_359_999,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect("first capped request completes");
        assert!(matches!(out1, PumpOutcome::Completed));
        assert!(cursor.resume_from <= cursor.end, "plan chunk not yet done");
        let subs_before = cursor.next_sub_index;

        // Second request: the rest, up to the TRUE plan-chunk end this time.
        let true_end = cursor.end;
        let mut s2 = stream::iter(
            linked(cursor.resume_from, true_end - cursor.resume_from + 1, 550)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out2 = pump_block_stream(
            &mut s2,
            &mut cursor,
            true_end,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
            EngineConfig::DEFAULT_CHUNK_SPLIT_BLOCKS as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
        )
        .await
        .expect("second request completes the plan chunk");
        assert!(matches!(out2, PumpOutcome::Completed));
        assert!(cursor.resume_from > cursor.end, "plan chunk now fully done");
        assert!(
            cursor.next_sub_index > subs_before,
            "sub_index continued, not reset"
        );

        drop(tx);
        let subs = drain_subs(&mut rx);
        assert_eq!(
            subs.iter().map(|s| s.sub_index).collect::<Vec<_>>(),
            (0..subs.len() as u64).collect::<Vec<_>>(),
            "sub_index dense across the capped-request boundary"
        );
        assert_eq!(
            subs.iter().filter(|s| s.is_last).count(),
            1,
            "exactly one is_last, on the request that reached the TRUE end"
        );
        assert!(subs.last().expect("nonempty").is_last);
        assert_heights_consecutive(&subs, 3_355_000, 3_364_999);
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
        let summary = release_ordered(&mut rx, &qtx, None, &floor, Instant::now(), None)
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
        let summary = release_ordered(&mut rx, &qtx, None, &floor, Instant::now(), None)
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
        let err = release_ordered(&mut rx, &qtx, None, &floor, Instant::now(), None)
            .await
            .expect_err("gap must fail");
        assert!(
            matches!(err, SlipstreamError::Discontinuity { at: 200, .. }),
            "got: {err}"
        );
    }
}
