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
//! strictly in height order — continuity-verified — into the
//! byte-budgeted ChunkQueue. Splitting + resume-from-height retry landed in
//! run T6.8-S, 2026-06-12.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    chunk::{Chunk, ChunkQueueSender, QueueMeter},
    config::{Endpoint, EngineConfig},
    connector::{ConnPurpose, TorConn, connect_via},
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
    /// Most concurrent `GetBlockRange` workers: a fetch starts one per plan chunk, up
    /// to this ([`FetchPlan::worker_count`]).
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
    /// Adaptive prefetch for a fetch-bound scan (see [`FetchBoost`]). `None`
    /// = the fixed plan: `streams` workers, the fixed ahead budget, plan chunks
    /// of `chunk_blocks`.
    pub boost: Option<FetchBoost>,
}

/// Adaptive prefetch, armed per fetch by the scheduler.
///
/// Armed, the fetch sizes its plan chunks by bytes from the start: the first is a
/// 64-block probe, every later one about one worker's share of the ahead budget
/// at the density being received, at most `chunk_blocks`. Normal-era chunks keep
/// the plan's span; in a dense range a fixed 2,000-block OHTTP chunk is 75-200
/// MB, and with four in flight the head chunk the scan needs gets a quarter of
/// the link while the others fill the ahead budget and park, after which the
/// download runs on one connection. With byte-sized chunks no worker parks for
/// long and every connection works on blocks the scan needs soon.
///
/// On top of that, while the scanner measurably waits for blocks:
///
/// The fetch watches the scanner's wait on the chunk queue
/// ([`crate::chunk::QueueMeter`]) in [`BOOST_WINDOW`] windows. After
/// [`BOOST_HOT_WINDOWS`] consecutive windows in which the scanner waited for at
/// least [`BOOST_ON_FRACTION`] of the time, it boosts:
///
/// * `extra_streams` more workers, each on its own connection (OHTTP gateway
///   and a memory budget not derated for a small device only: 4 + 2 block
///   streams stay far below a gateway's per-client limits). More connections
///   help where one connection cannot fill the link (loss, long RTT); plan
///   chunks handed out from then on are cut to the smaller share of the ahead
///   budget, so the added workers do not park on it;
/// * while the scanner waits for at least [`KICK_SCAN_WAIT_FRACTION`] of a
///   window, a head stream (the plan chunk the release waits for) that
///   delivered far less than the best window of any stream of this fetch
///   ([`KICK_RATE_FRACTION`], or under 64 KiB) is cut and requested again from
///   its resume height on a fresh connection: a mobile link leaves single
///   connections trickling (TCP backoff) while new ones are fine, and a
///   trickle never trips the idle timeout. The blocks it received are handed on
///   first; the restart does not count against the chunk's retry budget.
///
/// The ahead budget is unchanged (the head chunk never waits on it), so memory
/// stays bounded as without the boost. After [`BOOST_COLD_WINDOWS`] consecutive
/// windows in which the scanner waited for less than [`BOOST_OFF_FRACTION`] of
/// the time, the boost ends: extra workers finish their plan chunk and stop. A
/// scanner that never waits (a fast network) never boosts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchBoost {
    /// Workers added while boosted.
    pub extra_streams: usize,
}

/// Length of one starvation window.
pub const BOOST_WINDOW: Duration = Duration::from_secs(10);
/// Scanner-wait fraction of a window that counts as fetch-bound.
pub const BOOST_ON_FRACTION: f64 = 0.25;
/// Consecutive fetch-bound windows before boosting.
pub const BOOST_HOT_WINDOWS: u32 = 2;
/// Scanner-wait fraction of a window below which the scan is no longer fetch-bound.
pub const BOOST_OFF_FRACTION: f64 = 0.05;
/// Consecutive windows below [`BOOST_OFF_FRACTION`] before the boost ends.
pub const BOOST_COLD_WINDOWS: u32 = 6;
/// Smallest plan chunk the dispatcher cuts to, in blocks.
const BOOST_MIN_SPAN: u64 = 10;
/// Scanner-wait fraction of a window above which a slow head stream is restarted.
pub const KICK_SCAN_WAIT_FRACTION: f64 = 0.5;
/// A head stream that delivered less than this fraction of the best window any
/// stream of the fetch delivered is restarted.
pub const KICK_RATE_FRACTION: f64 = 0.125;
/// Below this many bytes in a window a head stream counts as slow whatever the
/// best window was.
const KICK_MIN_WINDOW_BYTES: u64 = 64 * 1024;
/// Shortest time between two restarts of the same worker's stream.
const KICK_COOLDOWN: Duration = Duration::from_secs(30);
/// Workers a boost adds through an OHTTP gateway: 4 + 2 block streams, far below
/// a regional gateway's per-client limits (96 in flight, 12 heavy; a block range
/// counts as a normal request).
pub const BOOST_EXTRA_OHTTP_STREAMS: usize = 2;

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
            boost: None,
        }
    }

    fn chunk_count(&self) -> u64 {
        let span = self.end - self.start + 1;
        span.div_ceil(self.chunk_blocks as u64)
    }

    #[cfg(test)]
    fn chunk_range(&self, index: u64) -> (u64, u64) {
        let s = self.start + index * self.chunk_blocks as u64;
        let e = (s + self.chunk_blocks as u64 - 1).min(self.end);
        (s, e)
    }

    /// The workers a fetch of this plan starts: one per plan chunk, up to `streams`, and
    /// at least one. A worker connects before it looks for a chunk, so one beyond the chunk
    /// count would open a connection and find nothing to fetch — a follow pass's one-chunk
    /// range used to open `streams` connections to download a single block.
    pub fn worker_count(&self) -> usize {
        let chunks = usize::try_from(self.chunk_count()).unwrap_or(usize::MAX);
        self.streams.max(1).min(chunks)
    }
}

/// Blocks and bytes all workers of one fetch have received, for the dispatcher's
/// density estimate.
#[derive(Debug, Default)]
struct FleetStats {
    blocks: AtomicU64,
    bytes: AtomicU64,
}

impl FleetStats {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.blocks.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

/// Blocks in a fetch's first plan chunk, handed out before anything is known of
/// the range's density.
const PROBE_SPAN: u64 = 64;
/// Blocks the fleet must have received before the second plan chunk is sized
/// by density (or [`DENSITY_WAIT`] passes).
const DENSITY_MIN_BLOCKS: u64 = 8;
/// Longest a worker waits for the density estimate before its first chunk.
const DENSITY_WAIT: Duration = Duration::from_secs(3);
/// Blocks received since the previous chunk was handed out that make a fresh
/// density sample; fewer and the fetch's running average is used.
const DENSITY_SAMPLE_BLOCKS: u64 = 32;

/// Hands out plan chunks in height order, consecutive indices from 0, sized by
/// the bytes they will carry rather than by a fixed block count.
///
/// Every plan chunk after the first is about `target_bytes` (one worker's share
/// of the ahead budget) at the density the workers are receiving, between
/// [`BOOST_MIN_SPAN`] and the plan's `chunk_blocks`. Normal-era chunks are far
/// below the share, so they keep the plan's span; in a dense range a fixed
/// 2,000-block OHTTP chunk is 75-200 MB, and with four of them in flight the
/// head chunk the scan needs gets a quarter of the link while the others fill
/// the ahead budget and park (the download then runs on one connection). Chunks
/// of a share of the ahead budget are all needed soon: no worker parks for long,
/// every connection works for the scan, and the head chunk is small.
///
/// The first chunk is [`PROBE_SPAN`] blocks, so a range that starts dense does
/// not open with such chunks; the other workers wait for the first blocks
/// (at most [`DENSITY_WAIT`]) before taking theirs.
///
/// A chunk handed out at the plan's full span that turns out far denser (the
/// light blocks right before a spam onset size the next chunks at that span) is
/// cut by its worker, while the fetch is boosted (the scanner waits for blocks),
/// as soon as the blocks it received show it ([`chunk_cut_end`]): the worker ends
/// it where it would have ended at that density and gives the rest back
/// ([`Self::give_back`]). Given-back ranges lie below every range not yet handed
/// out, so they are handed out first, lowest first, sized like any other chunk.
/// Chunks are then no longer in height order by index; the release stage orders
/// by height.
struct Dispatcher {
    end: u64,
    base_span: u64,
    /// `false`: every chunk is the plan's `chunk_blocks` (no adaptive prefetch).
    sized: bool,
    target_bytes: AtomicU64,
    /// Whether chunks are cut ([`chunk_cut_end`]): only while the fetch is boosted,
    /// the scanner waiting for blocks. On a link that keeps up, a cut only costs a
    /// new request and the bytes in flight on the dropped one (measured: -1.3 % in
    /// the Sapling spam unthrottled).
    cutting: AtomicBool,
    fleet: Arc<FleetStats>,
    created: tokio::time::Instant,
    next: std::sync::Mutex<DispatchState>,
}

/// What a [`Dispatcher`] has handed out so far.
struct DispatchState {
    /// Index of the next chunk handed out.
    index: u64,
    /// First height not handed out yet (given-back ranges aside).
    start: u64,
    /// Fleet snapshot at the previous hand-out.
    seen: (u64, u64),
    /// Ranges of cut chunks given back, `start -> end` (inclusive), all below `start`.
    returned: BTreeMap<u64, u64>,
}

impl Dispatcher {
    /// `target_bytes`: `None` hands out the plan's fixed chunks.
    fn new(plan: &FetchPlan, target_bytes: Option<u64>, fleet: Arc<FleetStats>) -> Self {
        Self {
            end: plan.end,
            base_span: u64::from(plan.chunk_blocks).max(1),
            sized: target_bytes.is_some(),
            target_bytes: AtomicU64::new(target_bytes.unwrap_or(1).max(1)),
            cutting: AtomicBool::new(false),
            fleet,
            created: tokio::time::Instant::now(),
            next: std::sync::Mutex::new(DispatchState {
                index: 0,
                start: plan.start,
                seen: (0, 0),
                returned: BTreeMap::new(),
            }),
        }
    }

    /// The next plan chunk `(index, start, end)`, or `None` once the plan is out.
    async fn take(&self) -> Option<(u64, u64, u64)> {
        loop {
            let (handed, out) = self.handed_out();
            let waiting = self.sized
                && handed > 0
                && !out
                && self.fleet.snapshot().0 < DENSITY_MIN_BLOCKS
                && self.created.elapsed() < DENSITY_WAIT;
            if !waiting {
                // The density may still be unknown here when another worker took
                // the probe in between: `take_now` then hands out the probe.
                return self.take_now();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// [`Self::take`] without waiting for the density estimate.
    fn take_now(&self) -> Option<(u64, u64, u64)> {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let (index, seen) = (next.index, next.seen);
        // A given-back range first: it lies below everything not handed out yet.
        let (start, range_end) = match next.returned.first_key_value() {
            Some((&start, &end)) => (start, end),
            None if next.start > self.end => return None,
            None => (next.start, self.end),
        };
        let now = self.fleet.snapshot();
        let unknown = now.0 < DENSITY_MIN_BLOCKS && self.created.elapsed() < DENSITY_WAIT;
        let span = if !self.sized {
            self.base_span
        } else if index == 0 || unknown {
            PROBE_SPAN.min(self.base_span)
        } else {
            let (blocks, bytes) = if now.0.saturating_sub(seen.0) >= DENSITY_SAMPLE_BLOCKS {
                (now.0 - seen.0, now.1.saturating_sub(seen.1))
            } else {
                now
            };
            match bytes.checked_div(blocks) {
                None => self.base_span,
                Some(per_block) => plan_span(
                    self.target_bytes.load(Ordering::Relaxed),
                    per_block,
                    self.base_span,
                ),
            }
        };
        let end = start.saturating_add(span - 1).min(range_end);
        if next.returned.remove(&start).is_some() {
            if end < range_end {
                next.returned.insert(end + 1, range_end);
            }
        } else {
            next.start = end + 1;
        }
        next.index = index + 1;
        next.seen = now;
        Some((index, start, end))
    }

    /// Plan chunks handed out so far, and whether that is all of them (no range
    /// left to hand out, given-back ones included).
    fn handed_out(&self) -> (u64, bool) {
        let next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        (
            next.index,
            next.start > self.end && next.returned.is_empty(),
        )
    }

    /// Whether a cut chunk's range is waiting to be handed out again.
    fn has_returned(&self) -> bool {
        let next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        !next.returned.is_empty()
    }

    /// Takes back `start..=end`, the rest of a chunk its worker cut: it is handed
    /// out again before any range not handed out yet.
    fn give_back(&self, start: u64, end: u64) {
        if start > end {
            return;
        }
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        debug_assert!(end < next.start, "a given-back range was handed out before");
        next.returned.insert(start, end);
    }

    /// The bytes a chunk is sized to (see [`chunk_cut_end`]) while chunks are cut;
    /// `None` otherwise, and always without the adaptive prefetch.
    fn cut_target(&self) -> Option<u64> {
        (self.sized && self.cutting.load(Ordering::Relaxed))
            .then(|| self.target_bytes.load(Ordering::Relaxed))
    }

    /// Starts or stops cutting chunks (the booster's on/off).
    fn set_cutting(&self, on: bool) {
        self.cutting.store(on, Ordering::Relaxed);
    }

    fn set_target_bytes(&self, bytes: u64) {
        self.target_bytes.store(bytes.max(1), Ordering::Relaxed);
    }
}

/// One worker's share of the ahead budget: the bytes a plan chunk is cut to.
fn chunk_target_bytes(ahead: usize, workers: usize) -> u64 {
    (ahead / workers.max(1)) as u64
}

/// Blocks per plan chunk: `target_bytes` at `bytes_per_block`, between
/// [`BOOST_MIN_SPAN`] and the plan's own span.
fn plan_span(target_bytes: u64, bytes_per_block: u64, base_span: u64) -> u64 {
    let span = target_bytes / bytes_per_block.max(1);
    span.clamp(BOOST_MIN_SPAN.min(base_span), base_span)
}

/// Where a worker ends the plan chunk `start..=end` it streams, or `None` to go on,
/// once it has received `got_blocks` blocks of `got_bytes` through `height`: when the
/// chunk at that density carries at least twice `target_bytes` (judged after
/// [`DENSITY_SAMPLE_BLOCKS`] blocks, or once it carried `target_bytes`), it ends
/// where a chunk sized at that density would ([`plan_span`]), or at `height` if the
/// stream is already past that, and only when at least [`BOOST_MIN_SPAN`] blocks are
/// left after it.
///
/// The pump asks only for a chunk handed out at the plan's full span, the span a
/// light stretch gets: over a spam onset such a chunk carries hundreds of MB, keeps
/// its worker on one connection for minutes on a slow link, and several of them keep
/// every worker far ahead of the scan while the head chunk gets a fraction of the
/// link. A chunk sized by density stays whole: within the spam the density of the
/// next blocks varies up to ~2.6x from the estimate it was sized at (measured), and
/// cutting it would cost a new request and the bytes in flight on the dropped one.
fn chunk_cut_end(
    target_bytes: u64,
    got_blocks: u64,
    got_bytes: u64,
    start: u64,
    height: u64,
    end: u64,
) -> Option<u64> {
    if got_blocks == 0 || (got_blocks < DENSITY_SAMPLE_BLOCKS && got_bytes < target_bytes) {
        return None;
    }
    let per_block = (got_bytes / got_blocks).max(1);
    let span = end.checked_sub(start)? + 1;
    if per_block.saturating_mul(span) < target_bytes.saturating_mul(2) {
        return None;
    }
    let keep = plan_span(target_bytes, per_block, span);
    let cut = height.max(start + keep - 1);
    (cut < end && end - cut >= BOOST_MIN_SPAN).then_some(cut)
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
/// index); `is_last` marks the plan chunk's final sub-chunk (the reorder stage
/// counts released plan chunks by it).
struct SubChunk {
    plan_index: u64,
    sub_index: u64,
    /// The height it was asked from (its worker's resume height): the release
    /// stage's ordering key.
    start: u64,
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
/// being released (the head chunk: every height below its start is released)
/// streams unthrottled — its sub-chunks flow
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
    /// The lowest height the reorder stage has not released (the "floor").
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

    /// Returns a budget permit for one sub-chunk of the plan chunk starting at
    /// `chunk_start`, or `None` when that chunk is (or becomes) the head chunk,
    /// every height below it released: the head chunk is exempt.
    async fn admit(&self, chunk_start: u64, bytes: usize) -> Option<OwnedSemaphorePermit> {
        // u32 saturation mirrors ChunkQueueSender::send; oversized sub-chunks
        // clamp to the whole budget instead of deadlocking.
        let need = u32::try_from(bytes.min(self.cap).max(1)).unwrap_or(u32::MAX);
        loop {
            if self.floor.load(Ordering::Acquire) >= chunk_start {
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
    /// Plan-chunk start (the ahead gate's key: see [`AheadGate::admit`]).
    start: u64,
    /// Plan-chunk end bound (inclusive); lowered when the chunk is cut.
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
    /// Blocks and wire bytes received for this plan chunk, all attempts.
    got_blocks: u64,
    got_bytes: u64,
}

#[derive(Debug)]
enum PumpOutcome {
    /// Stream delivered cleanly through `cursor.end`; `is_last` was emitted.
    Completed,
    /// The reorder stage hung up (abort path) — stop quietly.
    ConsumerGone,
    /// The booster cut this stream as a slow head stream (see `WorkerSlot`): the
    /// blocks received were handed on and the rest is to be requested again.
    /// Only the kick itself yields this; a stream or request error never does.
    Kicked,
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
    let permit = gate.admit(cursor.start, bytes).await;
    let sub = SubChunk {
        plan_index: cursor.plan_index,
        sub_index: cursor.next_sub_index,
        start: cursor.resume_from,
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

/// Ends a kicked attempt: hands on the blocks received so far like
/// [`flush_then_fail`] (never the plan chunk's final block), then reports
/// [`PumpOutcome::Kicked`].
async fn hand_on_then_kicked(
    tail: Option<(Vec<CompactBlock>, usize)>,
    cursor: &mut PlanChunkCursor,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
) -> Result<PumpOutcome, SlipstreamError> {
    if let Some((blocks, bytes)) = tail
        && blocks.last().map(|b| b.height) != Some(cursor.end)
        && !emit_sub_chunk(cursor, blocks, bytes, false, gate, out).await
    {
        return Ok(PumpOutcome::ConsumerGone);
    }
    Ok(PumpOutcome::Kicked)
}

/// Ends the plan chunk at `at` ([`chunk_cut_end`]) and gives `at + 1..=cursor.end`
/// back to `dispatcher`. The stream goes on to `at`, where the pump completes the
/// chunk and drops the stream, which cancels the rest of the request.
fn cut_chunk(
    at: u64,
    cursor: &mut PlanChunkCursor,
    dispatcher: &Dispatcher,
    slot: Option<&WorkerSlot>,
) {
    info!(
        plan_index = cursor.plan_index,
        start = cursor.start,
        cut_at = at,
        rest_blocks = cursor.end - at,
        received_kb = cursor.got_bytes / 1024,
        "plan chunk denser than it was sized for: cut, its rest handed out again"
    );
    dispatcher.give_back(at + 1, cursor.end);
    cursor.end = at;
    if let Some(slot) = slot {
        slot.chunk_end.store(at, Ordering::Relaxed);
    }
}

/// `pump_block_window` over the whole plan chunk (the request ends at `cursor.end`).
#[cfg(test)]
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
    let window_end = cursor.end;
    let mut refused = false;
    pump_block_window(
        stream,
        cursor,
        window_end,
        split_bytes,
        progress_deadline,
        gate,
        out,
        progress,
        &mut refused,
        None,
        None,
    )
    .await
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
///
/// The request ends at `window_end`, at or before the plan chunk's end: a clean end at
/// `window_end` completes the window, and carries `is_last` only when the window reaches
/// `cursor.end`. `refused` is set when the stream ended with `INVALID_ARGUMENT` (an OHTTP
/// gateway answers a range over its span limit that way, with the status as the stream's
/// trailers).
///
/// With `dispatcher` (the adaptive prefetch), a plan chunk denser than it was
/// sized for is cut ([`chunk_cut_end`], [`cut_chunk`]): once the stream reaches the
/// new end, the last sub-chunk is emitted there with `is_last` and the attempt
/// completes before the request does.
#[allow(clippy::too_many_arguments)]
async fn pump_block_window<S>(
    stream: &mut S,
    cursor: &mut PlanChunkCursor,
    window_end: u64,
    split_bytes: usize,
    progress_deadline: Duration,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
    progress: Option<&Progress>,
    refused: &mut bool,
    slot: Option<&WorkerSlot>,
    dispatcher: Option<&Dispatcher>,
) -> Result<PumpOutcome, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<CompactBlock, tonic::Status>> + Unpin,
{
    let ctx = format!(
        "block stream {}..{} (plan chunk {})",
        cursor.resume_from, window_end, cursor.plan_index
    );
    let mut splitter = ChunkSplitter::new(split_bytes);
    // tokio Instant (not std) so start_paused tests drive the deadline.
    let mut last_emit = tokio::time::Instant::now();
    loop {
        let next = match slot {
            // A kick (see `WorkerSlot`) ends the attempt with `Kicked`, but only
            // while the stream has nothing ready: whatever the stream yields first,
            // an error included, is handled as without a kick (the pending kick is
            // then dropped when the next attempt starts).
            Some(slot) => tokio::select! {
                biased;
                next = grpc::next_with_idle_timeout(stream, &ctx) => next,
                () = slot.kick.notified() => {
                    slot.kicked.store(false, Ordering::SeqCst);
                    debug!(plan_index = cursor.plan_index, "{ctx}: cut as a slow head stream");
                    return hand_on_then_kicked(splitter.finish(), cursor, gate, out).await;
                }
            },
            None => grpc::next_with_idle_timeout(stream, &ctx).await,
        };
        let item = match next {
            Ok(item) => item,
            // Idle timeout: the stream went silent.
            Err(err) => return flush_then_fail(splitter.finish(), cursor, gate, out, err).await,
        };
        let Some(item) = item else {
            // Clean end of stream: the tail carries `is_last` iff it completes the
            // plan chunk; a short delivery hands on what it got and fails.
            return match splitter.finish() {
                Some((blocks, bytes)) if blocks.last().map(|b| b.height) == Some(window_end) => {
                    let is_last = window_end == cursor.end;
                    if emit_sub_chunk(cursor, blocks, bytes, is_last, gate, out).await {
                        Ok(PumpOutcome::Completed)
                    } else {
                        Ok(PumpOutcome::ConsumerGone)
                    }
                }
                // A window before the plan chunk's end, already handed on in full.
                None if window_end < cursor.end && cursor.resume_from == window_end + 1 => {
                    Ok(PumpOutcome::Completed)
                }
                tail => {
                    let got = tail
                        .as_ref()
                        .and_then(|(blocks, _)| blocks.last().map(|b| b.height))
                        .unwrap_or_else(|| cursor.resume_from.saturating_sub(1));
                    let err = SlipstreamError::Transport(format!(
                        "{ctx}: stream ended short at {got}, expected {window_end}"
                    ));
                    flush_then_fail(tail, cursor, gate, out, err).await
                }
            };
        };
        let block = match item {
            Ok(block) => block,
            Err(status) => {
                *refused = status.code() == tonic::Code::InvalidArgument;
                let err = grpc::status_err(&ctx, status);
                return flush_then_fail(splitter.finish(), cursor, gate, out, err).await;
            }
        };
        // Liveness: data arriving is forward progress even while the
        // sub-chunk is still accumulating (the stall clock hosts watch).
        if let Some(p) = progress {
            p.touch();
        }
        let (height, block_bytes) = (block.height, block.encoded_len() as u64);
        if let Some(slot) = slot {
            slot.received(block_bytes);
        }
        cursor.got_blocks += 1;
        cursor.got_bytes += block_bytes;
        // Only a chunk handed out at the plan's full span: one sized by density is
        // close to its target, and cutting it for a denser stretch would cost a new
        // request and the bytes in flight on the dropped one.
        if let Some(dispatcher) = dispatcher
            && cursor.end - cursor.start + 1 >= dispatcher.base_span
            && let Some(target) = dispatcher.cut_target()
            && let Some(at) = chunk_cut_end(
                target,
                cursor.got_blocks,
                cursor.got_bytes,
                cursor.start,
                height,
                cursor.end,
            )
        {
            cut_chunk(at, cursor, dispatcher, slot);
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
        // A cut chunk is complete at its new end, before the request is: its last
        // block is still buffered (the deadline flush above never takes it).
        if height == cursor.end
            && cursor.end < window_end
            && let Some((blocks, bytes)) = splitter.take_partial()
        {
            return if emit_sub_chunk(cursor, blocks, bytes, true, gate, out).await {
                Ok(PumpOutcome::Completed)
            } else {
                Ok(PumpOutcome::ConsumerGone)
            };
        }
    }
}

/// The span of the next `GetBlockRange` request after a refusal of `span` blocks with
/// `INVALID_ARGUMENT`: half of it (rounded up), or `None` once it is a single block.
fn split_span(span: u64) -> Option<u64> {
    (span > 1).then(|| span.div_ceil(2))
}

/// Opens the (resume-aware) GetBlockRange stream and pumps it into sub-chunks.
///
/// `max_span` caps the blocks asked for in one request. An OHTTP gateway refuses a range over
/// its span limit with `INVALID_ARGUMENT` (`split_on_invalid`): the cap is halved and the rest
/// of the plan chunk is fetched in windows of that size; the cap stays for the worker's later
/// chunks.
#[allow(clippy::too_many_arguments)]
async fn open_and_pump(
    client: &mut LwdClient,
    cursor: &mut PlanChunkCursor,
    plan: &FetchPlan,
    gate: &AheadGate,
    out: &mpsc::Sender<SubChunk>,
    open_timeout: Duration,
    progress: Option<&Progress>,
    max_span: &mut u64,
    split_on_invalid: bool,
    slot: Option<&WorkerSlot>,
    dispatcher: Option<&Dispatcher>,
) -> Result<PumpOutcome, SlipstreamError> {
    loop {
        let window_end = cursor
            .end
            .min(cursor.resume_from.saturating_add((*max_span).max(1) - 1));
        let req = BlockRange {
            start: Some(BlockId {
                height: cursor.resume_from,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: window_end,
                hash: vec![],
            }),
            ..Default::default()
        };
        // B2 (#1755): response-headers deadline. A server that accepts the request
        // but never answers must fail fast into the worker's retry+reconnect loop.
        // (Longer for OHTTP gateways, whose buffered response = the whole chunk —
        // grpc::range_open_timeout.)
        grpc::net_stats::record(grpc::net_stats::NetEvent::GetBlockRange);
        let opened = tokio::time::timeout(open_timeout, client.get_block_range(req))
            .await
            .map_err(|_| {
                SlipstreamError::Transport(format!(
                    "get_block_range {}..{}: timed out after {}s",
                    cursor.resume_from,
                    window_end,
                    open_timeout.as_secs()
                ))
            })?;
        let start = cursor.resume_from;
        let span = window_end - start + 1;
        let split = |refusal: &dyn std::fmt::Display, max_span: &mut u64| {
            let smaller = split_span(span).filter(|_| split_on_invalid)?;
            warn!(
                span,
                smaller,
                resume_from = start,
                err = %refusal,
                "get_block_range refused as invalid — splitting the range"
            );
            *max_span = smaller;
            Some(())
        };
        let mut stream = match opened {
            Ok(response) => response.into_inner(),
            Err(status) => {
                if status.code() == tonic::Code::InvalidArgument
                    && split(&status, max_span).is_some()
                {
                    continue;
                }
                return Err(grpc::status_err(
                    &format!("get_block_range {}..{}", cursor.resume_from, window_end),
                    status,
                ));
            }
        };
        // The refusal may also come as the stream's status (a trailers-only answer through the
        // OHTTP connector): the blocks before it are handed on, the rest is asked for in
        // smaller windows.
        let mut refused = false;
        let pumped = pump_block_window(
            &mut stream,
            cursor,
            window_end,
            plan.split_bytes,
            plan.chunk_timeout,
            gate,
            out,
            progress,
            &mut refused,
            slot,
            dispatcher,
        )
        .await;
        match pumped {
            Ok(PumpOutcome::Completed) if window_end < cursor.end => continue,
            Ok(outcome) => return Ok(outcome),
            Err(err) if refused && split(&err, max_span).is_some() => continue,
            Err(err) => return Err(err),
        }
    }
}

/// What the booster sees of one worker, and how it restarts the worker's stream.
#[derive(Debug)]
struct WorkerSlot {
    /// The plan chunk being streamed (`u64::MAX` when none).
    plan_index: AtomicU64,
    /// Its heights (`u64::MAX` when none); the end is lowered when it is cut.
    chunk_start: AtomicU64,
    chunk_end: AtomicU64,
    /// Bytes received on the worker's streams.
    bytes: AtomicU64,
    kicked: AtomicBool,
    kick: tokio::sync::Notify,
    /// The whole fetch's receive counters (the dispatcher's density estimate).
    fleet: Arc<FleetStats>,
}

impl WorkerSlot {
    fn new(fleet: Arc<FleetStats>) -> Self {
        Self {
            plan_index: AtomicU64::new(u64::MAX),
            chunk_start: AtomicU64::new(u64::MAX),
            chunk_end: AtomicU64::new(u64::MAX),
            bytes: AtomicU64::new(0),
            kicked: AtomicBool::new(false),
            kick: tokio::sync::Notify::new(),
            fleet,
        }
    }

    /// Records the plan chunk the worker streams now, or none.
    fn set_chunk(&self, chunk: Option<(u64, u64, u64)>) {
        let (index, start, end) = chunk.unwrap_or((u64::MAX, u64::MAX, u64::MAX));
        self.plan_index.store(index, Ordering::Relaxed);
        self.chunk_start.store(start, Ordering::Relaxed);
        self.chunk_end.store(end, Ordering::Relaxed);
    }

    /// Whether the worker streams the plan chunk holding `height`.
    fn holds(&self, height: u64) -> bool {
        let start = self.chunk_start.load(Ordering::Relaxed);
        start != u64::MAX && start <= height && height <= self.chunk_end.load(Ordering::Relaxed)
    }

    /// Records one received block of `bytes`.
    fn received(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.fleet.blocks.fetch_add(1, Ordering::Relaxed);
        self.fleet.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Asks the worker to cut its stream and request the rest again.
    fn kick(&self) {
        self.kicked.store(true, Ordering::SeqCst);
        self.kick.notify_one();
    }

    /// Drops a kick that was requested but not acted on (its stream is gone).
    fn clear_kick(&self) {
        if self.kicked.swap(false, Ordering::SeqCst) {
            let _ = futures_util::FutureExt::now_or_never(self.kick.notified());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn worker(
    worker_id: usize,
    endpoint: Endpoint,
    tor: Option<TorConn>,
    plan: FetchPlan,
    dispatcher: Arc<Dispatcher>,
    boost_on: Arc<AtomicBool>,
    slot: Arc<WorkerSlot>,
    gate: AheadGate,
    out: mpsc::Sender<SubChunk>,
    progress: Option<Arc<Progress>>,
) -> Result<(), SlipstreamError> {
    // Bulk is direct (with bounded retry) for plain hosts even with Tor on; for an OHTTP gateway
    // with Tor on, `connect_via` routes it OHTTP-over-Tor so nothing bypasses the relay/Tor.
    let mut client = match connect_via(&endpoint, tor.as_ref(), ConnPurpose::BulkFetch).await {
        Ok(client) => client,
        // A worker added by a boost holds no plan chunk yet: the fetch goes on without it.
        Err(err) if worker_id >= plan.streams => {
            warn!(worker_id, %err, "boost worker could not connect — fetch continues without it");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let open_timeout = grpc::range_open_timeout(&endpoint);
    let split_on_invalid = crate::ohttp::relay_for(&endpoint.host).is_some();
    let mut max_span = u64::MAX;
    loop {
        // A worker added by a boost stops once the boost has ended, but not while
        // the rest of a cut chunk waits: it may be the one the release needs next,
        // and the workers ahead may all be parked on the ahead budget.
        if worker_id >= plan.streams
            && !boost_on.load(Ordering::Relaxed)
            && !dispatcher.has_returned()
        {
            debug!(worker_id, "boost over — extra worker stops");
            return Ok(());
        }
        let Some((index, s, e)) = dispatcher.take().await else {
            debug!(worker_id, "no more chunks");
            return Ok(());
        };
        slot.set_chunk(Some((index, s, e)));
        let mut cursor = PlanChunkCursor {
            plan_index: index,
            start: s,
            end: e,
            resume_from: s,
            next_sub_index: 0,
            emitted_this_attempt: false,
            got_blocks: 0,
            got_bytes: 0,
        };
        // Counts consecutive ZERO-PROGRESS attempts; an attempt that emitted a
        // sub-chunk resets the budget (resume makes such retries cheap and the
        // total attempt count stays bounded by sub-chunks × retries).
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            cursor.emitted_this_attempt = false;
            // A kick meant for a stream that is gone (the previous chunk's, or an
            // attempt that ended otherwise) does not cut this one.
            slot.clear_kick();
            match open_and_pump(
                &mut client,
                &mut cursor,
                &plan,
                &gate,
                &out,
                open_timeout,
                progress.as_deref(),
                &mut max_span,
                split_on_invalid,
                Some(&slot),
                Some(&dispatcher),
            )
            .await
            {
                Ok(PumpOutcome::Completed) => {
                    slot.set_chunk(None);
                    break;
                }
                Ok(PumpOutcome::ConsumerGone) => return Ok(()), // reorder stage gone (abort)
                // The booster cut a slow head stream: request the rest again on a fresh
                // connection at once. Not an attempt: the stream was alive, only slow.
                // Only `Kicked` gets here; every error takes the arms below.
                Ok(PumpOutcome::Kicked) => {
                    attempt -= 1;
                    info!(
                        worker_id,
                        index,
                        resume_from = cursor.resume_from,
                        "slow head stream cut; requesting the rest on a fresh connection"
                    );
                    client = connect_via(&endpoint, tor.as_ref(), ConnPurpose::BulkFetch).await?;
                }
                // An OHTTP policy denial or an oversized request is refused again on a retry.
                Err(err) if !err.is_transient() && !err.counts_as_unreachable() => {
                    return Err(err);
                }
                Err(err) => {
                    let failed_attempt = attempt;
                    if cursor.emitted_this_attempt {
                        attempt = 0; // progress was made — fresh retry budget
                    }
                    if attempt > plan.retries_per_chunk {
                        if !err.counts_as_unreachable() {
                            return Err(err);
                        }
                        return Err(SlipstreamError::Transport(format!(
                            "plan chunk {index} ({s}..{}) failed after {attempt} zero-progress attempts: {err}",
                            cursor.end
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
                    client = connect_via(&endpoint, tor.as_ref(), ConnPurpose::BulkFetch).await?;
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
/// them strictly in height order into the ChunkQueue, starting at the height
/// `unreleased_from` holds. Keyed by height, not by plan index: the rest of a cut
/// plan chunk is handed out again under a later index ([`Dispatcher`]).
///
/// After each release `unreleased_from` holds the lowest height not yet handed to
/// the scanner. It is also the AheadGate floor: the worker owning the plan chunk
/// that starts at or below it streams unthrottled, and budget held by its
/// buffered sub-chunks drains.
async fn release_ordered(
    rx: &mut mpsc::Receiver<SubChunk>,
    queue: &ChunkQueueSender,
    progress: Option<&Arc<Progress>>,
    unreleased_from: &AtomicU64,
    started: Instant,
    failover: Option<WireFailoverArm>,
) -> Result<ReleaseSummary, SlipstreamError> {
    let mut summary = ReleaseSummary::default();
    let mut continuity = Continuity::default();
    // Buffered sub-chunks by their first height.
    let mut pending: BTreeMap<u64, SubChunk> = BTreeMap::new();
    let mut next_height = unreleased_from.load(Ordering::Acquire);
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
        // Keyed by the height the sub-chunk was asked from: a sub-chunk that does
        // not start there is released in its place, and `continuity` rejects it.
        let key = sub.start;
        if key < next_height || pending.contains_key(&key) {
            return Err(SlipstreamError::Transport(format!(
                "fetch: plan chunk {} sub-chunk {} starts at {key}, already sent",
                sub.plan_index, sub.sub_index
            )));
        }
        pending.insert(key, sub);
        while let Some(sub) = pending.remove(&next_height) {
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
                next_height = height + 1;
                unreleased_from.store(next_height, Ordering::Release);
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
#[cfg(test)]
async fn supervise_fetch<R>(
    release: R,
    workers: JoinSet<Result<(), SlipstreamError>>,
    failover: Option<WireFailoverArm>,
    progress: Option<&Progress>,
    unreleased_from: &AtomicU64,
    plan_end: u64,
) -> Result<ReleaseSummary, SlipstreamError>
where
    R: std::future::Future<Output = Result<ReleaseSummary, SlipstreamError>>,
{
    supervise_fetch_boosted(
        release,
        workers,
        failover,
        progress,
        unreleased_from,
        plan_end,
        None,
    )
    .await
}

/// `supervise_fetch` with the adaptive prefetch's [`Booster`], when armed:
/// it is evaluated every [`BOOST_WINDOW`] and may add workers to `workers`.
async fn supervise_fetch_boosted<R>(
    release: R,
    mut workers: JoinSet<Result<(), SlipstreamError>>,
    failover: Option<WireFailoverArm>,
    progress: Option<&Progress>,
    unreleased_from: &AtomicU64,
    plan_end: u64,
    mut booster: Option<Booster>,
) -> Result<ReleaseSummary, SlipstreamError>
where
    R: std::future::Future<Output = Result<ReleaseSummary, SlipstreamError>>,
{
    tokio::pin!(release);
    let mut released: Option<ReleaseSummary> = None;
    let mut ticks =
        tokio::time::interval_at(tokio::time::Instant::now() + BOOST_WINDOW, BOOST_WINDOW);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if workers.is_empty()
            && let Some(summary) = released.take()
        {
            return Ok(summary);
        }
        tokio::select! {
            biased;
            Some(joined) = workers.join_next(), if !workers.is_empty() => match joined {
                Ok(Ok(())) => {
                    // The plan may be out: the booster then lets go of its sender, so
                    // the release ends once the workers have.
                    if let Some(b) = booster.as_mut() {
                        b.drop_sender_if_plan_out();
                    }
                }
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
            _ = ticks.tick(), if booster.is_some() => {
                if let Some(b) = booster.as_mut() {
                    b.evaluate(&mut workers);
                }
            },
        }
    }
}

/// Everything a boost needs to start one more worker. Dropped (with its
/// sender) once every plan chunk is handed out.
struct WorkerSpawn {
    endpoint: Endpoint,
    tor: Option<TorConn>,
    plan: FetchPlan,
    tx: mpsc::Sender<SubChunk>,
    progress: Option<Arc<Progress>>,
}

/// One worker as the booster tracks it.
struct TrackedWorker {
    slot: Arc<WorkerSlot>,
    /// `slot.bytes` at the start of the window.
    window_bytes: u64,
    last_kick: Option<Instant>,
    /// Plan index of the chunk this worker kicked most recently.
    last_kicked_plan_index: Option<u64>,
    /// Number of times we kicked this plan chunk.
    kick_count: u32,
}

/// The adaptive prefetch of one fetch (see [`FetchBoost`]).
struct Booster {
    cfg: FetchBoost,
    meter: Arc<QueueMeter>,
    dispatcher: Arc<Dispatcher>,
    boost_on: Arc<AtomicBool>,
    /// The lowest height the release stage has not released.
    floor: Arc<AtomicU64>,
    gate: AheadGate,
    base_streams: usize,
    ahead: usize,
    spawn: Option<WorkerSpawn>,
    workers: Vec<TrackedWorker>,
    /// Extra workers started by boosts (finished ones included).
    extras: Vec<tokio::task::AbortHandle>,
    next_extra_id: usize,
    window_started: Instant,
    window_waited: Duration,
    window_sent: (u64, u64),
    state: BoostState,
    /// Most bytes one stream delivered in a window so far. Decays gradually
    /// so the head is compared against recent performance, not an all-time peak.
    best_window_bytes: u64,
    /// Aggregate bytes received in the last pre-boost window (for boost effectiveness check).
    pre_boost_bytes: Option<u64>,
    /// Windows since boost started (to measure boost effectiveness).
    boost_window_count: u32,
    /// Aggregate bytes in the first full window after boost started.
    first_boost_window_bytes: Option<u64>,
    /// Set when boost was just retracted as ineffective. Cleared after one window.
    /// Used to skip head-kick when the link is known to be saturated.
    boost_just_retracted: bool,
}

impl Booster {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: FetchBoost,
        meter: Arc<QueueMeter>,
        dispatcher: Arc<Dispatcher>,
        boost_on: Arc<AtomicBool>,
        floor: Arc<AtomicU64>,
        gate: AheadGate,
        ahead: usize,
        slots: &[Arc<WorkerSlot>],
        spawn: WorkerSpawn,
    ) -> Self {
        let base_streams = spawn.plan.streams.max(1);
        let window_waited = meter.scan_waited();
        let window_sent = meter.sent();
        Self {
            cfg,
            meter,
            dispatcher,
            boost_on,
            floor,
            gate,
            base_streams,
            ahead,
            spawn: Some(spawn),
            workers: slots
                .iter()
                .map(|slot| TrackedWorker {
                    slot: Arc::clone(slot),
                    window_bytes: 0,
                    last_kick: None,
                    last_kicked_plan_index: None,
                    kick_count: 0,
                })
                .collect(),
            extras: Vec::new(),
            next_extra_id: base_streams,
            window_started: Instant::now(),
            window_waited,
            window_sent,
            state: BoostState::default(),
            best_window_bytes: 0,
            pre_boost_bytes: None,
            boost_window_count: 0,
            first_boost_window_bytes: None,
            boost_just_retracted: false,
        }
    }

    fn boosted(&self) -> bool {
        self.boost_on.load(Ordering::Relaxed)
    }

    fn drop_sender_if_plan_out(&mut self) {
        if self.spawn.is_some() && self.dispatcher.handed_out().1 {
            self.spawn = None;
        }
    }

    /// Closes one window: decides to boost, retune or end the boost, and cuts a
    /// slow head stream. Retracts boost if it doesn't improve aggregate throughput.
    fn evaluate(&mut self, workers: &mut JoinSet<Result<(), SlipstreamError>>) {
        self.drop_sender_if_plan_out();
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_started);
        let waited_total = self.meter.scan_waited();
        let sent_total = self.meter.sent();
        let waited = waited_total.saturating_sub(self.window_waited);
        self.window_started = now;
        self.window_waited = waited_total;
        self.window_sent = sent_total;
        let per_stream = self.close_stream_windows();
        // Nothing released yet: the first chunk's latency, not a fetch-bound scan.
        if sent_total.0 == 0 || elapsed.is_zero() {
            return;
        }

        let aggregate_bytes: u64 = per_stream.iter().sum();

        // Clear the retraction flag after one window (unless we retract again this window).
        let mut retracted_this_window = false;

        // Track boost effectiveness: if boosted and we have a baseline, check
        // if the boost actually improved throughput.
        if self.boosted() {
            self.boost_window_count += 1;
            if self.first_boost_window_bytes.is_none() {
                self.first_boost_window_bytes = Some(aggregate_bytes);
            } else if self.boost_window_count >= 2 {
                // After at least one full window with extra workers, check if throughput improved.
                if let Some(baseline) = self.pre_boost_bytes {
                    let improved = aggregate_bytes > (baseline as f64 * 1.2) as u64;
                    if !improved {
                        info!(
                            baseline_kb = baseline / 1024,
                            current_kb = aggregate_bytes / 1024,
                            "boost did not improve throughput — retracting extra workers"
                        );
                        // Retract boost without logging a fake "boost off" message.
                        self.boost_on.store(false, Ordering::Relaxed);
                        self.dispatcher.set_cutting(false);
                        self.dispatcher
                            .set_target_bytes(chunk_target_bytes(self.ahead, self.base_streams));
                        self.state.force_cooldown();
                        retracted_this_window = true;
                        self.boost_just_retracted = true;
                    }
                }
            }
        }

        if !retracted_this_window {
            self.boost_just_retracted = false;
        }

        let fraction = waited.as_secs_f64() / elapsed.as_secs_f64();
        match self.state.observe(fraction) {
            BoostStep::Start => {
                // Capture pre-boost baseline for effectiveness check.
                self.pre_boost_bytes = Some(aggregate_bytes);
                self.boost_window_count = 0;
                self.first_boost_window_bytes = None;
                self.boost_just_retracted = false;
                self.start(workers, fraction);
            }
            BoostStep::Stop => self.stop(fraction),
            BoostStep::Stay if self.boosted() => self.top_up_workers(workers),
            BoostStep::Stay => {}
        }
        if self.boosted() && fraction >= KICK_SCAN_WAIT_FRACTION && !self.boost_just_retracted {
            self.kick_slow_head(&per_stream, now);
        }
    }

    /// Bytes each tracked worker received in the window that just closed (in
    /// `self.workers` order); updates the best window with gradual decay.
    fn close_stream_windows(&mut self) -> Vec<u64> {
        let mut got = Vec::with_capacity(self.workers.len());
        for w in &mut self.workers {
            let total = w.slot.bytes.load(Ordering::Relaxed);
            let delta = total.saturating_sub(w.window_bytes);
            w.window_bytes = total;
            got.push(delta);
        }
        // Decay the best window: max of (current best * 0.9, this window's max).
        // This allows the "best" to fall gradually when link conditions worsen,
        // so the head is compared against recent performance, not an all-time peak.
        let window_max = got.iter().copied().max().unwrap_or(0);
        self.best_window_bytes = decayed_best_window(self.best_window_bytes, window_max);
        got
    }

    /// Restarts the stream of the head plan chunk when it is slow (see [`FetchBoost`]).
    /// Applies exponential backoff per plan chunk to avoid thrashing on saturated links.
    fn kick_slow_head(&mut self, per_stream: &[u64], now: Instant) {
        let floor = self.floor.load(Ordering::Acquire);
        let best = self.best_window_bytes;

        // Only kick when other streams are demonstrably faster: compare the head
        // against the CURRENT window's best, not an all-time max. If everything is
        // slow, the link is saturated and kicking won't help.
        let current_window_max = per_stream.iter().copied().max().unwrap_or(0);
        if current_window_max < KICK_MIN_WINDOW_BYTES {
            // All streams are slow — saturated link. Don't kick anything.
            return;
        }

        for (w, &delta) in self.workers.iter_mut().zip(per_stream) {
            if !w.slot.holds(floor) {
                continue;
            }

            let plan_index = w.slot.plan_index.load(Ordering::Relaxed);

            // Reset kick count if we moved to a new plan chunk.
            if w.last_kicked_plan_index != Some(plan_index) {
                w.kick_count = 0;
                w.last_kicked_plan_index = Some(plan_index);
            }

            // Exponential backoff: after each kick, wait longer before the next one
            // for the same plan chunk. Max 3 kicks per chunk.
            let max_kicks = 3;
            if w.kick_count >= max_kicks {
                continue;
            }

            let backoff = KICK_COOLDOWN * 2u32.saturating_pow(w.kick_count);
            let cooling = w.last_kick.is_some_and(|t| now.duration_since(t) < backoff);

            if !cooling && head_is_slow(delta, best) {
                info!(
                    plan_index,
                    window_kb = delta / 1024,
                    best_window_kb = best / 1024,
                    kick_count = w.kick_count + 1,
                    "head stream slow while the scanner waits — restarting it"
                );
                w.slot.kick();
                w.last_kick = Some(now);
                w.kick_count += 1;
            }
        }
    }

    fn start(&mut self, workers: &mut JoinSet<Result<(), SlipstreamError>>, fraction: f64) {
        self.boost_on.store(true, Ordering::Relaxed);
        self.dispatcher.set_cutting(true);
        self.top_up_workers(workers);
        // The ahead budget's share shrinks with the added workers.
        self.dispatcher.set_target_bytes(chunk_target_bytes(
            self.ahead,
            self.base_streams + self.cfg.extra_streams,
        ));
        info!(
            scan_wait_pct = (fraction * 100.0) as u64,
            workers = self.base_streams + self.live_extras(),
            "fetch boost on: the scanner is waiting for blocks"
        );
    }

    fn stop(&mut self, fraction: f64) {
        self.boost_on.store(false, Ordering::Relaxed);
        self.dispatcher.set_cutting(false);
        self.dispatcher
            .set_target_bytes(chunk_target_bytes(self.ahead, self.base_streams));
        info!(
            scan_wait_pct = (fraction * 100.0) as u64,
            "fetch boost off: the scanner no longer waits"
        );
    }

    fn live_extras(&self) -> usize {
        self.extras.iter().filter(|h| !h.is_finished()).count()
    }

    /// Starts extra workers up to `extra_streams` live ones, while the plan has
    /// chunks left to hand out.
    fn top_up_workers(&mut self, workers: &mut JoinSet<Result<(), SlipstreamError>>) {
        let Some(spawn) = &self.spawn else { return };
        self.extras.retain(|h| !h.is_finished());
        while self.extras.len() < self.cfg.extra_streams {
            let id = self.next_extra_id;
            self.next_extra_id += 1;
            let slot = Arc::new(WorkerSlot::new(Arc::clone(&self.dispatcher.fleet)));
            let handle = workers.spawn(worker(
                id,
                spawn.endpoint.clone(),
                spawn.tor.clone(),
                spawn.plan.clone(),
                Arc::clone(&self.dispatcher),
                Arc::clone(&self.boost_on),
                Arc::clone(&slot),
                self.gate.clone(),
                spawn.tx.clone(),
                spawn.progress.clone(),
            ));
            self.extras.push(handle);
            self.workers.push(TrackedWorker {
                slot,
                window_bytes: 0,
                last_kick: None,
                last_kicked_plan_index: None,
                kick_count: 0,
            });
        }
    }
}

/// The best per-stream window after one more window: the previous best decayed by 10 %,
/// or this window's best stream if higher.
fn decayed_best_window(prev_best: u64, window_max: u64) -> u64 {
    ((prev_best as f64 * 0.9) as u64).max(window_max)
}

/// Whether a head stream that received `window_bytes` in a window is slow next to
/// the best window `best_window_bytes` of any stream of the fetch.
fn head_is_slow(window_bytes: u64, best_window_bytes: u64) -> bool {
    window_bytes < KICK_MIN_WINDOW_BYTES
        || (window_bytes as f64) < KICK_RATE_FRACTION * best_window_bytes as f64
}

/// What one closed window asks of the booster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoostStep {
    Start,
    Stop,
    Stay,
}

/// The booster's on/off hysteresis over closed windows (see [`FetchBoost`]).
#[derive(Debug, Default)]
struct BoostState {
    on: bool,
    /// Consecutive fetch-bound windows while off.
    hot: u32,
    /// Consecutive windows without waiting while on.
    cold: u32,
    /// Windows remaining in a cooldown period after ineffective boost.
    /// While > 0, `Start` is blocked and this counter decrements each window.
    cooldown_windows: u32,
    /// Number of times boost has been retracted as ineffective. Used for exponential backoff.
    ineffective_count: u32,
}

impl BoostState {
    /// Records one window in which the scanner waited for `fraction` of the time.
    fn observe(&mut self, fraction: f64) -> BoostStep {
        // Decrement cooldown if active.
        if self.cooldown_windows > 0 {
            self.cooldown_windows -= 1;
            return BoostStep::Stay;
        }

        if !self.on {
            self.hot = if fraction >= BOOST_ON_FRACTION {
                self.hot + 1
            } else {
                0
            };
            if self.hot >= BOOST_HOT_WINDOWS {
                *self = Self {
                    on: true,
                    hot: 0,
                    cold: 0,
                    cooldown_windows: 0,
                    ineffective_count: self.ineffective_count,
                };
                return BoostStep::Start;
            }
        } else {
            self.cold = if fraction < BOOST_OFF_FRACTION {
                self.cold + 1
            } else {
                0
            };
            if self.cold >= BOOST_COLD_WINDOWS {
                *self = Self {
                    on: false,
                    hot: 0,
                    cold: 0,
                    cooldown_windows: 0,
                    ineffective_count: self.ineffective_count,
                };
                return BoostStep::Stop;
            }
        }
        BoostStep::Stay
    }

    /// Force a cooldown after an ineffective boost: exponential backoff.
    /// First retraction: 12 windows (~2 min). Each subsequent: doubled.
    fn force_cooldown(&mut self) {
        self.on = false;
        self.hot = 0;
        self.cold = 0;
        self.ineffective_count += 1;
        // 12 windows = ~2 minutes at 10s per window. Exponential backoff: 12, 24, 48, ...
        self.cooldown_windows = 12 * (1 << (self.ineffective_count - 1).min(4));
    }
}

/// Fetch `plan.start..=plan.end` with [`FetchPlan::worker_count`] initial workers,
/// adding adaptive workers when configured. Emits ordered, continuity-verified chunks
/// into `queue` and returns stats on success.
///
/// `progress` — if `Some`, bumps `fetched_blocks` by the block count of each
/// ordered sub-chunk as it is released (Relaxed atomic; no cross-counter guarantees).
///
/// `tor` — the session's Tor handle when Tor is on. Bulk stays direct for plain hosts; for an
/// OHTTP gateway it makes the workers dial the relay through Tor (see `connector::route`).
pub async fn run_fetch(
    endpoint: &Endpoint,
    tor: Option<TorConn>,
    plan: FetchPlan,
    queue: ChunkQueueSender,
    progress: Option<Arc<Progress>>,
) -> Result<FetchStats, SlipstreamError> {
    let started = Instant::now();
    let chunk_count = plan.chunk_count();
    let worker_count = plan.worker_count();
    info!(
        start = plan.start,
        end = plan.end,
        chunk_count,
        streams = plan.streams,
        workers = worker_count,
        split_bytes = plan.split_bytes,
        "fetch begin"
    );

    // Cap initial workers to the plan chunks even when later chunks are sized
    // adaptively. The booster uses the same base count when it starts/stops extras.
    let mut plan = plan;
    plan.streams = worker_count;
    let ahead = plan.split_bytes.saturating_mul(AHEAD_BUDGET_FACTOR);
    let fleet = Arc::new(FleetStats::default());
    // Byte-sized plan chunks come with the adaptive prefetch (see `Dispatcher`).
    let dispatcher = Arc::new(Dispatcher::new(
        &plan,
        plan.boost
            .map(|_| chunk_target_bytes(ahead, plan.streams.max(1))),
        Arc::clone(&fleet),
    ));
    let boost_on = Arc::new(AtomicBool::new(false));
    // The lowest block not yet handed to the scanner: the ahead gate's floor, and where the
    // download stands if a worker gives up (see `supervise_fetch`).
    let unreleased_from = Arc::new(AtomicU64::new(plan.start));
    let gate = AheadGate::new(ahead, Arc::clone(&unreleased_from));
    // Small reorder margin: each message is one sub-chunk (≤ ~split_bytes).
    let (tx, mut rx) = mpsc::channel::<SubChunk>(plan.streams.max(1));

    let mut workers = JoinSet::new();
    let slots: Vec<Arc<WorkerSlot>> = (0..plan.streams.max(1))
        .map(|_| Arc::new(WorkerSlot::new(Arc::clone(&fleet))))
        .collect();
    for (worker_id, slot) in slots.iter().enumerate() {
        workers.spawn(worker(
            worker_id,
            endpoint.clone(),
            tor.clone(),
            plan.clone(),
            Arc::clone(&dispatcher),
            Arc::clone(&boost_on),
            Arc::clone(slot),
            gate.clone(),
            tx.clone(),
            progress.clone(),
        ));
    }
    // The booster keeps a sender for the workers it may add, until the plan is out.
    let booster = plan.boost.map(|cfg| {
        Booster::new(
            cfg,
            queue.meter(),
            Arc::clone(&dispatcher),
            Arc::clone(&boost_on),
            Arc::clone(&unreleased_from),
            gate.clone(),
            ahead,
            &slots,
            WorkerSpawn {
                endpoint: endpoint.clone(),
                tor: tor.clone(),
                plan: plan.clone(),
                tx: tx.clone(),
                progress: progress.clone(),
            },
        )
    });
    drop(tx); // release loop ends when all workers (and the booster) let go of theirs

    // Workers are supervised WHILE the ordered release runs: one that gives up
    // fails the fetch now (see `supervise_fetch`) instead of after a release
    // that is waiting for its chunk.
    let summary = supervise_fetch_boosted(
        release_ordered(
            &mut rx,
            &queue,
            progress.as_ref(),
            &unreleased_from,
            started,
            plan.failover,
        ),
        workers,
        plan.failover,
        progress.as_deref(),
        &unreleased_from,
        plan.end,
        booster,
    )
    .await?;

    let (handed_out, plan_out) = dispatcher.handed_out();
    if !plan_out || summary.plans_released != handed_out {
        return Err(SlipstreamError::Transport(format!(
            "fetch incomplete: released {}/{handed_out} plan chunks (plan out: {plan_out})",
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
mod boost_tests {
    use super::*;

    /// Records `blocks` received blocks of `bytes_each` on the fleet.
    fn receive(fleet: &FleetStats, blocks: u64, bytes_each: u64) {
        fleet.blocks.fetch_add(blocks, Ordering::Relaxed);
        fleet
            .bytes
            .fetch_add(blocks * bytes_each, Ordering::Relaxed);
    }

    #[test]
    fn the_first_chunk_is_a_probe_and_normal_era_chunks_keep_the_plans_span() {
        let plan = FetchPlan::new(1000, 9999, 2000, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(16 << 20), Arc::clone(&fleet));
        assert_eq!(
            d.take_now(),
            Some((0, 1000, 1063)),
            "probe of PROBE_SPAN blocks"
        );
        // Normal era: ~600 bytes per block, 16 MiB covers far more than 2,000 blocks.
        receive(&fleet, 64, 600);
        assert_eq!(d.take_now(), Some((1, 1064, 3063)));
        assert_eq!(d.take_now(), Some((2, 3064, 5063)));
        assert_eq!(d.take_now(), Some((3, 5064, 7063)));
        assert_eq!(d.take_now(), Some((4, 7064, 9063)));
        assert_eq!(
            d.take_now(),
            Some((5, 9064, 9999)),
            "the last chunk ends at the plan's end"
        );
        assert_eq!(d.take_now(), None);
        assert_eq!(d.handed_out(), (6, true));
    }

    #[test]
    fn dense_chunks_are_cut_to_the_target_bytes_and_follow_the_density() {
        let plan = FetchPlan::new(0, 99_999, 2000, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(16 << 20), Arc::clone(&fleet));
        let _ = d.take_now();
        // Orchard spam: ~37 KB per block -> 16 MiB is ~453 blocks.
        receive(&fleet, 64, 37_000);
        assert_eq!(d.take_now(), Some((1, 64, 64 + 453 - 1)));
        // A fresh sample of a denser stretch (~116 KB per block) wins over the average.
        receive(&fleet, 200, 116_000);
        let (_, s, e) = d.take_now().expect("chunk");
        assert_eq!(e - s + 1, (16u64 << 20) / 116_000);
        // Fewer new blocks than a sample: the fetch's running average.
        receive(&fleet, 2, 116_000);
        let (_, s, e) = d.take_now().expect("chunk");
        let (blocks, bytes) = fleet.snapshot();
        assert_eq!(e - s + 1, (16u64 << 20) / (bytes / blocks));
        // A smaller share (more workers) cuts the chunks further.
        d.set_target_bytes(8 << 20);
        receive(&fleet, 100, 116_000);
        let (_, s, e) = d.take_now().expect("chunk");
        assert_eq!(e - s + 1, (8u64 << 20) / 116_000);
    }

    #[tokio::test(start_paused = true)]
    async fn workers_after_the_first_wait_for_the_density_then_go_on_without_it() {
        let plan = FetchPlan::new(0, 99_999, 2000, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Arc::new(Dispatcher::new(&plan, Some(16 << 20), Arc::clone(&fleet)));
        assert_eq!(d.take().await, Some((0, 0, 63)));
        let started = tokio::time::Instant::now();
        // Nothing ever arrives: after DENSITY_WAIT the plan's own span.
        assert_eq!(d.take().await, Some((1, 64, 2063)));
        assert!(started.elapsed() >= DENSITY_WAIT);
        // With the density known there is no wait.
        receive(&fleet, 64, 100_000);
        let before = tokio::time::Instant::now();
        let (_, s, e) = d.take().await.expect("chunk");
        assert_eq!(before.elapsed(), Duration::ZERO);
        assert_eq!(e - s + 1, (16u64 << 20) / 100_000);
    }

    #[test]
    fn a_chunk_is_cut_only_when_it_carries_twice_its_target_at_the_density_received() {
        let t = 16u64 << 20;
        // 2,000 blocks at ~168 KB: 330 MB, cut where a 16 MiB chunk would end.
        let at = |blocks, bytes, height| chunk_cut_end(t, blocks, bytes, 1000, height, 2999);
        assert_eq!(at(32, 32 * 168_000, 1031), Some(1000 + t / 168_000 - 1));
        // Fewer than a sample and less than the target received: go on.
        assert_eq!(at(31, 31 * 168_000, 1030), None);
        // Past where it would have ended: cut where the stream stands.
        assert_eq!(at(200, 200 * 168_000, 1199), Some(1199));
        // Light blocks: the chunk is far below its target, go on.
        assert_eq!(at(64, 64 * 600, 1063), None);
        // A chunk sized at its density (100 blocks of a 16 MiB target) is never cut.
        assert_eq!(chunk_cut_end(t, 50, 50 * (t / 100), 0, 49, 99), None);
        // Fewer than BOOST_MIN_SPAN blocks would be left: go on.
        assert_eq!(
            chunk_cut_end(t, 32, 32 * t, 0, 31, 31 + BOOST_MIN_SPAN - 1),
            None
        );
        // At or past its end there is nothing to cut.
        assert_eq!(chunk_cut_end(t, 100, 100 * t, 0, 99, 99), None);
        assert_eq!(chunk_cut_end(t, 0, 0, 0, 0, 99), None);
    }

    #[test]
    fn the_rest_of_a_cut_chunk_is_handed_out_first_lowest_first_and_sized_like_any_chunk() {
        let plan = FetchPlan::new(0, 99_999, 2000, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(16 << 20), Arc::clone(&fleet));
        assert_eq!(d.cut_target(), None, "no cuts before a boost");
        d.set_cutting(true);
        assert_eq!(d.cut_target(), Some(16 << 20));
        let _ = d.take_now();
        // Light blocks before an onset: full-span chunks.
        receive(&fleet, 64, 600);
        assert_eq!(d.take_now(), Some((1, 64, 2063)));
        assert_eq!(d.take_now(), Some((2, 2064, 4063)));
        // Both turn out dense and are cut; the rests come back, the higher first.
        d.give_back(2200, 4063);
        d.give_back(500, 2063);
        assert!(d.has_returned());
        assert_eq!(d.handed_out(), (3, false));
        // ~116 KB per block now: 144 blocks per chunk, from the lowest rest up.
        receive(&fleet, 100, 116_000);
        let span = (16u64 << 20) / 116_000;
        assert_eq!(d.take_now(), Some((3, 500, 500 + span - 1)));
        let mut handed = vec![(500, 500 + span - 1)];
        while let Some((_, s, e)) = d.take_now() {
            if s >= 4064 {
                assert_eq!(s, 4064, "the plan goes on after its rests");
                break;
            }
            handed.push((s, e));
        }
        assert!(!d.has_returned());
        let covered: Vec<u64> = handed.iter().flat_map(|&(s, e)| s..=e).collect();
        let expected: Vec<u64> = (500..=2063).chain(2200..=4063).collect();
        assert_eq!(
            covered, expected,
            "every given-back height exactly once, in height order"
        );
        // No chunk runs past the end of the rest it is cut from.
        assert!(handed.iter().any(|&(_, e)| e == 2063));
    }

    #[test]
    fn the_plan_is_out_only_once_no_rest_is_left() {
        let plan = FetchPlan::new(0, 999, 1000, 1);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(16 << 20), Arc::clone(&fleet));
        let _ = d.take_now();
        receive(&fleet, 64, 600);
        assert_eq!(d.take_now(), Some((1, 64, 999)));
        assert_eq!(d.handed_out(), (2, true));
        d.give_back(700, 999);
        assert_eq!(d.handed_out(), (2, false), "a rest is still to hand out");
        assert_eq!(d.take_now(), Some((2, 700, 999)));
        assert_eq!(d.handed_out(), (3, true));
        assert_eq!(d.take_now(), None);
        // Without the adaptive prefetch nothing is ever cut.
        let fixed = Dispatcher::new(&plan, None, Arc::clone(&fleet));
        assert_eq!(fixed.cut_target(), None);
    }

    #[test]
    fn without_the_adaptive_prefetch_the_plans_fixed_chunks() {
        let plan = FetchPlan::new(1000, 1999, 300, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, None, Arc::clone(&fleet));
        receive(&fleet, 100, 1 << 20);
        for i in 0..plan.chunk_count() {
            let (s, e) = plan.chunk_range(i);
            assert_eq!(d.take_now(), Some((i, s, e)));
        }
        assert_eq!(d.take_now(), None);
        assert_eq!(d.handed_out(), (plan.chunk_count(), true));
    }

    #[test]
    fn plan_span_is_bounded_by_the_floor_and_the_plans_span() {
        assert_eq!(plan_span(16 << 20, 600, 2_000), 2_000);
        assert_eq!(plan_span(1 << 20, 10 << 20, 2_000), BOOST_MIN_SPAN);
        assert_eq!(plan_span(1 << 20, 10 << 20, 4), 4);
        assert_eq!(plan_span(1 << 20, 0, 2_000), 2_000);
        assert_eq!(chunk_target_bytes(64 << 20, 4), 16 << 20);
        assert_eq!(chunk_target_bytes(64 << 20, 0), 64 << 20);
    }

    #[test]
    fn boost_starts_after_consecutive_fetch_bound_windows_only() {
        let mut st = BoostState::default();
        assert_eq!(st.observe(0.9), BoostStep::Stay);
        assert_eq!(
            st.observe(0.1),
            BoostStep::Stay,
            "a calm window resets the count"
        );
        assert_eq!(st.observe(0.3), BoostStep::Stay);
        assert_eq!(st.observe(BOOST_ON_FRACTION), BoostStep::Start);
        assert!(st.on);
    }

    #[test]
    fn a_scanner_that_never_waits_never_boosts() {
        let mut st = BoostState::default();
        for _ in 0..1000 {
            assert_eq!(st.observe(0.0), BoostStep::Stay);
            assert_eq!(st.observe(BOOST_ON_FRACTION - 0.01), BoostStep::Stay);
        }
        assert!(!st.on);
    }

    #[test]
    fn boost_ends_after_consecutive_calm_windows() {
        let mut st = BoostState {
            on: true,
            hot: 0,
            cold: 0,
            cooldown_windows: 0,
            ineffective_count: 0,
        };
        for _ in 0..BOOST_COLD_WINDOWS - 1 {
            assert_eq!(st.observe(0.0), BoostStep::Stay);
        }
        assert_eq!(
            st.observe(0.2),
            BoostStep::Stay,
            "a waiting window resets the count"
        );
        for _ in 0..BOOST_COLD_WINDOWS - 1 {
            assert_eq!(st.observe(0.01), BoostStep::Stay);
        }
        assert_eq!(st.observe(0.0), BoostStep::Stop);
        assert!(!st.on);
    }

    #[test]
    fn head_is_slow_relative_to_best() {
        // Head received 32 KB, best was 640 KB: head is slow (< 12.5% of best).
        assert!(head_is_slow(32 * 1024, 640 * 1024));
        // Exactly 12.5 % of the best is not slow; just under it is.
        assert!(!head_is_slow(80 * 1024, 640 * 1024));
        assert!(head_is_slow(79 * 1024, 640 * 1024));
        // Head received 100 KB, best was 640 KB: not slow (>= 12.5% of best).
        assert!(!head_is_slow(100 * 1024, 640 * 1024));
        // Head received < 64 KB: always slow regardless of best.
        assert!(head_is_slow(32 * 1024, 64 * 1024));
        assert!(head_is_slow(60 * 1024, 1_000_000));
    }

    #[test]
    fn best_window_decays_gradually() {
        // A fast window sets the best.
        let best = decayed_best_window(0, 640 * 1024);
        assert_eq!(best, 640 * 1024);
        // Slower windows let it fall 10 % per window, never below the current window.
        let best = decayed_best_window(best, 100 * 1024);
        assert_eq!(best, (640.0 * 1024.0 * 0.9) as u64);
        let mut b = best;
        for _ in 0..30 {
            b = decayed_best_window(b, 50 * 1024);
        }
        assert_eq!(b, 50 * 1024);
        // A new faster window raises it at once.
        assert_eq!(decayed_best_window(b, 700 * 1024), 700 * 1024);
    }

    #[test]
    fn boost_state_force_cooldown_blocks_start_for_12_windows() {
        let mut st = BoostState::default();
        // Warm up to boost.
        assert_eq!(st.observe(0.30), BoostStep::Stay);
        assert_eq!(st.observe(0.30), BoostStep::Start);
        assert!(st.on);

        // Force cooldown (first time: 12 windows).
        st.force_cooldown();
        assert!(!st.on);
        assert_eq!(st.cooldown_windows, 12);
        assert_eq!(st.ineffective_count, 1);

        // Next 11 windows: all Stay, even with high wait fractions.
        for i in 0..11 {
            assert_eq!(
                st.observe(0.99),
                BoostStep::Stay,
                "window {} during cooldown",
                i
            );
            assert_eq!(st.cooldown_windows, 11 - i);
        }

        // After 11 windows, cooldown_windows = 1.
        assert_eq!(st.cooldown_windows, 1);
        assert_eq!(st.observe(0.99), BoostStep::Stay); // This clears cooldown to 0.
        assert_eq!(st.cooldown_windows, 0);

        // Now can warm up again.
        assert_eq!(st.observe(0.30), BoostStep::Stay);
        assert_eq!(st.observe(0.30), BoostStep::Start);
        assert!(st.on);
    }

    #[test]
    fn boost_state_force_cooldown_exponential_backoff() {
        let mut st = BoostState::default();

        // First ineffective boost: 12 windows cooldown.
        st.observe(0.30);
        st.observe(0.30); // Start
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 12);
        assert_eq!(st.ineffective_count, 1);

        // Burn through the cooldown.
        for _ in 0..12 {
            st.observe(0.99);
        }
        assert_eq!(st.cooldown_windows, 0);

        // Second ineffective boost: 24 windows cooldown (12 * 2).
        st.observe(0.30);
        st.observe(0.30); // Start
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 24);
        assert_eq!(st.ineffective_count, 2);

        // Burn through again.
        for _ in 0..24 {
            st.observe(0.99);
        }
        assert_eq!(st.cooldown_windows, 0);

        // Third ineffective boost: 48 windows cooldown (12 * 4).
        st.observe(0.30);
        st.observe(0.30); // Start
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 48);
        assert_eq!(st.ineffective_count, 3);

        // Fourth: 96 windows (12 * 8).
        for _ in 0..48 {
            st.observe(0.99);
        }
        st.observe(0.30);
        st.observe(0.30);
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 96);
        assert_eq!(st.ineffective_count, 4);

        // Fifth and beyond: capped at 192 windows (12 * 16).
        for _ in 0..96 {
            st.observe(0.99);
        }
        st.observe(0.30);
        st.observe(0.30);
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 192); // 12 * (1 << 4) = 192
        assert_eq!(st.ineffective_count, 5);

        // Sixth: still capped.
        for _ in 0..192 {
            st.observe(0.99);
        }
        st.observe(0.30);
        st.observe(0.30);
        st.force_cooldown();
        assert_eq!(st.cooldown_windows, 192); // Still capped at 12 * 16.
        assert_eq!(st.ineffective_count, 6);
    }
}

#[cfg(test)]
mod split_span_tests {
    use super::split_span;

    #[test]
    fn a_refused_range_is_halved_down_to_one_block() {
        assert_eq!(split_span(2_000), Some(1_000));
        assert_eq!(split_span(1_001), Some(501));
        assert_eq!(split_span(2), Some(1));
        assert_eq!(split_span(1), None);
        let mut span = 10_000u64;
        let mut steps = 0;
        while let Some(next) = split_span(span) {
            span = next;
            steps += 1;
        }
        assert_eq!((span, steps), (1, 14));
    }
}

#[cfg(test)]
mod tests {

    /// The OHTTP span splitter must retain the per-pass RPC accounting: a refused
    /// request and both smaller windows are three requests, with each block handed on once.
    #[tokio::test]
    async fn ohttp_split_counts_each_range_attempt() {
        use std::{
            convert::Infallible,
            sync::Mutex,
            task::{Context, Poll},
        };
        use tonic::{
            body::Body,
            codegen::{BoxFuture, Service, http},
            server::{Grpc, NamedService, ServerStreamingService},
            transport::{Server, server::TcpIncoming},
        };
        use tonic_prost::ProstCodec;

        #[derive(Clone)]
        struct Ranges(Arc<Mutex<Vec<(u64, u64)>>>);

        impl NamedService for Ranges {
            const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
        }

        impl ServerStreamingService<BlockRange> for Ranges {
            type Response = CompactBlock;
            type ResponseStream =
                futures_util::stream::Iter<std::vec::IntoIter<Result<CompactBlock, tonic::Status>>>;
            type Future =
                std::future::Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

            fn call(&mut self, request: tonic::Request<BlockRange>) -> Self::Future {
                let request = request.into_inner();
                let start = request.start.expect("start").height;
                let end = request.end.expect("end").height;
                self.0.lock().expect("requests").push((start, end));
                std::future::ready(if end - start + 1 > 2 {
                    Err(tonic::Status::invalid_argument("gateway span cap"))
                } else {
                    Ok(tonic::Response::new(futures_util::stream::iter(
                        linked(start, end - start + 1, 1000)
                            .into_iter()
                            .map(Ok)
                            .collect::<Vec<_>>(),
                    )))
                })
            }
        }

        impl Service<http::Request<Body>> for Ranges {
            type Response = http::Response<Body>;
            type Error = Infallible;
            type Future = BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: http::Request<Body>) -> Self::Future {
                let service = self.clone();
                Box::pin(async move {
                    Ok(Grpc::new(ProstCodec::<CompactBlock, BlockRange>::default())
                        .server_streaming(service, request)
                        .await)
                })
            }
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let incoming = TcpIncoming::bind(([127, 0, 0, 1], 0).into()).expect("bind loopback");
        let port = incoming.local_addr().expect("bound address").port();
        let connections = Arc::new(AtomicU64::new(0));
        let connected = Arc::clone(&connections);
        let incoming = incoming.inspect(move |connection| {
            if connection.is_ok() {
                connected.fetch_add(1, Ordering::Relaxed);
            }
        });
        let server = tokio::spawn(
            Server::builder()
                .add_service(Ranges(Arc::clone(&requests)))
                .serve_with_incoming(incoming),
        );
        let endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port,
            tls: false,
        };
        let mut client = grpc::connect(&endpoint).await.expect("connect");
        let plan = FetchPlan::new(100, 103, 4, 1);
        let mut cursor = test_cursor(0, 100, 103);
        let (tx, mut rx) = mpsc::channel(16);
        let before = grpc::net_stats::totals();
        let mut max_span = u64::MAX;
        let outcome = open_and_pump(
            &mut client,
            &mut cursor,
            &plan,
            &open_gate(),
            &tx,
            grpc::OHTTP_RANGE_OPEN_TIMEOUT,
            None,
            &mut max_span,
            true,
            None,
            None,
        )
        .await
        .expect("split completes");
        assert!(matches!(outcome, PumpOutcome::Completed));
        assert_eq!(
            *requests.lock().expect("requests"),
            [(100, 103), (100, 101), (102, 103)]
        );
        assert_eq!(max_span, 2);
        drop(tx);
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 103);
        assert!(
            grpc::net_stats::totals()
                .delta_since(&before)
                .get_block_range
                >= 3,
            "every issued range, including the refused request, must be counted"
        );
        let before_connections = connections.load(Ordering::Relaxed);
        let mut follow = FetchPlan::new(100, 100, 2_000, 4);
        follow.boost = Some(FetchBoost { extra_streams: 0 });
        let (queue, mut received) = chunk_queue(1 << 20);
        let fetched = run_fetch(&endpoint, None, follow, queue, None)
            .await
            .expect("follow fetch");
        assert_eq!(fetched.blocks, 1);
        assert!(
            received.recv().await.is_some(),
            "the follow block is released"
        );
        server.abort();
        assert_eq!(
            connections.load(Ordering::Relaxed) - before_connections,
            1,
            "adaptive prefetch must retain one connection for a one-block follow range"
        );
    }
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

    /// A one-chunk range — a follow pass's single new block — starts exactly one
    /// worker, whatever `streams` is.
    #[test]
    fn one_chunk_range_starts_one_worker() {
        assert_eq!(FetchPlan::new(5, 5, 100, 4).worker_count(), 1);
        assert_eq!(FetchPlan::new(1_000, 1_099, 100, 4).worker_count(), 1);
        assert_eq!(FetchPlan::new(1_000, 1_000, 10_000, 64).worker_count(), 1);
    }

    /// Multi-chunk ranges start `min(streams, chunks)` workers, and at least one.
    #[test]
    fn worker_count_is_the_smaller_of_streams_and_chunks() {
        assert_eq!(FetchPlan::new(1_000, 1_199, 100, 4).worker_count(), 2); // 2 chunks
        assert_eq!(FetchPlan::new(1_000, 1_399, 100, 4).worker_count(), 4); // 4 chunks
        assert_eq!(FetchPlan::new(1_000, 1_999, 100, 4).worker_count(), 4); // 10 chunks
        assert_eq!(FetchPlan::new(1_000, 1_999, 100, 0).worker_count(), 1); // streams floor
    }

    /// Fewer workers than chunks still fetch every chunk exactly once: each worker
    /// keeps claiming from the shared cursor until it runs out.
    #[test]
    fn workers_claim_every_chunk_exactly_once() {
        let plan = FetchPlan::new(1_000, 1_999, 100, 4); // 10 chunks, 4 workers
        let dispatcher = Dispatcher::new(&plan, None, Arc::new(FleetStats::default()));
        let mut claimed: Vec<Vec<(u64, u64, u64)>> = vec![Vec::new(); plan.worker_count()];
        let mut idle = 0;
        while idle < claimed.len() {
            idle = 0;
            for worker in claimed.iter_mut() {
                match dispatcher.take_now() {
                    Some(chunk) => worker.push(chunk),
                    None => idle += 1,
                }
            }
        }
        assert!(
            claimed.iter().all(|w| !w.is_empty()),
            "every worker got work"
        );
        let mut all: Vec<(u64, u64, u64)> = claimed.into_iter().flatten().collect();
        all.sort_unstable();
        assert_eq!(
            all.iter().map(|c| c.0).collect::<Vec<_>>(),
            (0..10).collect::<Vec<_>>()
        );
        assert_eq!(all.first().map(|c| c.1), Some(1_000));
        assert_eq!(all.last().map(|c| c.2), Some(1_999));
        for pair in all.windows(2) {
            assert_eq!(pair[1].1, pair[0].2 + 1, "chunks tile the range");
        }
        assert_eq!(dispatcher.take_now(), None, "the cursor stays exhausted");
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
            start,
            end,
            resume_from: start,
            next_sub_index: 0,
            emitted_this_attempt: false,
            got_blocks: 0,
            got_bytes: 0,
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

    /// A window that ends early (`window_end` before the plan chunk's end) completes without
    /// `is_last`; a stream that ends with `INVALID_ARGUMENT` hands on what it received and
    /// reports the refusal, so the range can be split.
    #[tokio::test]
    async fn a_window_completes_and_an_invalid_argument_is_reported_as_a_refusal() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 129);
        let mut refused = false;
        let mut s = stream::iter(
            linked(100, 10, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            109,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            None,
        )
        .await
        .expect("the window completes");
        assert!(matches!(out, PumpOutcome::Completed));
        assert!(!refused);
        assert_eq!(cursor.resume_from, 110);
        let subs = drain_subs(&mut rx);
        assert!(
            subs.iter().all(|s| !s.is_last),
            "no is_last before the plan chunk's end"
        );

        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(110, 3, 1000).into_iter().map(Ok).collect();
        items.push(Err(tonic::Status::invalid_argument("range over the limit")));
        let mut s = stream::iter(items);
        let err = pump_block_window(
            &mut s,
            &mut cursor,
            129,
            usize::MAX >> 8,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            None,
        )
        .await
        .expect_err("the refusal fails the window");
        assert!(refused, "{err}");
        assert_eq!(
            cursor.resume_from, 113,
            "the blocks before it were handed on"
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

    /// The floor is a height: the rest of a cut chunk, handed out under a later
    /// index, waits on the budget until every height below it is released.
    #[tokio::test]
    async fn gate_exempts_a_chunk_once_every_height_below_it_is_released() {
        let floor = Arc::new(AtomicU64::new(100));
        let gate = AheadGate::new(1000, Arc::clone(&floor));
        assert!(gate.admit(100, 5000).await.is_none(), "the head chunk");
        assert!(gate.admit(90, 5000).await.is_none(), "below the floor");
        let _held = gate
            .admit(110, 1000)
            .await
            .expect("ahead: takes the budget");
        let gate2 = gate.clone();
        let waiter = tokio::spawn(async move { gate2.admit(110, 500).await });
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!waiter.is_finished(), "ahead of the floor, no budget");
        floor.store(110, Ordering::Release);
        let got = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("unblocks once the release reaches it")
            .expect("join");
        assert!(got.is_none());
    }

    /// A plan chunk handed out at a light density that turns out dense is cut once
    /// it carried its target: its last sub-chunk ends there with `is_last`, the
    /// attempt completes, and the rest goes back to the dispatcher, handed out next.
    #[tokio::test]
    async fn a_chunk_denser_than_it_was_sized_for_is_cut_where_the_stream_stands() {
        let target = 20_000u64;
        let plan = FetchPlan::new(36, 999, 100, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(target), Arc::clone(&fleet));
        d.set_cutting(true);
        assert_eq!(d.take_now(), Some((0, 36, 99)), "the probe");
        // The probe was light: the next chunk gets the plan's full span.
        fleet.blocks.fetch_add(64, Ordering::Relaxed);
        fleet.bytes.fetch_add(640, Ordering::Relaxed);
        assert_eq!(d.take_now(), Some((1, 100, 199)));

        let blocks = linked(100, 100, 1000);
        let per_block = blocks[0].encoded_len() as u64;
        let cut_at = 100 + target.div_ceil(per_block) - 1;
        let (tx, mut rx) = mpsc::channel::<SubChunk>(256);
        let gate = open_gate();
        let mut cursor = test_cursor(1, 100, 199);
        let mut refused = false;
        let mut s = stream::iter(blocks.into_iter().map(Ok::<_, tonic::Status>));
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            199,
            4 * per_block as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            Some(&d),
        )
        .await
        .expect("the cut completes the attempt");
        assert!(matches!(out, PumpOutcome::Completed), "{out:?}");
        assert_eq!(cursor.end, cut_at);
        assert_eq!(cursor.resume_from, cut_at + 1);
        let subs = drain_subs(&mut rx);
        assert_heights_consecutive(&subs, 100, cut_at);
        assert_eq!(subs.iter().filter(|s| s.is_last).count(), 1);
        assert!(subs.last().expect("non-empty").is_last);
        assert!(subs.iter().all(|s| s.start == s.blocks[0].height));
        assert!(d.has_returned());
        let (index, s, e) = d.take_now().expect("the rest");
        assert_eq!((index, s, e), (2, cut_at + 1, 199));
        assert!(!d.has_returned());
    }

    /// A chunk the first sample already shows too dense is cut ahead of the stream,
    /// where a chunk sized at that density would end: the stream goes on to there,
    /// then the chunk completes and the request is dropped.
    #[tokio::test]
    async fn a_chunk_seen_too_dense_early_is_cut_ahead_of_the_stream() {
        let target = 20_000u64;
        let plan = FetchPlan::new(36, 999, 900, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(target), Arc::clone(&fleet));
        d.set_cutting(true);
        assert_eq!(d.take_now(), Some((0, 36, 99)), "the probe");
        fleet.blocks.fetch_add(64, Ordering::Relaxed);
        fleet.bytes.fetch_add(64, Ordering::Relaxed);
        assert_eq!(d.take_now(), Some((1, 100, 999)));

        let blocks = linked(100, 900, 100);
        let per_block = blocks[0].encoded_len() as u64;
        let cut_at = 100 + target / per_block - 1;
        assert!(
            cut_at > 100 + DENSITY_SAMPLE_BLOCKS,
            "ahead of the first sample"
        );
        let (tx, mut rx) = mpsc::channel::<SubChunk>(1024);
        let gate = open_gate();
        let mut cursor = test_cursor(1, 100, 999);
        let mut refused = false;
        let mut s = stream::iter(blocks.into_iter().map(Ok::<_, tonic::Status>));
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            999,
            16 * per_block as usize,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            Some(&d),
        )
        .await
        .expect("the cut chunk completes");
        assert!(matches!(out, PumpOutcome::Completed), "{out:?}");
        assert_eq!(cursor.end, cut_at);
        let subs = drain_subs(&mut rx);
        assert_heights_consecutive(&subs, 100, cut_at);
        assert_eq!(subs.iter().filter(|s| s.is_last).count(), 1);
        assert!(subs.last().expect("non-empty").is_last);
        assert_eq!(d.take_now().map(|(_, s, _)| s), Some(cut_at + 1));
    }

    /// Before a boost (the scanner not waiting), a dense chunk streams whole.
    #[tokio::test]
    async fn without_a_boost_a_dense_chunk_is_never_cut() {
        let plan = FetchPlan::new(36, 999, 100, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(20_000), Arc::clone(&fleet));
        let (tx, mut rx) = mpsc::channel::<SubChunk>(1024);
        let gate = open_gate();
        let mut cursor = test_cursor(1, 100, 199);
        let mut refused = false;
        let mut s = stream::iter(
            linked(100, 100, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>),
        );
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            199,
            1 << 20,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            Some(&d),
        )
        .await
        .expect("stream");
        assert!(matches!(out, PumpOutcome::Completed));
        assert_eq!(cursor.end, 199);
        assert!(!d.has_returned());
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 199);
    }

    /// A chunk sized by density (below the plan's span) streams whole however much
    /// denser its blocks are than the estimate it was sized at.
    #[tokio::test]
    async fn a_chunk_sized_by_density_is_never_cut() {
        let plan = FetchPlan::new(36, 999, 2000, 4);
        let fleet = Arc::new(FleetStats::default());
        let d = Dispatcher::new(&plan, Some(20_000), Arc::clone(&fleet));
        d.set_cutting(true);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(1024);
        let gate = open_gate();
        let mut cursor = test_cursor(1, 100, 999);
        let mut refused = false;
        let mut s = stream::iter(
            linked(100, 900, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>),
        );
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            999,
            1 << 20,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            None,
            Some(&d),
        )
        .await
        .expect("stream");
        assert!(matches!(out, PumpOutcome::Completed));
        assert_eq!(cursor.end, 999);
        assert!(!d.has_returned());
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 999);
    }

    /// Without the adaptive prefetch (no dispatcher), a dense chunk streams whole.
    #[tokio::test]
    async fn without_a_dispatcher_a_dense_chunk_is_never_cut() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(256);
        let gate = open_gate();
        let mut cursor = test_cursor(1, 100, 199);
        let mut s = stream::iter(
            linked(100, 100, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>),
        );
        let out = pump_block_stream(
            &mut s,
            &mut cursor,
            4000,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
        )
        .await
        .expect("stream");
        assert!(matches!(out, PumpOutcome::Completed));
        assert_eq!(cursor.end, 199);
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 199);
    }

    /// Our own backpressure never trips the stream idle timeout: a worker parked
    /// on the ahead budget for longer than `STREAM_IDLE_TIMEOUT` is not polling
    /// its stream, so the timer is not running; once admitted it goes on.
    #[tokio::test(start_paused = true)]
    async fn parked_on_the_ahead_budget_longer_than_the_idle_timeout_is_not_idle() {
        let floor = Arc::new(AtomicU64::new(0));
        // Budget of one sub-chunk; plan chunk 1 is not the floor.
        let gate = AheadGate::new(2500, Arc::clone(&floor));
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let mut cursor = test_cursor(1, 100, 109);
        let mut s = stream::iter(
            linked(100, 10, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        );
        let pump = tokio::spawn(async move {
            let out = pump_block_stream(
                &mut s,
                &mut cursor,
                2500,
                Duration::from_secs(120),
                &gate,
                &tx,
                None,
            )
            .await;
            (out, cursor)
        });
        // The first sub-chunk takes the whole budget; the second parks.
        let first = rx.recv().await.expect("first sub-chunk");
        tokio::time::sleep(grpc::STREAM_IDLE_TIMEOUT * 3).await;
        assert!(!pump.is_finished(), "parked, not failed");
        drop(first); // releases its budget
        // Each sub-chunk's budget is released as it is taken (dropped here).
        let mut last = false;
        while let Some(sub) = rx.recv().await {
            last = sub.is_last;
        }
        let (out, cursor) = pump.await.expect("join");
        assert!(matches!(out, Ok(PumpOutcome::Completed)), "{out:?}");
        assert_eq!(cursor.resume_from, 110);
        assert!(last, "the plan chunk completes");
    }

    /// A kick ends the attempt like a stream error: the blocks received so far
    /// are handed on, the cursor resumes after them, and the worker can tell the
    /// kick from a failure.
    #[tokio::test]
    async fn a_kicked_stream_hands_on_its_blocks_and_ends_the_attempt() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        let slot = WorkerSlot::new(Arc::default());
        let mut refused = false;
        // Five blocks, then the stream goes silent (pending forever).
        let mut s = stream::iter(
            linked(100, 5, 1000)
                .into_iter()
                .map(Ok::<_, tonic::Status>)
                .collect::<Vec<_>>(),
        )
        .chain(stream::pending());
        let pump = pump_block_window(
            &mut s,
            &mut cursor,
            119,
            1 << 30,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            Some(&slot),
            None,
        );
        let kicker = async {
            while slot.bytes.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            slot.kick();
        };
        let (out, ()) = tokio::join!(pump, kicker);
        assert!(
            matches!(out, Ok(PumpOutcome::Kicked)),
            "the kick ends the attempt as a kick: {out:?}"
        );
        assert!(
            !slot.kicked.load(Ordering::SeqCst),
            "the kick was acted on and cleared"
        );
        assert!(slot.bytes.load(Ordering::Relaxed) > 5000);
        let subs = drain_subs(&mut rx);
        assert_heights_consecutive(&subs, 100, 104);
        assert!(subs.iter().all(|s| !s.is_last));
        assert_eq!(cursor.resume_from, 105);
    }

    /// A kick that is pending when the stream fails with a permanent error (an
    /// OHTTP policy denial) does not turn the error into a restart: the error
    /// comes back as the attempt's result, non-transient, so the worker returns
    /// it at once instead of retrying.
    #[tokio::test]
    async fn a_pending_kick_never_hides_a_permanent_error() {
        let (tx, mut rx) = mpsc::channel::<SubChunk>(64);
        let gate = open_gate();
        let mut cursor = test_cursor(0, 100, 119);
        let slot = WorkerSlot::new(Arc::default());
        slot.kick();
        let mut denied = tonic::Status::permission_denied("inner 403");
        denied.metadata_mut().insert(
            crate::ohttp::OHTTP_OUTCOME_HEADER,
            crate::ohttp::OUTCOME_POLICY_DENIED
                .parse()
                .expect("ascii metadata"),
        );
        let mut items: Vec<Result<CompactBlock, tonic::Status>> =
            linked(100, 3, 1000).into_iter().map(Ok).collect();
        items.push(Err(denied));
        let mut s = stream::iter(items);
        let mut refused = false;
        let out = pump_block_window(
            &mut s,
            &mut cursor,
            119,
            1 << 30,
            Duration::from_secs(120),
            &gate,
            &tx,
            None,
            &mut refused,
            Some(&slot),
            None,
        )
        .await;
        let err = out.expect_err("the denial is the attempt's result, not a kick");
        assert!(matches!(err, SlipstreamError::PolicyDenied(_)), "{err:?}");
        assert!(!err.is_transient() && !err.counts_as_unreachable());
        // The blocks before it were handed on; the kick is still pending and the
        // next attempt drops it.
        assert_heights_consecutive(&drain_subs(&mut rx), 100, 102);
        assert!(slot.kicked.load(Ordering::SeqCst));
        slot.clear_kick();
        assert!(!slot.kicked.load(Ordering::SeqCst));
        assert!(
            futures_util::FutureExt::now_or_never(slot.kick.notified()).is_none(),
            "no stale kick is left to cut the next stream"
        );
    }

    #[test]
    fn a_head_stream_is_slow_next_to_the_best_window_only() {
        let best = 10 << 20;
        assert!(
            !head_is_slow(best / 4, best),
            "a quarter of the link is fair"
        );
        assert!(head_is_slow(best / 10, best));
        assert!(
            head_is_slow(KICK_MIN_WINDOW_BYTES - 1, 0),
            "a trickle is slow"
        );
        assert!(!head_is_slow(KICK_MIN_WINDOW_BYTES, KICK_MIN_WINDOW_BYTES));
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
        let start = blocks.first().map_or(0, |b| b.height);
        sub_from(start, plan_index, sub_index, is_last, blocks)
    }

    /// A sub-chunk asked from `start` (which its blocks may not start at).
    fn sub_from(
        start: u64,
        plan_index: u64,
        sub_index: u64,
        is_last: bool,
        blocks: Vec<CompactBlock>,
    ) -> SubChunk {
        let bytes = blocks.iter().map(Message::encoded_len).sum();
        SubChunk {
            plan_index,
            sub_index,
            start,
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
        let floor = AtomicU64::new(100);
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
            160,
            "floor advanced past the last released height"
        );
    }

    /// The rest of a cut plan chunk is handed out again under a later index; the
    /// release still goes by height: the cut chunk, its rest, then the chunk after.
    #[tokio::test]
    async fn release_orders_a_cut_chunks_rest_by_height_not_by_index() {
        let all = linked(100, 30, 64);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        // plan 1: [120-129]; plan 2: the rest of plan 0, [110-119]; plan 0 cut at 109.
        tx.send(sub(1, 0, true, all[20..30].to_vec()))
            .await
            .expect("send");
        tx.send(sub(2, 0, true, all[10..20].to_vec()))
            .await
            .expect("send");
        tx.send(sub(0, 1, true, all[5..10].to_vec()))
            .await
            .expect("send");
        tx.send(sub(0, 0, false, all[0..5].to_vec()))
            .await
            .expect("send");
        drop(tx);
        let (qtx, mut qrx) = chunk_queue(usize::MAX >> 8);
        let floor = AtomicU64::new(100);
        let summary = release_ordered(&mut rx, &qtx, None, &floor, Instant::now(), None)
            .await
            .expect("release");
        assert_eq!(summary.plans_released, 3);
        assert_eq!(floor.load(Ordering::Acquire), 130);
        drop(qtx);
        let mut released_heights = Vec::new();
        while let Some((chunk, permit, _boundary)) = qrx.recv().await {
            released_heights.extend(chunk.blocks.iter().map(|b| b.height));
            drop(permit);
        }
        assert_eq!(released_heights, (100..130).collect::<Vec<_>>());
    }

    /// A sub-chunk asked from a height the release already passed is a second copy:
    /// the fetch fails instead of scanning blocks twice.
    #[tokio::test]
    async fn release_rejects_a_sub_chunk_below_what_it_released() {
        let all = linked(100, 20, 64);
        let (tx, mut rx) = mpsc::channel::<SubChunk>(16);
        tx.send(sub(0, 0, true, all[0..10].to_vec()))
            .await
            .expect("send");
        tx.send(sub(1, 0, true, all[5..15].to_vec()))
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let err = release_ordered(
            &mut rx,
            &qtx,
            None,
            &AtomicU64::new(100),
            Instant::now(),
            None,
        )
        .await
        .expect_err("a second copy fails the fetch");
        assert!(matches!(err, SlipstreamError::Transport(_)), "{err}");
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
        let summary = release_ordered(
            &mut rx,
            &qtx,
            None,
            &AtomicU64::new(100),
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
        // Asked from 105, the server answered from 200.
        tx.send(sub_from(105, 0, 1, true, linked(200, 5, 64)))
            .await
            .expect("send");
        drop(tx);
        let (qtx, _qrx) = chunk_queue(usize::MAX >> 8);
        let err = release_ordered(
            &mut rx,
            &qtx,
            None,
            &AtomicU64::new(100),
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
        let unreleased_from = AtomicU64::new(100);
        release_ordered(&mut rx, &qtx, None, &unreleased_from, Instant::now(), None)
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

    /// A worker connects before it claims a chunk, so one that cannot connect can fail the
    /// fetch after the others already handed every block to the scanner. The cursor then
    /// reads one past the plan end, a block no release of this fetch will ever cover: the
    /// fetch still fails, but no give-up is recorded.
    #[tokio::test(start_paused = true)]
    async fn supervise_records_nothing_once_every_block_was_released() {
        let progress = Progress::default();
        let plan_end = 1_999;
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            Err(SlipstreamError::Transport(
                "late worker could not connect".into(),
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
            err.to_string().contains("late worker could not connect"),
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
        release_ordered(
            &mut rx,
            &qtx,
            Some(&progress),
            &AtomicU64::new(100),
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
        release_ordered(
            &mut rx,
            &qtx,
            Some(&progress),
            &AtomicU64::new(100),
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
