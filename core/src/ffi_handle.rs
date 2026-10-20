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

//! Opaque FFI handle for the Slipstream engine.
//!
//! Lifecycle:
//!   open  → allocates SlipstreamHandle (tokio runtime + snapshot atomics + event ring)
//!   start → spawns sync task on the runtime; previous task cancelled and waited out first
//!   stop  → cancels the sync task and waits it out; handle stays live for snapshot/drain_events
//!   free  → drops the handle (drops runtime → all tasks cancel)
//!
//! [MOB-1850] Stopping is the engine's job, so every host shares one stop: hosts call
//! [`SlipstreamHandle::stop`] or [`SlipstreamHandle::stop_for_wallet_change`] to stop, and
//! [`SlipstreamHandle::quiesce_before_start`] before they spawn a new session, instead of keeping
//! their own copies of the two bounded waits ([`settle_passes`], [`drain_wallet_writers`]) and of
//! the record of unfinished passes ([`SlipstreamHandle::unfinished_passes`]). The C (iOS) and JNI
//! (Android) wrappers keep only their own extras around these calls: on iOS, the `last_stop_at`
//! stamp that keeps tip freshness across a quick stop→start hop.
//!
//! All fields are Send + Sync; the handle is always behind a raw pointer (Box::into_raw),
//! accessed from Swift/Obj-C single-threaded callers serialised by the actor.
//!
//! BINDING: SlipstreamHandle is NOT exposed in the C header (opaque pointer). Its fields
//! are internal. The C header only sees `typedef struct SlipstreamHandle SlipstreamHandle;`.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime, task::AbortHandle};

use crate::{config::Endpoint, events::Progress};

/// C-compatible snapshot struct. All fields are C-safe integers.
/// Maps to `FfiSlipstreamSnapshot` in `zcashlc.h` (cbindgen generates this).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FfiSlipstreamSnapshot {
    /// Current chain tip height (0 = not yet fetched).
    pub chain_tip: u64,
    /// Number of blocks fetched in the current/last sync pass.
    pub fetched_blocks: u64,
    /// Number of blocks scanned in the current/last sync pass.
    pub scanned_blocks: u64,
    /// Number of transactions enhanced in the current/last sync pass.
    pub enhanced_txs: u64,
    /// End height of the block range currently being processed.
    pub current_range_end: u64,
    /// Sync state: 0=idle, 1=syncing, 2=error, 3=done.
    pub state: u8,
    // ── T5.5 counter-based progress fields (appended at END for padding stability) ──
    /// Total blocks in the current pass. Set (not accumulated) by the scheduler each time
    /// suggest_scan_ranges returns: value = scanned_so_far + sum(all returned ranges).
    /// Denominator for the blessed progress (`progress_permille`): `fetched_blocks` and
    /// `scanned_blocks`, each first measured from the per-round baseline the scheduler
    /// snapshots at the same time (so blocks a re-baselined pass already credited are not
    /// counted a second time), then clamped to this total, weighed half each.
    pub pass_total_blocks: u64,
    /// Spendable hint: 0 = not yet spendable; 1 = a ChainTip-priority range has completed
    /// scanning (≈ SBS funds-spendable semantics). Latches to 1; never resets within a pass.
    pub spendable_hint: u8,
    // ── T5.6 range-boundary signals (appended at END for padding stability) ──
    /// Number of suggested ranges whose scan+enhancement has completed in the current pass.
    /// Swift observes this counter and triggers ONE balance-summary fetch per boundary.
    pub ranges_completed: u64,
    // ── API v2 fields (ENGINE_API_V2.md §4.4; appended at END for padding stability) ──
    /// 1 while the wallet is inside its recovery (restore backfill) window. Engine-computed
    /// from suggested ranges vs `accounts.recover_until_height`, with the fail-safe latch
    /// built in: terminal states (Done / Error) force 0, so a dead pass can never wedge a
    /// host's "Restoring" UI.
    pub is_recovering: u8,
    /// Blessed progress value, 0..=1000, session-monotonic (never regresses while the
    /// handle lives). Done forces 1000. Replaces host-side % math.
    ///
    /// Computed as a two-stage blend: the pass's own progress is `fetched_blocks` and
    /// `scanned_blocks`, each relative to the pass's per-round baseline and clamped to
    /// `pass_total_blocks`, weighed half each (see `pass_total_blocks`); that pass-local
    /// fraction is then stretched from the pass's own starting position — its GLOBAL
    /// position when the pass began, or wherever the scan scope last expanded under it —
    /// up to 1000, so a resync's reading climbs from where the wallet already stood instead
    /// of restarting at 0. The stretched result is folded into the session-monotonic floor,
    /// which only ever rises — the reason this field never regresses.
    pub progress_permille: u16,
    /// Seconds without forward progress while state == Syncing; 0 otherwise — the longer of the
    /// time since the last progress and the time the block download has kept failing at the
    /// same block (see HOSTING.md §5.3). The host keeps the policy (log vs restart); the engine
    /// supplies the fact.
    pub stalled_seconds: u32,
    // ── API v2.1 E-4 (appended at END for padding stability) ──
    /// Monotonic version of the wallet's stored transaction set (see
    /// `Progress::tx_set_version`). Host rule: version moved since last poll →
    /// re-fetch transactions + publish. Never reset while the handle lives.
    pub tx_set_version: u64,
}

/// C-compatible event record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FfiSlipstreamEvent {
    /// Event tag: 1=SyncStarted, 2=SyncProgress, 3=SyncDone, 4=SyncError, 5=FoundTransactions.
    pub tag: u8,
    /// For SyncDone: count of transactions stored; for SyncError: error code; others: 0.
    pub value: u64,
}

/// State of the sync task.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncState {
    Idle,
    Syncing,
    Error(u8), // error code (u8 for C compat)
    Done,
}

/// Maximum events to keep in the ring before dropping oldest.
pub const EVENT_RING_CAP: usize = 64;

/// Push onto the bounded event ring with the v2 CRITICALITY policy ([audit ENG-4] / API v2 §4.5):
/// on overflow, evict the oldest DROPPABLE event first — tag 1 (SyncStarted) / tag 2 (SyncProgress)
/// are pure UI pacing and safe to lose; tags 3 (SyncDone), 4 (SyncError), 5 (FoundTransactions) are
/// edge signals a host may act on exactly once, so they survive as long as anything droppable
/// remains. Only a ring FULL of critical events (pathological — the host stopped draining) evicts a
/// critical, and every eviction logs a warning so field logs show event loss instead of silence.
pub fn push_event_bounded(ring: &mut Vec<FfiSlipstreamEvent>, e: FfiSlipstreamEvent) {
    if ring.len() >= EVENT_RING_CAP {
        let droppable = ring.iter().position(|ev| ev.tag == 1 || ev.tag == 2);
        let evicted = ring.remove(droppable.unwrap_or(0));
        tracing::warn!(
            evicted_tag = evicted.tag,
            incoming_tag = e.tag,
            critical_evicted = droppable.is_none(),
            "slipstream event ring overflow — oldest {} event dropped",
            if droppable.is_some() {
                "droppable"
            } else {
                "CRITICAL"
            }
        );
    }
    ring.push(e);
}

pub struct SlipstreamHandle {
    /// Single multi-thread tokio runtime owned by this handle (dropped with the handle).
    /// D7 deviation: runtime is created at `open` and dropped at `free` (not per-start/stop).
    pub runtime: Runtime,
    /// Shared progress atomics — read by snapshot; written by the sync task.
    pub progress: Arc<Progress>,
    /// Current sync state — written by sync task, read by snapshot.
    pub state: Arc<Mutex<SyncState>>,
    /// Event ring — sync task pushes; Swift drains.
    pub events: Arc<Mutex<Vec<FfiSlipstreamEvent>>>,
    /// Abort handle for the currently-running sync task (None = not started or stopped).
    ///
    /// B1 (#1755 failure-path hardening): the sync task's `JoinHandle` is OWNED by a
    /// supervisor task (spawned alongside it in `zcashlc_slipstream_start`) that awaits
    /// it and converts a panic (`JoinError::is_panic`) into `SyncState::Error` + a
    /// tag=4 event — a panicking pass can no longer die silently leaving the state
    /// stuck at "Syncing" forever (field failure 2, 2026-06-12). `stop()` / `free()` /
    /// restart only need to CANCEL the task, and the stops to watch it finish
    /// ([`settle_passes`] polls `AbortHandle::is_finished`), so they hold this `AbortHandle`
    /// instead of the `JoinHandle` (the abort is observed by the supervisor as a
    /// cancellation and deliberately ignored — the stop sets the state to Idle itself).
    /// The stop or start that aborts the task TAKES it out of this slot and keeps it in
    /// [`Self::unfinished_passes`] until it has finished.
    pub task: Option<AbortHandle>,
    /// [MOB-1850] Aborted passes that had not finished when a stop or start gave up waiting; a
    /// later stop reports quiescence only once this is empty. The only other handle the engine
    /// keeps on a pass is [`Self::task`], and the stop that aborts a pass TAKES it — so without
    /// this record the next stop would find an empty slot and report a pass quiescent that it
    /// never watched finish, while that pass is still inside a synchronous wallet write.
    /// Construct it empty; [`settle_passes`] keeps it.
    pub unfinished_passes: Vec<AbortHandle>,
    /// Serializes overlapping sync passes on this handle. `session::run_session` holds this for
    /// the WHOLE pass (acquired as its outermost local). On a `start()`-while-running restart the
    /// host aborts the previous task (`zcashlc_slipstream_start`), but tokio's `abort()` is
    /// ASYNCHRONOUS — the old pass keeps running until its next await. This lock makes the new
    /// pass wait until the aborted old pass has unwound and dropped the guard; because guards drop
    /// in reverse acquisition order, the old pass's `WalletSession` (and its `data.db` connection)
    /// is already closed by then, so two passes never touch `data.db` concurrently. Without it the
    /// `importAccount` restart raced two passes on one DB → panic → `SyncState::Error(2)` (Keystone
    /// restore field failure, 2026-06-30). The host always abort()s the old task before spawning the
    /// new one, so the old holder is guaranteed to release — no deadlock.
    pub pass_lock: Arc<tokio::sync::Mutex<()>>,
    /// Server endpoint — set at open; used for start.
    pub endpoint: Endpoint,
    /// Wallet db path — set at open.
    pub wallet_db_path: std::path::PathBuf,
    /// Network (MainNetwork or TestNetwork).
    pub network: zcash_protocol::consensus::Network,
    /// Host physical memory in bytes, passed by Swift at open (`ProcessInfo`
    /// `.physicalMemory`); 0 = unknown. Drives `EngineConfig::scaled_for_device_memory`
    /// at start so <3 GiB devices get derated fetch/split budgets (T8.4).
    pub total_memory_bytes: u64,
}

/// Spawns `fut` on `runtime` together with a SUPERVISOR task that owns the
/// spawned task's `JoinHandle`, and returns the `AbortHandle` for the spawned task.
///
/// B1 (#1755 failure-path hardening): tokio swallows panics inside spawned tasks —
/// they surface only through the `JoinHandle`, which nothing previously inspected,
/// so a panicking sync pass died silently and the state stayed "Syncing" forever
/// (field failure 2, 2026-06-12). The supervisor converts a PANIC `JoinError` into
/// `SyncState::Error(2)` + a tag=4/value=2 event + a `tracing::error!` carrying the
/// panic payload. A CANCELLED `JoinError` (the returned `AbortHandle` was used by
/// stop()/free()/restart) is deliberately ignored — the canceller already set the
/// state. Normal completion needs nothing (the task body sets Done/Error itself).
///
/// Known benign race (pre-existing class): a start()-while-running restart aborts the
/// old task, but if that task panicked just before the abort landed, its supervisor
/// writes Error(2) concurrently with the new pass — the same unguarded window in
/// which the OLD task body could always write Done/Error around a restart. The Swift
/// layer never restarts without stop() (which aborts first → supervisor sees
/// cancellation), and switchTo() re-opens a fresh handle with fresh state Arcs.
pub fn spawn_supervised<F>(
    runtime: &Runtime,
    fut: F,
    state: Arc<Mutex<SyncState>>,
    events: Arc<Mutex<Vec<FfiSlipstreamEvent>>>,
) -> AbortHandle
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let task = runtime.spawn(fut);
    let abort_handle = task.abort_handle();
    runtime.spawn(async move {
        match task.await {
            Ok(()) => {}
            Err(join_err) if join_err.is_cancelled() => {}
            Err(join_err) => {
                let panic_msg = match join_err.try_into_panic() {
                    Ok(payload) => payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload".to_string()),
                    Err(join_err) => join_err.to_string(),
                };
                tracing::error!(
                    panic = %panic_msg,
                    "slipstream sync task PANICKED — converting to error state"
                );
                *state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Error(2);
                let mut ring = events.lock().unwrap_or_else(|p| p.into_inner());
                // SyncError (tag=4): value = error code 2 (task panicked). v2 bounded push —
                // the error event evicts a droppable (started/progress) entry, never a critical.
                push_event_bounded(&mut ring, FfiSlipstreamEvent { tag: 4, value: 2 });
            }
        }
    });
    abort_handle
}

/// Aborts the running pass (if any), keeps every pass that has not finished yet on record, and
/// waits within `budget` for all of them to finish. Returns whether the engine is quiescent with
/// respect to its passes. A pass that outlives the budget STAYS on record in `unfinished`, so a
/// later stop cannot claim quiescence merely because the most recent handle has already been
/// taken out of `task`.
///
/// [B4-16 drain] `abort()` is ASYNCHRONOUS — the task keeps running until its next await
/// point, so a synchronous in-flight wallet write (an enhance `decrypt_and_store`, a
/// chain-tip or subtree-roots update — field evidence: a `deleteAccount` landing in that
/// window failed its read→write lock upgrade, "error + try again") can land AFTER
/// `abort()` returns. Wait (bounded) for the task to finish unwinding. Combined with
/// [`drain_wallet_writers`] (the persist lane's `spawn_blocking` commit — the engine's ONLY
/// detached writer), a stop or start whose two waits both return `true` means the wallet
/// file is FULLY quiescent; `false` means it could not be proved so within the budget.
///
/// The handle's stops call this with [`SlipstreamHandle::task`] and
/// [`SlipstreamHandle::unfinished_passes`]. It blocks the calling thread for up to `budget`,
/// polling every 10 ms: call it from a host thread (Swift hops the C stop off its cooperative
/// pool), never from a task on the runtime the passes run on, whose worker the unwinding pass
/// may need.
pub fn settle_passes(
    task: &mut Option<AbortHandle>,
    unfinished: &mut Vec<AbortHandle>,
    budget: Duration,
) -> bool {
    if let Some(pass) = task.take() {
        pass.abort();
        unfinished.push(pass);
    }
    let deadline = Instant::now() + budget;
    loop {
        unfinished.retain(|pass| !pass.is_finished());
        if unfinished.is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: {} aborted pass(es) still unwinding at the deadline — reporting a non-quiescent stop",
                unfinished.len()
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// [B4-16 drain] Bounded wait for the engine's in-flight wallet-file writer — the
/// write-behind lane's deferred commit, a `spawn_blocking` closure `task.abort()` cannot
/// cancel. Field evidence (2026-07-04): an orphan commit outlived an `importAccount`
/// restart, collided with the new pass's first writes ("database is locked" →
/// non-transient failure, absorbed by the revival loop) and — worse — landed its
/// Scanned-mark AFTER the import's force-rescan re-queue, silently shrinking the new
/// account's scan scope. The handle's stops and its start call this right after
/// settling the passes ([`settle_passes`]); the hosts' budget of ten seconds is far
/// above the worst observed device commit (a few seconds, A10).
///
/// [MOB-1850] A timeout is REPORTED (`false`) rather than logged away: a caller that is about
/// to mutate the wallet needs to know the file was never proved quiescent, and can refuse
/// instead of writing on top of a live writer. The busy_timeouts remain the backstop for the
/// callers that proceed anyway.
///
/// Blocks the calling thread for up to `budget`, polling every 10 ms, under the same rule as
/// [`settle_passes`].
pub fn drain_wallet_writers(progress: &Progress, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    let mut waited = false;
    while progress.wallet_writers() > 0 {
        if Instant::now() >= deadline {
            tracing::warn!(
                "slipstream stop/start: in-flight wallet commit still running at the deadline — reporting a non-quiescent stop"
            );
            return false;
        }
        waited = true;
        std::thread::sleep(Duration::from_millis(10));
    }
    if waited {
        tracing::info!("slipstream stop/start: drained in-flight wallet commit");
    }
    true
}

/// What a stop found: whether each of its two bounded waits finished within the budget, and how
/// long each took. Returned by [`SlipstreamHandle::stop`],
/// [`SlipstreamHandle::stop_for_wallet_change`] and [`SlipstreamHandle::quiesce_before_start`].
///
/// [MOB-1850] The verdict a caller acts on is [`Self::quiescent`], the `bool` the C stop answers
/// with. The rest is the detail behind it: a bare `false` cannot say WHICH wait ran out or after
/// how long, and the device log of a refused account import could not say it either. With the
/// report, a host can tell the user, or its own log, exactly that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopReport {
    /// Every aborted pass on record finished unwinding within the budget ([`settle_passes`]).
    pub settled: bool,
    /// No engine wallet writer was still running within the budget ([`drain_wallet_writers`]).
    pub drained: bool,
    /// How long the wait for the aborted passes took: at least the budget when it ran out, close
    /// to zero when there was no pass left to wait for.
    pub settle_wait: Duration,
    /// How long the wait for the engine's wallet writers took, measured the same way.
    pub drain_wait: Duration,
}

impl StopReport {
    /// Whether the stop PROVED the wallet file quiescent: every aborted pass finished
    /// ([`Self::settled`]) AND no engine wallet writer was left running ([`Self::drained`]).
    /// A caller about to change the wallet file (import, delete, rewind, wipe) refuses on
    /// `false` rather than writing on top of an engine writer. `false` does not mean the stop
    /// failed: a stop leaves the engine Idle either way.
    pub fn quiescent(&self) -> bool {
        self.settled && self.drained
    }
}

impl SlipstreamHandle {
    /// Push one event onto the ring (v2 bounded policy: overflow evicts the oldest
    /// started/progress event first; done/error/found-transactions survive; loss is logged).
    pub fn push_event(&self, event: FfiSlipstreamEvent) {
        let mut ring = self.events.lock().unwrap_or_else(|p| p.into_inner());
        push_event_bounded(&mut ring, event);
    }

    /// Read a point-in-time snapshot of progress counters and sync state.
    pub fn snapshot(&self) -> FfiSlipstreamSnapshot {
        let state = *self.state.lock().unwrap_or_else(|p| p.into_inner());
        derive_snapshot(&self.progress, state)
    }

    /// Stops the sync task and waits, bounded, for the wallet file to fall quiet. The handle
    /// stays live: snapshot and event drain still work, and a later start restarts it.
    ///
    /// Settles, then drains, then goes Idle. [`settle_passes`] aborts the running pass and waits
    /// for every pass on record to finish unwinding; [`drain_wallet_writers`] then waits for the
    /// engine's detached wallet commit. The order matters: the persist lane takes its writer gate
    /// BEFORE it spawns a commit, so once every pass has finished no new commit can start, and
    /// every commit already handed off is counted by the drain. Each wait gets the whole `budget`
    /// on its own (the hosts pass ten seconds, for the passes and for the commit each), so a stop
    /// blocks for at most twice `budget`. The state then goes `Idle`, whatever the waits found.
    ///
    /// [MOB-1850] The pass is stopped either way. What the report says
    /// ([`StopReport::quiescent`]) is whether the wallet file was PROVED quiescent, which is the
    /// only thing a caller about to mutate that file can act on. One info line logs how long each
    /// wait took and what it found: `settle_ms`, `drain_ms`, `settled`, `drained` and
    /// `for_wallet_change`.
    ///
    /// This is the plain stop (backgrounding, shutdown): a scan in the middle of a chunk runs to
    /// the end of that chunk before the abort reaches it. Right before changing the wallet, stop
    /// with [`Self::stop_for_wallet_change`] instead.
    ///
    /// Hosts call this instead of keeping their own copy of the waits; the C and JNI wrappers add
    /// only their own extras around it (on iOS, the `last_stop_at` stamp for tip freshness). It
    /// blocks the calling thread, so call it from a host thread, never from a task on this
    /// handle's runtime (see [`settle_passes`]).
    pub fn stop(&mut self, budget: Duration) -> StopReport {
        self.stop_and_report(budget, false)
    }

    /// Asks the running session to stop at its next block, then stops exactly as [`Self::stop`]
    /// does. The host calls this right before it changes the wallet (adding or removing an
    /// account, a rewind, a wipe) and refuses the change when the report is not
    /// [`StopReport::quiescent`].
    ///
    /// The request ([`Progress::request_stop_for_wallet_change`]) goes out BEFORE the abort, and
    /// that order is the point: the scan runs synchronously inside `block_in_place`, where an
    /// abort cannot reach it until the whole chunk is scanned, which can outlast the budget when
    /// accounts are added in quick succession. The scan checks the request between blocks
    /// instead, so the pass ends at its next block, without writing anything for the interrupted
    /// chunk, and the settle can see it finish within the budget. The next session scans that
    /// chunk again. The request is armed per session, so it never stops a session that starts
    /// after it.
    pub fn stop_for_wallet_change(&mut self, budget: Duration) -> StopReport {
        self.progress.request_stop_for_wallet_change();
        self.stop_and_report(budget, true)
    }

    /// Settles and drains before the host spawns a new session: aborts the previous pass (a
    /// start while running), waits it out, and waits for the engine's wallet commit, exactly as a
    /// stop does. [B4-16 drain] The aborted pass's write-behind commit may still be running
    /// (`spawn_blocking`, uncancellable); once the drain has waited it out, BEFORE the new
    /// session spawns, the new pass's first writes cannot collide with that orphan ("database is
    /// locked" at pass start), and no orphan Scanned-mark can land after this point.
    ///
    /// [MOB-1850] A start proceeds whatever the report says, as it always has: the new session
    /// waits for [`Self::pass_lock`] before it touches the wallet, so two passes never overlap,
    /// and only the stop-then-mutate callers act on a verdict, which they get from a stop. But a
    /// pass this could not wait out STAYS on record ([`Self::unfinished_passes`]), so the next
    /// stop still answers for it. The state is left alone: the host sets `Syncing` itself, as
    /// before. Blocks the calling thread, like a stop.
    pub fn quiesce_before_start(&mut self, budget: Duration) -> StopReport {
        self.settle_then_drain(budget)
    }

    /// The two bounded waits every stop and start makes, in order, each one timed.
    fn settle_then_drain(&mut self, budget: Duration) -> StopReport {
        let settle_started = Instant::now();
        let settled = settle_passes(&mut self.task, &mut self.unfinished_passes, budget);
        let settle_wait = settle_started.elapsed();
        let drain_started = Instant::now();
        let drained = drain_wallet_writers(&self.progress, budget);
        let drain_wait = drain_started.elapsed();
        StopReport {
            settled,
            drained,
            settle_wait,
            drain_wait,
        }
    }

    /// The body [`Self::stop`] and [`Self::stop_for_wallet_change`] share: the two waits, the
    /// Idle state, and the one info line.
    fn stop_and_report(&mut self, budget: Duration, for_wallet_change: bool) -> StopReport {
        let report = self.settle_then_drain(budget);
        *self.state.lock().unwrap_or_else(|p| p.into_inner()) = SyncState::Idle;
        tracing::info!(
            settle_ms = report.settle_wait.as_millis(),
            drain_ms = report.drain_wait.as_millis(),
            settled = report.settled,
            drained = report.drained,
            for_wallet_change,
            "slipstream stop: engine idle"
        );
        report
    }
}

/// Derive the v2 snapshot from live progress + state. Shared by the FFI handle and Rust
/// hosts (e.g. `slipstream-cli watch`) so the v2 semantics — the recovery fail-safe latch,
/// the session-monotonic permille floor, the stall clock — have exactly ONE implementation.
pub fn derive_snapshot(p: &crate::events::Progress, state: SyncState) -> FfiSlipstreamSnapshot {
    {
        let state_u8 = match state {
            SyncState::Idle => 0,
            SyncState::Syncing => 1,
            SyncState::Error(_) => 2,
            SyncState::Done => 3,
        };
        // ── API v2 derived fields (ENGINE_API_V2.md §4.4) ──
        // Blessed progress: the pass blend folded into the session-monotonic floor (reported
        // progress never regresses while the handle lives). Done folds 1000 into the floor so
        // a later catch-up pass can't display below a completed pass's 100%.
        //
        // [h10] The pass-local ratio weighs downloaded and scanned blocks half each — a
        // resync's downloaded-but-not-yet-scanned blocks now move the reading instead of
        // being invisible until scanning alone crosses the pass's global start position.
        // Each term clamps to `pass_total` independently: a same-pass retry (e.g. a
        // ScanContinuity truncate-and-re-suggest, scheduler.rs) can re-fetch and re-count
        // blocks an earlier attempt in the SAME pass already counted, so `fetched` (and
        // `scanned`) can exceed `pass_total` within one pass — the clamp keeps such a
        // retry's over-count from giving its term more than its intended half-weight share.
        //
        // [h16-1] Each term is measured from the pass-local BASELINE the scheduler
        // snapshots every suggest round (`Progress::set_pass_baseline`), not from the raw
        // counter: the raw `fetched_blocks`/`scanned_blocks` counters are shared with other
        // readers (this snapshot's own `fetched_blocks`/`scanned_blocks` fields below, and
        // the CLI ticker) and so are never zeroed mid-pass, but a scope-expansion
        // re-baseline (`rebaseline_floor_if_scope_expanded`) folds already-credited work
        // into the new `pass_start_permille` — without subtracting the baseline here, that
        // same work would ALSO inflate this pass-local ratio and double-count it.
        let pass_total = p.pass_total();
        let fetched_capped = p
            .fetched()
            .saturating_sub(p.pass_base_fetched())
            .min(pass_total);
        let scanned_capped = p
            .scanned()
            .saturating_sub(p.pass_base_scanned())
            .min(pass_total);
        let pass_permille = fetched_capped
            .saturating_add(scanned_capped)
            .saturating_mul(1000)
            .checked_div(pass_total.saturating_mul(2))
            .unwrap_or(0);
        // The pass's own progress is stretched between where the wallet's GLOBAL position
        // stood when the pass began (`pass_start_permille`, latched by the scheduler's first
        // suggest round of this pass) and 1000 — so a resync inherits the position the
        // wallet already proved instead of restarting the pass-local ratio at 0. Before any
        // suggest round has run (the pass-open E-3 seed only raises the FLOOR, not this
        // pass's own start), the raw reading is the pass-local ratio alone.
        let raw_permille = match p.pass_start_permille() {
            Some(start) => {
                let start = start.min(1000);
                let climb = 1000u64
                    .saturating_sub(start)
                    .saturating_mul(pass_permille)
                    .checked_div(1000)
                    .unwrap_or(0);
                start.saturating_add(climb)
            }
            None => pass_permille,
        };
        let progress_permille = match state {
            SyncState::Done => p.permille_floor(1000) as u16,
            _ => p.permille_floor(raw_permille) as u16,
        };
        // Fail-safe latch: terminal states force NOT-recovering regardless of the live flag —
        // a dead pass can never wedge a host's "Restoring" UI (previously Swift-side hardening).
        let is_recovering_u8 = match state {
            SyncState::Done | SyncState::Error(_) => 0u8,
            _ => u8::from(p.recovering()),
        };
        // Stall fact: only meaningful while actively syncing; 0 when idle/terminal. The longer
        // of the time since the last progress stamp and a repeatedly failing download's span
        // (`Progress::stall_secs`).
        let stalled_seconds = match state {
            SyncState::Syncing => {
                u32::try_from(p.stall_secs(crate::events::unix_now_secs())).unwrap_or(u32::MAX)
            }
            _ => 0u32,
        };
        FfiSlipstreamSnapshot {
            chain_tip: p.chain_tip(),
            fetched_blocks: p.fetched(),
            scanned_blocks: p.scanned(),
            enhanced_txs: p.enhanced(),
            current_range_end: p.range_end(),
            state: state_u8,
            pass_total_blocks: p.pass_total(),
            spendable_hint: p.spendable() as u8,
            ranges_completed: p.ranges_completed(),
            is_recovering: is_recovering_u8,
            progress_permille,
            stalled_seconds,
            tx_set_version: p.tx_set_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::events::WalletWriterGate;

    /// [API v2 §4.5] Overflow evicts the oldest DROPPABLE (started/progress) event, so a critical
    /// event pushed into a full ring never displaces another critical while pacing events remain.
    #[test]
    fn ring_overflow_evicts_droppable_before_critical() {
        let mut ring: Vec<FfiSlipstreamEvent> = Vec::new();
        // 3 criticals first (found-transactions), then fill the rest with progress.
        for i in 0..3 {
            push_event_bounded(&mut ring, FfiSlipstreamEvent { tag: 5, value: i });
        }
        for i in 0..(EVENT_RING_CAP - 3) {
            push_event_bounded(
                &mut ring,
                FfiSlipstreamEvent {
                    tag: 2,
                    value: i as u64,
                },
            );
        }
        assert_eq!(ring.len(), EVENT_RING_CAP);
        // Push a critical into the full ring: the oldest PROGRESS event (value 0) must go,
        // all 3 early criticals must survive, and the new critical must be at the tail.
        push_event_bounded(&mut ring, FfiSlipstreamEvent { tag: 4, value: 9 });
        assert_eq!(ring.len(), EVENT_RING_CAP);
        assert_eq!(
            ring.iter().filter(|e| e.tag == 5).count(),
            3,
            "early criticals survive"
        );
        assert!(
            !ring.iter().any(|e| e.tag == 2 && e.value == 0),
            "oldest droppable evicted, not position 0"
        );
        let last = ring.last().unwrap();
        assert_eq!((last.tag, last.value), (4, 9));
    }

    /// Pathological fallback: a ring FULL of criticals still accepts (evicts oldest overall).
    #[test]
    fn ring_overflow_all_critical_falls_back_to_oldest() {
        let mut ring: Vec<FfiSlipstreamEvent> = Vec::new();
        for i in 0..EVENT_RING_CAP {
            push_event_bounded(
                &mut ring,
                FfiSlipstreamEvent {
                    tag: 5,
                    value: i as u64,
                },
            );
        }
        push_event_bounded(&mut ring, FfiSlipstreamEvent { tag: 3, value: 7 });
        assert_eq!(ring.len(), EVENT_RING_CAP);
        assert!(
            !ring.iter().any(|e| e.value == 0 && e.tag == 5),
            "oldest critical evicted"
        );
        let last = ring.last().unwrap();
        assert_eq!((last.tag, last.value), (3, 7));
    }

    #[test]
    fn ffi_snapshot_default_is_zero() {
        let s = FfiSlipstreamSnapshot::default();
        assert_eq!(s.chain_tip, 0);
        assert_eq!(s.fetched_blocks, 0);
        assert_eq!(s.scanned_blocks, 0);
        assert_eq!(s.enhanced_txs, 0);
        assert_eq!(s.current_range_end, 0);
        assert_eq!(s.state, 0);
        assert_eq!(
            s.pass_total_blocks, 0,
            "pass_total_blocks default must be 0"
        );
        assert_eq!(s.spendable_hint, 0, "spendable_hint default must be 0");
        assert_eq!(s.ranges_completed, 0, "ranges_completed default must be 0");
        assert_eq!(s.is_recovering, 0, "is_recovering default must be 0");
        assert_eq!(
            s.progress_permille, 0,
            "progress_permille default must be 0"
        );
        assert_eq!(s.stalled_seconds, 0, "stalled_seconds default must be 0");
        assert_eq!(s.tx_set_version, 0, "tx_set_version default must be 0");
    }

    /// [API v2 §4.4] The permille floor is session-monotonic: raw regressions never lower
    /// the reported value, and raw values clamp to 1000.
    #[test]
    fn permille_floor_is_monotonic_and_clamped() {
        let p = crate::events::Progress::default();
        assert_eq!(p.permille_floor(300), 300);
        assert_eq!(p.permille_floor(100), 300, "regression must hold the floor");
        assert_eq!(p.permille_floor(999), 999);
        assert_eq!(p.permille_floor(5000), 1000, "raw clamps to 1000");
        assert_eq!(p.permille_floor(0), 1000, "floor persists at max");
    }

    /// A handle around `progress` in `state`, for snapshot tests (no task, no network).
    fn handle_in(
        state: SyncState,
        progress: std::sync::Arc<crate::events::Progress>,
    ) -> SlipstreamHandle {
        SlipstreamHandle {
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("tokio runtime"),
            progress,
            state: std::sync::Arc::new(Mutex::new(state)),
            events: std::sync::Arc::new(Mutex::new(Vec::new())),
            task: None,
            unfinished_passes: Vec::new(),
            pass_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint: Endpoint {
                host: "localhost".into(),
                port: 9067,
                tls: false,
            },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
            total_memory_bytes: 0,
        }
    }

    /// [API v2 §4.4] Terminal states force is_recovering = 0 (the fail-safe latch), and Done
    /// forces progress to 1000 — a dead or finished pass can never wedge a "Restoring" UI or
    /// show partial progress.
    #[test]
    fn snapshot_terminal_states_apply_v2_latches() {
        // Syncing + recovering flag set → surfaces as recovering, permille from the pass
        // blend. No pass start recorded (fresh Progress) ⇒ raw = pass_permille =
        // (0 fetched + 250 scanned)/(2×1000) = 125 — the new half-weighted formula (was
        // 250 under the old scanned/pass_total ratio; [h10]).
        let p1 = std::sync::Arc::new(crate::events::Progress::default());
        p1.set_recovering(true);
        p1.set_pass_total(1000);
        p1.add_scanned(250);
        let snap = handle_in(SyncState::Syncing, p1.clone()).snapshot();
        assert_eq!(snap.is_recovering, 1);
        assert_eq!(snap.progress_permille, 125);

        // Error → latch forces NOT recovering even though the live flag is still true.
        let snap = handle_in(SyncState::Error(2), p1.clone()).snapshot();
        assert_eq!(
            snap.is_recovering, 0,
            "Error must release the recovery gate"
        );
        assert_eq!(
            snap.stalled_seconds, 0,
            "stall clock only ticks while Syncing"
        );

        // Done → recovery off AND progress forced to (and floored at) 1000.
        let snap = handle_in(SyncState::Done, p1).snapshot();
        assert_eq!(snap.is_recovering, 0, "Done must clear recovering");
        assert_eq!(
            snap.progress_permille, 1000,
            "Done must complete the progress"
        );
    }

    /// [h10] A fresh pass has no recorded start (no suggest round has run yet — see
    /// `Progress::pass_start_permille`): the snapshot reads the pass blend alone, with
    /// fetched and scanned blocks weighed half each. Half the pass fetched and nothing
    /// scanned must move the reading off 0 — downloaded-but-unscanned blocks now count
    /// toward progress instead of being invisible until 93.6% of the pass is scanned.
    #[test]
    fn snapshot_fresh_pass_with_no_start_reads_the_pass_blend_alone() {
        let p = std::sync::Arc::new(crate::events::Progress::default());
        p.set_pass_total(10_000);
        p.add_fetched(5_000); // half the pass fetched
        // scanned stays 0; pass_start_permille is unset on a fresh Progress.
        let snap = handle_in(SyncState::Syncing, p).snapshot();
        assert_eq!(
            snap.progress_permille, 250,
            "no pass start ⇒ raw = pass_permille = (5_000 fetched + 0 scanned)/(2×10_000) = 250"
        );
    }

    /// [h10] A pass that starts at a known GLOBAL position (936‰, matching the brief's
    /// worked example of a wallet that was 51k blocks in with three accounts scanning): the
    /// blend stretches from 936 to 1000 as the pass-local ratio climbs, weighing fetched and
    /// scanned blocks half each — a resync's downloaded blocks move the reading well before
    /// 93.6% of the pass is SCANNED. The session floor holds even if the counters are
    /// replayed lower (e.g. a stray reset).
    #[test]
    fn snapshot_pass_blend_climbs_from_known_pass_start_and_never_regresses() {
        let pass_total = 51_271u64;
        let p = std::sync::Arc::new(crate::events::Progress::default());
        p.set_pass_total(pass_total);
        p.set_pass_start_permille(936);

        let snap = handle_in(SyncState::Syncing, p.clone()).snapshot();
        assert_eq!(
            snap.progress_permille, 936,
            "nothing fetched or scanned yet: raw = start"
        );

        p.add_fetched(pass_total);
        let snap = handle_in(SyncState::Syncing, p.clone()).snapshot();
        assert_eq!(
            snap.progress_permille, 968,
            "everything fetched, nothing scanned: half-weighted climb off the start"
        );

        p.add_scanned(pass_total);
        let snap = handle_in(SyncState::Syncing, p.clone()).snapshot();
        assert_eq!(
            snap.progress_permille, 1000,
            "everything fetched and scanned: the pass is done"
        );

        // Replay the counters lower (e.g. a stray reset) — the session floor must hold.
        p.fetched_blocks
            .store(0, std::sync::atomic::Ordering::Relaxed);
        p.scanned_blocks
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let snap = handle_in(SyncState::Syncing, p).snapshot();
        assert_eq!(
            snap.progress_permille, 1000,
            "reported progress never regresses while the handle lives"
        );
    }

    /// [h16-2 pin] A same-pass retry (e.g. a ScanContinuity truncate-and-re-suggest) can
    /// re-fetch and re-count blocks an earlier attempt in the SAME pass already counted, so
    /// `fetched`/`scanned` can exceed `pass_total` within one pass — each term must clamp to
    /// `pass_total` independently instead of overflowing the blend past its intended
    /// half-weight share. Unaffected by the h16-1 baseline (default 0), so this already held
    /// before h16-2; pinned here as regression coverage for the reviewer's round.
    #[test]
    fn fetched_exceeding_pass_total_stays_clamped() {
        let p = std::sync::Arc::new(crate::events::Progress::default());
        p.set_pass_total(100);
        p.add_fetched(150); // exceeds pass_total
        p.add_scanned(150); // exceeds pass_total
        let snap = handle_in(SyncState::Syncing, p).snapshot();
        assert_eq!(
            snap.progress_permille, 1000,
            "fetched/scanned beyond pass_total must clamp to it, not overflow the blend"
        );
    }

    /// [h16-2 pin] `pass_total == 0` (no suggest round has run yet, or a degenerate empty
    /// pass) must read the pass start alone, not divide-by-zero into 0 and mask a known
    /// GLOBAL position. Unaffected by the h16-1 baseline (both clamp to a 0 pass_total
    /// regardless of the baseline), so this already held before h16-2; pinned here as
    /// regression coverage for the reviewer's round.
    #[test]
    fn pass_total_zero_with_start_set_reads_the_start() {
        let p = std::sync::Arc::new(crate::events::Progress::default());
        p.set_pass_start_permille(620);
        // pass_total left at 0 (default).
        let snap = handle_in(SyncState::Syncing, p).snapshot();
        assert_eq!(
            snap.progress_permille, 620,
            "pass_total == 0 must read the pass start, not divide by zero into 0"
        );
    }

    #[test]
    fn ffi_snapshot_counter_fields_roundtrip() {
        // Build a fake Progress, set the new counters, and verify they surface in snapshot().
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let progress = std::sync::Arc::new(crate::events::Progress::default());
        let handle = SlipstreamHandle {
            runtime,
            progress: progress.clone(),
            state: std::sync::Arc::new(Mutex::new(SyncState::Syncing)),
            events: std::sync::Arc::new(Mutex::new(Vec::new())),
            task: None,
            unfinished_passes: Vec::new(),
            pass_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint: Endpoint {
                host: "localhost".into(),
                port: 9067,
                tls: false,
            },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
            total_memory_bytes: 0,
        };

        // Simulate F1: scheduler calls set_pass_total with whole-pass total.
        // First suggest: scanned=0 + 10_000 (ChainTip) + 5_000 (Historic) = 15_000.
        progress.set_pass_total(15_000);
        progress.add_scanned(7_500);
        progress.set_spendable();

        // F2: simulate completing two ranges.
        progress.add_ranges_completed(); // range 1 done
        progress.add_ranges_completed(); // range 2 done

        let snap = handle.snapshot();
        assert_eq!(
            snap.pass_total_blocks, 15_000,
            "pass_total_blocks must equal set_pass_total value (F1 store semantics)"
        );
        assert_eq!(
            snap.spendable_hint, 1,
            "spendable_hint must be 1 after set_spendable()"
        );
        assert_eq!(
            snap.scanned_blocks, 7_500,
            "scanned_blocks must equal add_scanned total"
        );
        assert_eq!(snap.state, 1, "state must be 1 (Syncing)");
        assert_eq!(
            snap.ranges_completed, 2,
            "ranges_completed must reflect add_ranges_completed calls (F2)"
        );
    }

    #[test]
    fn ffi_snapshot_ranges_completed_roundtrip() {
        // Verify ranges_completed surfaces correctly from Progress → snapshot.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let progress = std::sync::Arc::new(crate::events::Progress::default());
        let handle = SlipstreamHandle {
            runtime,
            progress: progress.clone(),
            state: std::sync::Arc::new(Mutex::new(SyncState::Idle)),
            events: std::sync::Arc::new(Mutex::new(Vec::new())),
            task: None,
            unfinished_passes: Vec::new(),
            pass_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint: Endpoint {
                host: "localhost".into(),
                port: 9067,
                tls: false,
            },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
            total_memory_bytes: 0,
        };

        assert_eq!(
            handle.snapshot().ranges_completed,
            0,
            "initial value must be 0"
        );
        progress.add_ranges_completed();
        assert_eq!(
            handle.snapshot().ranges_completed,
            1,
            "must be 1 after first range"
        );
        progress.add_ranges_completed();
        progress.add_ranges_completed();
        assert_eq!(
            handle.snapshot().ranges_completed,
            3,
            "must be 3 after three ranges"
        );
    }

    #[test]
    fn event_ring_cap_at_64() {
        // Build a handle with a real tokio runtime for the ring test.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let handle = SlipstreamHandle {
            runtime,
            progress: Arc::new(Progress::default()),
            state: Arc::new(Mutex::new(SyncState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
            task: None,
            unfinished_passes: Vec::new(),
            pass_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint: Endpoint {
                host: "localhost".into(),
                port: 9067,
                tls: false,
            },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
            total_memory_bytes: 0,
        };

        // Push 70 events — only the last 64 should survive.
        for i in 0u64..70 {
            handle.push_event(FfiSlipstreamEvent { tag: 1, value: i });
        }
        let ring = handle.events.lock().unwrap();
        assert_eq!(ring.len(), EVENT_RING_CAP);
        // The oldest 6 (values 0..5) were dropped; first kept value is 6.
        assert_eq!(ring[0].value, 6);
        // Last kept value is 69.
        assert_eq!(ring[EVENT_RING_CAP - 1].value, 69);
    }

    // ── B1 (#1755) supervisor tests ────────────────────────────────────────────

    /// Polls `state` until `pred` holds or ~5 s elapse. The supervisor runs on the
    /// runtime's worker threads; the test thread observes its effects.
    fn wait_for_state(
        state: &Arc<Mutex<SyncState>>,
        pred: impl Fn(&SyncState) -> bool,
    ) -> SyncState {
        for _ in 0..500 {
            {
                let s = state.lock().unwrap();
                if pred(&s) {
                    return *s;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        *state.lock().unwrap()
    }

    /// A panicking sync task must surface as Error(2) + a tag=4/value=2 event —
    /// never a silent death with the state stuck at Syncing (field failure 2).
    #[test]
    fn supervisor_converts_panic_to_error_state() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let state = Arc::new(Mutex::new(SyncState::Syncing));
        let events: Arc<Mutex<Vec<FfiSlipstreamEvent>>> = Arc::new(Mutex::new(Vec::new()));

        let _abort = spawn_supervised(
            &runtime,
            async { panic!("boom: synthetic sync panic") },
            Arc::clone(&state),
            Arc::clone(&events),
        );

        let observed = wait_for_state(&state, |s| matches!(s, SyncState::Error(_)));
        assert_eq!(observed, SyncState::Error(2), "panic must become Error(2)");
        let ring = events.lock().unwrap();
        assert!(
            ring.iter().any(|e| e.tag == 4 && e.value == 2),
            "panic must push a tag=4/value=2 event, got {ring:?}"
        );
    }

    /// Cancellation via the AbortHandle (stop()/free()/restart) must NOT be
    /// reported as an error — the canceller owns the state transition.
    #[test]
    fn supervisor_ignores_cancellation() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let state = Arc::new(Mutex::new(SyncState::Syncing));
        let events: Arc<Mutex<Vec<FfiSlipstreamEvent>>> = Arc::new(Mutex::new(Vec::new()));

        let abort = spawn_supervised(
            &runtime,
            async {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            },
            Arc::clone(&state),
            Arc::clone(&events),
        );
        abort.abort();

        // Give the supervisor time to observe the cancellation; the state and the
        // event ring must remain untouched.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            *state.lock().unwrap(),
            SyncState::Syncing,
            "cancel must not write state"
        );
        assert!(
            events.lock().unwrap().is_empty(),
            "cancel must not push events"
        );
    }

    /// Normal completion writes nothing — the task body owns Done/Error.
    #[test]
    fn supervisor_passes_through_normal_completion() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let state = Arc::new(Mutex::new(SyncState::Syncing));
        let events: Arc<Mutex<Vec<FfiSlipstreamEvent>>> = Arc::new(Mutex::new(Vec::new()));

        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_inner = Arc::clone(&done);
        let _abort = spawn_supervised(
            &runtime,
            async move {
                done_inner.store(true, std::sync::atomic::Ordering::SeqCst);
            },
            Arc::clone(&state),
            Arc::clone(&events),
        );

        for _ in 0..500 {
            if done.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(200)); // let the supervisor settle
        assert_eq!(
            *state.lock().unwrap(),
            SyncState::Syncing,
            "completion must not write state"
        );
        assert!(
            events.lock().unwrap().is_empty(),
            "completion must not push events"
        );
    }

    #[test]
    fn event_ring_drain_is_atomic() {
        // Build a handle and verify drain removes exactly the pushed events.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let handle = SlipstreamHandle {
            runtime,
            progress: Arc::new(Progress::default()),
            state: Arc::new(Mutex::new(SyncState::Idle)),
            events: Arc::new(Mutex::new(Vec::new())),
            task: None,
            unfinished_passes: Vec::new(),
            pass_lock: Arc::new(tokio::sync::Mutex::new(())),
            endpoint: Endpoint {
                host: "localhost".into(),
                port: 9067,
                tls: false,
            },
            wallet_db_path: std::path::PathBuf::from("/tmp/test.db"),
            network: zcash_protocol::consensus::Network::TestNetwork,
            total_memory_bytes: 0,
        };

        handle.push_event(FfiSlipstreamEvent { tag: 1, value: 10 });
        handle.push_event(FfiSlipstreamEvent { tag: 3, value: 2 });

        // Simulate drain by locking and draining.
        let drained: Vec<FfiSlipstreamEvent> = {
            let mut ring = handle.events.lock().unwrap();
            ring.drain(..).collect()
        };
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].value, 10);
        assert_eq!(drained[1].value, 2);

        // Ring must be empty after drain.
        let ring = handle.events.lock().unwrap();
        assert!(ring.is_empty());
    }

    /// While Syncing, `stalled_seconds` reports a block download that keeps failing at the same
    /// block even though the retried passes keep stamping progress; in any other state it
    /// stays 0.
    #[test]
    fn snapshot_reports_a_repeatedly_failing_download_while_syncing() {
        let now = crate::events::unix_now_secs();
        let p = std::sync::Arc::new(crate::events::Progress::default());
        p.note_download_gave_up_at(500, now - 300);
        p.note_download_gave_up_at(500, now - 200);
        p.touch(); // a retried pass's fresh sign of life
        let syncing = handle_in(SyncState::Syncing, p.clone()).snapshot();
        assert!(
            syncing.stalled_seconds >= 300,
            "counted from the first give-up, got {}",
            syncing.stalled_seconds
        );
        let done = handle_in(SyncState::Done, p).snapshot();
        assert_eq!(done.stalled_seconds, 0, "only Syncing reports a stall");
    }

    // ── [MOB-1850] the shared quiescent stop ──────────────────────────────────

    /// [MOB-1850] A wallet writer still holding the gate when the drain's budget runs out is a
    /// NON-QUIESCENT stop, and the drain must say so. Logging the timeout away and answering
    /// "quiescent" is what let the host mutate the wallet on top of a live engine writer.
    #[test]
    fn drain_reports_a_writer_that_outlives_the_deadline() {
        let progress = crate::events::ProgressArc::default();
        // The RAII gate is the engine's own way of holding the counter up for the life of a
        // commit, so the test raises it exactly as the persist lane does.
        let gate = WalletWriterGate::hold(progress.clone());
        let quiescent = drain_wallet_writers(&progress, Duration::from_millis(50));
        assert!(
            !quiescent,
            "a writer still running at the deadline must be reported, not logged away"
        );
        drop(gate);
        assert!(drain_wallet_writers(&progress, Duration::from_millis(50)));
    }

    /// Releases a `spawn_gated_pass` loop, explicitly via `release()` or implicitly when this
    /// guard is dropped. A failing assertion panics and unwinds BEFORE a test reaches its explicit
    /// release, and local variables are dropped in reverse declaration order during unwinding, so a
    /// guard declared after the runtime is always dropped — and so releases its worker thread —
    /// before the runtime itself is. Without that, `Runtime::drop` would block forever joining a
    /// worker still parked in the gated loop, turning a failing assertion into a hang. A handle
    /// owns its runtime, so the same goes for a handle: declare it first and the guard after it.
    struct PassRelease(Arc<AtomicBool>);

    impl PassRelease {
        fn release(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl Drop for PassRelease {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Spawns a pass parked in a synchronous loop (no await point, so `abort()` cannot take it
    /// down) and returns its join handle plus the guard that releases it.
    fn spawn_gated_pass(runtime: &Runtime) -> (tokio::task::JoinHandle<()>, PassRelease) {
        let release = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let (held, running) = (release.clone(), started.clone());
        let task = runtime.spawn(async move {
            running.store(true, Ordering::SeqCst);
            while !held.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        while !started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        (task, PassRelease(release))
    }

    /// [MOB-1850] The pass half of the same contract, and the reason a pass has to STAY on record.
    /// `abort()` cannot interrupt a task that is inside a synchronous stretch, so one that is still
    /// there when the budget runs out must be reported — and it must go on being reported by every
    /// later stop, because taking the handle out of the slot is not the same as the pass finishing.
    #[test]
    fn a_repeated_stop_stays_non_quiescent_while_the_original_pass_is_unfinished() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let budget = Duration::from_millis(50);
        let (first, release_first) = spawn_gated_pass(&runtime);
        let observer = first.abort_handle();
        let mut slot = Some(first.abort_handle());
        let mut unfinished: Vec<AbortHandle> = Vec::new();

        assert!(
            !settle_passes(&mut slot, &mut unfinished, budget),
            "first stop: the pass outlives the budget"
        );
        assert!(
            !settle_passes(&mut slot, &mut unfinished, budget),
            "second stop must not claim quiescence while the first pass still runs"
        );
        assert!(!observer.is_finished());

        // A start-style replacement installs a new pass while the old one is still unfinished.
        let (second, release_second) = spawn_gated_pass(&runtime);
        let _ = settle_passes(&mut slot, &mut unfinished, budget);
        slot = Some(second.abort_handle());
        assert!(
            !settle_passes(&mut slot, &mut unfinished, budget),
            "a stop after a replacement must still see the original unfinished pass"
        );
        assert_eq!(
            unfinished.len(),
            2,
            "both unfinished passes stay on record after the replacement"
        );

        release_first.release();
        release_second.release();
        assert!(
            settle_passes(&mut slot, &mut unfinished, Duration::from_secs(5)),
            "quiescence once every pass has actually finished"
        );
        assert!(unfinished.is_empty());
    }

    /// A host about to change the wallet acts on the AND of the two verdicts: one wait that ran
    /// out is enough to leave the wallet file unproved.
    #[test]
    fn a_report_is_quiescent_only_when_settled_and_drained() {
        for (settled, drained) in [(false, false), (false, true), (true, false), (true, true)] {
            let report = StopReport {
                settled,
                drained,
                settle_wait: Duration::ZERO,
                drain_wait: Duration::ZERO,
            };
            assert_eq!(report.quiescent(), settled && drained, "{report:?}");
        }
    }

    /// Only the stop a host makes right before it changes the wallet asks the running session to
    /// end at its next block. A plain stop (backgrounding, shutdown) must leave that request
    /// alone, so every other stop behaves exactly as it did before the wallet-change stop.
    #[test]
    fn only_a_stop_for_a_wallet_change_asks_the_scan_to_stop() {
        let progress = Arc::new(Progress::default());
        let mut handle = handle_in(SyncState::Syncing, progress.clone());
        let budget = Duration::from_millis(50);

        let report = handle.stop(budget);
        assert!(report.quiescent(), "nothing was running: {report:?}");
        assert!(
            !progress.stop_requested(),
            "a plain stop must not ask the scan to stop early"
        );

        let report = handle.stop_for_wallet_change(budget);
        assert!(report.quiescent(), "nothing was running: {report:?}");
        assert!(
            progress.stop_requested(),
            "a stop for a wallet change must ask the running session to stop at its next block"
        );
    }

    /// Both stops leave the handle Idle, and they do so also when they could not prove the wallet
    /// file quiescent: the pass is stopped either way, and the report is what says whether the
    /// file is safe to change.
    #[test]
    fn a_stop_sets_the_state_to_idle() {
        let budget = Duration::from_millis(50);
        for for_wallet_change in [false, true] {
            for writer_outlives_the_budget in [false, true] {
                let progress = Arc::new(Progress::default());
                let mut handle = handle_in(SyncState::Syncing, progress.clone());
                let gate =
                    writer_outlives_the_budget.then(|| WalletWriterGate::hold(progress.clone()));
                let report = if for_wallet_change {
                    handle.stop_for_wallet_change(budget)
                } else {
                    handle.stop(budget)
                };
                assert_eq!(
                    report.quiescent(),
                    !writer_outlives_the_budget,
                    "{report:?}"
                );
                assert_eq!(
                    *handle.state.lock().unwrap(),
                    SyncState::Idle,
                    "for_wallet_change={for_wallet_change}, quiescent={}",
                    report.quiescent()
                );
                drop(gate);
            }
        }
    }

    /// A stop measures each of its two waits, so a host can tell the user WHICH one ran out and
    /// after how long. A wait that ran into its budget took at least that budget.
    #[test]
    fn a_stop_measures_the_wait_that_ran_out() {
        let progress = Arc::new(Progress::default());
        let mut handle = handle_in(SyncState::Syncing, progress.clone());
        let budget = Duration::from_millis(50);

        // The drain's wait: a wallet writer that outlives the budget.
        let gate = WalletWriterGate::hold(progress.clone());
        let report = handle.stop(budget);
        assert!(report.settled && !report.drained, "{report:?}");
        assert!(
            report.drain_wait >= budget,
            "the drain waited out its whole budget: {report:?}"
        );
        drop(gate);

        // The settle's wait: a pass that outlives the budget. Declared after the handle, so the
        // guard releases the runtime's only worker before the handle's runtime is dropped.
        let (pass, release) = spawn_gated_pass(&handle.runtime);
        handle.task = Some(pass.abort_handle());
        let report = handle.stop(budget);
        assert!(!report.settled && report.drained, "{report:?}");
        assert!(
            report.settle_wait >= budget,
            "the settle waited out its whole budget: {report:?}"
        );

        release.release();
        let report = handle.stop(Duration::from_secs(5));
        assert!(report.quiescent(), "the pass has finished: {report:?}");
    }

    /// [MOB-1850] The start's half: `quiesce_before_start` aborts and waits out the previous pass
    /// as a stop does, but leaves the state to the start that follows (the host sets `Syncing`
    /// itself). A pass it could not wait out STAYS on record, so the next stop still answers for
    /// it instead of reporting it quiescent.
    #[test]
    fn quiesce_before_start_leaves_the_state_alone_and_keeps_an_unfinished_pass_on_record() {
        let mut handle = handle_in(SyncState::Done, Arc::new(Progress::default()));
        let budget = Duration::from_millis(50);
        let (pass, release) = spawn_gated_pass(&handle.runtime);
        handle.task = Some(pass.abort_handle());

        let report = handle.quiesce_before_start(budget);
        assert!(!report.settled && report.drained, "{report:?}");
        assert!(report.settle_wait >= budget, "{report:?}");
        assert_eq!(
            *handle.state.lock().unwrap(),
            SyncState::Done,
            "the start that follows owns the state change"
        );
        assert!(handle.task.is_none(), "the aborted pass left the slot");
        assert_eq!(
            handle.unfinished_passes.len(),
            1,
            "the pass the start could not wait out stays on record"
        );

        let report = handle.stop(budget);
        assert!(
            !report.settled,
            "the next stop still answers for that pass: {report:?}"
        );

        release.release();
        let report = handle.stop(Duration::from_secs(5));
        assert!(
            report.quiescent(),
            "quiescent once the pass has actually finished: {report:?}"
        );
        assert!(handle.unfinished_passes.is_empty());
    }
}
