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

//! Engine → shell surface: a polled `Snapshot` plus a drained `Event` ring
//! (decision D8). Fields grow in P3; keep
//! both types additive (`#[non_exhaustive]`).

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

/// Current wall-clock time in whole Unix seconds (0 if the clock reads before the epoch).
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A block download that has given up this many times at the same block, each give-up within
/// [`DOWNLOAD_FAILURE_RUN_GAP_SECS`] of the one before, counts toward `stalled_seconds` from its
/// first give-up (see [`Progress::download_failure_secs`]). Two: the engine's own retry gets one
/// chance first.
pub const DOWNLOAD_FAILURE_STALL_STREAK: u32 = 2;

/// Give-ups at the same block more than this many seconds apart are separate runs. The time in
/// between was not spent failing that download: for example, a synced wallet sitting idle between
/// catch-up passes, or the engine busy downloading other ranges. It sits well above the few
/// minutes between consecutive give-ups when a server keeps failing a range. A run also stops
/// counting toward `stalled_seconds` once its latest give-up is older than this: see
/// [`Progress::download_failure_secs`].
pub const DOWNLOAD_FAILURE_RUN_GAP_SECS: u64 = 600;

/// A safety bound on how many runs [`Progress`] keeps. Runs normally hold only the one or two
/// blocks the download is stuck on, because a later release removes each run.
const MAX_DOWNLOAD_FAILURE_RUNS: usize = 8;

/// A run of block-download give-ups at one block (see [`Progress::note_download_gave_up`]).
///
/// There is one run per block. A run ends in one of four ways: a later release of its block to
/// the scanner ([`Progress::note_blocks_released`]), a completed pass
/// ([`Progress::note_pass_completed`]), a sync attempt that failed without its download giving up
/// ([`Progress::note_attempt_failed`]), or a new session ([`Progress::begin_session`]). A give-up
/// at its block more than [`DOWNLOAD_FAILURE_RUN_GAP_SECS`] after the previous one starts it
/// over, and until then it counts only while live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadFailure {
    /// Give-ups at `at_height` in this run.
    pub streak: u32,
    /// The block the download could not deliver: the lowest block not yet handed to the scanner
    /// when it gave up. Give-ups at any other block belong to that block's own run.
    pub at_height: u64,
    /// Unix seconds of the run's first give-up.
    pub since_unix: u64,
    /// Unix seconds of the run's latest give-up.
    pub last_unix: u64,
}

/// Shared engine progress for poll-based consumers (decision D8).
///
/// All counters are monotonic during one sync pass; `Relaxed` ordering is
/// sufficient because no cross-counter invariants are promised to readers
/// (each field is independent; the consumer only needs an eventually-consistent
/// view for UI display, not a fully-consistent snapshot).
///
/// Wrap in `Arc<Progress>` and pass `Some(arc)` to `engine::sync_once` to
/// receive live updates. `None` disables all progress tracking with zero overhead.
#[derive(Debug, Default)]
pub struct Progress {
    /// Current chain tip height as reported by the server.
    pub chain_tip: AtomicU64,
    /// Number of compact blocks fetched so far.
    pub fetched_blocks: AtomicU64,
    /// Number of compact blocks scanned so far.
    pub scanned_blocks: AtomicU64,
    /// Number of transactions enhanced (decrypt_and_store) so far.
    pub enhanced_txs: AtomicU64,
    /// End height of the range currently being processed (inclusive).
    pub current_range_end: AtomicU64,
    /// Number of reorg recoveries (truncate + re-suggest) performed.
    pub reorgs_recovered: AtomicU64,
    /// Total blocks in the current pass. Set (not accumulated) by the scheduler each
    /// time it calls `suggest_scan_ranges`: the new value is `scanned_so_far_in_pass +
    /// sum(block-lengths of ALL returned ranges)`. Because all ranges for a pass are
    /// returned together by `suggest_scan_ranges`, the denominator is complete from the
    /// very first suggestion — no snap-back when Historic ranges are revealed.
    /// Updated via `set_pass_total(n)`.
    pub pass_total_blocks: AtomicU64,
    /// Spendable hint latch: 0 = funds not yet spendable; 1 = a ChainTip-priority range
    /// completed scanning (≈ SBS "funds-spendable" semantics). Latches to 1 and never
    /// resets to 0 within a pass. Read with `spendable()`.
    pub spendable_hint: AtomicU64,
    /// Number of suggested ranges whose scan+enhancement has completed in the current
    /// pass. Monotonically incremented by the scheduler after each range finishes
    /// (scan + per-range enhancement). Used by Swift to trigger a balance-summary
    /// fetch at each range boundary while Syncing.
    pub ranges_completed: AtomicU64,
    // ── API v2 fields (ENGINE_API_V2.md §4.4) ──
    /// 1 while the current pass still has suggested ranges below the wallet's
    /// recover-until height (the restore backfill window); 0 otherwise. Written by the
    /// scheduler on every suggest round. The SNAPSHOT mapping forces 0 on terminal
    /// states (Done / Error) — the fail-safe latch that previously lived in the Swift
    /// SDK ("a dead pass can never wedge Restoring") now holds for every host.
    pub recovering: AtomicU64,
    /// Unix seconds of the last forward progress: any counter bump, a pass start,
    /// data arriving from the server during a pass (every streamed block and
    /// every metadata message, direct or over Tor), or a unit of
    /// local work completing (a persisted chunk, the range-end tree build). The
    /// snapshot's `stalled_seconds` (while Syncing) is the longer of `now − this` and the
    /// time the block download has kept failing at the same block — see [`Self::stall_secs`].
    pub last_progress_unix: AtomicU64,
    /// Session-monotonic progress floor in permille (0..=1000). The snapshot fetch-maxes
    /// the raw `scanned / pass_total` ratio into this and reports the floor, so reported
    /// progress NEVER regresses while the handle lives (subsumes the SDK's
    /// monotonicRecoveryProgress floor and its warm-start seeding: a follow-up catch-up
    /// pass holds the prior high-water mark instead of flashing back to 0%).
    pub progress_permille_floor: AtomicU64,
    /// [API v2.1 E-2/E-3] Count of successful `update_chain_tip` persists across the handle's
    /// life. Bumped by the ENGINE only (never by the E-3 open-time seed, which stores a
    /// persisted tip VALUE without proving freshness) — the FFI's `tip_fresh` fact latches
    /// when this counter has advanced since `start()`, i.e. "THIS run refreshed the tip",
    /// independent of whether the fetched tip happens to equal the persisted one.
    /// Monotonic per handle; deliberately NOT reset by [`Self::begin_pass`].
    pub tip_refreshes: AtomicU64,
    /// [API v2.1 E-4] Monotonic version of the wallet's STORED transaction set. Bumped exactly
    /// when the set changes: a transaction stored/updated by enhancement or the mempool
    /// monitor, a reconcile-linkage transition detected at a range boundary (the scheduler's
    /// `(tx_count, unreconciled_count)` signature moved), or a host submit-poke
    /// (`zcashlc_slipstream_notify_tx_change`). The HOST rule is one line: version moved →
    /// re-fetch + publish `foundTransactions` (replaces the SDK's counter-watch + SyncDone
    /// fallback + count-dedup strategy). The host's own reconcile-FILTER edge (`is_recovering`
    /// flips — visibility policy per API v2 §0) is deliberately NOT folded in here: the filter
    /// is host policy, so its edge is host-observed from the same snapshot.
    /// Monotonic per handle; deliberately NOT reset by [`Self::begin_pass`].
    pub tx_set_version: AtomicU64,
    /// [B4-16 drain] Number of in-flight WALLET-FILE writers owned by the engine — the
    /// write-behind persist lane's deferred commit, a `spawn_blocking` closure that
    /// `task.abort()` CANNOT cancel. Each commit holds a [`WalletWriterGate`] for its
    /// WHOLE life (tree compute + DB transaction); `zcashlc_slipstream_stop`/`_start`
    /// drain on this (bounded) after aborting, so a returned stop means the wallet file
    /// is quiescent. Field-caught 2026-07-04: an orphan commit landed AFTER an
    /// importAccount's force-rescan re-queue (silently shrinking the new account's scan
    /// scope) and collided with the next pass's first writes ("database is locked").
    /// Deliberately NOT reset by [`Self::begin_pass`] — an orphan outlives its pass by
    /// definition.
    pub wallet_writers: AtomicUsize,
    /// The runs of block-download give-ups, one per block, keyed by `at_height` (see
    /// [`Self::note_download_gave_up`]). Deliberately NOT reset by [`Self::begin_pass`]: a run
    /// spans the retried passes it is about. A run ends when a later release covers its block
    /// ([`Self::note_blocks_released`]); every run ends when a pass completes
    /// ([`Self::note_pass_completed`]), a sync attempt fails without its download giving up
    /// ([`Self::note_attempt_failed`]), or a new session begins ([`Self::begin_session`]).
    download_failures: std::sync::Mutex<std::collections::BTreeMap<u64, DownloadFailure>>,
    /// Whether the block download gave up since the last sync attempt ended: set by every
    /// give-up, spent by [`Self::note_attempt_failed`], and cleared by
    /// [`Self::note_pass_completed`] and [`Self::begin_session`].
    download_gave_up_this_attempt: AtomicBool,
}

/// [API v2.1 E-5] Scope-expansion detection margin for the session progress floor: a
/// suggest-round seed this many permille (or more) BELOW the current floor means the scan
/// scope grew (import/rewind), not that progress regressed. See
/// [`Progress::rebaseline_floor_if_scope_expanded`].
pub const FLOOR_REBASELINE_EPSILON_PERMILLE: u64 = 50;

impl Progress {
    /// Bump `fetched_blocks` by `n` (Relaxed — poll-only, no ordering guarantee).
    #[inline]
    pub fn add_fetched(&self, n: u64) {
        self.fetched_blocks.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Bump `scanned_blocks` by `n`.
    #[inline]
    pub fn add_scanned(&self, n: u64) {
        self.scanned_blocks.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Bump `enhanced_txs` by `n`.
    #[inline]
    pub fn add_enhanced(&self, n: u64) {
        self.enhanced_txs.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// Set `chain_tip` (Relaxed store). Stores a VALUE only — callers that just persisted a
    /// freshly-fetched server tip must also call [`Self::note_tip_refreshed`]; the E-3
    /// open-time seed calls this alone (a persisted tip is not proof of freshness).
    #[inline]
    pub fn set_chain_tip(&self, tip: u64) {
        self.chain_tip.store(tip, Ordering::Relaxed);
    }

    /// [API v2.1 E-2] Record that a sync pass successfully persisted a freshly-fetched
    /// server tip (`session.update_chain_tip` returned Ok). Drives the FFI `tip_fresh` fact.
    #[inline]
    pub fn note_tip_refreshed(&self) {
        self.tip_refreshes.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the tip-refresh counter (see [`Self::note_tip_refreshed`]).
    #[inline]
    pub fn tip_refreshes(&self) -> u64 {
        self.tip_refreshes.load(Ordering::Relaxed)
    }

    /// [B4-16 drain] Live count of in-flight engine wallet-file writers (see the
    /// `wallet_writers` field doc). SeqCst pairs with the gate's increments: the drain
    /// loop must never read a stale 0 while a commit is still running.
    #[inline]
    pub fn wallet_writers(&self) -> usize {
        self.wallet_writers.load(Ordering::SeqCst)
    }

    /// [API v2.1 E-4] Record that the wallet's stored transaction set changed (see the
    /// `tx_set_version` field doc for the exact bump sites).
    #[inline]
    pub fn bump_tx_set_version(&self) {
        self.tx_set_version.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Read the tx-set version (see [`Self::bump_tx_set_version`]).
    #[inline]
    pub fn tx_set_version(&self) -> u64 {
        self.tx_set_version.load(Ordering::Relaxed)
    }

    /// Set `current_range_end` (Relaxed store).
    #[inline]
    pub fn set_range_end(&self, end: u64) {
        self.current_range_end.store(end, Ordering::Relaxed);
    }

    /// Bump `reorgs_recovered` by 1.
    #[inline]
    pub fn add_reorg(&self) {
        self.reorgs_recovered.fetch_add(1, Ordering::Relaxed);
    }

    /// Set `pass_total_blocks` to `n` (STORE, not add). Called by the scheduler each
    /// time `suggest_scan_ranges` returns: the new value is `scanned_so_far_in_pass +
    /// sum(block-lengths of all returned ranges)`. Because the scheduler computes the
    /// whole-pass denominator in one shot after every re-suggest, the denominator is
    /// complete from the first suggestion and never causes a % snap-back when Historic
    /// ranges appear. Supersedes the old `add_pass_total` (accumulated per-range),
    /// which caused the 0→100→60% oscillation observed on the user's iPad A10 run.
    #[inline]
    pub fn set_pass_total(&self, n: u64) {
        self.pass_total_blocks.store(n, Ordering::Relaxed);
    }

    /// Deprecated: use `set_pass_total` instead.  Retained for any call sites that
    /// have not yet been updated; calls store (not add) to avoid accumulated-per-range
    /// semantics that caused the % snap-back bug.
    #[inline]
    #[deprecated(
        note = "use set_pass_total (store semantics); add_pass_total (accumulate) caused % snap-back"
    )]
    pub fn add_pass_total(&self, n: u64) {
        // Preserve behaviour for callers that haven't migrated: treat as set.
        self.pass_total_blocks.store(n, Ordering::Relaxed);
    }

    /// Latch `spendable_hint` to 1. Called by the scheduler after a `ChainTip`-priority
    /// range completes scanning (≈ SBS funds-spendable semantics). Never resets within a pass.
    #[inline]
    pub fn set_spendable(&self) {
        self.spendable_hint.store(1, Ordering::Relaxed);
    }

    /// Bump `ranges_completed` by 1. Called by the scheduler after each suggested range's
    /// scan + per-range enhancement completes. Swift observes this counter and triggers a
    /// single balance-summary fetch at each range boundary (F2 — boundary balance refresh).
    ///
    /// Monotonic per HANDLE (deliberately NOT reset by [`Self::begin_pass`]): Swift
    /// detects boundaries via a strict-greater comparison against its last-seen value,
    /// which only works if the counter never moves backwards while the handle lives.
    #[inline]
    pub fn add_ranges_completed(&self) {
        self.ranges_completed.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    // ── API v2 (ENGINE_API_V2.md §4.4) ──

    /// Stamp `last_progress_unix` with the current wall-clock second. Called by every
    /// counter bump, at pass start, whenever server data arrives during a pass, and when a
    /// unit of local work completes (a persisted chunk, the range-end tree build); the
    /// snapshot derives stalledness from it.
    #[inline]
    pub fn touch(&self) {
        let now = unix_now_secs();
        self.last_progress_unix.store(now, Ordering::Relaxed);
    }

    /// Record that the block download gave up: a fetch worker failed (or panicked) and failed
    /// the fetch while `at_height` was the lowest block not yet released to the scanner.
    ///
    /// A failed pass is retried, and its retries show signs of life — a pass start, metadata
    /// answers, scans of new blocks near the tip — so a server that can never deliver a block
    /// range would otherwise keep the stall clock fresh forever, and the host's stall recovery
    /// would never see it.
    ///
    /// There is one run per block. A give-up at `at_height` no more than
    /// [`DOWNLOAD_FAILURE_RUN_GAP_SECS`] after that block's previous one continues its run; a
    /// later one starts the run over. A give-up at any other block starts or continues that
    /// block's own run and never touches this one: scan ranges are not downloaded in height
    /// order (ChainTip, FoundNote and Verify ranges come before Historic ones, and truncation
    /// rewinds), so a give-up at one block says nothing about another. Each run ends when a
    /// later release covers its block ([`Self::note_blocks_released`]), a pass completes
    /// ([`Self::note_pass_completed`]), a sync attempt fails without its download giving up
    /// ([`Self::note_attempt_failed`]), or a new session begins ([`Self::begin_session`]).
    /// Should more than a handful of blocks have runs at once, the one that failed least
    /// recently is dropped.
    pub fn note_download_gave_up(&self, at_height: u64) {
        self.note_download_gave_up_at(at_height, unix_now_secs());
    }

    /// [`Self::note_download_gave_up`] with an explicit clock (tests).
    pub(crate) fn note_download_gave_up_at(&self, at_height: u64, now_unix: u64) {
        let (run, evicted) = {
            let mut runs = self
                .download_failures
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let run = match runs.get(&at_height) {
                Some(run)
                    if now_unix.saturating_sub(run.last_unix) <= DOWNLOAD_FAILURE_RUN_GAP_SECS =>
                {
                    DownloadFailure {
                        streak: run.streak.saturating_add(1),
                        last_unix: now_unix,
                        ..*run
                    }
                }
                _ => DownloadFailure {
                    streak: 1,
                    at_height,
                    since_unix: now_unix,
                    last_unix: now_unix,
                },
            };
            runs.insert(at_height, run);
            let evicted = if runs.len() > MAX_DOWNLOAD_FAILURE_RUNS {
                // The run that failed least recently — never the one just recorded.
                let least_recent = runs
                    .values()
                    .filter(|other| other.at_height != at_height)
                    .min_by_key(|other| other.last_unix)
                    .map(|other| other.at_height);
                least_recent.and_then(|height| runs.remove(&height))
            } else {
                None
            };
            (run, evicted)
        };
        self.download_gave_up_this_attempt
            .store(true, Ordering::SeqCst);
        if run.streak == DOWNLOAD_FAILURE_STALL_STREAK {
            tracing::warn!(
                at_height = run.at_height,
                since_unix = run.since_unix,
                "block download keeps giving up at the same height — stall time counts from its first give-up"
            );
        }
        if let Some(evicted) = evicted {
            tracing::info!(
                streak = evicted.streak,
                at_height = evicted.at_height,
                reason = "least recently failed of too many runs",
                "block download failure run cleared"
            );
        }
    }

    /// A pass completed: the download got past whatever it failed on before, so every run ends.
    pub fn note_pass_completed(&self) {
        self.download_gave_up_this_attempt
            .store(false, Ordering::SeqCst);
        self.clear_download_failures("pass completed");
    }

    /// A new sync session starts (a host start or restart). It gets a fresh count: every run
    /// ends, so the session's first give-up at any block starts a new run instead of extending
    /// one from before the restart.
    pub fn begin_session(&self) {
        self.download_gave_up_this_attempt
            .store(false, Ordering::SeqCst);
        self.clear_download_failures("new session");
    }

    /// A sync attempt failed: a pass, or the tip check between passes. If the block download
    /// gave up during that attempt, the failure is the download's and every run stays.
    /// Otherwise the attempt failed for another reason — typically it could not reach the
    /// server at all, as when the device is offline — so nothing shows the download is still
    /// failing, and every run ends. Without this, a run from before the device went offline
    /// would keep reporting its growing span through every pass that fails before its download
    /// starts.
    pub fn note_attempt_failed(&self) {
        if !self
            .download_gave_up_this_attempt
            .swap(false, Ordering::SeqCst)
        {
            self.clear_download_failures("sync attempt failed without its download giving up");
        }
    }

    /// A fetch handed `first_height..=last_height` to the scanner: every run whose block falls
    /// in that span ends, because the download got past the block it had stopped at. Runs at
    /// other blocks are untouched.
    ///
    /// Without this, a run started in one scan range (say ChainTip) would last through the
    /// hours-long Historic download that follows it in the same pass, and keep counting as a
    /// stall long after its block was delivered. Does nothing when no run's block is in the
    /// span.
    pub fn note_blocks_released(&self, first_height: u64, last_height: u64) {
        if first_height > last_height {
            return;
        }
        let ended: Vec<DownloadFailure> = {
            let mut runs = self
                .download_failures
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let covered: Vec<u64> = runs
                .range(first_height..=last_height)
                .map(|(&height, _)| height)
                .collect();
            covered
                .into_iter()
                .filter_map(|height| runs.remove(&height))
                .collect()
        };
        for run in ended {
            tracing::info!(
                streak = run.streak,
                at_height = run.at_height,
                reason = "download got past it",
                "block download failure run cleared"
            );
        }
    }

    /// Ends every run (see [`Self::note_pass_completed`], [`Self::begin_session`] and
    /// [`Self::note_attempt_failed`]).
    fn clear_download_failures(&self, reason: &str) {
        let cleared = {
            let mut runs = self
                .download_failures
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let cleared = runs.len();
            runs.clear();
            cleared
        };
        if cleared > 0 {
            tracing::info!(
                runs = cleared,
                reason,
                "block download failure runs cleared"
            );
        }
    }

    /// The current runs of block-download give-ups, one per block, in ascending block order.
    pub fn download_failures(&self) -> Vec<DownloadFailure> {
        self.download_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .copied()
            .collect()
    }

    /// Seconds the block download has kept failing at the same block, as of `now_unix`: the
    /// longest time since a run's first give-up, over the live runs — latest give-up at most
    /// [`DOWNLOAD_FAILURE_RUN_GAP_SECS`] old — with at least
    /// [`DOWNLOAD_FAILURE_STALL_STREAK`] give-ups; 0 when no run qualifies. A run that has gone
    /// quiet for longer than the gap no longer counts: the download is not shown to be failing
    /// any more, and its next give-up starts the run over.
    pub fn download_failure_secs(&self, now_unix: u64) -> u64 {
        self.download_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|run| run.streak >= DOWNLOAD_FAILURE_STALL_STREAK)
            .filter(|run| now_unix.saturating_sub(run.last_unix) <= DOWNLOAD_FAILURE_RUN_GAP_SECS)
            .map(|run| now_unix.saturating_sub(run.since_unix))
            .max()
            .unwrap_or(0)
    }

    /// The stall fact as of `now_unix`: the longer of the time since the last progress stamp
    /// (0 before the first stamp) and [`Self::download_failure_secs`]. The FFI snapshot
    /// reports it as `stalled_seconds` while Syncing, and 0 otherwise.
    pub fn stall_secs(&self, now_unix: u64) -> u64 {
        let last = self.last_progress_unix_secs();
        let since_progress = if last == 0 {
            0
        } else {
            now_unix.saturating_sub(last)
        };
        since_progress.max(self.download_failure_secs(now_unix))
    }

    /// Scheduler: set whether the pass is still inside the recovery (restore backfill)
    /// window — i.e. suggested ranges remain below the wallet's recover-until height.
    #[inline]
    pub fn set_recovering(&self, recovering: bool) {
        self.recovering
            .store(u64::from(recovering), Ordering::Relaxed);
    }

    /// Read the live recovering flag (terminal-state forcing happens in the snapshot).
    #[inline]
    pub fn recovering(&self) -> bool {
        self.recovering.load(Ordering::Relaxed) != 0
    }

    /// Read `last_progress_unix`.
    #[inline]
    pub fn last_progress_unix_secs(&self) -> u64 {
        self.last_progress_unix.load(Ordering::Relaxed)
    }

    /// Fold `raw` (0..=1000) into the session-monotonic floor and return the floor.
    /// fetch_max keeps reported progress from ever regressing while the handle lives.
    #[inline]
    pub fn permille_floor(&self, raw: u64) -> u64 {
        let clamped = raw.min(1000);
        self.progress_permille_floor
            .fetch_max(clamped, Ordering::Relaxed);
        self.progress_permille_floor.load(Ordering::Relaxed)
    }

    /// [API v2.1 E-5] When a suggest round's GLOBAL seed lands materially BELOW the current
    /// session floor, the scan SCOPE EXPANDED under the floor's feet — an imported account
    /// with an older birthday, or a rewind re-growing the queue — and the old floor (folded
    /// to ~1000 by the previous scope's Done) would MASK the whole re-scan at ~100%. Reset
    /// the floor to the new truthful seed so the blessed permille reads a genuine climb.
    /// Normal operation can never trigger it: within one scope the seed is monotone (the
    /// queue only shrinks between suggest rounds) and tip drift moves it by <1‰ — the
    /// epsilon is 50× above that noise and far below any real expansion (an import drops
    /// the seed by hundreds of permille). Returns whether a re-baseline happened.
    pub fn rebaseline_floor_if_scope_expanded(&self, seed: u64) -> bool {
        let current = self.progress_permille_floor.load(Ordering::Relaxed);
        if seed.saturating_add(FLOOR_REBASELINE_EPSILON_PERMILLE) < current {
            self.progress_permille_floor
                .store(seed.min(1000), Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Reset the per-pass RATIO counters at the start of a sync pass.
    ///
    /// The FFI handle outlives individual sync passes (Swift `prepare()` opens it once;
    /// `stop()`/`start()` reuse it across app background/foreground cycles), so without
    /// this reset a resumed pass would compute `scanned / pass_total` with a stale
    /// numerator from the previous pass — e.g. 100k stale scanned / 169k remaining
    /// = 59% at pass start, climbing past 100% (clamped) long before the pass is done.
    ///
    /// Resets: `scanned_blocks`, `fetched_blocks`, `pass_total_blocks`,
    /// `current_range_end`, and the `spendable_hint` latch (the new pass's ChainTip
    /// range re-latches it within seconds, mirroring old-SDK per-sync semantics).
    ///
    /// Deliberately NOT reset (monotonic per handle — Swift consumes these as deltas
    /// via strict-greater/last-seen comparisons): `enhanced_txs`, `ranges_completed`,
    /// `reorgs_recovered`. `chain_tip` is overwritten early in every pass anyway.
    pub fn begin_pass(&self) {
        self.scanned_blocks.store(0, Ordering::Relaxed);
        self.fetched_blocks.store(0, Ordering::Relaxed);
        self.pass_total_blocks.store(0, Ordering::Relaxed);
        self.current_range_end.store(0, Ordering::Relaxed);
        self.spendable_hint.store(0, Ordering::Relaxed);
        // v2: a new pass starts the stall clock fresh. `recovering` and the permille
        // floor are deliberately NOT reset — recovering is recomputed on the first
        // suggest round, and the floor is session-monotonic by contract (§4.4).
        self.touch();
    }

    /// Read `chain_tip` (Relaxed load).
    #[inline]
    pub fn chain_tip(&self) -> u64 {
        self.chain_tip.load(Ordering::Relaxed)
    }

    /// Read `fetched_blocks` (Relaxed load).
    #[inline]
    pub fn fetched(&self) -> u64 {
        self.fetched_blocks.load(Ordering::Relaxed)
    }

    /// Read `scanned_blocks` (Relaxed load).
    #[inline]
    pub fn scanned(&self) -> u64 {
        self.scanned_blocks.load(Ordering::Relaxed)
    }

    /// Read `enhanced_txs` (Relaxed load).
    #[inline]
    pub fn enhanced(&self) -> u64 {
        self.enhanced_txs.load(Ordering::Relaxed)
    }

    /// Read `current_range_end` (Relaxed load).
    #[inline]
    pub fn range_end(&self) -> u64 {
        self.current_range_end.load(Ordering::Relaxed)
    }

    /// Read `reorgs_recovered` (Relaxed load).
    #[inline]
    pub fn reorgs(&self) -> u64 {
        self.reorgs_recovered.load(Ordering::Relaxed)
    }

    /// Read `pass_total_blocks` (Relaxed load).
    #[inline]
    pub fn pass_total(&self) -> u64 {
        self.pass_total_blocks.load(Ordering::Relaxed)
    }

    /// Read `spendable_hint` (Relaxed load). Returns 1 when spendable, 0 otherwise.
    #[inline]
    pub fn spendable(&self) -> u64 {
        self.spendable_hint.load(Ordering::Relaxed)
    }

    /// Read `ranges_completed` (Relaxed load).
    #[inline]
    pub fn ranges_completed(&self) -> u64 {
        self.ranges_completed.load(Ordering::Relaxed)
    }
}

/// Convenience alias used throughout the engine.
pub type ProgressArc = Arc<Progress>;

/// [B4-16 drain] RAII writer-gate token: holds `Progress::wallet_writers` +1 for the
/// WHOLE life of an engine wallet-file write (tree compute + DB transaction), so
/// stop()/start() can drain to a quiescent file before the host's next wallet write.
/// Held by the persist lane's deferred-commit closure; releases on completion AND on
/// panic (unwinding runs `Drop` — a stuck counter would make every later stop() spin
/// its full drain bound).
pub struct WalletWriterGate(ProgressArc);

impl WalletWriterGate {
    /// Increment the writer count and hold it until this token drops.
    pub fn hold(progress: ProgressArc) -> Self {
        progress.wallet_writers.fetch_add(1, Ordering::SeqCst);
        Self(progress)
    }
}

impl Drop for WalletWriterGate {
    fn drop(&mut self) {
        self.0.wallet_writers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Which resource currently bounds throughput (honest-ETA reporting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Download,
    Cpu,
    Commit,
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    /// Foreground restore: all cores, large buffers.
    Sprint,
    /// Foreground catch-up.
    Cruise,
    /// Background slice: minimal footprint, checkpoint-eager.
    Drip,
}

/// Point-in-time engine state; cheap to clone out for UI polling.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct Snapshot {
    pub chain_tip: u32,
    pub fully_scanned_height: u32,
    /// 0.0..=1.0 across the whole wallet recovery window.
    pub coverage: f32,
    pub download_bytes_per_sec: u64,
    pub scan_outputs_per_sec: u64,
    pub bound: Option<Bound>,
}

/// Engine lifecycle/progress events, drained by the platform shell.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    Started { mode: SyncMode },
    Progress(Snapshot),
    Finished { fully_scanned_height: u32 },
    Failed { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [B4-16 drain] The gate must count while held and release on BOTH normal drop and
    /// panic-unwind — a stuck counter would make every later stop() spin its full drain
    /// bound instead of returning promptly.
    #[test]
    fn writer_gate_counts_and_releases_on_drop_and_panic() {
        let p: ProgressArc = Arc::new(Progress::default());
        assert_eq!(p.wallet_writers(), 0);
        let gate = WalletWriterGate::hold(p.clone());
        assert_eq!(p.wallet_writers(), 1);
        let nested = WalletWriterGate::hold(p.clone());
        assert_eq!(p.wallet_writers(), 2);
        drop(nested);
        drop(gate);
        assert_eq!(p.wallet_writers(), 0);

        let p2 = p.clone();
        let _ = std::panic::catch_unwind(move || {
            let _gate = WalletWriterGate::hold(p2);
            panic!("commit panicked");
        });
        assert_eq!(p.wallet_writers(), 0, "unwind must release the gate");
    }

    #[test]
    fn snapshot_default_is_idle_zeroes() {
        let s = Snapshot::default();
        assert_eq!(s.coverage, 0.0);
        assert_eq!(s.bound, None);
    }

    #[test]
    fn progress_counters_bump_and_read() {
        let p = Progress::default();

        // Initial state: all zeros.
        assert_eq!(p.chain_tip(), 0);
        assert_eq!(p.fetched(), 0);
        assert_eq!(p.scanned(), 0);
        assert_eq!(p.enhanced(), 0);
        assert_eq!(p.range_end(), 0);
        assert_eq!(p.reorgs(), 0);
        assert_eq!(p.pass_total(), 0);
        assert_eq!(p.spendable(), 0);
        assert_eq!(p.ranges_completed(), 0);

        // Set helpers.
        p.set_chain_tip(3_373_435);
        assert_eq!(p.chain_tip(), 3_373_435);

        p.set_range_end(3_323_500);
        assert_eq!(p.range_end(), 3_323_500);

        // Additive helpers.
        p.add_fetched(1_000);
        p.add_fetched(500);
        assert_eq!(p.fetched(), 1_500);

        p.add_scanned(800);
        assert_eq!(p.scanned(), 800);

        p.add_enhanced(3);
        assert_eq!(p.enhanced(), 3);

        p.add_reorg();
        p.add_reorg();
        assert_eq!(p.reorgs(), 2);
    }

    #[test]
    fn progress_pass_total_and_spendable_hint() {
        let p = Progress::default();

        // Initial state: both zero.
        assert_eq!(p.pass_total(), 0);
        assert_eq!(p.spendable(), 0);

        // set_pass_total stores (not accumulates) — F1 whole-pass denominator fix.
        // First suggest: scanned_so_far=0, sum_of_ranges=15_000 → store 15_000.
        p.set_pass_total(15_000);
        assert_eq!(p.pass_total(), 15_000);
        // Re-suggest after first range (scanned_so_far=10_000 + remaining 5_000) → still 15_000.
        p.set_pass_total(15_000);
        assert_eq!(
            p.pass_total(),
            15_000,
            "re-suggest with same total stays stable"
        );
        // Re-suggest exposes more ranges: new total = 20_000 → store overwrites.
        p.set_pass_total(20_000);
        assert_eq!(
            p.pass_total(),
            20_000,
            "set_pass_total must overwrite, not add"
        );

        // spendable latches to 1 and stays there.
        assert_eq!(p.spendable(), 0, "not yet spendable before set_spendable()");
        p.set_spendable();
        assert_eq!(
            p.spendable(),
            1,
            "spendable must be 1 after set_spendable()"
        );
        p.set_spendable(); // idempotent
        assert_eq!(p.spendable(), 1, "set_spendable is idempotent");
    }

    #[test]
    fn pass_total_is_whole_pass() {
        // Simulates the F1 scheduler logic:
        //   - suggest returns [ChainTip(100), Historic(200)] → total = 0+100+200 = 300
        //   - after scanning ChainTip (100 blocks), re-suggest returns [Historic(200)]
        //     → scanned_so_far = 100, remaining = 200 → total = 100+200 = 300 (unchanged)
        //   - after scanning Historic (200 blocks), queue empty → done.
        // The denominator must be 300 throughout — no snap-back.
        let p = Progress::default();

        // First suggest: 0 scanned + 100 (ChainTip) + 200 (Historic) = 300.
        p.set_pass_total(300);
        assert_eq!(
            p.pass_total(),
            300,
            "whole-pass denominator set on first suggest"
        );

        // Scan ChainTip range.
        p.add_scanned(100);

        // Re-suggest: 100 scanned + 200 remaining = 300 → same value; store is idempotent.
        p.set_pass_total(300);
        assert_eq!(
            p.pass_total(),
            300,
            "denominator stays 300 after re-suggest"
        );

        // At this point, progress = 100/300 ≈ 33.3% — no 100→60% snap-back.
        let ratio = p.scanned() as f64 / p.pass_total() as f64;
        assert!(
            (ratio - 1.0 / 3.0).abs() < 1e-9,
            "progress must be ~33.3% mid-pass"
        );

        // Scan Historic range.
        p.add_scanned(200);
        let final_ratio = p.scanned() as f64 / p.pass_total() as f64;
        assert!(
            (final_ratio - 1.0).abs() < 1e-9,
            "progress must be 100% when all ranges done"
        );
    }

    #[test]
    fn counter_progress_ratio() {
        // scanned / max(pass_total, 1) is used in Swift tickPoll.
        // Mirror the formula here to verify the Rust side provides the right inputs.
        let p = Progress::default();
        p.set_pass_total(10_000);
        p.add_scanned(5_000);

        let ratio = p.scanned() as f64 / p.pass_total().max(1) as f64;
        assert!((ratio - 0.5).abs() < 1e-9, "5000/10000 must be 0.5");

        // pass_total == 0 edge: denominator is max(0, 1) = 1 → ratio = 0.
        let p2 = Progress::default();
        let ratio2 = p2.scanned() as f64 / p2.pass_total().max(1) as f64;
        assert_eq!(ratio2, 0.0, "0 scanned / 1 (clamped) must be 0.0");
    }

    #[test]
    fn ranges_completed_increments() {
        let p = Progress::default();
        assert_eq!(p.ranges_completed(), 0, "initial value must be 0");

        p.add_ranges_completed();
        assert_eq!(p.ranges_completed(), 1, "must be 1 after first range");

        p.add_ranges_completed();
        assert_eq!(p.ranges_completed(), 2, "must be 2 after second range");

        // Monotonic: never resets to 0 within a pass.
        for _ in 0..10 {
            p.add_ranges_completed();
        }
        assert_eq!(
            p.ranges_completed(),
            12,
            "must accumulate across all ranges"
        );
    }

    #[test]
    fn progress_arc_shared_across_threads() {
        use std::sync::Arc;
        use std::thread;

        let p = Arc::new(Progress::default());
        let p2 = Arc::clone(&p);

        let handle = thread::spawn(move || {
            p2.add_fetched(42);
        });
        handle.join().expect("thread panicked");

        // Our thread adds 10; the spawned thread adds 42: total = 52.
        p.add_fetched(10);
        assert_eq!(p.fetched_blocks.load(Ordering::Relaxed), 52);
    }

    /// begin_pass resets the per-pass RATIO counters but preserves the monotonic
    /// delta counters Swift consumes via last-seen comparisons. Simulates an
    /// interrupted pass followed by a resume on the SAME handle (Swift prepare()
    /// opens once; stop()/start() reuse the handle).
    #[test]
    fn begin_pass_resets_ratio_counters_only() {
        let p = Progress::default();

        // Pass 1: interrupted mid-restore.
        p.set_chain_tip(3_374_188);
        p.add_fetched(120_000);
        p.add_scanned(100_000);
        p.set_pass_total(269_188);
        p.set_range_end(3_321_165);
        p.set_spendable();
        p.add_enhanced(20);
        p.add_ranges_completed();
        p.add_reorg();
        p.note_tip_refreshed();
        p.bump_tx_set_version();
        p.bump_tx_set_version();

        // Pass 2 begins (app foregrounded, start() on the same handle).
        p.begin_pass();

        // Ratio counters reset: scanned/pass_total must start at 0/0, not 100k/0.
        assert_eq!(p.scanned(), 0, "scanned must reset per pass");
        assert_eq!(p.fetched(), 0, "fetched must reset per pass");
        assert_eq!(p.pass_total(), 0, "pass_total must reset per pass");
        assert_eq!(p.range_end(), 0, "range_end must reset per pass");
        assert_eq!(p.spendable(), 0, "spendable latch re-arms each pass");

        // Monotonic delta counters preserved (Swift compares strict-greater).
        assert_eq!(p.enhanced(), 20, "enhanced_txs is monotonic per handle");
        assert_eq!(
            p.ranges_completed(),
            1,
            "ranges_completed is monotonic per handle"
        );
        assert_eq!(p.reorgs(), 1, "reorgs_recovered is cumulative diagnostics");
        assert_eq!(
            p.chain_tip(),
            3_374_188,
            "chain_tip is overwritten by the new pass anyway"
        );
        // [E-2/E-4] The freshness and tx-set counters are per-handle facts, not pass ratios.
        assert_eq!(
            p.tip_refreshes(),
            1,
            "tip_refreshes is monotonic per handle"
        );
        assert_eq!(
            p.tx_set_version(),
            2,
            "tx_set_version is monotonic per handle"
        );
    }

    /// [API v2.1 E-5] The floor re-baselines when the scope EXPANDS (seed materially below
    /// the floor — import/rewind) and stays monotone against within-scope noise.
    #[test]
    fn floor_rebaseline_on_scope_expansion_only() {
        let p = Progress::default();
        assert_eq!(p.permille_floor(990), 990);
        // Within-scope drift up to the epsilon never re-baselines (tip drift is <1‰).
        assert!(
            !p.rebaseline_floor_if_scope_expanded(989),
            "1‰ dip is noise"
        );
        assert!(
            !p.rebaseline_floor_if_scope_expanded(990 - FLOOR_REBASELINE_EPSILON_PERMILLE),
            "exactly-epsilon dip is still within scope"
        );
        assert_eq!(p.permille_floor(0), 990, "floor held through noise");
        // Import with an older birthday: the seed plummets → re-baseline to the truth.
        assert!(
            p.rebaseline_floor_if_scope_expanded(120),
            "material drop = scope expansion"
        );
        assert_eq!(
            p.permille_floor(0),
            120,
            "floor re-baselined to the expanded-scope seed"
        );
        // …and climbs monotonically again within the new scope.
        assert_eq!(p.permille_floor(300), 300);
    }

    // ── download-failure runs (the repeated-give-up stall span) ──────────────────

    /// A run as [`Progress::download_failures`] reports it.
    fn run(streak: u32, at_height: u64, since_unix: u64, last_unix: u64) -> DownloadFailure {
        DownloadFailure {
            streak,
            at_height,
            since_unix,
            last_unix,
        }
    }

    #[test]
    fn a_give_up_at_the_same_block_within_the_gap_continues_its_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        p.note_download_gave_up_at(100, 1_020);
        assert_eq!(
            p.download_failures(),
            vec![run(3, 100, 1_000, 1_020)],
            "the streak goes up; the run keeps its block and its first give-up"
        );
    }

    #[test]
    fn a_give_up_at_a_different_block_starts_its_own_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        p.note_download_gave_up_at(150, 1_500);
        p.note_download_gave_up_at(90, 1_600);
        assert_eq!(
            p.download_failures(),
            vec![
                run(1, 90, 1_600, 1_600),
                run(2, 100, 1_000, 1_010),
                run(1, 150, 1_500, 1_500),
            ],
            "a block above and a block below each start their own run; block 100's is untouched"
        );
    }

    /// Scan ranges are not downloaded in height order, so the retried passes can also give up
    /// at other blocks in between: a block stuck at H keeps its run through them, and the span
    /// counts from H's first give-up.
    #[test]
    fn a_stuck_block_keeps_its_run_while_give_ups_elsewhere_interleave() {
        let p = Progress::default();
        p.note_download_gave_up_at(500, 1_000); // H
        p.note_download_gave_up_at(900, 1_100); // T
        p.note_download_gave_up_at(500, 1_200); // H
        p.note_download_gave_up_at(900, 1_300); // T
        assert_eq!(
            p.download_failures(),
            vec![run(2, 500, 1_000, 1_200), run(2, 900, 1_100, 1_300)]
        );
        assert_eq!(
            p.download_failure_secs(1_400),
            400,
            "counted from H's first give-up"
        );
    }

    /// Same-block give-ups far apart are separate runs: in between, the download was not failing
    /// there (for example, a synced wallet sitting idle between catch-up passes, or the engine
    /// busy downloading other ranges).
    #[test]
    fn a_same_block_give_up_after_the_gap_starts_the_run_over() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        p.note_download_gave_up_at(100, 1_010 + DOWNLOAD_FAILURE_RUN_GAP_SECS + 1);
        assert_eq!(p.download_failures(), vec![run(1, 100, 1_611, 1_611)]);
        assert_eq!(
            p.download_failure_secs(2_000),
            0,
            "a run that starts over needs its second give-up again"
        );
    }

    #[test]
    fn a_same_block_give_up_exactly_the_gap_later_continues_the_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_000 + DOWNLOAD_FAILURE_RUN_GAP_SECS);
        assert_eq!(p.download_failures(), vec![run(2, 100, 1_000, 1_600)]);
    }

    #[test]
    fn download_failure_counts_only_from_the_second_give_up() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        assert_eq!(
            p.download_failure_secs(1_300),
            0,
            "one give-up: the engine's own retry gets its chance"
        );
        p.note_download_gave_up_at(100, 1_050);
        assert_eq!(
            p.download_failure_secs(1_300),
            300,
            "counted from the FIRST give-up of the run"
        );
    }

    #[test]
    fn download_failure_secs_is_the_longest_of_the_qualifying_runs() {
        let p = Progress::default();
        p.note_download_gave_up_at(300, 900); // the oldest run, but a single give-up
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(200, 1_200);
        p.note_download_gave_up_at(100, 1_500); // still live at 2_000: within the gap
        p.note_download_gave_up_at(200, 1_600); // still live at 2_000: within the gap
        assert_eq!(
            p.download_failure_secs(2_000),
            1_000,
            "block 100's run is the longest of those with two give-ups"
        );
    }

    #[test]
    fn a_completed_pass_or_a_new_session_clears_every_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        p.note_download_gave_up_at(200, 1_020);
        p.note_pass_completed();
        assert_eq!(p.download_failures(), vec![]);
        assert_eq!(p.download_failure_secs(2_000), 0);

        p.note_download_gave_up_at(100, 3_000);
        p.note_download_gave_up_at(100, 3_010);
        p.note_download_gave_up_at(200, 3_020);
        p.begin_session();
        assert_eq!(p.download_failures(), vec![]);
        assert_eq!(p.download_failure_secs(4_000), 0);
    }

    #[test]
    fn pass_starts_touches_and_counters_leave_the_runs_alone() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        p.begin_pass();
        p.touch();
        p.add_scanned(5);
        p.add_ranges_completed();
        assert_eq!(
            p.download_failures(),
            vec![run(2, 100, 1_000, 1_010)],
            "a pass start, a stamp or a counter never ends a run"
        );
    }

    #[test]
    fn stall_secs_is_the_longer_of_the_two_spans() {
        let p = Progress::default();
        assert_eq!(
            p.stall_secs(5_000),
            0,
            "no stamp and no run: nothing to report"
        );
        p.last_progress_unix.store(1_000, Ordering::Relaxed);
        assert_eq!(
            p.stall_secs(1_100),
            100,
            "no run: the time since the last stamp"
        );
        p.note_download_gave_up_at(100, 900);
        p.note_download_gave_up_at(100, 950);
        p.last_progress_unix.store(1_090, Ordering::Relaxed);
        assert_eq!(
            p.stall_secs(1_100),
            200,
            "a fresh stamp must not hide a download that keeps failing"
        );
    }

    /// Runs normally hold only the block or two the download is stuck on, but they are bounded:
    /// a ninth block evicts the run that failed least recently, whatever its height.
    #[test]
    fn a_ninth_block_evicts_the_least_recently_failed_run() {
        let p = Progress::default();
        for (i, height) in (100..=800).step_by(100).enumerate() {
            p.note_download_gave_up_at(height, 1_000 + 10 * i as u64);
        }
        // Block 100 fails again, so block 200 (last failed at 1_010) is now the least recent.
        p.note_download_gave_up_at(100, 1_080);
        p.note_download_gave_up_at(900, 1_090);
        let runs = p.download_failures();
        assert_eq!(
            runs.iter().map(|run| run.at_height).collect::<Vec<_>>(),
            vec![100, 300, 400, 500, 600, 700, 800, 900],
            "block 200's run is the one evicted"
        );
        assert_eq!(
            runs[0],
            run(2, 100, 1_000, 1_080),
            "the survivors keep their runs"
        );
    }

    // ── note_blocks_released: a run also ends when a release covers its block ──

    #[test]
    fn a_release_ends_only_the_run_whose_block_it_covers() {
        let p = Progress::default();
        p.note_download_gave_up_at(300, 1_000);
        p.note_download_gave_up_at(300, 1_010);
        p.note_download_gave_up_at(105, 1_020);
        p.note_download_gave_up_at(105, 1_030);
        p.note_blocks_released(100, 110);
        assert_eq!(
            p.download_failures(),
            vec![run(2, 300, 1_000, 1_010)],
            "the release got past block 105, not block 300"
        );
    }

    #[test]
    fn a_release_covering_several_runs_ends_them_all() {
        let p = Progress::default();
        for height in [99, 100, 107, 110, 111] {
            p.note_download_gave_up_at(height, 1_000);
        }
        p.note_blocks_released(100, 110);
        assert_eq!(
            p.download_failures()
                .iter()
                .map(|run| run.at_height)
                .collect::<Vec<_>>(),
            vec![99, 111],
            "every run from block 100 through block 110 ends; blocks 99 and 111 were not released"
        );
    }

    #[test]
    fn a_release_that_does_not_cover_a_runs_block_keeps_it() {
        let p = Progress::default();
        p.note_download_gave_up_at(105, 1_000);
        p.note_download_gave_up_at(105, 1_010);
        p.note_blocks_released(50, 99);
        p.note_blocks_released(110, 100); // a reversed span covers nothing
        assert_eq!(
            p.download_failures(),
            vec![run(2, 105, 1_000, 1_010)],
            "a release that never reaches the run's block must not end it"
        );
    }

    /// A give-up in the ChainTip range starts a run, and the retried pass re-fetches that range
    /// successfully, so the run ends right there instead of lingering through the Historic
    /// download that follows. A later give-up at a lower block (Historic ranges lie behind
    /// ChainTip) is a different problem and starts a fresh run of its own.
    #[test]
    fn a_give_up_after_the_run_ended_starts_a_fresh_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(1_003, 1_000);
        p.note_blocks_released(1_000, 1_010);
        p.note_download_gave_up_at(900, 5_000);
        assert_eq!(
            p.download_failures(),
            vec![run(1, 900, 5_000, 5_000)],
            "the ended run must not linger beside the new one"
        );
    }

    // ── live runs and failed sync attempts ───────────────────────────────────

    #[test]
    fn a_run_stops_counting_once_its_latest_give_up_is_older_than_the_gap() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        assert_eq!(
            p.download_failure_secs(1_010 + DOWNLOAD_FAILURE_RUN_GAP_SECS),
            10 + DOWNLOAD_FAILURE_RUN_GAP_SECS,
            "still live at exactly the gap"
        );
        assert_eq!(
            p.download_failure_secs(1_010 + DOWNLOAD_FAILURE_RUN_GAP_SECS + 1),
            0,
            "no give-up for longer than the gap: the run no longer counts"
        );
    }

    /// Two give-ups, then nothing more for longer than the gap while the engine keeps showing
    /// signs of life: the stall fact is only the time since the latest progress stamp, however
    /// old the run's first give-up is.
    #[test]
    fn an_inactive_run_does_not_hide_a_fresh_progress_stamp() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(100, 1_010);
        let now = 1_010 + DOWNLOAD_FAILURE_RUN_GAP_SECS + 1;
        p.last_progress_unix.store(now - 5, Ordering::Relaxed);
        assert_eq!(p.stall_secs(now), 5);
    }

    #[test]
    fn an_attempt_that_failed_without_a_give_up_ends_every_run() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_download_gave_up_at(200, 1_005);
        p.note_attempt_failed(); // the attempt that gave up
        assert_eq!(
            p.download_failures().len(),
            2,
            "an attempt that failed because the download gave up keeps every run"
        );
        p.note_attempt_failed(); // an attempt that failed without giving up
        assert!(
            p.download_failures().is_empty(),
            "an attempt that failed without its download giving up ends every run"
        );
    }

    #[test]
    fn each_attempt_that_gave_up_keeps_the_run_going() {
        let p = Progress::default();
        p.note_download_gave_up_at(100, 1_000);
        p.note_attempt_failed();
        p.note_download_gave_up_at(100, 1_020);
        p.note_attempt_failed();
        assert_eq!(
            p.download_failures().first().map(|run| run.streak),
            Some(2),
            "every failed attempt gave up at the block: the run continues"
        );
        p.note_attempt_failed();
        assert!(
            p.download_failures().is_empty(),
            "the give-up was spent by the attempt before; this one failed without one"
        );
    }
}
