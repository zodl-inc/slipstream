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

//! Scheduler v0: drive the wallet's own scan-queue (decision D3 — the coverage
//! ledger IS data.db's suggested ranges). For each suggested range, run the
//! fetch∥scan pipeline; re-suggest after each range until the queue is empty.
//! Priority handling (Verify-first) comes for free: suggest_scan_ranges returns
//! Verify ranges first by upstream contract.

use std::{collections::HashSet, sync::Arc, time::Duration};

use tracing::{debug, info, warn};
use zcash_client_backend::data_api::scanning::ScanPriority;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    chunk::chunk_queue,
    config::EngineConfig,
    connector::TorConn,
    enhance::{EnhanceStats, enhancement_connection, run_enhancement_lazily_isolated},
    error::SlipstreamError,
    events::{PASS_UNIT_BLOCKS, PASS_UNIT_WORK, Progress},
    fetch::{FetchPlan, FetchStats, run_fetch},
    scan::{ScanStats, local_treestate_active, needs_server_boundary_state, scan_chunks},
    wallet_session::WalletSession,
};

/// Maximum number of consecutive reorg recoveries before giving up.
/// After this many back-to-back ScanContinuity errors without a successful
/// range completion, run_to_completion returns the error to break ping-pong.
const MAX_CONSECUTIVE_REORGS: u64 = 5;

// Compile-time bounds: ≥1 (otherwise the first reorg is never recovered) and
// ≤10 (otherwise infinite ping-pong is possible). Fails the build if violated.
const _: () = {
    assert!(MAX_CONSECUTIVE_REORGS >= 1);
    assert!(MAX_CONSECUTIVE_REORGS <= 10);
};

/// B3 (#1755 failure-path hardening): backoff before re-suggesting after a reorg
/// truncate, growing with the consecutive-recovery count.
///
/// Rationale: a tip-desync across a load-balanced lightwalletd cluster (zec.rocks /
/// eu.zec.rocks terminate one hostname on several backends) heals within seconds —
/// but instant retries can burn the whole MAX_CONSECUTIVE_REORGS budget against the
/// same momentarily-stale view, failing a multi-minute restore for a transient
/// condition (field failure 1 candidate trigger, 2026-06-12). Deterministic growth:
/// 500 ms × consecutive, capped at 3 s — total worst-case added latency across the
/// 5-recovery budget is 500+1000+1500+2000+2500 = 7.5 s, negligible vs a restore.
pub(crate) fn reorg_backoff_ms(consecutive: u64) -> u64 {
    consecutive.saturating_mul(500).min(3_000)
}

/// [API v2 §4.4 / Phase E] The wallet's GLOBAL scan position in permille: how much of
/// `[birthday, tip]` is NOT in the remaining scan queue. Seeds the session-monotonic
/// permille floor so the blessed progress never reads pass-local on a fresh handle —
/// the raw pass ratio would flash a 99.9%-synced wallet's UI to ~0% on every cold-launch
/// catch-up (the SDK used to mask this with its own summary-derived floor; this is that
/// floor's engine-owned successor). `None` when the inputs cannot express a position
/// (no tip advertised yet, no accounts, or a tip below the birthday).
pub(crate) fn global_floor_permille(
    tip: u64,
    birthday: Option<u64>,
    remaining: u64,
) -> Option<u64> {
    let birthday = birthday?;
    if tip == 0 || tip < birthday {
        return None;
    }
    let span = tip - birthday + 1;
    let scanned = span.saturating_sub(remaining);
    Some(scanned.saturating_mul(1000) / span)
}

/// B4: Work-unit variant of `global_floor_permille`. When a WorkEstimator is available,
/// the GLOBAL scan position is computed from work units instead of block counts:
/// `(total_span_work - remaining_work) * 1000 / total_span_work`.
pub(crate) fn global_floor_permille_work(
    tip: u64,
    birthday: Option<u64>,
    remaining_work: u64,
    estimator: &crate::work::WorkEstimator,
) -> Option<u64> {
    let birthday = birthday?;
    if tip == 0 || tip < birthday {
        return None;
    }
    let total_work = estimator.range(birthday, tip);
    if total_work == 0 {
        // Empty range or estimator has no data - fall back to None
        return None;
    }
    let scanned_work = total_work.saturating_sub(remaining_work);
    Some(scanned_work.saturating_mul(1000) / total_work)
}

/// Estimated work of the suggested ranges (`block_range().end` is END-EXCLUSIVE, so each
/// range covers `start..=end − 1`).
pub(crate) fn remaining_work(
    est: &crate::work::WorkEstimator,
    ranges: &[zcash_client_backend::data_api::scanning::ScanRange],
) -> u64 {
    ranges
        .iter()
        .map(|r| {
            let s = u64::from(r.block_range().start);
            let e = u64::from(r.block_range().end);
            if e > s { est.range(s, e - 1) } else { 0 }
        })
        .sum()
}

/// [h16-1] One suggest round's progress bookkeeping: set the pass total and seed/re-baseline
/// the session floor + pass start from the GLOBAL seed. Extracted from the `run_to_completion`
/// loop body (behaviour unchanged by the extraction itself) so it can be driven directly in
/// tests without a live fetch/scan pass — everything here is scheduler bookkeeping over
/// already-known pending ranges, no network I/O. Reads `p.chain_tip()` live, like the inline
/// block it replaces. Returns whether this round re-baselined the session floor (test hook;
/// `run_to_completion` ignores it).
pub(crate) fn update_pass_progress(
    p: &Progress,
    scanned_so_far_in_pass: &mut u64,
    pending: &[std::ops::Range<u64>],
    wallet_birthday: Option<u64>,
    scanned_work_so_far_in_pass: &mut u64,
    sum_remaining_work: u64,
    work_estimator: Option<&crate::work::WorkEstimator>,
) -> bool {
    let sum_remaining = pending.iter().fold(0u64, |sum, r| {
        sum.saturating_add(r.end.saturating_sub(r.start))
    });
    // [h16-1] Snapshot the pass-local blend baseline BEFORE the pass total is set: from
    // this moment, `derive_snapshot` reads `fetched()`/`scanned()` relative to this
    // baseline instead of raw, so blocks already credited to `scanned_so_far_in_pass`
    // (this pass's completed-range tally) are not counted a second time against the new
    // total. At this instant the pass-local counters equal the work the pass has credited.
    // The block fields are kept in every pass, also one measured in work: they are the
    // fallback `derive_snapshot` uses when the work total is 0, and the snapshot's own
    // `pass_total_blocks`.
    p.set_pass_baseline(
        p.fetched().saturating_sub(*scanned_so_far_in_pass),
        p.scanned().saturating_sub(*scanned_so_far_in_pass),
    );
    p.set_pass_total(*scanned_so_far_in_pass + sum_remaining);
    // Output-weighted progress: the same bookkeeping in work units. The pass's FIRST suggest
    // round fixes the unit (work when the estimator can express the global position), and
    // every later round of the pass keeps it.
    let work_seed = work_estimator.and_then(|est| {
        global_floor_permille_work(p.chain_tip(), wallet_birthday, sum_remaining_work, est)
    });
    let use_work = p.fix_pass_unit(work_seed.is_some());
    if !use_work && p.floor_unit() == crate::events::PASS_UNIT_WORK {
        // The floor is in work units and this pass reports blocks (the estimator could not be
        // read): a block seed never lowers a work floor, so an expansion of the scope in this
        // pass (an imported older account) is not shown until the next pass.
        tracing::warn!(
            "work estimator unavailable: scope-expansion detection is off for this pass"
        );
    }
    if use_work {
        // Mirror of the block baseline above: baseline = counter − credited work so far,
        // total = credited work so far + remaining work.
        p.set_pass_baseline_work(
            p.fetched_work()
                .saturating_sub(*scanned_work_so_far_in_pass),
            p.scanned_work()
                .saturating_sub(*scanned_work_so_far_in_pass),
        );
        p.set_pass_total_work(*scanned_work_so_far_in_pass + sum_remaining_work);
    }
    // [API v2 §4.4 / Phase E] Seed the session-monotonic floor with the GLOBAL position.
    // fetch_max semantics: the seed can only RAISE the floor, and re-seeding every suggest
    // round tracks global progress as ranges complete. Two behaviours fall out for free:
    // a cold-launch catch-up starts at ~99.9% instead of flashing 0% (the old Swift
    // summary floor), and a relaunched restore RESUMES near its true position instead of
    // 0% (the old Swift monotonic floor could not survive a relaunch). The seed is in the
    // pass's unit.
    let seed = if use_work {
        work_seed
    } else {
        global_floor_permille(p.chain_tip(), wallet_birthday, sum_remaining)
    };
    let Some(seed) = seed else {
        return false;
    };
    // [API v2.1 E-5] Scope-expansion re-baseline: an imported account with an
    // older birthday (or a rewind) grows the span under the session floor —
    // without this, the ~1000 floor from the previous scope's Done would mask
    // the whole re-scan at ~100% (the host used to bypass every floor with
    // `forceCounterProgressUntilDone`; the blessed permille now reads the
    // genuine climb by itself).
    //
    // [h17-1] Decide with the PURE read (`Progress::scope_expanded`) first. When the numeric
    // gap qualifies and scope evidence permits it, publish the re-baselined pass — baseline,
    // total, then start — and only THEN lower the floor, last. `derive_snapshot` can run on
    // another thread at any instant while this function is mid-flight, folding its reads into the
    // floor with `fetch_max`, so every intermediate combination of fields it can observe here
    // must compute a raw value AT MOST the floor the OLD scope already published, or that
    // stale-but-too-high reading gets latched permanently (fetch_max never lowers):
    //   - before `set_pass_start_permille` below: a poll reads the OLD start together with
    //     the NEW baseline/total — a ZERO pass-local count — so raw is the old start alone,
    //     which the floor already holds (that start was itself seeded through the floor
    //     earlier).
    //   - after it, before the floor call: a poll reads the NEW (lower) seed as the start,
    //     still with a zero pass-local count — raw is the new seed alone, below the floor
    //     the OLD scope holds (that gap below the floor is exactly what "expanded" means).
    // Neither window can produce a raw value above the old floor, so nothing above it gets
    // latched. Lowering the floor first, or moving the start before the baseline/total (the
    // two orders this replaces), each open a window where a poll mixes a low/new field with
    // high/old ones and computes a raw value ABOVE the floor at that instant — that mixed,
    // double-counted read is the bug fixed here (confirmed against this exact seed/credit
    // combination in scheduler::tests::rebaseline_old_order_used_to_latch_a_double_counted_697).
    //
    // Compute the seed's unit for scope-expansion detection.
    let unit = if use_work {
        PASS_UNIT_WORK
    } else {
        PASS_UNIT_BLOCKS
    };

    // Estimator/exact-credit gaps alone never justify lowering a retained WORK floor.
    let lower_bound = if use_work {
        wallet_birthday
            .zip(work_estimator)
            .map(|(birthday, est)| p.work_scope_lower_bound(birthday, pending, est))
    } else {
        None
    };
    let correction_seed = if use_work && p.floor_unit() == PASS_UNIT_WORK {
        seed.max(lower_bound.unwrap_or_else(|| {
            p.progress_permille_floor
                .load(std::sync::atomic::Ordering::Relaxed)
        }))
    } else {
        seed
    };
    if p.scope_expanded(correction_seed, unit) {
        // [h16-1] The new start already includes everything credited so far: fold the
        // pass-local accumulator back to 0 and re-snapshot the baseline to the CURRENT
        // counters, so the next blend reads 0 pass-local progress against the fresh
        // `sum_remaining`-only total below, instead of replaying the pre-expansion
        // credit a second time against the new (smaller, re-baselined) denominator.
        *scanned_so_far_in_pass = 0;
        p.set_pass_baseline(p.fetched(), p.scanned());
        p.set_pass_total(sum_remaining);
        *scanned_work_so_far_in_pass = 0;
        if use_work {
            p.set_pass_baseline_work(p.fetched_work(), p.scanned_work());
            p.set_pass_total_work(sum_remaining_work);
        }
        // [h10] The pass start follows the re-baseline: the scope grew UNDER
        // this running pass, so the pass's own progress must stretch from the
        // re-baselined position too, or it would still stretch from the stale
        // pre-expansion start and under-report the re-scan's climb.
        p.set_pass_start_permille(correction_seed);
        // [h17-1] Lower the floor LAST, now that the rest of the re-baselined pass is fully
        // published (see above). `scope_expanded` and this call share exactly one condition
        // (it calls that method) and the floor only ever RISES in between — and, per the
        // invariant above, nothing a concurrent poll can fetch_max it with in this window
        // exceeds the floor this call is about to compare `seed` against — so this re-check
        // is guaranteed to still see the expansion.
        let rebaselined = p.rebaseline_floor_if_scope_expanded(correction_seed, unit);
        debug_assert!(
            rebaselined,
            "scope_expanded just reported an expansion and nothing between here and there \
             can raise the floor above what it already held, so the re-check cannot flip"
        );
        if use_work && rebaselined {
            p.acknowledge_work_scope(correction_seed);
        }
        info!(
            seed = correction_seed,
            birthday = wallet_birthday,
            "scan scope expanded — session progress floor re-baselined (re-scan reads as a genuine climb)"
        );
        rebaselined
    } else {
        // [h10] First suggest round of the pass latches the start; later rounds
        // of the same pass keep it — the pass's reported progress is measured
        // from where the GLOBAL position stood when the pass began.
        p.set_pass_start_permille_if_unset(seed);
        let floor = p.permille_floor(seed, unit);
        if use_work && seed >= floor {
            p.acknowledge_work_scope(floor);
        }
        false
    }
}

/// Carry a successful rewind boundary into the lifetime correction bound.
fn record_continuity_scope(p: &Progress, at: u64) {
    // Completion evidence comes only from successful persistence. Scan counters
    // can include unsubmitted work, so a rewind never promotes them to completion.
    p.note_work_rewind(at.saturating_sub(10)..p.chain_tip().saturating_add(1));
}

/// [h16-2] How much of an aborted range's work survives a `ScanContinuity` truncate: the
/// span below `rewind_height` (clamped to the aborted range's own bounds), which the
/// truncate does NOT discard. The ScanContinuity branch (`run_to_completion`) credits this
/// to `scanned_so_far_in_pass` right after the truncate, so the next suggest round's
/// baseline snapshot (h16-1) folds it in — without this, `pass_total` would cover only the
/// small repair range while `fetched`/`scanned` still held the whole aborted range, so the
/// blend would read the still-in-flight repair as already done.
pub(crate) fn scan_continuity_repair_credit(
    start: u64,
    end_exclusive: u64,
    rewind_height: u64,
) -> u64 {
    rewind_height
        .saturating_sub(start)
        .min(end_exclusive.saturating_sub(start))
}

/// B3: Work-unit variant of `scan_continuity_repair_credit`. Returns the work units
/// in the surviving prefix `[start, rewind_height-1]`, clamped to the aborted range's bounds.
/// The ScanContinuity branch credits this to `scanned_work_so_far_in_pass` so the next
/// suggest round's baseline snapshot accounts for it.
pub(crate) fn scan_continuity_work_credit(
    est: &crate::work::WorkEstimator,
    start: u64,
    end_exclusive: u64,
    rewind_height: u64,
) -> u64 {
    if rewind_height <= start {
        return 0;
    }
    // The surviving prefix is [start, rewind_height-1], clamped to [start, end_exclusive-1].
    let prefix_end = (rewind_height - 1).min(end_exclusive.saturating_sub(1));
    est.range(start, prefix_end)
}

/// [API v2.1 E-3] Seed the snapshot atomics from PERSISTED wallet state, so the snapshot is
/// truthful from `open()` — before the first suggest round — and hosts never compensate for
/// a pre-pass snapshot that "lies" (the ENGINE_API_V2.md §0 known gap: `is_recovering` read
/// 0 mid-restore and `progress_permille` read 0 on a 99%-synced wallet until the scheduler's
/// first suggest round, which on a Tor cold start can be many seconds away).
///
/// Replicates the first suggest round's math against the DB alone (no network):
///   - `chain_tip`  — the wallet's persisted tip view (`WalletRead::chain_height`, the height
///     the last `update_chain_tip` recorded). The live pass overwrites it on its first fetch.
///   - `recovering` — any suggested range still starts below MAX(`accounts.recover_until_height`)
///     (identical to the per-round computation in [`run_to_completion`]).
///   - permille floor — `global_floor_permille` over (persisted tip, MIN(birthday),
///     Σ remaining queue), folded via `fetch_max` (a seed can only raise the floor).
///   - `spendable`  — latched when NO ChainTip/Verify-priority range remains pending: the
///     recent window is fully scanned, which is exactly what the in-pass latch records.
///
/// A wallet with no accounts seeds nothing — a fresh wallet's zero snapshot IS truthful.
/// Callers treat errors as "no seed" (presentation state, never correctness state).
///
/// The seed uses the subtree roots stored at open, before the pass fetches new ones, so it can
/// differ from a refreshed in-pass estimate. Estimator-only gaps retain the displayed floor
/// until real progress passes it. Recorded birthday/tip/pending scope evidence permits only
/// proportional corrections for actual added or reopened work, subject to the epsilon.
pub fn seed_progress_from_wallet(
    progress: &Progress,
    session: &WalletSession,
) -> Result<(), SlipstreamError> {
    let Some(birthday) = session.min_birthday()? else {
        return Ok(()); // no accounts — the zero snapshot is the truth
    };
    let ranges = session.suggest_scan_ranges()?;
    let recover_until = session.max_recover_until()?;
    let recovering = recover_until
        .is_some_and(|ru| ranges.iter().any(|r| u64::from(r.block_range().start) < ru));
    progress.set_recovering(recovering);

    // `Anchor` (librustzcash#2333): the unscanned part of the chain-tip pruning window after
    // the tip advanced or the anchor was disturbed — value is spendable again only once it is
    // scanned, so it is pending tip work like `ChainTip`.
    let recent_pending = ranges.iter().any(|r| {
        matches!(
            r.priority(),
            ScanPriority::ChainTip | ScanPriority::Anchor | ScanPriority::Verify
        )
    });
    if !recent_pending {
        progress.set_spendable();
    }

    let tip = session.chain_height()?.unwrap_or(0);
    if tip != 0 {
        progress.set_chain_tip(tip);
    }
    let sum_remaining: u64 = ranges
        .iter()
        .map(|r| {
            let s = u64::from(r.block_range().start);
            let e = u64::from(r.block_range().end);
            e.saturating_sub(s)
        })
        .sum();
    // Same unit choice as the pass's first suggest round: in work when the estimator can
    // express the position, so the pass's first work seed is not read as a scope expansion
    // against a higher block-based floor seeded here.
    let work_estimator = session.build_work_estimator();
    let work_seed = work_estimator.as_ref().and_then(|est| {
        global_floor_permille_work(tip, Some(birthday), remaining_work(est, &ranges), est)
    });
    let seed = work_seed.or_else(|| global_floor_permille(tip, Some(birthday), sum_remaining));
    if let Some(seed) = seed {
        let unit = if work_seed.is_some() {
            PASS_UNIT_WORK
        } else {
            PASS_UNIT_BLOCKS
        };
        let _ = progress.permille_floor(seed, unit);
        if work_seed.is_some()
            && let Some(est) = work_estimator.as_ref()
        {
            // The persisted seed is known history, including an empty pending queue.
            // Account imports before the first pass must compare against this scope.
            let pending: Vec<_> = ranges
                .iter()
                .map(|r| u64::from(r.block_range().start)..u64::from(r.block_range().end))
                .collect();
            let _ = progress.work_scope_lower_bound(birthday, &pending, est);
        }
    }
    tracing::info!(
        tip,
        birthday,
        sum_remaining,
        recovering,
        spendable = !recent_pending,
        "E-3 snapshot seeded from persisted wallet state (truthful from open)"
    );
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub ranges_processed: u64,
    pub fetch: FetchStatsTotals,
    pub scan: ScanStatsTotals,
    /// Enhancement stats accumulated across ALL per-range enhancement runs.
    /// F3: each range's enhancement contributes to this sum; the engine's final
    /// post-loop enhancement also accumulates here via SyncOutcome merge in engine.rs.
    pub enhance: EnhanceStats,
    /// Number of reorg recoveries performed (truncate + re-suggest) during this sync.
    pub reorgs_recovered: u64,
    /// Total wall-clock time spent in the fetch pipeline (across all ranges).
    /// Accumulated from `FetchStats::elapsed` per range. Default: zero.
    pub fetch_elapsed: Duration,
    /// [v0.7 P0] Total estimated wire bytes across all ranges — with
    /// `fetch_elapsed` this yields the pass-average wire MB/s.
    pub wire_bytes: u64,
    /// [v0.7 P0] Worst sustained 5 s wire throughput across all ranges
    /// (MB/s; the minimum of each range's `FetchStats::worst_window_mbps`).
    /// 0.0 = no range produced a full window. Interpret beside recv_wait
    /// (the ahead-gate caveat on `FetchStats::worst_window_mbps`).
    pub wire_worst_window_mbps: f64,
    /// Total wall-clock time spent in scan_chunks (across all ranges).
    /// Measured around the scan call per range. Default: zero.
    pub scan_elapsed: Duration,
    /// Total wall-clock time spent in per-range run_enhancement_lazily_isolated calls (F3).
    /// The engine's final post-loop enhancement adds its own elapsed to SyncOutcome
    /// directly; this field covers the scheduler's interleaved runs only.
    pub enhance_elapsed: Duration,
    /// T6.9 write-behind: Σ time the scan loop was blocked awaiting deferred
    /// commits (0 ≈ perfect overlap; always 0 with the flag off).
    pub persist_wait_elapsed: Duration,
    /// T6.9 write-behind: Σ wall time of the deferred commits themselves.
    pub persist_busy_elapsed: Duration,
    /// v0.5 pacer split (plan §3) — the scan lane's wall decomposed, summed
    /// across ranges. See `ScanStats` for the per-field contracts.
    pub scan_recv_wait: Duration,
    pub scan_call: Duration,
    pub scan_prefetch_wait: Duration,
    pub scan_interleave_drain: Duration,
    pub scan_final_drain: Duration,
    pub scan_absorb: Duration,
    /// v0.6 P1 residue split — see `ScanStats` for the per-field contracts.
    pub scan_state_prep: Duration,
    pub scan_prefetch_spawn: Duration,
    pub scan_submit_wait: Duration,
    pub scan_submit_extra: Duration,
    pub scan_reseed: Duration,
    /// v0.6 P6 two-pass split of scan_call — see `ScanStats`.
    pub scan_pass1: Duration,
    pub scan_pass2: Duration,
    /// v0.4 census (spec §3.2): per-pool shard census unioned across all ranges.
    pub census_sapling: crate::census::ShardCensus,
    pub census_orchard: crate::census::ShardCensus,
}

#[derive(Debug, Default, Clone)]
pub struct FetchStatsTotals {
    pub blocks: u64,
    pub bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ScanStatsTotals {
    pub blocks: u64,
    pub sapling_received: u64,
    pub orchard_received: u64,
}

/// Requests an abort of the wrapped task when dropped, instead of leaving it to keep running
/// detached.
///
/// A plain `JoinHandle` that is only awaited on the normal path is not enough: an early `?`
/// return, or the enclosing future being dropped outright (a host restart aborts the SESSION
/// task, not this one), skips the `.await` and leaves the spawned task running orphaned. For
/// the per-range fetch task below, an orphan keeps fetching after its scanner is gone — its
/// worker eventually exhausts its retries and records a download give-up into whatever
/// `Progress` it still holds, corrupting a session that has already started fresh (see
/// `Progress::begin_session`).
///
/// The guarantee is limited: dropping the wrapper requests the abort, and the task stops at
/// its next `.await`. `abort()` does not wait for that. A fetch task spends its life at
/// awaits, so an aborted pass's fetch practically cannot record into a later session, but
/// nothing here waits until it is gone. Aborting an already-finished task is a no-op, so the
/// normal path (`.await` to a result) is unaffected.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> std::future::Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.get_mut().0).poll(cx)
    }
}

/// Process every suggested range until none remain. The caller has already
/// run put_subtree_roots_at + update_chain_tip (engine.rs).
///
/// `progress` — if `Some`, bumps `fetched_blocks`, `scanned_blocks`, `reorgs_recovered`,
/// and `current_range_end` atomics so poll-based consumers (CLI ticker, iOS D8) get
/// live updates. Pass `None` to skip all atomic stores (the default for tests).
pub async fn run_to_completion(
    config: &EngineConfig,
    session: &mut WalletSession,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
    tor: Option<&TorConn>,
) -> Result<SyncReport, SlipstreamError> {
    let mut report = SyncReport::default();
    // v0.4 Plan A: before any range plans, build (or queue a rescan of) the graft-buffer
    // runs no range will resume: a range stopped between its last commit and its range-end
    // build leaves them, and Historic ranges run newest first, so none comes back for them.
    // With the buffer empty it costs a connection open and two queries. Warn-and-continue,
    // as the open-time heals: a sweep that fails leaves the rows buffered (no range deletes
    // rows at positions it does not feed) for the next pass's sweep, and the pass runs.
    // Its SQLite and tree work blocks, so it runs off the async worker, as the range-end
    // finish does (`block_in_place`, which a current-thread runtime does not offer).
    let anchor_retention =
        crate::persist::anchor_retention(&*session.db_mut(), config.anchor_retention.as_ref())?;
    let mut sweep = || {
        crate::persist::sweep_stranded_graft_rows(
            session.db_mut(),
            &config.wallet_db_path,
            config.graft_subtree,
            anchor_retention.as_ref(),
        )
    };
    let swept = match tokio::runtime::Handle::current().runtime_flavor() {
        tokio::runtime::RuntimeFlavor::CurrentThread => sweep(),
        _ => tokio::task::block_in_place(sweep),
    };
    if let Err(e) = swept {
        warn!(%e, "graft sweep failed (non-fatal) — continuing");
    }
    // Counter for back-to-back ScanContinuity recoveries without a successful range.
    // Reset to 0 on any successful range completion. Capped at MAX_CONSECUTIVE_REORGS
    // to prevent infinite ping-pong (e.g. adversarial server or database corruption).
    let mut consecutive_reorgs: u64 = 0;
    // F1: track blocks scanned so far in this pass (local accumulator).
    // Used to compute the whole-pass denominator: scanned_so_far + sum(remaining ranges).
    let mut scanned_so_far_in_pass: u64 = 0;
    // B1: Build WorkEstimator once per pass for output-weighted progress.
    // Returns None on any error (logged) or when no usable shard data exists.
    let work_estimator = session.build_work_estimator();
    // B1: Track work scanned so far in this pass (parallel to scanned_so_far_in_pass).
    let mut scanned_work_so_far_in_pass: u64 = 0;
    // [API v2 §4.4] The wallet's recovery ceiling, read once per pass: the snapshot's
    // `is_recovering` is true while any suggested range still starts below it (the restore
    // backfill window). A read failure degrades to "not recovering" rather than failing the
    // pass — the flag is presentation state, never correctness state.
    let recover_until: Option<u64> = session.max_recover_until().unwrap_or_default();
    // [API v2.1 E-4] Pass-start baseline for the boundary tx-set signature check (see the
    // range-boundary block at the bottom of the loop). `None` (read failure) = the first
    // successful boundary read becomes the baseline without bumping.
    let mut last_tx_sig: Option<(u64, u64)> = session.tx_set_signature().ok();
    loop {
        let ranges = session.suggest_scan_ranges()?;
        // [API v2 §4.4] Recompute the recovery flag on every suggest round: still recovering
        // iff work remains below the recovery ceiling. An empty queue (handled below) or a
        // queue entirely above the ceiling flips it false — recovery is over even though the
        // pass may keep scanning newer ranges.
        if let Some(ref p) = progress {
            let recovering = recover_until
                .is_some_and(|ru| ranges.iter().any(|r| u64::from(r.block_range().start) < ru));
            p.set_recovering(recovering);
        }
        let Some(range) = ranges.first() else {
            info!("scan queue empty — sync complete");
            return Ok(report);
        };

        // F1: Compute whole-pass denominator from ALL returned ranges (not just the first).
        // `suggest_scan_ranges` returns all pending ranges for this pass together
        // (both ChainTip and Historic are returned on the first call — confirmed by the
        // user's iPad log showing the 0→100→60% snap-back: the old code accumulated
        // per-range, so ChainTip alone filled 100% before Historic expanded the denominator).
        // By summing ALL returned ranges and STORING (not adding), the denominator is
        // complete from the very first suggestion. Re-suggest after each range recomputes
        // correctly: scanned_so_far + sum(remaining) stays constant unless new ranges appear.
        if let Some(ref p) = progress {
            // B1: Compute sum_remaining_work when a WorkEstimator is available.
            let sum_remaining_work = work_estimator
                .as_ref()
                .map_or(0, |est| remaining_work(est, &ranges));
            // [h16-4] Read every suggest round, not once per pass: an account imported
            // BETWEEN two rounds of the same pass, with an older birthday, widens the span
            // above (sum_remaining grows) while a pass-level read would still hold the
            // stale, newer birthday — once sum_remaining exceeds that stale span,
            // global_floor_permille saturates to 0 and the re-baseline below stretches from
            // 0 instead of the true global position. A read failure degrades to `None`,
            // exactly as before.
            let wallet_birthday: Option<u64> = session.min_birthday().unwrap_or_default();
            update_pass_progress(
                p,
                &mut scanned_so_far_in_pass,
                &ranges
                    .iter()
                    .map(|r| u64::from(r.block_range().start)..u64::from(r.block_range().end))
                    .collect::<Vec<_>>(),
                wallet_birthday,
                &mut scanned_work_so_far_in_pass,
                sum_remaining_work,
                work_estimator.as_ref(),
            );
        }

        // block_range() returns a Range<BlockHeight> where .end is END-EXCLUSIVE
        // (standard Rust Range semantics, confirmed at zcash_client_backend-0.22.0/src/data_api/scanning.rs:62).
        // Both u32::from(BlockHeight) and u64::from(BlockHeight) exist; use u64 directly
        // to avoid a two-step cast and to match the rest of the scheduler's u64 arithmetic.
        let start: u64 = u64::from(range.block_range().start);
        let end_exclusive: u64 = u64::from(range.block_range().end);

        // Guard the degenerate empty range (should not happen per upstream contract, but if it
        // does, return a Wallet error rather than constructing an invalid FetchPlan).
        if end_exclusive <= start {
            return Err(SlipstreamError::Wallet(format!(
                "degenerate scan range: start={start} end_exclusive={end_exclusive}"
            )));
        }

        // FetchPlan takes inclusive [start, end]; subtract 1 from the exclusive end.
        let end = end_exclusive - 1;
        info!(start, end, priority = ?range.priority(), "processing suggested range");

        // Advertise the current range end to poll-based consumers.
        if let Some(ref p) = progress {
            p.set_range_end(end);
        }

        // [B3 fix] Snapshot scanned_work at range start to clamp continuity credit: only credit
        // the work actually done in THIS attempt, not work from earlier attempts at overlapping
        // ranges that the counter already holds.
        let range_start_scanned_work = progress.as_ref().map(|p| p.scanned_work()).unwrap_or(0);

        let (mut tx, rx) = chunk_queue(config.memory_budget_bytes);
        // v0.5 pacer fix: boundary treestate fetches start when the chunk is
        // EMITTED (fetch side), so the RTT hides under queue wait + scan
        // instead of racing one scan call (P1: that overhang was 62 % of the
        // Mac scan wall on a slow-treestate day). In server mode the range's
        // last boundary is never read, so it is not fetched. Whether a
        // local-mode boundary is audited is decided scan-side, so local mode
        // still fetches every boundary here.
        {
            let ep = config.endpoint.clone();
            let tor_owned = tor.cloned();
            let boundary_progress = progress.clone();
            let local_mode = local_treestate_active(config);
            tx.set_boundary_fetcher(std::sync::Arc::new(move |end_height| {
                if !needs_server_boundary_state(local_mode, true, end_height, end) {
                    return None;
                }
                let ep = ep.clone();
                let tor_owned = tor_owned.clone();
                let progress = boundary_progress.clone();
                Some(tokio::spawn(async move {
                    crate::grpc::retry_get_tree_state(
                        &ep,
                        end_height,
                        "boundary prefetch (fetch-side)",
                        tor_owned.as_ref(),
                        crate::connector::ConnPurpose::SyncShared,
                        progress,
                    )
                    .await
                }))
            }));
        }
        // Smaller plan chunks when bulk rides OHTTP (whole-chunk buffered responses, gateway
        // response cap) — connector::bulk_chunk_blocks; unchanged for direct gRPC.
        let chunk_blocks =
            crate::connector::bulk_chunk_blocks(config.chunk_blocks, &config.endpoint);
        let mut plan = FetchPlan::new(start, end, chunk_blocks, config.fetch_streams);
        // T6.8-S: byte-budgeted sub-chunk splitting (sandblasting-era survival).
        plan.split_bytes = config.chunk_split_bytes;
        // [v0.7 P2] Arm the wire-collapse detector only when the engine has
        // somewhere to fail over TO (and the kill switch is on). Tor passes
        // never have alternates armed (the probe is skipped there too).
        if config.wire_failover && !config.alternate_endpoints.is_empty() {
            plan.failover = Some(crate::fetch::WireFailoverArm::default());
        }
        // Adaptive prefetch while the scan waits for blocks (fetch::FetchBoost). Extra
        // block streams only through an OHTTP gateway and where the memory budget is
        // not derated for a small device.
        if config.fetch_boost {
            let gateway = crate::ohttp::relay_for(&config.endpoint.host).is_some();
            let roomy =
                config.memory_budget_bytes >= crate::config::EngineConfig::DEFAULT_MEMORY_BUDGET;
            plan.boost = Some(crate::fetch::FetchBoost {
                extra_streams: if gateway && roomy {
                    crate::fetch::BOOST_EXTRA_OHTTP_STREAMS
                } else {
                    0
                },
            });
        }
        let endpoint = config.endpoint.clone();
        // Clone the progress Arc for the fetch task so it can bump fetched_blocks.
        let fetch_progress = progress.clone();
        // Tor handle for the bulk workers: when present, every host uses Tor with one
        // circuit per connection, including plain lightwalletd hosts (connector::route).
        let fetch_tor = tor.cloned();

        // Spawn the fetch task so it runs concurrently with scan_chunks below.
        // The tx is moved into the task; when the task finishes, tx is dropped, which
        // closes the channel and causes scan_chunks's rx.recv() loop to terminate.
        // Wrapped in AbortOnDrop: if this whole future is dropped (a host restart aborts
        // the session, not this task), the fetch task is aborted instead of orphaned (see
        // `AbortOnDrop`'s doc).
        let fetch_task = AbortOnDrop(tokio::spawn(async move {
            run_fetch(&endpoint, fetch_tor, plan, tx, fetch_progress).await
        }));

        // scan_chunks runs in the current task. Its interleaved enhancement opens its own
        // connection when it first needs the server, separate from the fetch workers'.
        let scan_started = std::time::Instant::now();
        let scan_result: Result<ScanStats, SlipstreamError> = scan_chunks(
            session,
            start,
            end,
            rx,
            progress.clone(),
            config,
            skipped_keys,
            tor,
            // v0.4 Plan A: only Historic ranges buffer (accumulator rule 2).
            range.priority() == ScanPriority::Historic,
        )
        .await;
        let scan_wall = scan_started.elapsed();

        // Error-precedence rationale (deviation from plan's draft `??` which loses nuance):
        // If scan_chunks fails first, dropping rx causes the fetch task to see a
        // send-error and finish with Stopped or a transport error — both are secondary.
        // We ALWAYS await the JoinHandle so the task is not left running in the background,
        // but if scan already failed we prefer returning the scan error; the fetch's secondary
        // error is downgraded to a tracing::warn.
        //
        // ScanContinuity is the special case: the fetch task for the aborted range is
        // awaited (to avoid leaking the task), its secondary error is warned but NOT
        // propagated, then we truncate + re-suggest and continue the loop.
        let fetch_result: Result<FetchStats, SlipstreamError> = fetch_task
            .await
            .map_err(|e| SlipstreamError::Transport(format!("fetch task panicked: {e}")))?;

        // Reorg recovery arm — mirrors upstream sync.rs:404-418
        // (zcash_client_backend-0.22.0/src/sync.rs:404-418):
        //
        //   Err(ChainError::Scan(err)) if err.is_continuity_error() => {
        //       let rewind_height = err.at_height().saturating_sub(10);
        //       db_data.truncate_to_height(rewind_height)?;
        //       // re-suggest via Ok(true)
        //   }
        //
        // Rewind computation: subtract 10 blocks from the error height, matching upstream
        // exactly. `saturating_sub` prevents underflow at low heights.
        if let Err(SlipstreamError::ScanContinuity { at }) = scan_result {
            // Await the fetch task for the aborted range (must not leave it running).
            // Its secondary error (Stopped / send-error from dropped rx) is demoted to warn.
            if let Err(ref fetch_err) = fetch_result {
                warn!(%fetch_err, "fetch task also errored during reorg recovery (secondary, demoted)");
            }

            consecutive_reorgs += 1;
            if consecutive_reorgs > MAX_CONSECUTIVE_REORGS {
                warn!(
                    consecutive_reorgs,
                    at, "too many consecutive reorg recoveries — giving up"
                );
                return Err(SlipstreamError::ScanContinuity { at });
            }

            // Mirror upstream rewind: err_height.saturating_sub(10)
            // (sync.rs:409: `let rewind_height = err.at_height().saturating_sub(10)`)
            let rewind_height = at.saturating_sub(10);
            warn!(
                at,
                rewind_height,
                consecutive = consecutive_reorgs,
                "continuity break detected — truncating wallet DB and re-suggesting"
            );

            // Upstream's truncate_to_height (data_api.rs:3233) and, in its transaction, the
            // drop of the graft-buffer rows of the blocks it removed: they may be the
            // abandoned chain's.
            session.truncate_to_height(BlockHeight::from(rewind_height))?;

            // [h16-2] The truncate discards blocks above rewind_height, but the blocks
            // BELOW it (the surviving prefix of the aborted range) are still done — credit
            // them now so the next suggest round's baseline snapshot (h16-1) folds them
            // into scanned_so_far_in_pass instead of leaving pass_total cover only the
            // small repair range while fetched/scanned still hold the whole aborted range.
            scanned_so_far_in_pass +=
                scan_continuity_repair_credit(start, end_exclusive, u64::from(rewind_height));
            // B3: Credit surviving work when using work-based progress. [B3 fix] Clamp to the
            // work actually done in this attempt (scanned_work_now - range_start snapshot), so we
            // never credit work from earlier attempts that the counter already holds.
            if let Some(ref est) = work_estimator {
                let raw_credit = scan_continuity_work_credit(
                    est,
                    start,
                    end_exclusive,
                    u64::from(rewind_height),
                );
                let actual_work_done = progress
                    .as_ref()
                    .map(|p| p.scanned_work().saturating_sub(range_start_scanned_work))
                    .unwrap_or(0);
                let clamped_credit = raw_credit.min(actual_work_done);
                scanned_work_so_far_in_pass += clamped_credit;
            }

            report.reorgs_recovered += 1;
            if let Some(ref p) = progress {
                record_continuity_scope(p, u64::from(at));
                p.add_reorg();
            }

            // B3 (#1755): give a desynced load-balanced cluster a heal window before
            // retrying — see reorg_backoff_ms. Connection freshness on retry is
            // structural, not added here: every client a range uses is opened within
            // that range (scan_chunks' tree states and interleaved enhancement, and
            // run_fetch's per-worker connections — fetch.rs worker() connects per
            // worker, per range) — no gRPC channel survives into the retry, so the
            // retry cannot be pinned to the same stale backend.
            let backoff_ms = reorg_backoff_ms(consecutive_reorgs);
            warn!(
                backoff_ms,
                consecutive = consecutive_reorgs,
                "reorg backoff before re-suggest (cluster tip-desync heal window)"
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            // `continue` causes the outer loop to call suggest_scan_ranges again;
            // the repair range (from rewind_height up to current tip) is now suggested.
            continue;
        }

        let (scan_stats, fetch_stats) = match (scan_result, fetch_result) {
            (Ok(s), Ok(f)) => (s, f),
            (Err(scan_err), fetch_outcome) => {
                // Scan failed — fetch's secondary error (Stopped, send-error) is demoted.
                if let Err(ref fetch_err) = fetch_outcome {
                    if scan_err.is_stop_for_wallet_change() {
                        // A wallet-change stop ends the scan on purpose and drops its chunk
                        // receiver, so a fetch task that is still sending fails with the
                        // closed-channel `Stopped`: the usual outcome of every such stop. That
                        // echo of a stop the host asked for is no fault, and at `warn!` it would
                        // send whoever reads the device logs chasing a failure that never
                        // happened, so it stays at `debug!`.
                        debug!(%fetch_err, "fetch task also errored after a wallet-change stop (expected: the stopped scan closed its channel)");
                    } else {
                        warn!(%fetch_err, "fetch task also errored (secondary, scan error takes precedence)");
                    }
                }
                return Err(scan_err);
            }
            (Ok(_), Err(fetch_err)) => {
                // Fetch failed but scan succeeded — this is unusual (scan consumed all chunks
                // before fetch detected the error, or fetch had a worker panic after sending
                // all chunks). Return the fetch error so the caller is informed.
                return Err(fetch_err);
            }
        };

        // Successful range completion: reset the consecutive-reorg counter.
        consecutive_reorgs = 0;
        report.ranges_processed += 1;
        report.fetch.blocks += fetch_stats.blocks;
        report.fetch.bytes += fetch_stats.bytes;
        report.fetch_elapsed += fetch_stats.elapsed;
        // [v0.7 P0] wire health: pass-total bytes + the worst sustained
        // 5 s window across ranges (skip windowless ranges, e.g. tiny tips).
        report.wire_bytes += fetch_stats.bytes;
        if !fetch_stats.wire_samples.is_empty() {
            let w = fetch_stats.worst_window_mbps(5.0);
            if w > 0.0
                && (report.wire_worst_window_mbps == 0.0 || w < report.wire_worst_window_mbps)
            {
                report.wire_worst_window_mbps = w;
            }
        }
        report.scan.blocks += scan_stats.blocks;
        report.scan.sapling_received += scan_stats.sapling_received;
        report.scan.orchard_received += scan_stats.orchard_received;
        // T6.1: interleaved-enhancement time is enhancement, not scan.
        report.scan_elapsed += scan_wall.saturating_sub(scan_stats.interleaved_enhance_elapsed);
        report.enhance_elapsed += scan_stats.interleaved_enhance_elapsed;
        // T6.9: persist overlap accounting (scan_elapsed deliberately KEEPS the
        // persist_wait portion — it is honest loop wall time; see engine.rs log).
        report.persist_wait_elapsed += scan_stats.persist_wait;
        report.persist_busy_elapsed += scan_stats.persist_busy;
        // v0.5 pacer split.
        report.scan_recv_wait += scan_stats.recv_wait;
        report.scan_call += scan_stats.scan_call;
        report.scan_prefetch_wait += scan_stats.prefetch_wait;
        report.scan_interleave_drain += scan_stats.interleave_drain;
        report.scan_final_drain += scan_stats.final_drain;
        report.scan_absorb += scan_stats.treestate_absorb;
        // v0.6 P1 residue split.
        report.scan_state_prep += scan_stats.state_prep;
        report.scan_prefetch_spawn += scan_stats.prefetch_spawn;
        report.scan_submit_wait += scan_stats.submit_wait;
        report.scan_submit_extra += scan_stats.submit_extra;
        report.scan_reseed += scan_stats.reseed;
        // v0.6 P6 two-pass split.
        report.scan_pass1 += scan_stats.scan_pass1;
        report.scan_pass2 += scan_stats.scan_pass2;
        report.census_sapling.merge(&scan_stats.census_sapling);
        report.census_orchard.merge(&scan_stats.census_orchard);
        report.enhance.requests += scan_stats.interleaved_enhance.requests;
        report.enhance.txs_stored += scan_stats.interleaved_enhance.txs_stored;
        report.enhance.statuses_set += scan_stats.interleaved_enhance.statuses_set;
        report.enhance.skipped += scan_stats.interleaved_enhance.skipped;
        report.enhance.fetch_wait += scan_stats.interleaved_enhance.fetch_wait;
        report.enhance.store += scan_stats.interleaved_enhance.store;
        report.enhance.address += scan_stats.interleaved_enhance.address;

        // F1: accumulate scanned blocks for next iteration's whole-pass denominator.
        scanned_so_far_in_pass += scan_stats.blocks;
        // B1: accumulate scanned work when using work-based progress.
        scanned_work_so_far_in_pass += scan_stats.work;

        // Spendable latch: if this range was ChainTip (or Anchor: the pruning window
        // re-established after the tip moved) priority, funds are now likely spendable
        // (SBS semantics — the tip-priority range covers the most-recent blocks where
        // the wallet's own notes appear as spendable).
        if matches!(
            range.priority(),
            ScanPriority::ChainTip | ScanPriority::Anchor
        ) && let Some(ref p) = progress
        {
            p.set_spendable();
        }

        // F3: Per-range interleaved enhancement.
        // Runs AFTER scan_chunks completes for this range (scanner paused, DB in a
        // consistent state, low contention vs. rayon trial-decryption).
        // Cost on iPad A10: ~0.69s/run at sync end → interleaving is ~free per range.
        // This makes transactions visible progressively during the sync, not just at
        // the very end. The engine's final post-loop run_enhancement still fires
        // (catches any leftovers) and its stats are accumulated into SyncOutcome
        // separately. The connection is opened at the first request that needs the
        // server, so a range with nothing to fetch — a follow pass on a quiet wallet,
        // whose only requests are address checks the run skips — opens none.
        //
        // NON-FATAL: interleaved enhancement is an optimization (progressive tx
        // visibility), not a correctness guarantee — that is the final post-loop run's
        // job. A transient connect/fetch failure here must NOT abort a multi-minute
        // sync at a range boundary; we log and continue scanning.
        {
            let enhance_started = std::time::Instant::now();
            let mut enhance_client = enhancement_connection(&config.endpoint, tor);
            let enhance_result = crate::grpc::with_ohttp_endpoint(
                &config.endpoint,
                tor.is_some(),
                run_enhancement_lazily_isolated(
                    session,
                    &mut enhance_client,
                    config.network,
                    progress.clone(),
                    skipped_keys,
                    tor.map(|t| (t, &config.endpoint)),
                ),
            )
            .await;
            match enhance_result {
                Ok(enhance_stats) => {
                    // Accumulate into report so stage-split in engine.rs sums all runs.
                    report.enhance.requests += enhance_stats.requests;
                    report.enhance.txs_stored += enhance_stats.txs_stored;
                    report.enhance.statuses_set += enhance_stats.statuses_set;
                    report.enhance.skipped += enhance_stats.skipped;
                }
                Err(err) => {
                    warn!(
                        %err,
                        start,
                        end,
                        "per-range enhancement failed — continuing; final post-loop enhancement will retry"
                    );
                }
            }
            report.enhance_elapsed += enhance_started.elapsed();
        }

        // F2: Bump ranges_completed AFTER scan + per-range enhancement.
        // Swift observes this counter and triggers ONE balance-summary fetch per boundary.
        if let Some(ref p) = progress {
            p.add_ranges_completed();
            // [API v2.1 E-4] Boundary tx-set signature check: catches set changes that arrive
            // WITHOUT an enhancement write — e.g. scanning a historic block stores the received
            // note that LINKS an already-stored dangling spend (reconciled flips with no new
            // tx). Direct writes (enhance/mempool) bump the version at their own sites; this
            // closes the scan-driven linkage class. Read failure = skip (presentation state).
            if let Ok(sig) = session.tx_set_signature()
                && last_tx_sig != Some(sig)
            {
                if last_tx_sig.is_some() {
                    p.bump_tx_set_version();
                }
                last_tx_sig = Some(sig);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_handle::{SyncState, derive_snapshot};
    use zcash_client_backend::data_api::WalletWrite as _;

    #[test]
    fn sync_report_default_is_zero() {
        let r = SyncReport::default();
        assert_eq!(r.ranges_processed, 0);
        assert_eq!(r.fetch.blocks, 0);
        assert_eq!(r.fetch.bytes, 0);
        assert_eq!(r.scan.blocks, 0);
        assert_eq!(r.scan.sapling_received, 0);
        assert_eq!(r.scan.orchard_received, 0);
        assert_eq!(r.reorgs_recovered, 0);
        assert_eq!(r.fetch_elapsed, Duration::ZERO);
        assert_eq!(r.scan_elapsed, Duration::ZERO);
        assert_eq!(r.enhance_elapsed, Duration::ZERO);
        // T6.9 write-behind totals default to zero (and stay zero with the flag off).
        assert_eq!(r.persist_wait_elapsed, Duration::ZERO);
        assert_eq!(r.persist_busy_elapsed, Duration::ZERO);
        // F3 EnhanceStats default
        assert_eq!(r.enhance.requests, 0);
        assert_eq!(r.enhance.txs_stored, 0);
        assert_eq!(r.enhance.statuses_set, 0);
        assert_eq!(r.enhance.skipped, 0);
    }

    /// [API v2 §4.4 / Phase E] Cold-launch catch-up: a 99.9%-synced wallet must seed a
    /// near-1000 floor, so the blessed permille can never flash ~0% while the small pass runs.
    #[test]
    fn global_floor_catch_up_seeds_near_complete() {
        // tip 2.0M, birthday 1.0M (span 1_000_001), 3_000 blocks left to scan.
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 3_000).unwrap();
        assert!(
            (990..=1000).contains(&seed),
            "catch-up must seed near 1000, got {seed}"
        );
    }

    /// A fresh from-birthday restore has (almost) the whole span in the queue — the seed
    /// must stay ~0 so the restore bar still climbs 0→100% off the pass counters.
    #[test]
    fn global_floor_fresh_restore_seeds_zero() {
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 1_000_001).unwrap();
        assert_eq!(seed, 0, "fresh restore must not pre-raise the floor");
    }

    /// A relaunched half-done restore resumes near its true global position (the property
    /// the old Swift monotonic floor could not deliver across a relaunch).
    #[test]
    fn global_floor_relaunched_restore_resumes_position() {
        let seed = global_floor_permille(2_000_000, Some(1_000_000), 500_000).unwrap();
        assert_eq!(seed, 500, "half the span remaining ⇒ ~500‰");
    }

    /// Degenerate inputs cannot express a position: no seed (floor untouched).
    #[test]
    fn global_floor_degenerate_inputs_yield_none() {
        assert_eq!(
            global_floor_permille(0, Some(1_000_000), 10),
            None,
            "no tip yet"
        );
        assert_eq!(
            global_floor_permille(2_000_000, None, 10),
            None,
            "no accounts"
        );
        assert_eq!(
            global_floor_permille(999, Some(1_000), 10),
            None,
            "tip below birthday"
        );
        // Remaining exceeding the span clamps to 0 rather than underflowing.
        assert_eq!(global_floor_permille(1_100, Some(1_000), 5_000), Some(0));
    }

    /// [h16-1] Reviewer's example on 10c9f633 (PR #14 review round): an older-birthday
    /// account import expands the scan scope mid-pass. Drives the real suggest-round
    /// accounting (`update_pass_progress`) across three rounds, polling the FFI snapshot
    /// between them the way a host would — the poll matters because `derive_snapshot`
    /// itself latches the session floor (`Progress::permille_floor`), and the pre-fix bug's
    /// inflated reading re-latches a floor high enough to wrongly trigger ANOTHER
    /// re-baseline on the very next round (the reviewer's "fires again on every round").
    #[test]
    fn scope_expansion_rebaseline_does_not_double_count_or_oscillate() {
        let p = Progress::default();
        const TIP: u64 = 3_000_000;
        const B1: u64 = TIP - 1_000_000 + 1; // pre-import birthday: span 1,000,000
        const B0: u64 = TIP - 2_000_000 + 1; // post-import (older) birthday: span 2,000,000
        p.set_chain_tip(TIP);
        let mut scanned_so_far_in_pass = 0u64;

        // Round 1: the pass's first suggest round, no expansion yet — a 1,000,000-block
        // span with everything still remaining, so the seed (and the latched start) is 0.
        let rebaselined = progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_000_000,
            Some(B1),
            &mut 0,
            0,
            None,
        );
        assert!(!rebaselined, "first round of a pass is never a re-baseline");
        assert_eq!(p.pass_start_permille(), Some(0));

        // This pass scans 900k of its original 1M-block span before anything changes.
        p.add_fetched(900_000);
        p.add_scanned(900_000);
        scanned_so_far_in_pass += 900_000;

        // A host poll between suggest rounds (polling is continuous in practice) latches
        // the session floor at 900 before the import lands.
        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 900,
            "900k/1M fetched+scanned, no start stretch yet (start=0) ⇒ 900"
        );

        // Round 2: an older-birthday account is imported — the scope expands to a
        // 2,000,000-block span with 1,100,000 remaining (the reviewer's own example).
        // seed = (2,000,000 − 1,100,000) × 1000 / 2,000,000 = 450, far enough below the
        // 900 floor to read as scope expansion, not noise.
        let rebaselined = progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_100_000,
            Some(B0),
            &mut 0,
            0,
            None,
        );
        assert!(
            rebaselined,
            "450 is >50‰ below the 900 floor ⇒ scope expansion"
        );
        assert_eq!(p.pass_start_permille(), Some(450));

        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 450,
            "right after the re-baseline the reading must be the new start alone (450), \
             not the pre-expansion 900k/900k double-counted against the new 1.1M total"
        );

        // Round 3: the very next suggest round, nothing scanned since round 2 — the seed
        // is still 450, which must NOT read as a further expansion against the now-correct
        // 450 floor (pre-fix, the round-2 poll above re-inflates the floor and this round
        // wrongly re-baselines again).
        let rebaselined_again = progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_100_000,
            Some(B0),
            &mut 0,
            0,
            None,
        );
        assert!(
            !rebaselined_again,
            "the next suggest round must not re-baseline again"
        );

        // The repair climbs from 450 to 1000 as the remaining 1.1M blocks are fetched and
        // scanned — not instantly, and not before both are done.
        p.add_fetched(1_100_000);
        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 725,
            "everything fetched, nothing scanned since the re-baseline: half-weighted climb \
             off the 450 start"
        );

        p.add_scanned(1_100_000);
        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 1000,
            "the pass reaches 1000 only once the remaining 1.1M are fetched AND scanned"
        );
    }

    /// [h17-1] A real concurrent poll can't be made to land inside `update_pass_progress` at
    /// an exact instant deterministically — but every store its re-baseline branch makes is a
    /// plain `Progress` method, so replaying them by hand with a `derive_snapshot` poll spliced
    /// between each one reads exactly what a poll on another thread could see at that instant.
    /// This does NOT exercise `update_pass_progress` itself (its own branch is verified by
    /// reading it against this same sequence) — it exercises the ORDER the brief specifies, to
    /// confirm that order is safe. Same round-2 setup as
    /// `scope_expansion_rebaseline_does_not_double_count_or_oscillate` (TIP 3,000,000; 900,000
    /// credited and polled, latching the floor at 900; seed 450 for the import).
    #[test]
    fn rebaseline_new_order_never_reads_above_the_old_floor_mid_publish() {
        let p = Progress::default();
        const TIP: u64 = 3_000_000;
        const B1: u64 = TIP - 1_000_000 + 1;
        p.set_chain_tip(TIP);
        let mut scanned_so_far_in_pass = 0u64;
        progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_000_000,
            Some(B1),
            &mut 0,
            0,
            None,
        );
        p.add_fetched(900_000);
        p.add_scanned(900_000);
        // (round 1 credited nothing to `scanned_so_far_in_pass`: the non-expanded branch
        // never touches it. Round 2 below is replayed by hand, not via another
        // `update_pass_progress` call, so — unlike the counterfactual test below, which reads
        // it back — this test has no further use for the local accumulator.)
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        // Round 2, replayed by hand in the NEW order: baseline, then total, then start, then
        // (last) the floor call — polling after each step.
        const SEED: u64 = 450; // global_floor_permille(3_000_000, Some(B0), 1_100_000)

        p.set_pass_baseline(p.fetched(), p.scanned());
        p.set_pass_total(1_100_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900,
            "zero pass-local count under the OLD (round-1) start ⇒ raw ≪ 900, floor unmoved"
        );

        p.set_pass_start_permille(SEED);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900,
            "zero pass-local count under the NEW seed ⇒ raw = 450 ≤ 900, floor still unmoved"
        );

        let rebaselined = p.rebaseline_floor_if_scope_expanded(SEED, PASS_UNIT_BLOCKS);
        assert!(rebaselined, "the re-check must still see the expansion");
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            450,
            "only once the floor call runs does the reading drop to the true post-rebaseline value"
        );
    }

    /// [h17-1] Counterfactual: replays the PRE-fix order (floor lowered first, start moved
    /// second, baseline/total published last — the exact order `update_pass_progress` used
    /// before this fix) against the identical round-2 state, to reproduce what the reviewer's
    /// report describes — a poll between the start moving and the baseline/total catching up
    /// reads a DOUBLE-COUNTED value: the new 450 start stretched by a pass-local ratio still
    /// measured against the pass's PRE-refresh baseline/total (900,000 fetched+scanned over a
    /// 2,000,000 total, i.e. the scheduler's unconditional top-of-function snapshot for THIS
    /// round, not round 1's). `fetch_max` latches that 697 and the true 450 can never surface
    /// for the rest of the pass. This sequence is no longer reachable from
    /// `update_pass_progress` (see its new order, and
    /// `rebaseline_new_order_never_reads_above_the_old_floor_mid_publish` above) — this test
    /// documents why the old order was wrong; it does not exercise production code.
    #[test]
    fn rebaseline_old_order_used_to_latch_a_double_counted_697() {
        let p = Progress::default();
        const TIP: u64 = 3_000_000;
        const B1: u64 = TIP - 1_000_000 + 1;
        p.set_chain_tip(TIP);
        let mut scanned_so_far_in_pass = 0u64;
        progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_000_000,
            Some(B1),
            &mut 0,
            0,
            None,
        );
        p.add_fetched(900_000);
        p.add_scanned(900_000);
        scanned_so_far_in_pass += 900_000;
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        const SEED: u64 = 450;

        // The unconditional top-of-function step `update_pass_progress` always runs before
        // deciding expansion (unchanged by this fix): baseline from this round's zeroed-so-far
        // accounting, total from `scanned_so_far_in_pass` + the NEW `sum_remaining`.
        p.set_pass_baseline(
            p.fetched().saturating_sub(scanned_so_far_in_pass),
            p.scanned().saturating_sub(scanned_so_far_in_pass),
        );
        p.set_pass_total(scanned_so_far_in_pass + 1_100_000);

        // OLD step 1: lower the floor FIRST.
        assert!(p.rebaseline_floor_if_scope_expanded(SEED, PASS_UNIT_BLOCKS));

        // OLD step 2: move the start SECOND, still ahead of the baseline/total refresh.
        p.set_pass_start_permille(SEED);

        // The poll the reviewer's report describes: new start, stale pre-refresh baseline/total.
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            697,
            "the new 450 start stretched by a pass-local ratio still measured against the \
             stale pre-refresh baseline/total — the double-counted value fetch_max then latches"
        );

        // OLD step 3 (too late): the baseline/total refresh can no longer help — 697 is latched.
        p.set_pass_baseline(p.fetched(), p.scanned());
        p.set_pass_total(1_100_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            697,
            "fetch_max never lowers: the true 450 can no longer surface for this pass"
        );
    }

    /// [h16-4] The fix under test: `run_to_completion` now reads `session.min_birthday()`
    /// fresh every suggest round instead of once per pass. Drives two rounds against a REAL
    /// `WalletSession` (not the hardcoded `Some(B1)`/`Some(B0)` literals the sibling test
    /// above uses): round 1 sees the single TEST_UFVK account (birthday 663_150, tip
    /// 700_000, via `wallet_with_account`); between rounds a second, older-birthday account
    /// lands via a real `create_account` import — the same synthetic `[7u8; 32]` filler seed
    /// `oracle.rs`'s `t10b_fixture`/`t10b_prepare` already uses to create a spending account
    /// in these unit tests, never a real wallet's key material — before round 2's read.
    ///
    /// Contrasts the STALE seed a once-per-pass read would still feed in (birthday still
    /// 663_150: remaining 60_000 now exceeds that pre-import 36_851 span, so
    /// `global_floor_permille` saturates to 0 — the exact bug from the brief) against the
    /// FRESH seed a per-round read reaches (birthday 600_000: seed 400) — `pass_start_permille`
    /// must land on 400, the true global position, not 0. The re-baseline MATH itself (this is
    /// a `rebaseline_floor_if_scope_expanded` case, `50 + 400 < 918`) is already covered by
    /// `scope_expansion_rebaseline_does_not_double_count_or_oscillate` above; this test is the
    /// new-here half — a live session read actually SEES a mid-pass import.
    #[test]
    fn min_birthday_refresh_sees_a_mid_pass_import_with_an_older_birthday() {
        let dir = tempfile::tempdir().expect("tempdir");
        const TIP: u64 = 700_000;
        let mut s = wallet_with_account(&dir, TIP); // TEST_UFVK, birthday 663_150 (span 36_851)

        let p = Progress::default();
        p.set_chain_tip(TIP);
        let mut scanned_so_far_in_pass = 0u64;

        // Round 1: a fresh read of the single-account wallet.
        let birthday = s.min_birthday().expect("min_birthday");
        assert_eq!(
            birthday,
            Some(663_150),
            "single-account wallet reads that account's birthday"
        );
        let rebaselined = progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            3_000,
            birthday,
            &mut 0,
            0,
            None,
        );
        assert!(!rebaselined, "first round of a pass is never a re-baseline");
        assert_eq!(p.pass_start_permille(), Some(918));

        // Between rounds: a second, OLDER-birthday account lands — e.g. a Ledger import
        // mid-pass. `db_mut().create_account` (not `ensure_account`, which no-ops once any
        // account exists) mirrors production's real import path.
        let birthday2 = zcash_client_backend::data_api::AccountBirthday::from_treestate(
            zcash_client_backend::proto::service::TreeState {
                network: "main".into(),
                height: 599_999,
                hash: "0".repeat(64),
                time: 1,
                ..Default::default()
            },
            None,
        )
        .expect("birthday2");
        s.db_mut()
            .create_account(
                "h16-4 second account (older birthday)",
                &secrecy::SecretVec::new([7u8; 32].to_vec()),
                &birthday2,
                None,
            )
            .expect("create_account");

        // Round 2: the refresh under test. First, the counterfactual — a STALE read (the old
        // once-per-pass value, still 663_150) would feed a remaining (60_000) that now
        // exceeds the pre-import span (36_851), saturating the seed to 0.
        assert_eq!(
            global_floor_permille(TIP, Some(663_150), 60_000),
            Some(0),
            "the STALE birthday saturates the seed to 0 once remaining exceeds its span"
        );
        // Now the real fix: a FRESH read — not the round-1 value reused — sees the import.
        let birthday = s.min_birthday().expect("min_birthday");
        assert_eq!(
            birthday,
            Some(600_000),
            "a fresh read after the mid-pass import returns the NEW minimum birthday"
        );
        let rebaselined = progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            60_000,
            birthday,
            &mut 0,
            0,
            None,
        );
        assert!(
            rebaselined,
            "400 is >50‰ below the 918 floor ⇒ scope expansion"
        );
        assert_eq!(
            p.pass_start_permille(),
            Some(400),
            "the re-baseline stretches from the TRUE global position (400), not 0"
        );
    }

    /// [h16-2] Reviewer's example on 10c9f633 (PR #14 review round): a 10k-block range
    /// breaks continuity at height 9,000 (rewind to 8,990, matching upstream's
    /// `at.saturating_sub(10)`). The blocks below 8,990 stay done after the truncate — this
    /// test credits them to `scanned_so_far_in_pass` the same way the real ScanContinuity
    /// branch does (via `scan_continuity_repair_credit`, the exact formula that branch
    /// calls; driving a live ScanContinuity error needs a full darkside scan failure, so the
    /// branch's OWN wiring is verified by reading, not by this test — see the report). No
    /// birthday is seeded (`global_floor_permille` returns `None` on `None`, per
    /// `global_floor_degenerate_inputs_yield_none`), isolating the fetched/scanned/pass_total
    /// interaction from h16-1's separate `pass_start_permille` stretch.
    #[test]
    fn continuity_repair_credits_the_surviving_prefix_not_the_whole_range() {
        let p = Progress::default();
        let mut scanned_so_far_in_pass = 0u64;

        // Round 1: the range about to break is [0, 10_000) — "a 10k-block range".
        let (start, end_exclusive) = (0u64, 10_000u64);
        progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            end_exclusive - start,
            None,
            &mut 0,
            0,
            None,
        );
        assert_eq!(p.pass_total(), 10_000);

        // The break: fetch ran ahead to the whole range (f=10,000); scan got to 9,000
        // (s=9,000) before the continuity error at height 9,000.
        p.add_fetched(10_000);
        p.add_scanned(9_000);

        // ScanContinuity { at: 9_000 } -> rewind_height = 9_000 - 10 = 8_990 (at is u32,
        // matching error.rs's ScanContinuity::at and the branch's own rewind_height).
        let at: u32 = 9_000;
        let rewind_height = at.saturating_sub(10);
        assert_eq!(rewind_height, 8_990);

        // The fix under test: credit the surviving prefix right after the truncate, via the
        // SAME formula (`scan_continuity_repair_credit`) the production branch calls.
        scanned_so_far_in_pass +=
            scan_continuity_repair_credit(start, end_exclusive, u64::from(rewind_height));
        assert_eq!(scanned_so_far_in_pass, 8_990);

        // Next suggest round: the repair range is [8_990, 10_000) -> 1_010 remaining
        // ("T ≈ 1,010" in the reviewer's own notation for the UNCREDITED pre-fix total —
        // post-fix, T is the credited 8_990 plus this 1_010 repair range).
        progress_for_suffix(
            &p,
            &mut scanned_so_far_in_pass,
            1_010,
            None,
            &mut 0,
            0,
            None,
        );
        assert_eq!(
            p.pass_total(),
            10_000,
            "T = the credited 8_990 + the 1_010 repair range"
        );

        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 899,
            "right after the rewind the reading must be ~900, not 1000 mid-repair \
             (no pass start is seeded here, so this is the pass-local ratio alone: \
             fetched (10,000−1,010=8,990) + scanned (9,000−10=8,990) over 2×10,000)"
        );

        // The repair completes: the remaining 1_010 blocks are fetched and scanned.
        p.add_fetched(1_010);
        p.add_scanned(1_010);
        let snap = derive_snapshot(&p, SyncState::Syncing);
        assert_eq!(
            snap.progress_permille, 1000,
            "reaches 1000 only once the repair completes"
        );
    }

    // ── Output-weighted progress (work units) ───────────────────────────────────

    use crate::work::{BLOCK_WEIGHT, WorkEstimator};

    /// Heights 1..=1000 carry no shielded leaves (4 000 work), 1001..=2000 carry 32 leaves
    /// each (36 000 work): a 2 000-block pass whose first half is 10 % of its work.
    fn sparse_then_dense() -> WorkEstimator {
        WorkEstimator::new_for_test(vec![(1, vec![], vec![(1_000, 0), (2_000, 32_000)])])
    }

    fn progress_for_suffix(
        p: &Progress,
        b: &mut u64,
        remaining: u64,
        birthday: Option<u64>,
        w: &mut u64,
        remaining_work: u64,
        estimator: Option<&WorkEstimator>,
    ) -> bool {
        // These older arithmetic fixtures describe one contiguous suffix. Tests of
        // irregular scheduling geometry call update_pass_progress directly.
        let end = p.chain_tip().saturating_add(1).max(remaining);
        update_pass_progress(
            p,
            b,
            std::slice::from_ref(&(end.saturating_sub(remaining)..end)),
            birthday,
            w,
            remaining_work,
            estimator,
        )
    }

    /// Uniform density: 6 leaves per block, so every block is 10 work units.
    fn uniform(tip: u64) -> WorkEstimator {
        WorkEstimator::new_for_test(vec![(1, vec![], vec![(tip, 6 * tip)])])
    }

    // A numeric seed gap caused only by actual leaf density must not reset progress.
    fn assert_dense_tip_stays_monotonic(est: WorkEstimator, birthday: u64) {
        let tip = birthday + 10_999;
        let p = Progress::default();
        p.set_chain_tip(tip);
        let (mut blocks_done, mut work_done) = (0, 0);
        let historic_work = est.range(birthday, birthday + 9_999);
        let initial_work = est.range(birthday, tip);
        assert!(!update_pass_progress(
            &p,
            &mut blocks_done,
            std::slice::from_ref(&(birthday..birthday + 11_000)),
            Some(birthday),
            &mut work_done,
            initial_work,
            Some(&est)
        ));
        let actual_tip_work = 60_000 + 1_000 * BLOCK_WEIGHT;
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.add_fetched_work(actual_tip_work);
        p.add_scanned_work(actual_tip_work);
        p.note_work_completed(birthday + 10_000..birthday + 11_000);
        blocks_done += 1_000;
        work_done += actual_tip_work;
        let before = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        let estimated_seed =
            global_floor_permille_work(tip, Some(birthday), historic_work, &est).unwrap();
        assert_eq!(before, 551);
        assert_eq!(estimated_seed, 90);
        assert!(u64::from(before) > estimated_seed + 50);
        assert_ne!(
            before, 90,
            "the display follows actual work, not the block ratio"
        );
        let rebaselined = update_pass_progress(
            &p,
            &mut blocks_done,
            std::slice::from_ref(&(birthday..birthday + 10_000)),
            Some(birthday),
            &mut work_done,
            historic_work,
            Some(&est),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!(
            "dense tip: before={before}, estimated_seed={estimated_seed}, after={after}, rebaselined={rebaselined}"
        );
        assert!(!rebaselined);
        assert_eq!(after, before);
        assert_eq!(blocks_done, 1_000);
        assert_eq!(work_done, actual_tip_work);
        let rebaselined_again = update_pass_progress(
            &p,
            &mut blocks_done,
            std::slice::from_ref(&(birthday..birthday + 10_000)),
            Some(birthday),
            &mut work_done,
            historic_work,
            Some(&est),
        );
        let after_again = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(!rebaselined_again);
        assert_eq!(after_again, before);
        p.add_fetched(10_000);
        p.add_scanned(10_000);
        p.add_fetched_work(historic_work);
        p.add_scanned_work(historic_work);
        let complete = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert_eq!(complete, 1000);
    }

    #[test]
    fn work_progress_dense_tip_does_not_rebaseline_unchanged_scope() {
        assert_dense_tip_stays_monotonic(WorkEstimator::new(vec![(1, vec![(0, 10_000)])]), 1);
    }

    #[test]
    fn work_progress_dense_tip_with_mainnet_subtree_indices_stays_monotonic() {
        assert_dense_tip_stays_monotonic(
            WorkEstimator::new(vec![(419_200, vec![(100, 2_000_000), (101, 2_010_000)])]),
            2_000_001,
        );
    }

    fn dense_tip_fixture(est: &WorkEstimator, birthday: u64) -> (Progress, u64, u64) {
        let p = Progress::default();
        let tip = birthday + 10_999;
        p.set_chain_tip(tip);
        let (mut b, mut w) = (0, 0);
        update_pass_progress(
            &p,
            &mut b,
            std::slice::from_ref(&(birthday..birthday + 11_000)),
            Some(birthday),
            &mut w,
            est.range(birthday, tip),
            Some(est),
        );
        let actual = 60_000 + 1_000 * BLOCK_WEIGHT;
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.add_fetched_work(actual);
        p.add_scanned_work(actual);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        p.note_work_completed(birthday + 10_000..birthday + 11_000);
        (p, 1_000, actual)
    }

    fn assert_dense_tip_restart(est: WorkEstimator, birthday: u64) {
        let (p, mut b, mut w) = dense_tip_fixture(&est, birthday);
        update_pass_progress(
            &p,
            &mut b,
            std::slice::from_ref(&(birthday..birthday + 10_000)),
            Some(birthday),
            &mut w,
            est.range(birthday, birthday + 9_999),
            Some(&est),
        );
        let before = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        p.begin_pass();
        b = 0;
        w = 0;
        let rebaselined = update_pass_progress(
            &p,
            &mut b,
            std::slice::from_ref(&(birthday..birthday + 10_000)),
            Some(birthday),
            &mut w,
            est.range(birthday, birthday + 9_999),
            Some(&est),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!("restart before={before} after={after} rebaselined={rebaselined}");
        assert_eq!(before, 551);
        assert!(!rebaselined);
        assert_eq!(after, 551);
    }

    #[test]
    fn work_progress_dense_tip_restart_keeps_floor() {
        assert_dense_tip_restart(WorkEstimator::new(vec![(1, vec![(0, 10_000)])]), 1);
    }

    #[test]
    fn work_progress_dense_tip_mainnet_restart_keeps_floor() {
        assert_dense_tip_restart(
            WorkEstimator::new(vec![(419_200, vec![(100, 2_000_000), (101, 2_010_000)])]),
            2_000_001,
        );
    }

    #[test]
    fn work_progress_dense_tip_short_rewind_is_bounded() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        let before = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        // The dense ChainTip attempt breaks at the tip and rewinds ten blocks.
        let (start, end, at) = (10_001, 11_001, 11_000u64);
        let rewind = at.saturating_sub(10);
        b = b - 1_000 + scan_continuity_repair_credit(start, end, rewind);
        w = w - (60_000 + 1_000 * BLOCK_WEIGHT)
            + scan_continuity_work_credit(&est, start, end, rewind).min(p.scanned_work());
        record_continuity_scope(&p, at);
        p.add_reorg();
        let remaining = est.range(1, 10_000) + est.range(rewind, 11_000);
        let rebaselined = update_pass_progress(
            &p,
            &mut b,
            &[1..10_001, rewind..11_001],
            Some(1),
            &mut w,
            remaining,
            Some(&est),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!("rewind before={before} after={after} rebaselined={rebaselined}");
        let reopened_share = (u128::from(est.range(rewind, 11_000)) * 1000)
            .div_ceil(u128::from(est.range(1, 11_000))) as u16;
        assert_eq!(before, 551);
        assert!(after >= 551 - reopened_share);
        assert_eq!(after, 551);
    }

    fn dense_suggest(
        p: &Progress,
        b: &mut u64,
        w: &mut u64,
        est: &WorkEstimator,
        birthday: Option<u64>,
        pending: &[std::ops::Range<u64>],
    ) -> bool {
        let work = pending.iter().map(|r| est.range(r.start, r.end - 1)).sum();
        update_pass_progress(p, b, pending, birthday, w, work, Some(est))
    }

    #[test]
    fn work_progress_blocks_fallback_keeps_work_floor() {
        let est = WorkEstimator::new(vec![(6_001, vec![(0, 10_000)])]);
        let p = Progress::default();
        p.set_chain_tip(11_000);
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001)),
        ));
        p.add_fetched(7_000);
        p.add_scanned(7_000);
        p.add_fetched_work(69_400);
        p.add_scanned_work(69_400);
        p.note_work_completed(1..6_001);
        p.note_work_completed(10_001..11_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );

        p.begin_pass();
        let (mut b, mut w) = (0, 0);
        let pending = 6_001..10_001;
        assert!(!update_pass_progress(
            &p,
            &mut b,
            std::slice::from_ref(&pending),
            Some(1),
            &mut w,
            0,
            None,
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            636
        );

        p.begin_pass();
        let (mut b, mut w) = (0, 0);
        let rebaselined = dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending),
        );
        let recovered = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert_eq!(recovered, 636, "rebaselined={rebaselined}");
        assert!(!rebaselined);
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            636
        );
    }

    fn block_snapshot_advance_fixture() -> (Progress, WorkEstimator) {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..10_001)),
        ));
        p.add_fetched(6_000);
        p.add_scanned(6_000);
        p.add_fetched_work(60_000);
        p.add_scanned_work(60_000);
        p.note_work_completed(1..6_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            600
        );
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);

        p.begin_pass();
        assert!(!update_pass_progress(
            &p,
            &mut 0,
            std::slice::from_ref(&(6_001..10_001)),
            Some(1),
            &mut 0,
            0,
            None,
        ));
        assert_eq!(p.pass_start_permille(), Some(600));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            600
        );
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.note_work_completed(6_001..7_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            700
        );
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        (p, est)
    }

    #[test]
    fn work_progress_block_snapshot_retains_work_provenance() {
        let (p, est) = block_snapshot_advance_fixture();
        let pending = 7_001..10_001;
        for _ in 0..2 {
            p.begin_pass();
            assert!(!update_pass_progress(
                &p,
                &mut 0,
                std::slice::from_ref(&pending),
                Some(1),
                &mut 0,
                0,
                None,
            ));
            assert_eq!(
                derive_snapshot(&p, SyncState::Syncing).progress_permille,
                700
            );
            assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
            p.begin_pass();
            assert!(!dense_suggest(
                &p,
                &mut 0,
                &mut 0,
                &est,
                Some(1),
                std::slice::from_ref(&pending)
            ));
            assert_eq!(
                derive_snapshot(&p, SyncState::Syncing).progress_permille,
                700
            );
            assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        }
    }

    #[test]
    fn work_progress_fallback_recovery_preserves_real_rewind() {
        let (p, est) = block_snapshot_advance_fixture();
        p.note_work_rewind(5_001..10_001);
        p.begin_pass();
        let pending = 5_001..10_001;
        let (mut b, mut w) = (0, 0);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            500
        );
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            500
        );
        p.add_fetched(5_000);
        p.add_scanned(5_000);
        p.add_fetched_work(50_000);
        p.add_scanned_work(50_000);
        p.note_work_completed(5_001..10_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
        assert_eq!(derive_snapshot(&p, SyncState::Done).progress_permille, 1000);
    }

    #[test]
    fn work_progress_fallback_recovery_preserves_real_expansion() {
        let (p, est) = block_snapshot_advance_fixture();
        p.set_chain_tip(20_000);
        p.begin_pass();
        let pending = 7_001..20_001;
        let (mut b, mut w) = (0, 0);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            350
        );
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            350
        );
    }

    #[test]
    fn work_progress_initial_blocks_to_work_still_rebaselines() {
        let est = WorkEstimator::new(vec![(6_001, vec![(0, 10_000)])]);
        let p = Progress::default();
        p.set_chain_tip(11_000);
        let pending = 6_001..10_001;
        assert!(!update_pass_progress(
            &p,
            &mut 0,
            std::slice::from_ref(&pending),
            Some(1),
            &mut 0,
            0,
            None,
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            636
        );
        assert_eq!(p.floor_unit(), PASS_UNIT_BLOCKS);
        p.begin_pass();
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            352
        );
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&pending)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            352
        );
    }

    #[test]
    fn work_progress_repeated_restarts_keep_floor() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, _, _) = dense_tip_fixture(&est, 1);
        for _ in 0..3 {
            p.begin_pass();
            let (mut b, mut w) = (0, 0);
            assert!(!dense_suggest(
                &p,
                &mut b,
                &mut w,
                &est,
                Some(1),
                std::slice::from_ref(&(1..10_001))
            ));
            assert_eq!(
                derive_snapshot(&p, SyncState::Syncing).progress_permille,
                551
            );
        }
        p.add_fetched_work(est.range(1, 10_000));
        p.add_scanned_work(est.range(1, 10_000));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    #[test]
    fn work_progress_restart_before_resuggestion_keeps_floor() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, _, _) = dense_tip_fixture(&est, 1);
        // No post-completion suggestion has recorded a reduced queue yet.
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        // Nor may an interrupted, partially scanned range turn into queue growth.
        p.add_fetched_work(10_000);
        p.add_scanned_work(5_000);
        let before = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            before
        );
    }

    #[test]
    fn work_progress_estimator_refresh_without_growth_keeps_floor() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, _, _) = dense_tip_fixture(&est, 1);
        p.begin_pass();
        let refreshed = WorkEstimator::new(vec![(1, vec![(0, 5_000), (1, 10_000)])]);
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &refreshed,
            Some(1),
            std::slice::from_ref(&(1..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        // A later real extension must price BOTH spans with refreshed density.
        p.set_chain_tip(22_000);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &refreshed,
            Some(1),
            &[1..10_001, 11_001..22_001]
        ));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert_eq!(after, 275, "the common-model global work doubled");
    }

    #[test]
    fn work_progress_small_scope_growth_is_bounded() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1_001);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1_001),
            &[1_001..11_001, 11_001..11_011]
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(991),
            &[991..11_001, 11_001..11_011]
        ));
        let share = (u128::from(est.range(991, 1_000)) * 1000)
            .div_ceil(u128::from(est.range(991, 12_000))) as u16;
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(after >= 551 - share);
        assert_eq!(after, 551);
    }

    #[test]
    fn work_progress_continuity_without_scanned_credit_cannot_spend_floor() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        // A Historic attempt fails inside an uncredited chunk. The error height
        // cannot turn its unscanned prefix into completed-and-reopened work.
        record_continuity_scope(&p, 9_001);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!((460..=461).contains(&after), "after={after}");
    }

    #[test]
    fn work_progress_large_rewind_rebaselines_once() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        // Most of this rewind was already pending Historic work. Only the dense
        // completed tip is newly reopened, even though the repair spans 6,000 blocks.
        record_continuity_scope(&p, 5_011);
        p.add_reorg();
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        let share = (u128::from(est.range(10_001, 11_000)) * 1000)
            .div_ceil(u128::from(est.range(1, 11_000))) as u16;
        assert!(
            after >= 551 - share,
            "after={after}, reopened share={share}"
        );
        assert!(after < 501);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
        p.add_fetched_work(est.range(1, 11_000));
        p.add_scanned_work(est.range(1, 11_000));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    #[test]
    fn work_progress_overlapping_rewind_observations_are_not_double_charged() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.note_work_rewind(10_201..11_001);
        p.note_work_rewind(10_501..11_001);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 10_201..11_001]
        ));
        let first = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        p.note_work_rewind(10_001..10_701);
        dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001)),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        let share = (u128::from(est.range(10_001, 11_000)) * 1000)
            .div_ceil(u128::from(est.range(1, 11_000))) as u16;
        assert!(after >= 551 - share);
        assert!(after <= first);
        p.note_work_rewind(10_001..11_001);
        p.add_reorg();
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
    }

    #[test]
    fn work_progress_scope_growth_across_pass_boundary_is_visible() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, _, _) = dense_tip_fixture(&est, 1);
        p.begin_pass();
        // Requiring the completed tip again is a real same-birthday rescan.
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!((460..=461).contains(&after));
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
    }

    #[test]
    fn work_progress_completed_rewind_during_metadata_gap_is_not_charged() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.note_work_rewind(10_001..11_001);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            None,
            std::slice::from_ref(&(1..11_001))
        ));
        let completed = est.range(10_001, 10_500);
        p.add_fetched(500);
        p.add_scanned(500);
        p.add_fetched_work(completed);
        p.add_scanned_work(completed);
        b += 500;
        w += completed;
        p.note_work_completed(10_001..10_501);
        let rebaselined = dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 10_501..11_001],
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!("metadata gap completed rewind: after={after}, rebaselined={rebaselined}");
        assert!(!rebaselined);
        assert_eq!(after, 551);
    }

    #[test]
    fn work_progress_cumulative_small_growth_survives_tolerance_and_restart() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        let mut drops = 0;
        for step in 1..=11 {
            let tip = 11_000 + step * 1_000;
            p.set_chain_tip(tip);
            let pending = [1..10_001, 11_001..tip + 1];
            if dense_suggest(&p, &mut b, &mut w, &est, Some(1), &pending) {
                drops += 1;
            }
            let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
            assert!(!dense_suggest(&p, &mut b, &mut w, &est, Some(1), &pending));
            assert_eq!(
                derive_snapshot(&p, SyncState::Syncing).progress_permille,
                after
            );
            if step == 1 {
                assert_eq!(after, 551, "the first correction is within tolerance");
                p.begin_pass();
                b = 0;
                w = 0;
                assert!(!dense_suggest(&p, &mut b, &mut w, &est, Some(1), &pending));
                assert_eq!(
                    derive_snapshot(&p, SyncState::Syncing).progress_permille,
                    551
                );
            }
        }
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!("cumulative doubled span: after={after}, drops={drops}");
        assert!(drops > 0);
        assert!(
            (275..=325).contains(&after),
            "a doubled span has bound 275 plus tolerance"
        );
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            &[1..10_001, 11_001..22_001]
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
    }

    #[test]
    fn work_progress_cumulative_growth_preserves_intervening_earned_share() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.set_chain_tip(12_000);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 11_001..12_001]
        ));
        p.add_fetched_work(50_000);
        p.add_scanned_work(50_000);
        let earned = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(
            earned > 551,
            "real partial-range work raises the displayed floor"
        );
        p.set_chain_tip(13_000);
        let rebaselined = dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 11_001..13_001],
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        let bound = (551u128 * u128::from(est.range(1, 11_000))
            + u128::from(earned - 551) * u128::from(est.range(1, 12_000)))
            / u128::from(est.range(1, 13_000));
        eprintln!("intervening work earned={earned}, after={after}, bound={bound}");
        assert!(rebaselined);
        assert!((bound as u16..=bound as u16 + 1).contains(&after));
        assert!(after > 466, "the partial-range earned share is retained");
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 11_001..13_001]
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
    }

    #[test]
    fn work_progress_completed_unapplied_rewind_cancels_its_entitlement() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.note_work_rewind(10_001..10_501);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..10_501))
        ));
        p.note_work_completed(10_001..10_501);
        // An independent small new queue cannot combine with an already-completed
        // held rewind to manufacture a material correction.
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 10_501..11_001]
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
    }

    #[test]
    fn work_progress_raw_seed_settles_unapplied_correction() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.set_chain_tip(12_000);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 11_001..12_001]
        ));
        let completed = est.range(1, 10_000);
        p.add_fetched_work(completed);
        p.add_scanned_work(completed);
        b += 10_000;
        w += completed;
        p.note_work_completed(1..10_001);
        // The truthful global seed now exceeds the retained displayed floor.
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(11_001..12_001))
        ));
        let earned = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        p.set_chain_tip(13_000);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(11_001..13_001))
        ));
        let bound = u128::from(earned) * u128::from(est.range(1, 12_000))
            / u128::from(est.range(1, 13_000));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(
            (bound as u16..=bound as u16 + 1).contains(&after),
            "the settled earlier expansion must not be replayed: after={after}, bound={bound}"
        );
    }

    #[test]
    fn work_progress_missing_metadata_preserves_scope() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (p, mut b, mut w) = dense_tip_fixture(&est, 1);
        p.note_work_rewind(10_001..11_001);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            None,
            std::slice::from_ref(&(1..11_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        p.begin_pass();
        assert!(!update_pass_progress(
            &p,
            &mut 0,
            std::slice::from_ref(&(1..11_001)),
            Some(1),
            &mut 0,
            0,
            None
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            551
        );
        p.begin_pass();
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        assert!((460..=461).contains(&derive_snapshot(&p, SyncState::Syncing).progress_permille));
    }

    // Queue growth must remain visible even when the wallet birthday is unchanged.
    #[test]
    fn work_scope_queue_growth_without_earlier_birthday_rebaselines() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        let (mut b, mut w) = (0, 0);
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            10_000,
            Some(1),
            &mut w,
            100_000,
            Some(&est)
        ));
        p.add_fetched(9_000);
        p.add_scanned(9_000);
        p.add_fetched_work(90_000);
        p.add_scanned_work(90_000);
        b = 9_000;
        w = 90_000;
        p.note_work_completed(1..9_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        assert!(progress_for_suffix(
            &p,
            &mut b,
            2_000,
            Some(1),
            &mut w,
            20_000,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            800
        );
        assert_eq!((b, w), (0, 0));
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            2_000,
            Some(1),
            &mut w,
            20_000,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            800
        );
        p.add_fetched_work(10_000);
        p.add_scanned_work(10_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
    }

    // Ten reopened blocks cannot spend the unrelated fifty-permille fetch-ahead gap.
    #[test]
    fn work_scope_short_rewind_preserves_fetch_ahead_floor() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        let (mut b, mut w) = (0, 0);
        progress_for_suffix(&p, &mut b, 10_000, Some(1), &mut w, 100_000, Some(&est));
        p.add_fetched(10_000);
        p.add_scanned(9_000);
        p.add_fetched_work(100_000);
        p.add_scanned_work(90_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            950
        );
        b = 8_990;
        w = 89_900;
        p.note_work_completed(1..9_001);
        p.note_work_rewind(8_991..10_001);
        p.add_reorg();
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            1_010,
            Some(1),
            &mut w,
            10_100,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            950
        );
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            1_010,
            Some(1),
            &mut w,
            10_100,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            950
        );
        p.add_fetched_work(10_100);
        p.add_scanned_work(10_100);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    // An invalid suggest must neither erase the observation nor consume real later growth.
    #[test]
    fn work_scope_missing_birthday_preserves_observation() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        let (mut b, mut w) = (0, 0);
        progress_for_suffix(&p, &mut b, 10_000, Some(1), &mut w, 100_000, Some(&est));
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.add_fetched_work(90_000);
        p.add_scanned_work(90_000);
        b = 1_000;
        w = 90_000;
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            9_000,
            None,
            &mut w,
            90_000,
            Some(&est)
        ));
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            9_000,
            Some(1),
            &mut w,
            90_000,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            10_000,
            None,
            &mut w,
            100_000,
            Some(&est)
        ));
        assert!(progress_for_suffix(
            &p,
            &mut b,
            10_000,
            Some(1),
            &mut w,
            100_000,
            Some(&est)
        ));
        // Reopening 1,000 of 10,000 uniform blocks permits at most 100 permille,
        // preserving the unrelated exact-work/estimate gap.
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            800
        );
    }

    // Resetting credited work changes the comparison baseline for the next genuine growth.
    #[test]
    fn work_scope_rebaseline_records_remaining_only_total() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        let (mut b, mut w) = (0, 0);
        progress_for_suffix(&p, &mut b, 10_000, Some(1), &mut w, 100_000, Some(&est));
        p.add_fetched(9_000);
        p.add_scanned(9_000);
        p.add_fetched_work(90_000);
        p.add_scanned_work(90_000);
        b = 9_000;
        w = 90_000;
        p.note_work_completed(1..9_001);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        assert!(progress_for_suffix(
            &p,
            &mut b,
            2_000,
            Some(1),
            &mut w,
            20_000,
            Some(&est)
        ));
        assert_eq!(p.pass_total(), 2_000);
        p.add_fetched(100);
        p.add_scanned(100);
        p.add_fetched_work(1_000);
        p.add_scanned_work(1_000);
        b = 100;
        w = 1_000;
        p.note_work_completed(8_001..8_101);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            810
        );
        // 2,600 blocks is larger than the rebased 2,000, but below the old 11,000.
        assert!(progress_for_suffix(
            &p,
            &mut b,
            2_500,
            Some(1),
            &mut w,
            25_000,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            750
        );
        assert_eq!((b, w), (0, 0));
        assert!(!progress_for_suffix(
            &p,
            &mut b,
            2_500,
            Some(1),
            &mut w,
            25_000,
            Some(&est)
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            750
        );
    }

    // A prior BLOCKS floor still permits initial correction into WORK units.
    // WORK-to-WORK retry preservation is covered by the dense restart regressions.
    #[test]
    fn work_scope_new_pass_preserves_initial_correction() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        progress_for_suffix(&p, &mut 0, 10_000, Some(1), &mut 0, 100_000, Some(&est));
        p.permille_floor(900, PASS_UNIT_BLOCKS);
        p.begin_pass();
        assert!(progress_for_suffix(
            &p,
            &mut 0,
            10_000,
            Some(1),
            &mut 0,
            100_000,
            Some(&est)
        ));
        assert_eq!(derive_snapshot(&p, SyncState::Syncing).progress_permille, 0);
        assert!(!progress_for_suffix(
            &p,
            &mut 0,
            10_000,
            Some(1),
            &mut 0,
            100_000,
            Some(&est)
        ));
    }

    #[test]
    fn work_scope_first_observation_does_not_invent_growth() {
        let p = Progress::default();
        p.set_chain_tip(10_000);
        p.permille_floor(900, PASS_UNIT_WORK);
        assert!(!progress_for_suffix(
            &p,
            &mut 0,
            10_000,
            Some(1),
            &mut 0,
            100_000,
            Some(&uniform(10_000))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
    }

    #[test]
    fn work_fixture_values() {
        let est = sparse_then_dense();
        assert_eq!(est.range(1, 1_000), 1_000 * BLOCK_WEIGHT);
        assert_eq!(est.range(1_001, 2_000), 36_000);
        assert_eq!(uniform(3_000_000).range(1_000_001, 3_000_000), 20_000_000);
        assert_eq!(uniform(10_000).range(1, 8_990), 89_900);
    }

    /// B2: a pass of range A (10 % of the work) then range B (90 %). After A completes the
    /// next suggest round must keep the reading at ~10 %, not drop it to 0 (the old baseline
    /// subtracted the work credited so far from neither side).
    #[test]
    fn baseline_math_a100_b900_scenario() {
        let est = sparse_then_dense();
        let p = Progress::default();
        p.set_chain_tip(2_000);
        let (mut blocks_done, mut work_done) = (0u64, 0u64);

        // Round 1: A = [1, 1001), B = [1001, 2001).
        progress_for_suffix(
            &p,
            &mut blocks_done,
            2_000,
            Some(1),
            &mut work_done,
            40_000,
            Some(&est),
        );
        assert!(p.pass_unit_is_work());
        assert_eq!(p.pass_total_work(), 40_000);
        assert_eq!(p.pass_start_permille(), Some(0));

        // Range A is fetched and scanned; the scheduler credits its ScanStats.
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.add_fetched_work(4_000);
        p.add_scanned_work(4_000);
        blocks_done += 1_000;
        work_done += 4_000;
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            100
        );

        // Round 2: only B remains.
        progress_for_suffix(
            &p,
            &mut blocks_done,
            1_000,
            Some(1),
            &mut work_done,
            36_000,
            Some(&est),
        );
        assert_eq!(
            p.pass_total_work(),
            40_000,
            "credited 4 000 + remaining 36 000"
        );
        assert_eq!(p.pass_base_fetched_work(), 0, "fetched_work − work_so_far");
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            100,
            "after A the ratio stays at 10 %"
        );

        p.add_fetched_work(36_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            550
        );
        p.add_scanned_work(36_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    /// Over one dense range the permille moves with the work done, not the blocks: the
    /// sparse first half is 10 %, half of the dense second half another 45 %.
    #[test]
    fn derive_snapshot_moves_permille_proportional_to_outputs() {
        let est = sparse_then_dense();
        let p = Progress::default();
        p.set_chain_tip(2_000);
        progress_for_suffix(&p, &mut 0, 2_000, Some(1), &mut 0, 40_000, Some(&est));

        let credit = |blocks: u64, work: u64| {
            p.add_fetched(blocks);
            p.add_scanned(blocks);
            p.add_fetched_work(work);
            p.add_scanned_work(work);
            derive_snapshot(&p, SyncState::Syncing).progress_permille
        };
        // Heights 1..=1000: half the blocks, a tenth of the work.
        assert_eq!(
            credit(1_000, est.range(1, 1_000)),
            100,
            "the block ratio would read 500"
        );
        // Heights 1001..=1500: three quarters of the blocks, 55 % of the work.
        assert_eq!(
            credit(500, est.range(1_001, 1_500)),
            550,
            "the block ratio would read 750"
        );
        assert_eq!(credit(500, est.range(1_501, 2_000)), 1000);
    }

    /// Work-unit variant of `scope_expansion_rebaseline_does_not_double_count_or_oscillate`:
    /// the same three rounds at 10 work units per block, driven only through the work counters.
    #[test]
    fn scope_expansion_rebaseline_does_not_double_count_or_oscillate_in_work() {
        const TIP: u64 = 3_000_000;
        const B1: u64 = TIP - 1_000_000 + 1;
        const B0: u64 = TIP - 2_000_000 + 1;
        let est = uniform(TIP);
        let p = Progress::default();
        p.set_chain_tip(TIP);
        let (mut blocks_done, mut work_done) = (0u64, 0u64);

        let rebaselined = progress_for_suffix(
            &p,
            &mut blocks_done,
            1_000_000,
            Some(B1),
            &mut work_done,
            10_000_000,
            Some(&est),
        );
        assert!(!rebaselined);
        assert!(p.pass_unit_is_work());
        assert_eq!(p.pass_start_permille(), Some(0));

        p.add_fetched_work(9_000_000);
        p.add_scanned_work(9_000_000);
        work_done += 9_000_000;
        blocks_done += 900_000;
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        // Import with an older birthday: 20 M work in scope, 11 M remaining ⇒ seed 450.
        let rebaselined = progress_for_suffix(
            &p,
            &mut blocks_done,
            1_100_000,
            Some(B0),
            &mut work_done,
            11_000_000,
            Some(&est),
        );
        assert!(
            rebaselined,
            "a 450 seed under a 900 floor is a scope expansion"
        );
        assert_eq!(
            work_done, 0,
            "the work accumulator folds into the new start"
        );
        assert_eq!(blocks_done, 0);
        assert_eq!(p.pass_total_work(), 11_000_000);
        assert_eq!(p.pass_start_permille(), Some(450));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            450
        );

        let rebaselined_again = progress_for_suffix(
            &p,
            &mut blocks_done,
            1_100_000,
            Some(B0),
            &mut work_done,
            11_000_000,
            Some(&est),
        );
        assert!(
            !rebaselined_again,
            "the next round must not re-baseline again"
        );
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            450
        );

        p.add_fetched_work(11_000_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            725
        );
        p.add_scanned_work(11_000_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    /// Work-unit variant of `rebaseline_new_order_never_reads_above_the_old_floor_mid_publish`:
    /// the round-2 publish replayed by hand in the production order, with the work fields.
    #[test]
    fn rebaseline_new_order_never_reads_above_the_old_floor_mid_publish_in_work() {
        const TIP: u64 = 3_000_000;
        const B1: u64 = TIP - 1_000_000 + 1;
        let est = uniform(TIP);
        let p = Progress::default();
        p.set_chain_tip(TIP);
        progress_for_suffix(
            &p,
            &mut 0,
            1_000_000,
            Some(B1),
            &mut 0,
            10_000_000,
            Some(&est),
        );
        p.add_fetched_work(9_000_000);
        p.add_scanned_work(9_000_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        const SEED: u64 = 450;
        p.set_pass_baseline(p.fetched(), p.scanned());
        p.set_pass_total(1_100_000);
        p.set_pass_baseline_work(p.fetched_work(), p.scanned_work());
        p.set_pass_total_work(11_000_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        p.set_pass_start_permille(SEED);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );

        assert!(p.rebaseline_floor_if_scope_expanded(SEED, PASS_UNIT_WORK));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            450
        );
    }

    /// Work-unit variant of `continuity_repair_credits_the_surviving_prefix_not_the_whole_range`
    /// (B3): range [1, 10 001) at 10 work per block breaks at 9 001 (rewind 8 991). The
    /// surviving prefix 1..=8990 is credited in work; the aborted attempt's fetch above the
    /// rewind, and its re-fetch, do not push the reading past the true position.
    #[test]
    fn continuity_repair_credits_the_surviving_prefix_not_the_whole_range_in_work() {
        let est = uniform(10_000);
        let p = Progress::default();
        p.set_chain_tip(10_000);
        let (mut blocks_done, mut work_done) = (0u64, 0u64);
        let (start, end_exclusive) = (1u64, 10_001u64);
        progress_for_suffix(
            &p,
            &mut blocks_done,
            10_000,
            Some(1),
            &mut work_done,
            100_000,
            Some(&est),
        );
        assert!(p.pass_unit_is_work());
        assert_eq!(p.pass_total_work(), 100_000);

        // Fetch ran ahead over the whole range; scan reached 9 000 blocks.
        p.add_fetched(10_000);
        p.add_scanned(9_000);
        p.add_fetched_work(100_000);
        p.add_scanned_work(90_000);

        let rewind_height = 9_001u64 - 10;
        blocks_done += scan_continuity_repair_credit(start, end_exclusive, rewind_height);
        work_done += scan_continuity_work_credit(&est, start, end_exclusive, rewind_height);
        assert_eq!(blocks_done, 8_990);
        assert_eq!(work_done, 89_900);

        // Repair range [8 991, 10 001): 1 010 blocks, 10 100 work.
        progress_for_suffix(
            &p,
            &mut blocks_done,
            1_010,
            Some(1),
            &mut work_done,
            10_100,
            Some(&est),
        );
        assert_eq!(
            p.pass_total_work(),
            100_000,
            "credited 89 900 + repair 10 100"
        );
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            899
        );

        // The repair re-fetches its 1 010 blocks: no jump to 1000 before they are scanned.
        p.add_fetched_work(10_100);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            949
        );
        p.add_scanned_work(10_100);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    /// The unit is fixed by the pass's first suggest round: a later round that could not
    /// express the position in work (here: no birthday) does not switch the pass to blocks.
    #[test]
    fn unit_fixed_per_pass() {
        let est = sparse_then_dense();
        let p = Progress::default();
        p.set_chain_tip(2_000);
        let (mut b, mut w) = (0u64, 0u64);
        progress_for_suffix(&p, &mut b, 2_000, Some(1), &mut w, 40_000, Some(&est));
        assert!(p.pass_unit_is_work());
        p.add_fetched_work(4_000);
        p.add_scanned_work(4_000);
        b += 1_000;
        w += 4_000;
        progress_for_suffix(&p, &mut b, 1_000, None, &mut w, 36_000, Some(&est));
        assert!(p.pass_unit_is_work(), "still work");
        assert_eq!(p.pass_total_work(), 40_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            100
        );
    }

    /// A pass whose first round ran in blocks stays in blocks even if an estimator shows up
    /// later, and reads exactly what the block path read before work progress existed.
    #[test]
    fn work_unit_regression_if_pass_starts_in_blocks() {
        let est = sparse_then_dense();
        let p = Progress::default();
        p.set_chain_tip(2_000);
        let (mut b, mut w) = (0u64, 0u64);
        progress_for_suffix(&p, &mut b, 2_000, Some(1), &mut w, 0, None);
        assert!(!p.pass_unit_is_work());
        p.add_fetched(1_000);
        p.add_scanned(1_000);
        p.add_fetched_work(4_000);
        p.add_scanned_work(4_000);
        b += 1_000;
        w += 4_000;
        progress_for_suffix(&p, &mut b, 1_000, Some(1), &mut w, 36_000, Some(&est));
        assert!(!p.pass_unit_is_work(), "still blocks");
        assert_eq!(
            p.pass_total_work(),
            0,
            "the work total is never set in a block pass"
        );
        assert_eq!(p.pass_total(), 2_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            500,
            "1 000 of 2 000 blocks, as before"
        );
        // The next pass picks its own unit.
        p.begin_pass();
        progress_for_suffix(&p, &mut 0, 1_000, Some(1), &mut 0, 36_000, Some(&est));
        assert!(p.pass_unit_is_work());
    }

    #[test]
    fn continuity_work_credit_clamped_to_range() {
        let est = uniform(10_000);
        assert_eq!(
            scan_continuity_work_credit(&est, 1_000, 2_000, 1_000),
            0,
            "rewind at start"
        );
        assert_eq!(
            scan_continuity_work_credit(&est, 1_000, 2_000, 500),
            0,
            "rewind below start"
        );
        assert_eq!(
            scan_continuity_work_credit(&est, 1_000, 2_000, 5_000),
            est.range(1_000, 1_999),
            "rewind above the range credits the whole range, not beyond it"
        );
        assert_eq!(
            scan_continuity_work_credit(&est, 1_000, 1_000, 1_500),
            0,
            "empty range"
        );
    }

    #[test]
    fn continuity_work_credit_prefix_only() {
        let est = uniform(10_000);
        let credit = scan_continuity_work_credit(&est, 1_000, 2_000, 1_500);
        assert_eq!(credit, est.range(1_000, 1_499));
        assert_eq!(credit, 500 * 10);
    }

    /// Each work term clamps to the work total, like the block terms.
    #[test]
    fn clamp_fetched_work_exceeds_total() {
        let p = Progress::default();
        assert!(p.fix_pass_unit(true));
        p.set_pass_total_work(1_000);
        p.add_fetched_work(5_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            500,
            "the fetched term is capped at its half share"
        );
        p.add_scanned_work(5_000);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            1000
        );
    }

    /// A work pass with a zero work total reads the block terms.
    #[test]
    fn zero_total_work_falls_back_to_blocks() {
        let p = Progress::default();
        assert!(p.fix_pass_unit(true));
        p.set_pass_total(100);
        p.add_fetched(50);
        p.add_scanned(50);
        p.add_fetched_work(999);
        assert_eq!(p.pass_total_work(), 0);
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            500
        );
    }

    /// B4: the global seed in work units.
    #[test]
    fn global_floor_in_work_units() {
        let est = sparse_then_dense();
        assert_eq!(
            global_floor_permille_work(2_000, Some(1), 36_000, &est),
            Some(100)
        );
        assert_eq!(
            global_floor_permille_work(2_000, Some(1), 40_000, &est),
            Some(0)
        );
        assert_eq!(global_floor_permille_work(2_000, None, 0, &est), None);
        assert_eq!(global_floor_permille_work(0, Some(1), 0, &est), None);
        assert_eq!(
            global_floor_permille_work(2_000, Some(1), 99_999, &est),
            Some(0),
            "clamps"
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum PartialCommitMode {
        Deferred,
        Sparse,
        Vanilla,
        Unsubmitted,
        Failed,
        FailedVanilla,
    }

    // Scan through the real production persistence targets. Deferred success
    // abandons the async lane owner while its real worker holds the writer gate.
    async fn commit_interrupted_prefix(
        p: &std::sync::Arc<Progress>,
        range: std::ops::Range<u64>,
        mode: PartialCommitMode,
    ) {
        use zcash_client_backend::proto::compact_formats::{ChainMetadata, CompactBlock};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wallet.db");
        let network = crate::network::SlipstreamNetwork::Custom {
            constants: zcash_protocol::consensus::NetworkType::Main,
            heights: crate::network::CustomActivations::all_from_genesis(),
        };
        let mut wallet = WalletSession::open(network, &path).expect("wallet");
        let hash = |h: u64| {
            let mut bytes = vec![0; 32];
            bytes[..8].copy_from_slice(&h.to_le_bytes());
            bytes
        };
        let blocks = range
            .clone()
            .map(|height| CompactBlock {
                height,
                hash: hash(height),
                prev_hash: if height == range.start {
                    vec![0; 32]
                } else {
                    hash(height - 1)
                },
                chain_metadata: Some(ChainMetadata::default()),
                ..Default::default()
            })
            .collect();
        let chunk = crate::chunk::Chunk::from_blocks(0, blocks);
        let source = crate::block_source::MemBlockSource::new(&chunk);
        let state = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: range.start - 1,
            hash: "0".repeat(64),
            ..Default::default()
        }
        .to_chain_state()
        .expect("state");
        let lock = rusqlite::Connection::open(&path).expect("write lock");
        if matches!(
            mode,
            PartialCommitMode::Sparse
                | PartialCommitMode::Vanilla
                | PartialCommitMode::FailedVanilla
        ) {
            if matches!(mode, PartialCommitMode::FailedVanilla) {
                lock.execute_batch(&format!(
                    "CREATE TRIGGER reject_inline_commit BEFORE INSERT ON blocks WHEN NEW.height = {} BEGIN SELECT RAISE(ABORT, 'reject inline commit'); END",
                    range.start + (range.end-range.start)/2,
                )).expect("reject inline transaction");
            }
            let mut sparse = crate::persist::SparseTreeState::default();
            let result = tokio::task::block_in_place(|| {
                let target = if matches!(mode, PartialCommitMode::Sparse) {
                    crate::scan::ScanTarget::Sparse(&mut sparse)
                } else {
                    crate::scan::ScanTarget::Inline
                };
                crate::scan::scan_batch(
                    &mut wallet,
                    &source,
                    BlockHeight::from(range.start as u32),
                    &state,
                    (range.end - range.start) as usize,
                    target,
                    Some(p),
                )
            });
            if matches!(mode, PartialCommitMode::FailedVanilla) {
                assert!(
                    result
                        .expect_err("inline transaction must fail")
                        .to_string()
                        .contains("reject inline commit")
                );
                let count: u64 = lock
                    .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
                    .expect("no rolled-back inline blocks");
                assert_eq!(count, 0);
                return;
            }
            result.expect("serialized prefix commit");
        } else {
            let mut facade = crate::persist::WriteBehindFacade::seed(wallet.db_mut(), range.start)
                .expect("facade");
            tokio::task::block_in_place(|| {
                crate::scan::scan_batch(
                    &mut wallet,
                    &source,
                    BlockHeight::from(range.start as u32),
                    &state,
                    (range.end - range.start) as usize,
                    crate::scan::ScanTarget::Deferred(&mut facade),
                    Some(p),
                )
            })
            .expect("scan into deferred stash");
            let pending = facade.take_stash().expect("pending commit");
            if matches!(mode, PartialCommitMode::Unsubmitted) {
                drop(pending);
                let count: u64 = lock
                    .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
                    .expect("no committed blocks");
                assert_eq!(count, 0);
                return;
            }
            let mut lane =
                crate::persist::PersistLane::open(&path, network, 1, false, 0, false, None)
                    .expect("persist lane");
            lane.attach_writer_gate(std::sync::Arc::clone(p));
            if matches!(mode, PartialCommitMode::Failed) {
                lock.execute_batch(&format!(
                    "CREATE TRIGGER reject_partial_commit BEFORE INSERT ON blocks WHEN NEW.height = {} BEGIN SELECT RAISE(ABORT, 'reject partial commit'); END",
                    range.start + (range.end-range.start)/2,
                )).expect("reject transaction after a partial insert");
                lane.submit(pending).await.expect("submit failing unit");
                let error = lane.drain().await.expect_err("commit must fail");
                assert!(
                    error.to_string().contains("reject partial commit"),
                    "{error}"
                );
                assert_eq!(p.wallet_writers(), 0);
                let count: u64 = lock
                    .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
                    .expect("no failed commit rows");
                assert_eq!(count, 0);
                return;
            }
            let mut pause = lane.pause_before_next_job_for_test();
            lane.submit(pending).await.expect("submit prefix");
            pause.arrived().await;
            assert_eq!(p.wallet_writers(), 1);
            drop(lane);
            assert_eq!(
                p.wallet_writers(),
                1,
                "worker owns the gate after lane drop"
            );
            pause.release();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while p.wallet_writers() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("orphan commit releases gate");
        }
        let count: u64 = lock
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
            .expect("confirmed block rows");
        assert_eq!(count, range.end - range.start);
    }

    async fn dense_partial_commit_restart(control: bool, mode: PartialCommitMode) -> u16 {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (progress, mut b, mut w) = dense_tip_fixture(&est, 1);
        let p = std::sync::Arc::new(progress);
        p.note_work_rewind(10_501..11_001);
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 10_501..11_001]
        ));
        commit_interrupted_prefix(&p, 10_501..10_751, mode).await;
        if control {
            p.note_work_completed(10_501..10_751);
        }
        p.begin_pass();
        b = 0;
        w = 0;
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_001, 10_751..11_001]
        ));
        p.note_work_rewind(10_001..10_301);
        dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_301, 10_751..11_001],
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(!dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            &[1..10_301, 10_751..11_001]
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
        eprintln!("dense committed prefix: control={control}, after={after}");
        after
    }

    async fn uniform_partial_commit_restart(control: bool, mode: PartialCommitMode) -> u16 {
        let est = uniform(10_000);
        let p = std::sync::Arc::new(Progress::default());
        p.set_chain_tip(10_000);
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(9_001..10_001)),
        );
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        p.note_work_rewind(7_001..9_001);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(7_001..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            700
        );
        commit_interrupted_prefix(&p, 7_001..8_001, mode).await;
        if control {
            p.note_work_completed(7_001..8_001);
        }
        p.begin_pass();
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(8_001..10_001)),
        );
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            800
        );
        p.note_work_rewind(7_001..8_001);
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(7_001..10_001)),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(7_001..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
        eprintln!("uniform committed prefix: control={control}, after={after}");
        after
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_dense_restart_refunds_only_outstanding_work() {
        assert!(dense_partial_commit_restart(false, PartialCommitMode::Deferred).await >= 500);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_uniform_restart_reopens_completed_prefix() {
        assert_eq!(
            uniform_partial_commit_restart(false, PartialCommitMode::Deferred).await,
            700
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_inline_sparse_restart() {
        assert_eq!(
            uniform_partial_commit_restart(false, PartialCommitMode::Sparse).await,
            700
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_inline_vanilla_restart() {
        assert_eq!(
            uniform_partial_commit_restart(false, PartialCommitMode::Vanilla).await,
            700
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_unsubmitted_continuity_cannot_clear_charges() {
        let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
        let (progress, mut b, mut w) = dense_tip_fixture(&est, 1);
        let p = std::sync::Arc::new(progress);
        p.note_work_rewind(10_001..11_001);
        assert!(dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001))
        ));
        let before = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        commit_interrupted_prefix(&p, 10_001..10_601, PartialCommitMode::Unsubmitted).await;
        // Production chunk counters can include the facade's unsubmitted stash.
        p.add_scanned(600);
        p.add_scanned_work(600 * BLOCK_WEIGHT);
        record_continuity_scope(&p, 10_601);
        let rebaselined = dense_suggest(
            &p,
            &mut b,
            &mut w,
            &est,
            Some(1),
            std::slice::from_ref(&(1..11_001)),
        );
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!(
            "unsubmitted continuity: before={before}, after={after}, rebaselined={rebaselined}"
        );
        assert!(!rebaselined);
        assert_eq!(after, before);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_failed_transaction_does_not_refund() {
        for mode in [PartialCommitMode::Failed, PartialCommitMode::FailedVanilla] {
            let est = WorkEstimator::new(vec![(1, vec![(0, 10_000)])]);
            let (progress, mut b, mut w) = dense_tip_fixture(&est, 1);
            let p = std::sync::Arc::new(progress);
            p.note_work_rewind(10_501..11_001);
            assert!(!dense_suggest(
                &p,
                &mut b,
                &mut w,
                &est,
                Some(1),
                &[1..10_001, 10_501..11_001]
            ));
            commit_interrupted_prefix(&p, 10_501..10_751, mode).await;
            p.begin_pass();
            b = 0;
            w = 0;
            assert!(!dense_suggest(
                &p,
                &mut b,
                &mut w,
                &est,
                Some(1),
                &[1..10_001, 10_501..11_001]
            ));
            p.note_work_rewind(10_001..10_301);
            assert!(dense_suggest(
                &p,
                &mut b,
                &mut w,
                &est,
                Some(1),
                &[1..10_301, 10_501..11_001]
            ));
            let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
            assert_eq!(after, 478, "all 800 reopened blocks still need scanning");
            assert!(!dense_suggest(
                &p,
                &mut b,
                &mut w,
                &est,
                Some(1),
                &[1..10_301, 10_501..11_001]
            ));
            assert_eq!(
                derive_snapshot(&p, SyncState::Syncing).progress_permille,
                after
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_reopened_before_resuggestion_is_visible() {
        let est = uniform(10_000);
        let p = std::sync::Arc::new(Progress::default());
        p.set_chain_tip(10_000);
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(9_001..10_001)),
        );
        p.note_work_rewind(7_001..9_001);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(7_001..10_001))
        ));
        commit_interrupted_prefix(&p, 7_001..8_001, PartialCommitMode::Deferred).await;
        // Model the previously displayed earned share after this confirmed scan.
        // No ordinary suggestion has observed its shorter pending queue yet.
        p.permille_floor(800, PASS_UNIT_WORK);
        p.begin_pass();
        p.note_work_rewind(7_001..8_001);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(1),
            std::slice::from_ref(&(7_001..10_001))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            700
        );
    }

    // Diagnostic controls, not the production completion-notification path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn work_progress_partial_commit_explicit_completion_controls() {
        assert_eq!(
            dense_partial_commit_restart(true, PartialCommitMode::Deferred).await,
            500
        );
        assert_eq!(
            uniform_partial_commit_restart(true, PartialCommitMode::Deferred).await,
            700
        );
    }

    #[test]
    fn work_progress_no_proposal_ack_preserves_fractional_credit() {
        let a = WorkEstimator::new_for_test(vec![(1, vec![], vec![(1_300, 7_800)])]);
        let b = WorkEstimator::new_for_test(vec![(
            1,
            vec![],
            vec![(900, 4_400), (1_100, 6_600), (1_200, 7_200), (1_300, 7_800)],
        )]);
        let c = WorkEstimator::new_for_test(vec![(
            1,
            vec![],
            vec![(900, 5_390), (1_200, 7_200), (1_300, 7_800)],
        )]);
        let p = Progress::default();
        p.set_chain_tip(1_000);
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &a,
            Some(1),
            std::slice::from_ref(&(901..1_001)),
        );
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            900
        );
        p.set_chain_tip(1_100);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &a,
            Some(1),
            std::slice::from_ref(&(901..1_101))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            818
        );
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &a,
            Some(1),
            std::slice::from_ref(&(901..1_101))
        ));
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &b,
            Some(1),
            std::slice::from_ref(&(901..1_101))
        ));
        p.set_chain_tip(1_200);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &b,
            Some(1),
            std::slice::from_ref(&(901..1_201))
        ));
        let middle = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &c,
            Some(1),
            std::slice::from_ref(&(901..1_201))
        ));
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &b,
            Some(1),
            std::slice::from_ref(&(901..1_201))
        ));
        p.set_chain_tip(1_300);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &b,
            Some(1),
            std::slice::from_ref(&(901..1_301))
        ));
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        eprintln!("fractional acknowledgment: middle={middle}, after={after}, exact=692.307692");
        assert_eq!(after, 692);
    }

    #[test]
    fn work_progress_higher_raw_seed_settles_fractional_credit() {
        let a = WorkEstimator::new_for_test(vec![(1, vec![], vec![(1_300, 7_800)])]);
        let d = WorkEstimator::new_for_test(vec![(
            1,
            vec![],
            vec![(900, 5_410), (1_100, 6_600), (1_200, 7_200), (1_300, 7_800)],
        )]);
        let p = Progress::default();
        p.set_chain_tip(1_000);
        dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &a,
            Some(1),
            std::slice::from_ref(&(901..1_001)),
        );
        p.set_chain_tip(1_100);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &a,
            Some(1),
            std::slice::from_ref(&(901..1_101))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            818
        );
        // A truthful higher seed supports 819, independently of the old fraction.
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &d,
            Some(1),
            std::slice::from_ref(&(901..1_101))
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            819
        );
        p.set_chain_tip(1_184);
        assert!(dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &d,
            Some(1),
            std::slice::from_ref(&(901..1_185))
        ));
        // 819*11000/11840 = 760.895..., while stale fractional credit would yield761.
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            760
        );
    }

    // ── [API v2.1 E-3] truthful-from-open seed ─────────────────────────────────

    /// Open a wallet with one imported account (TEST_UFVK, birthday treestate at 663149)
    /// and the chain tip persisted at `tip`. Returns the session (birthday = 663150).
    fn wallet_with_account(dir: &tempfile::TempDir, tip: u64) -> WalletSession {
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(zcash_protocol::consensus::Network::MainNetwork, &path)
            .expect("open wallet");
        let ts = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(crate::wallet_session::TEST_UFVK, ts)
            .expect("import account");
        s.update_chain_tip(tip).expect("update tip");
        s
    }

    fn wallet_with_work_seed(dir: &tempfile::TempDir) -> WalletSession {
        let s = wallet_with_account(dir, 700_000);
        let conn = rusqlite::Connection::open(dir.path().join("data.db")).expect("side conn");
        // Persisted complete queue and completed subtree rows, using upstream's
        // existing schema exactly as the wallet estimator fixtures do.
        conn.execute("DELETE FROM scan_queue", [])
            .expect("complete queue");
        // Upstream derives persisted chain height from queue coverage, including
        // Scanned bookkeeping rows that are excluded from suggestions.
        conn.execute("INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES (663150, 700001, 10)", [])
            .expect("persist scanned coverage");
        conn.execute(
            "INSERT INTO sapling_tree_shards (shard_index, subtree_end_height) VALUES (0, 500000), (1, 600000)",
            [],
        ).expect("completed subtrees");
        s
    }

    #[test]
    fn work_progress_seeded_work_scope_accounts_for_first_import() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = wallet_with_work_seed(&dir);
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("persisted work seed");
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        assert_eq!(derive_snapshot(&p, SyncState::Idle).progress_permille, 1000);
        let birthday = zcash_client_backend::data_api::AccountBirthday::from_treestate(
            zcash_client_backend::proto::service::TreeState {
                network: "main".into(),
                height: 599_999,
                hash: "0".repeat(64),
                time: 1,
                ..Default::default()
            },
            None,
        )
        .expect("older birthday");
        s.db_mut()
            .create_account(
                "older account after persisted seed",
                &secrecy::SecretVec::new([7u8; 32].to_vec()),
                &birthday,
                None,
            )
            .expect("import older account");
        let est = s.build_work_estimator().expect("work estimator");
        let pending: Vec<_> = s
            .suggest_scan_ranges()
            .expect("expanded queue")
            .iter()
            .map(|r| u64::from(r.block_range().start)..u64::from(r.block_range().end))
            .collect();
        let birthday = s.min_birthday().expect("expanded birthday");
        assert_eq!(birthday, Some(600_000));
        p.begin_pass();
        let rebaselined = dense_suggest(&p, &mut 0, &mut 0, &est, birthday, &pending);
        let after = derive_snapshot(&p, SyncState::Syncing).progress_permille;
        let reopened: u64 = pending
            .iter()
            .map(|r| {
                let start = r.start.max(663_150);
                let end = r.end.min(700_001);
                if start < end {
                    est.range(start, end - 1)
                } else {
                    0
                }
            })
            .sum();
        let bound = ((1000u128 * u128::from(est.range(663_150, 700_000)))
            .saturating_sub(u128::from(reopened) * 1000)
            / u128::from(est.range(600_000, 700_000))) as u16;
        eprintln!("persisted WORK import: after={after}, bound={bound}, rebaselined={rebaselined}");
        assert!(rebaselined);
        assert_eq!(after, bound);
        assert!(after < 950);
        assert!(!dense_suggest(&p, &mut 0, &mut 0, &est, birthday, &pending));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            after
        );
    }

    #[test]
    fn work_progress_seeded_work_scope_refresh_without_growth_keeps_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = wallet_with_work_seed(&dir);
        let conn = rusqlite::Connection::open(dir.path().join("data.db")).expect("side conn");
        conn.execute(
            "UPDATE scan_queue SET block_range_end=680001 WHERE priority=10",
            [],
        )
        .expect("persist partially scanned coverage");
        conn.execute("INSERT INTO scan_queue (block_range_start, block_range_end, priority) VALUES (680001, 700001, 20)", [])
            .expect("persisted Historic work");
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("persisted work seed");
        assert_eq!(p.floor_unit(), PASS_UNIT_WORK);
        let before = derive_snapshot(&p, SyncState::Idle).progress_permille;
        conn.execute(
            "UPDATE sapling_tree_shards SET subtree_end_height=680000 WHERE shard_index=1",
            [],
        )
        .expect("refresh anchor");
        conn.execute(
            "INSERT INTO sapling_tree_shards (shard_index, subtree_end_height) VALUES (2, 699999)",
            [],
        )
        .expect("refresh density");
        let est = s.build_work_estimator().expect("refreshed estimator");
        let pending: Vec<_> = s
            .suggest_scan_ranges()
            .expect("same queue")
            .iter()
            .map(|r| u64::from(r.block_range().start)..u64::from(r.block_range().end))
            .collect();
        let work: u64 = pending.iter().map(|r| est.range(r.start, r.end - 1)).sum();
        let raw = global_floor_permille_work(700_000, Some(663_150), work, &est).unwrap();
        assert!(
            raw + 50 < u64::from(before),
            "density change must be material"
        );
        p.begin_pass();
        assert!(!dense_suggest(
            &p,
            &mut 0,
            &mut 0,
            &est,
            Some(663_150),
            &pending
        ));
        assert_eq!(
            derive_snapshot(&p, SyncState::Syncing).progress_permille,
            before
        );
    }

    /// A wallet with NO accounts seeds nothing — the zero snapshot is already truthful.
    #[test]
    fn seed_is_noop_on_fresh_wallet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let s = WalletSession::open(zcash_protocol::consensus::Network::MainNetwork, &path)
            .expect("open wallet");
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");
        assert_eq!(p.chain_tip.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(!p.recovering());
        assert_eq!(p.spendable(), 0);
        assert_eq!(
            p.progress_permille_floor
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// Never-scanned restore-shaped wallet: the seed reports the persisted tip, a truthful
    /// ~0 floor (the whole span is still queued), NOT recovering (no recover_until), and
    /// spendability mirroring whether a ChainTip/Verify range is still pending.
    #[test]
    fn seed_reports_persisted_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tip = 700_000u64;
        let s = wallet_with_account(&dir, tip);
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");

        assert_eq!(
            p.chain_tip.load(std::sync::atomic::Ordering::Relaxed),
            tip,
            "seed must surface the persisted chain tip"
        );
        assert!(!p.recovering(), "no recover_until ⇒ not recovering");
        assert_eq!(
            p.progress_permille_floor
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing scanned ⇒ truthful 0‰ floor (restore bar still climbs from 0)"
        );
        // Wiring proof: the spendable latch mirrors the actual queue contents.
        let ranges = s.suggest_scan_ranges().expect("ranges");
        let recent_pending = ranges.iter().any(|r| {
            matches!(
                r.priority(),
                ScanPriority::ChainTip | ScanPriority::Anchor | ScanPriority::Verify
            )
        });
        assert_eq!(
            p.spendable() == 1,
            !recent_pending,
            "spendable ⇔ no recent range pending"
        );
        // The seed must never bump the tip-REFRESH counter (persisted ≠ freshly proven).
        assert_eq!(p.tip_refreshes(), 0, "E-3 seed must not fake tip freshness");
    }

    /// With `recover_until_height` persisted (a restore in flight), queued ranges below it
    /// must seed `recovering = true` — the mid-restore relaunch case that used to lie 0.
    #[test]
    fn seed_detects_recovering_from_persisted_recover_until() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tip = 700_000u64;
        let s = wallet_with_account(&dir, tip);
        {
            let conn = rusqlite::Connection::open(dir.path().join("data.db")).expect("side conn");
            conn.execute("UPDATE accounts SET recover_until_height = ?1", [tip])
                .expect("set recover_until");
        }
        let p = Progress::default();
        seed_progress_from_wallet(&p, &s).expect("seed");
        assert!(
            p.recovering(),
            "queued ranges below recover_until must seed recovering=true from open"
        );
    }

    #[test]
    fn fetch_stats_totals_default_is_zero() {
        let t = FetchStatsTotals::default();
        assert_eq!(t.blocks, 0);
        assert_eq!(t.bytes, 0);
    }

    #[test]
    fn scan_stats_totals_default_is_zero() {
        let t = ScanStatsTotals::default();
        assert_eq!(t.blocks, 0);
        assert_eq!(t.sapling_received, 0);
        assert_eq!(t.orchard_received, 0);
    }

    #[test]
    fn reorgs_recovered_accumulates() {
        let mut report = SyncReport::default();
        assert_eq!(report.reorgs_recovered, 0);
        report.reorgs_recovered += 1;
        assert_eq!(report.reorgs_recovered, 1);
        report.reorgs_recovered += 1;
        assert_eq!(report.reorgs_recovered, 2);
    }

    // NOTE: MAX_CONSECUTIVE_REORGS bounds are enforced at compile time via the
    // `const _: () = { assert!(...) }` block next to the constant definition.

    /// B3 (#1755): backoff grows 500 ms per consecutive recovery and caps at 3 s.
    #[test]
    fn reorg_backoff_grows_and_caps() {
        assert_eq!(
            reorg_backoff_ms(0),
            0,
            "no recoveries -> no wait (unreachable in the arm)"
        );
        assert_eq!(reorg_backoff_ms(1), 500, "first recovery waits 500 ms");
        assert_eq!(reorg_backoff_ms(2), 1_000);
        assert_eq!(reorg_backoff_ms(5), 2_500, "the cap budget's last step");
        assert_eq!(reorg_backoff_ms(6), 3_000, "capped at 3 s");
        assert_eq!(
            reorg_backoff_ms(u64::MAX),
            3_000,
            "saturating mul + cap, no overflow"
        );
    }

    #[test]
    fn report_accumulates_correctly() {
        let mut report = SyncReport::default();
        report.ranges_processed += 1;
        report.fetch.blocks += 10_000;
        report.fetch.bytes += 1_024 * 1_024;
        report.scan.blocks += 9_500;
        report.scan.sapling_received += 3;
        report.scan.orchard_received += 7;

        assert_eq!(report.ranges_processed, 1);
        assert_eq!(report.fetch.blocks, 10_000);
        assert_eq!(report.fetch.bytes, 1_024 * 1_024);
        assert_eq!(report.scan.blocks, 9_500);
        assert_eq!(report.scan.sapling_received, 3);
        assert_eq!(report.scan.orchard_received, 7);

        // Second range accumulation.
        report.ranges_processed += 1;
        report.fetch.blocks += 5_000;
        report.scan.blocks += 5_000;
        assert_eq!(report.ranges_processed, 2);
        assert_eq!(report.fetch.blocks, 15_000);
        assert_eq!(report.scan.blocks, 14_500);
    }

    /// F3: EnhanceStats fields in SyncReport accumulate correctly across multiple ranges.
    #[test]
    fn enhance_stats_accumulate_across_ranges() {
        let mut report = SyncReport::default();

        // Simulate per-range enhancement for range 1.
        report.enhance.requests += 5;
        report.enhance.txs_stored += 2;
        report.enhance.statuses_set += 1;
        report.enhance.skipped += 0;

        assert_eq!(report.enhance.requests, 5);
        assert_eq!(report.enhance.txs_stored, 2);
        assert_eq!(report.enhance.statuses_set, 1);
        assert_eq!(report.enhance.skipped, 0);

        // Simulate per-range enhancement for range 2.
        report.enhance.requests += 3;
        report.enhance.txs_stored += 1;
        report.enhance.statuses_set += 2;
        report.enhance.skipped += 1;

        assert_eq!(
            report.enhance.requests, 8,
            "requests must sum across ranges"
        );
        assert_eq!(
            report.enhance.txs_stored, 3,
            "txs_stored must sum across ranges"
        );
        assert_eq!(
            report.enhance.statuses_set, 3,
            "statuses_set must sum across ranges"
        );
        assert_eq!(report.enhance.skipped, 1, "skipped must sum across ranges");
    }

    // ── AbortOnDrop: an orphaned fetch task must not keep running ──────────────

    /// Dropped before it is ever awaited, the wrapper must stop the wrapped task instead of
    /// leaving it to run detached — the exact shape of the bug where an orphaned fetch task
    /// kept running after its session was abandoned and recorded a give-up into the NEXT
    /// session's fresh `Progress` count.
    #[tokio::test(start_paused = true)]
    async fn abort_on_drop_stops_the_task_before_it_sets_its_flag() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_in_task = flag.clone();
        let task = AbortOnDrop(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            flag_in_task.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        drop(task);
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(
            !flag.load(std::sync::atomic::Ordering::SeqCst),
            "the aborted task must never set the flag"
        );
    }
}

#[test]
fn empty_first_pass_then_work_seed_rebaselines() {
    // Empty first pass (e.g. synced wallet, cold start, run_to_completion before update_pass_progress)
    // stores floor_unit = UNSET. Importing an older account then seeds in WORK must re-baseline.
    use crate::events::{PASS_UNIT_UNSET, PASS_UNIT_WORK, Progress};
    use crate::ffi_handle::{SyncState, derive_snapshot};

    let p = Progress::default();

    // Empty first pass: Done immediately, pass_unit stays UNSET.
    // derive_snapshot calls permille_floor(1000, UNSET) which should store floor using floor's own unit.
    p.begin_pass();
    assert_eq!(p.pass_unit(), PASS_UNIT_UNSET);
    let _ = derive_snapshot(&p, SyncState::Done);

    // Floor is now 1000, floor_unit should be UNSET (since pass_unit was UNSET).
    // But derive_snapshot must have used floor's own unit, so floor_unit should still allow seeds.

    // Import an older account: WORK seed at 300‰ must re-baseline (not blocked by unit mismatch).
    assert!(p.rebaseline_floor_if_scope_expanded(300, PASS_UNIT_WORK));
    assert_eq!(
        p.progress_permille_floor
            .load(std::sync::atomic::Ordering::Relaxed),
        300
    );
}

#[test]
fn unit_guard_one_directional() {
    // BLOCKS seed rejected against WORK floor (transient failure).
    // WORK seed can re-baseline BLOCKS floor.
    use crate::events::{PASS_UNIT_BLOCKS, PASS_UNIT_WORK, Progress};

    let p = Progress::default();

    // WORK floor at 900‰.
    let _ = p.permille_floor(900, PASS_UNIT_WORK);

    // BLOCKS seed at 700‰: rejected (one-directional guard).
    assert!(!p.rebaseline_floor_if_scope_expanded(700, PASS_UNIT_BLOCKS));
    assert_eq!(
        p.progress_permille_floor
            .load(std::sync::atomic::Ordering::Relaxed),
        900
    );

    // WORK seed at 950‰: advances normally (same unit).
    let _ = p.permille_floor(950, PASS_UNIT_WORK);
    assert_eq!(
        p.progress_permille_floor
            .load(std::sync::atomic::Ordering::Relaxed),
        950
    );

    // Start fresh with BLOCKS floor.
    let p2 = Progress::default();
    let _ = p2.permille_floor(800, PASS_UNIT_BLOCKS);

    // WORK seed at 300‰: CAN re-baseline BLOCKS floor (one-directional allows this).
    assert!(p2.rebaseline_floor_if_scope_expanded(300, PASS_UNIT_WORK));
    assert_eq!(
        p2.progress_permille_floor
            .load(std::sync::atomic::Ordering::Relaxed),
        300
    );
}
