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

use tracing::{info, warn};
use zcash_client_backend::data_api::{WalletWrite, scanning::ScanPriority};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    chunk::chunk_queue,
    config::EngineConfig,
    connector::{ConnPurpose, TorConn, connect_via},
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    fetch::{FetchPlan, FetchStats, run_fetch},
    scan::{ScanStats, scan_chunks},
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

/// [h16-1] One suggest round's progress bookkeeping: set the pass total and seed/re-baseline
/// the session floor + pass start from the GLOBAL seed. Extracted from the `run_to_completion`
/// loop body (behaviour unchanged by the extraction itself) so it can be driven directly in
/// tests without a live fetch/scan pass — everything here is pure atomic bookkeeping over an
/// already-known range-length sum, no network I/O. Reads `p.chain_tip()` live, like the inline
/// block it replaces. Returns whether this round re-baselined the session floor (test hook;
/// `run_to_completion` ignores it).
pub(crate) fn update_pass_progress(
    p: &Progress,
    scanned_so_far_in_pass: &mut u64,
    sum_remaining: u64,
    wallet_birthday: Option<u64>,
) -> bool {
    // [h16-1] Snapshot the pass-local blend baseline BEFORE the pass total is set: from
    // this moment, `derive_snapshot` reads `fetched()`/`scanned()` relative to this
    // baseline instead of raw, so blocks already credited to `scanned_so_far_in_pass`
    // (this pass's completed-range tally) are not counted a second time against the new
    // total. At this instant the pass-local counters equal the work the pass has credited.
    p.set_pass_baseline(
        p.fetched().saturating_sub(*scanned_so_far_in_pass),
        p.scanned().saturating_sub(*scanned_so_far_in_pass),
    );
    p.set_pass_total(*scanned_so_far_in_pass + sum_remaining);
    // [API v2 §4.4 / Phase E] Seed the session-monotonic floor with the GLOBAL position.
    // fetch_max semantics: the seed can only RAISE the floor, and re-seeding every suggest
    // round tracks global progress as ranges complete. Two behaviours fall out for free:
    // a cold-launch catch-up starts at ~99.9% instead of flashing 0% (the old Swift
    // summary floor), and a relaunched restore RESUMES near its true position instead of
    // 0% (the old Swift monotonic floor could not survive a relaunch).
    let Some(seed) = global_floor_permille(p.chain_tip(), wallet_birthday, sum_remaining) else {
        return false;
    };
    // [API v2.1 E-5] Scope-expansion re-baseline: an imported account with an
    // older birthday (or a rewind) grows the span under the session floor —
    // without this, the ~1000 floor from the previous scope's Done would mask
    // the whole re-scan at ~100% (the host used to bypass every floor with
    // `forceCounterProgressUntilDone`; the blessed permille now reads the
    // genuine climb by itself).
    let rebaselined = p.rebaseline_floor_if_scope_expanded(seed);
    if rebaselined {
        info!(
            seed,
            birthday = wallet_birthday,
            "scan scope expanded — session progress floor re-baselined (re-scan reads as a genuine climb)"
        );
        // [h10] The pass start follows the re-baseline: the scope grew UNDER
        // this running pass, so the pass's own progress must stretch from the
        // re-baselined position too, or it would still stretch from the stale
        // pre-expansion start and under-report the re-scan's climb.
        p.set_pass_start_permille(seed);
        // [h16-1] The new start already includes everything credited so far: fold the
        // pass-local accumulator back to 0 and re-snapshot the baseline to the CURRENT
        // counters, so the next blend reads 0 pass-local progress against the fresh
        // `sum_remaining`-only total below, instead of replaying the pre-expansion
        // credit a second time against the new (smaller, re-baselined) denominator.
        *scanned_so_far_in_pass = 0;
        p.set_pass_baseline(p.fetched(), p.scanned());
        p.set_pass_total(sum_remaining);
    } else {
        // [h10] First suggest round of the pass latches the start; later rounds
        // of the same pass keep it — the pass's reported progress is measured
        // from where the GLOBAL position stood when the pass began.
        p.set_pass_start_permille_if_unset(seed);
    }
    let _ = p.permille_floor(seed);
    rebaselined
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

    let recent_pending = ranges
        .iter()
        .any(|r| matches!(r.priority(), ScanPriority::ChainTip | ScanPriority::Verify));
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
    if let Some(seed) = global_floor_permille(tip, Some(birthday), sum_remaining) {
        let _ = progress.permille_floor(seed);
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
    /// Total wall-clock time spent in per-range run_enhancement calls (F3).
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
/// run update_chain_tip + put_subtree_roots (engine.rs).
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
    // Counter for back-to-back ScanContinuity recoveries without a successful range.
    // Reset to 0 on any successful range completion. Capped at MAX_CONSECUTIVE_REORGS
    // to prevent infinite ping-pong (e.g. adversarial server or database corruption).
    let mut consecutive_reorgs: u64 = 0;
    // F1: track blocks scanned so far in this pass (local accumulator).
    // Used to compute the whole-pass denominator: scanned_so_far + sum(remaining ranges).
    let mut scanned_so_far_in_pass: u64 = 0;
    // [API v2 §4.4] The wallet's recovery ceiling, read once per pass: the snapshot's
    // `is_recovering` is true while any suggested range still starts below it (the restore
    // backfill window). A read failure degrades to "not recovering" rather than failing the
    // pass — the flag is presentation state, never correctness state.
    let recover_until: Option<u64> = session.max_recover_until().unwrap_or_default();
    // [API v2 §4.4 / Phase E] The wallet's oldest birthday, read once per pass alongside the
    // recovery ceiling: with the chain tip and the remaining queue it seeds the global permille
    // floor each suggest round (below). A read failure degrades to "no seed" — presentation
    // state, never correctness state.
    let wallet_birthday: Option<u64> = session.min_birthday().unwrap_or_default();
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
            let sum_remaining: u64 = ranges
                .iter()
                .map(|r| {
                    let s = u64::from(r.block_range().start);
                    let e = u64::from(r.block_range().end);
                    e.saturating_sub(s)
                })
                .sum();
            update_pass_progress(
                p,
                &mut scanned_so_far_in_pass,
                sum_remaining,
                wallet_birthday,
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

        let (mut tx, rx) = chunk_queue(config.memory_budget_bytes);
        // v0.5 pacer fix: boundary treestate fetches start when the chunk is
        // EMITTED (fetch side), so the RTT hides under queue wait + scan
        // instead of racing one scan call (P1: that overhang was 62 % of the
        // Mac scan wall on a slow-treestate day).
        {
            let ep = config.endpoint.clone();
            let tor_owned = tor.cloned();
            let boundary_progress = progress.clone();
            tx.set_boundary_fetcher(std::sync::Arc::new(move |end_height| {
                let ep = ep.clone();
                let tor_owned = tor_owned.clone();
                let progress = boundary_progress.clone();
                tokio::spawn(async move {
                    crate::grpc::retry_get_tree_state(
                        &ep,
                        end_height,
                        "boundary prefetch (fetch-side)",
                        tor_owned.as_ref(),
                        progress,
                    )
                    .await
                })
            }));
        }
        let mut plan = FetchPlan::new(start, end, config.chunk_blocks, config.fetch_streams);
        // T6.8-S: byte-budgeted sub-chunk splitting (sandblasting-era survival).
        plan.split_bytes = config.chunk_split_bytes;
        // [v0.7 P2] Arm the wire-collapse detector only when the engine has
        // somewhere to fail over TO (and the kill switch is on). Tor passes
        // never have alternates armed (the probe is skipped there too).
        if config.wire_failover && !config.alternate_endpoints.is_empty() {
            plan.failover = Some(crate::fetch::WireFailoverArm::default());
        }
        let endpoint = config.endpoint.clone();
        // Clone the progress Arc for the fetch task so it can bump fetched_blocks.
        let fetch_progress = progress.clone();

        // Spawn the fetch task so it runs concurrently with scan_chunks below.
        // The tx is moved into the task; when the task finishes, tx is dropped, which
        // closes the channel and causes scan_chunks's rx.recv() loop to terminate.
        // Wrapped in AbortOnDrop: if `connect_via` below fails (`?` returns early) or this
        // whole future is dropped (a host restart aborts the session, not this task), the
        // fetch task is aborted instead of orphaned (see `AbortOnDrop`'s doc).
        let fetch_task = AbortOnDrop(tokio::spawn(async move {
            run_fetch(&endpoint, plan, tx, fetch_progress).await
        }));

        // scan_chunks runs in the current task using a SEPARATE grpc client so it
        // does not contend with the fetch workers' connections.
        let mut scan_client =
            connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;

        let scan_started = std::time::Instant::now();
        let scan_result: Result<ScanStats, SlipstreamError> = scan_chunks(
            session,
            &mut scan_client,
            start,
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

            // truncate_to_height returns Result<BlockHeight, WalletDb::Error>
            // (data_api.rs:3233: `fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error>`)
            session
                .db_mut()
                .truncate_to_height(BlockHeight::from(rewind_height))
                .map_err(|e| SlipstreamError::Wallet(format!("truncate_to_height: {e}")))?;

            // [h16-2] The truncate discards blocks above rewind_height, but the blocks
            // BELOW it (the surviving prefix of the aborted range) are still done — credit
            // them now so the next suggest round's baseline snapshot (h16-1) folds them
            // into scanned_so_far_in_pass instead of leaving pass_total cover only the
            // small repair range while fetched/scanned still hold the whole aborted range.
            scanned_so_far_in_pass +=
                scan_continuity_repair_credit(start, end_exclusive, u64::from(rewind_height));

            report.reorgs_recovered += 1;
            if let Some(ref p) = progress {
                p.add_reorg();
            }

            // B3 (#1755): give a desynced load-balanced cluster a heal window before
            // retrying — see reorg_backoff_ms. Connection freshness on retry is
            // structural, not added here: the next loop iteration creates a NEW
            // scan-side client (grpc::connect per range, above) and run_fetch spawns
            // NEW per-worker connections (fetch.rs worker() connects per worker, per
            // range) — no gRPC channel survives into the retry, so the retry cannot
            // be pinned to the same stale backend.
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
                    warn!(%fetch_err, "fetch task also errored (secondary, scan error takes precedence)");
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

        // Spendable latch: if this range was ChainTip priority, funds are now likely
        // spendable (SBS semantics — the tip-priority range covers the most-recent
        // blocks where the wallet's own notes appear as spendable).
        if range.priority() == ScanPriority::ChainTip
            && let Some(ref p) = progress
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
        // separately. We reuse a fresh gRPC client per call (same pattern as engine.rs).
        //
        // NON-FATAL: interleaved enhancement is an optimization (progressive tx
        // visibility), not a correctness guarantee — that is the final post-loop run's
        // job. A transient connect/fetch failure here must NOT abort a multi-minute
        // sync at a range boundary; we log and continue scanning.
        {
            let enhance_started = std::time::Instant::now();
            let enhance_result = async {
                let mut enhance_client =
                    connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;
                run_enhancement(
                    session,
                    &mut enhance_client,
                    config.network,
                    progress.clone(),
                    skipped_keys,
                )
                .await
            }
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
        let rebaselined =
            update_pass_progress(&p, &mut scanned_so_far_in_pass, 1_000_000, Some(B1));
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
        let rebaselined =
            update_pass_progress(&p, &mut scanned_so_far_in_pass, 1_100_000, Some(B0));
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
        let rebaselined_again =
            update_pass_progress(&p, &mut scanned_so_far_in_pass, 1_100_000, Some(B0));
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
        update_pass_progress(&p, &mut scanned_so_far_in_pass, end_exclusive - start, None);
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
        update_pass_progress(&p, &mut scanned_so_far_in_pass, 1_010, None);
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
        let recent_pending = ranges
            .iter()
            .any(|r| matches!(r.priority(), ScanPriority::ChainTip | ScanPriority::Verify));
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
