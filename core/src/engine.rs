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

//! Engine v0: one full sync pass (preflight → chain state → scheduler → enhancement).
//! P3 adds enhancement/transparent/events; P4 wraps this behind FFI.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{info, warn};

use crate::{
    config::{Endpoint, EngineConfig},
    connector::{ConnPurpose, TorConn, connect_via},
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    grpc,
    scheduler::{SyncReport, run_to_completion},
    transparent::{TransparentStats, refresh_utxos},
    wallet_session::WalletSession,
};

/// Engine build tag, logged at every sync start and in the stage-split line.
/// BUMP THIS on every performance-relevant engine change (anything that warrants a
/// framework rebuild) — it is the definitive freshness check for device logs: if the
/// tag in the log doesn't match HEAD's value, the device is running a stale
/// XCFramework (the three-layer gotcha, consuming side). Probe a built slice with:
/// `strings <slice>/libzcashlc.framework/libzcashlc | grep <tag>`.
pub const ENGINE_BUILD: &str = "2026-07-08.v07-wire-p2";

/// [v0.7 P2] Mid-pass endpoint switches allowed per pass before the
/// detector disarms and the pass grinds to completion (the all-sick
/// guarantee). Each switch costs a drain + ~1.2 s re-probe, resuming from
/// the wallet DB.
const MAX_WIRE_SWITCHES: u32 = 2;

/// Current wall-clock time as a `YYYY-MM-DD HH:MM:SSZ` UTC string.
///
/// Logged at pass start, in the stage-split line, and on runner failure so a
/// long-running device/simulator sync can be timed from the log alone — no need
/// to remember when it was started. No external date dependency: civil-from-days
/// per Howard Hinnant's algorithm, unit-tested against known epochs.
pub fn wall_clock_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

/// Format a unix timestamp (seconds) as `YYYY-MM-DD HH:MM:SSZ` (UTC).
fn format_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // Civil-from-days (Hinnant): days since 1970-01-01 → (y, m, d) in the
    // proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(month <= 2);
    format!("{y:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

#[derive(Debug)]
pub struct SyncOutcome {
    pub report: SyncReport,
    pub enhance: EnhanceStats,
    pub transparent: TransparentStats,
    /// Total wall-clock time for the `run_enhancement` call.
    pub enhance_elapsed: std::time::Duration,
    pub elapsed: std::time::Duration,
    pub chain_tip: u64,
}

impl SyncOutcome {
    /// Returns the name of the stage that consumed the most wall-clock time:
    /// `"fetch"`, `"scan"`, `"enhance"`, or `"idle"` if all stages are < 1 s.
    ///
    /// Used for honest G5 "bound" reporting (Decision-Log requirement, 2026-06-10).
    /// F3: `enhance_elapsed` is now the SUM of all per-range runs + the final post-loop run.
    pub fn bound(&self) -> &'static str {
        let fetch_s = self.report.fetch_elapsed.as_secs_f64();
        let scan_s = self.report.scan_elapsed.as_secs_f64();
        let enhance_s = self.enhance_elapsed.as_secs_f64();

        // Threshold: stages < 1 s on a real sync are noise.
        if fetch_s < 1.0 && scan_s < 1.0 && enhance_s < 1.0 {
            return "idle";
        }

        if fetch_s >= scan_s && fetch_s >= enhance_s {
            "fetch"
        } else if scan_s >= enhance_s {
            "scan"
        } else {
            "enhance"
        }
    }
}

/// True when an observed server tip justifies a new follow pass (T8.1).
///
/// A server replying with a LOWER tip than the last synced one (load-balanced
/// cluster lag) must NOT trigger a pass — the pass would no-op at best and
/// fight reorg logic at worst; the next probe of a caught-up backend recovers.
pub fn should_resync(last_synced_tip: u64, observed_tip: u64) -> bool {
    observed_tip > last_synced_tip
}

/// One cheap tip probe (T8.1 fast path): connect + GetLatestBlock ONLY —
/// none of the preflight work of a full pass (subtree roots, UTXO refresh).
///
/// Fresh connection per probe (TLS ~100-300 ms every FOLLOW_POLL; a held
/// connection would need its own keepalive/staleness handling). All awaits
/// carry the hardening1 deadlines (connect 10 s, unary 30 s).
pub async fn probe_tip(
    config: &EngineConfig,
    tor: Option<&TorConn>,
) -> Result<u64, SlipstreamError> {
    let mut client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;
    grpc::get_latest_block_height(&mut client).await
}

/// One sync pass. If `ufvk` is Some and the wallet has no accounts, imports it
/// with a birthday at `birthday_height` (treestate fetched from the server at
/// `birthday_height - 1`).
///
/// `progress` — optional shared progress state for poll-based consumers (decision D8).
/// Pass `Some(Arc::new(Progress::default()))` to receive live counter updates;
/// `None` for no-op (default in all tests and the darkside suite).
/// The `chain_tip` and `current_range_end` fields are set by the engine;
/// `fetched_blocks` / `scanned_blocks` / `enhanced_txs` are bumped during the pipeline.
///
/// # Deviation from plan draft
/// The plan does not guard against `birthday_height == 0`. Since `birthday_height`
/// is u64, `birthday_height - 1` would underflow for 0. We guard here and return
/// a Config error; a birthday of 0 is never valid for a mainnet/testnet wallet.
pub async fn sync_once(
    config: &EngineConfig,
    ufvk: Option<(&str, u64)>,
    progress: Option<Arc<Progress>>,
    tor: Option<&TorConn>,
) -> Result<SyncOutcome, SlipstreamError> {
    config.validate()?;

    // Early guard: birthday_height == 0 would underflow (birthday_height - 1) below.
    // A birthday of 0 is never valid for mainnet/testnet. Check here, before any I/O,
    // so the error is a clean Config failure regardless of network availability.
    // (u64 subtraction wraps in release builds without overflow checks — guard is required.)
    if let Some((_, 0)) = ufvk {
        return Err(SlipstreamError::Config(
            "birthday_height must be >= 1 (height 0 is not a valid wallet birthday)".into(),
        ));
    }

    let started = Instant::now();

    // Reset per-pass ratio counters (scanned/fetched/pass_total/range_end/spendable).
    // The FFI handle — and therefore this Progress — outlives individual passes
    // (Swift opens it once in prepare(); stop()/start() reuse it across app
    // background/foreground cycles), so stale pass-1 counters would corrupt pass-2's
    // scanned/pass_total ratio. Monotonic delta counters (enhanced_txs,
    // ranges_completed, reorgs_recovered) are deliberately left untouched.
    if let Some(ref p) = progress {
        p.begin_pass();
    }

    // Definitive device-log freshness marker (see ENGINE_BUILD doc).
    info!(
        engine_build = ENGINE_BUILD,
        sparse = config.sparse_persistence,
        write_behind = config.write_behind,
        gpu_subtree = config.gpu_subtree,
        graft_subtree = config.graft_subtree,
        batch_combine = config.batch_combine,
        batch_decrypt = config.batch_decrypt,
        endo_mul = config.endo_mul,
        local_treestate = config.local_treestate,
        started_at_utc = %wall_clock_utc(),
        "engine pass starting"
    );
    // v0.5 C1: the forked orchard's batched-DH kernel is a process-global
    // toggle (the swap point is a trait impl with no config channel).
    crate::vendor_shim::set_batch_dh_enabled(config.batch_decrypt);
    // v0.5 C2: GLV endomorphism per-item multiplication (same toggle pattern).
    crate::vendor_shim::set_endo_enabled(config.endo_mul);
    // v0.6 P2: persist-lane totals are process-cumulative atomics — snapshot
    // here so the pass-end log reports THIS pass's delta.
    let persist_lane_start = crate::persist::lane_stats::totals();

    // [v0.7 P1] Probe-then-commit: with alternates configured, race every
    // endpoint (~1 s shared budget: tip + timed ~100-block sample) and
    // commit the winner for THIS pass. The rest of the engine reads the
    // chosen endpoint through a config clone, so every downstream consumer
    // (metadata client, scheduler fetch, treestate prefetch, enhance)
    // transparently follows. No alternates = the pre-v0.7 single-server
    // path, zero cost. Tor passes SKIP the probe: `probe_endpoints` dials
    // direct, which would bypass the Tor circuit — a privacy leak, not a
    // ranking.
    let probed_config;
    let (config, wire_probe_ms) = if config.alternate_endpoints.is_empty() || tor.is_some() {
        (config, 0.0)
    } else {
        let mut endpoints = Vec::with_capacity(1 + config.alternate_endpoints.len());
        endpoints.push(config.endpoint.clone());
        endpoints.extend(config.alternate_endpoints.iter().cloned());
        let outcome = crate::probe::probe_endpoints(&endpoints, Duration::from_millis(1200)).await;
        info!(
            chosen = outcome.chosen,
            host = endpoints[outcome.chosen].host.as_str(),
            port = endpoints[outcome.chosen].port,
            probe_ms = outcome.elapsed.as_millis() as u64,
            "wire probe committed"
        );
        let mut c = config.clone();
        c.endpoint = endpoints[outcome.chosen].clone();
        probed_config = c;
        (&probed_config, outcome.elapsed.as_secs_f64() * 1e3)
    };

    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;

    if let Some((ufvk_str, birthday_height)) = ufvk {
        let birthday_ts = grpc::get_tree_state(&mut client, birthday_height - 1).await?;
        session.ensure_account(ufvk_str, birthday_ts)?;
    }

    let roots = grpc::get_subtree_roots(&mut client).await?;
    session.put_subtree_roots(&roots)?;

    let tip = grpc::get_latest_block_height(&mut client).await?;
    session.update_chain_tip(tip)?;
    info!(tip, "chain tip updated");

    // Advertise the chain tip to poll-based consumers, and record the refresh FACT —
    // [E-2] `update_chain_tip` just succeeded, so this run has proven the wallet-DB tip
    // (the FFI `tip_fresh` latch keys on this counter, not on the tip value changing).
    if let Some(ref p) = progress {
        p.set_chain_tip(tip);
        p.note_tip_refreshed();
    }

    // Transparent UTXO refresh — runs BEFORE the shielded scan loop, mirroring upstream
    // sync.rs:108-121 ("We do this before we perform any shielded scanning, to ensure
    // that we discover any UTXOs between the old fully-scanned height and the current
    // chain tip.").
    let transparent = refresh_utxos(&mut session, &mut client).await?;

    // T6.1: per-pass dedupe set for TransactionsInvolvingAddress skip keys.
    // Scope = one sync pass (all interleaved/per-range/final runs share it).
    let mut skipped_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    // [v0.7 P2] Failover loop: WireCollapse (raised by the fetch detector,
    // and ONLY when armed — alternates present + wire_failover on) cools the
    // offending endpoint, re-probes the remainder, and re-runs; the
    // scheduler resumes from the wallet DB, so a switch costs the drain +
    // probe (~2–3 s), never progress. After MAX_WIRE_SWITCHES the detector
    // is DISARMED and the pass grinds to completion on the best-known
    // endpoint — the all-sick guarantee: completion beats speed. Tor passes
    // never arm (the re-probe dials direct, which would bypass the circuit).
    let mut attempt_config = config.clone();
    if tor.is_some() {
        attempt_config.wire_failover = false;
    }
    let mut wire_switches: u32 = 0;
    let mut cooled: Vec<Endpoint> = Vec::new();
    let report = loop {
        let attempt = run_to_completion(
            &attempt_config,
            &mut session,
            progress.clone(),
            &mut skipped_keys,
            tor,
        )
        .await;
        match attempt {
            Err(SlipstreamError::WireCollapse {
                measured_mbps,
                floor_mbps,
            }) => {
                wire_switches += 1;
                warn!(
                    measured_mbps = format!("{measured_mbps:.2}").as_str(),
                    floor_mbps = format!("{floor_mbps:.2}").as_str(),
                    from = attempt_config.endpoint.host.as_str(),
                    switch = wire_switches,
                    "wire collapse — failing over"
                );
                cooled.push(attempt_config.endpoint.clone());
                let mut candidates: Vec<Endpoint> = std::iter::once(config.endpoint.clone())
                    .chain(config.alternate_endpoints.iter().cloned())
                    .filter(|e| !cooled.contains(e))
                    .collect();
                if candidates.is_empty() {
                    // Everything configured has collapsed at least once this
                    // pass — clear the cooldown and pick among the others.
                    cooled.clear();
                    candidates = std::iter::once(config.endpoint.clone())
                        .chain(config.alternate_endpoints.iter().cloned())
                        .filter(|e| *e != attempt_config.endpoint)
                        .collect();
                }
                let next = if candidates.len() == 1 {
                    candidates.remove(0)
                } else {
                    let outcome =
                        crate::probe::probe_endpoints(&candidates, Duration::from_millis(1200))
                            .await;
                    candidates.swap_remove(outcome.chosen)
                };
                info!(
                    to = next.host.as_str(),
                    port = next.port,
                    "wire failover committed"
                );
                attempt_config.endpoint = next;
                if wire_switches >= MAX_WIRE_SWITCHES {
                    attempt_config.wire_failover = false;
                    info!(
                        switches = wire_switches,
                        "wire failover budget spent — detector disarmed for the remainder"
                    );
                }
            }
            other => break other?,
        }
    };

    // Final enhancement: fetch full tx data for any remaining TransactionDataRequests
    // that were not caught by the per-range enhancement (F3 cleanup run). This is cheap
    // on a wallet with few remaining requests (typically zero after per-range runs).
    // Stats are merged into the report's `enhance` field so the stage-split log
    // reports total enhancement time (per-range runs + this final run) correctly.
    let enhance_started = Instant::now();
    let final_enhance = run_enhancement(
        &mut session,
        &mut client,
        config.network,
        progress.clone(),
        &mut skipped_keys,
    )
    .await?;
    let final_enhance_elapsed = enhance_started.elapsed();

    // F3: merge final enhancement stats into report so the total is correct.
    let mut report = report;
    report.enhance.requests += final_enhance.requests;
    report.enhance.txs_stored += final_enhance.txs_stored;
    report.enhance.statuses_set += final_enhance.statuses_set;
    report.enhance.skipped += final_enhance.skipped;
    report.enhance.fetch_wait += final_enhance.fetch_wait;
    report.enhance.store += final_enhance.store;
    report.enhance.address += final_enhance.address;
    // Total enhance_elapsed = per-range elapsed (in report) + final run elapsed.
    let total_enhance_elapsed = report.enhance_elapsed + final_enhance_elapsed;

    // Expose the merged enhance stats and total elapsed via SyncOutcome.
    let enhance = report.enhance.clone();
    let enhance_elapsed = total_enhance_elapsed;

    let outcome = SyncOutcome {
        report,
        enhance,
        transparent,
        enhance_elapsed,
        elapsed: started.elapsed(),
        chain_tip: tip,
    };

    // Log the stage split: total time + per-stage breakdown + bound.
    // F3: enhance_s is now the SUM of all per-range runs + the final post-loop run.
    // T6.6: sparse field added so log clearly shows which persistence path ran.
    // T6.9 (write-behind semantics): scan_s stays the HONEST scan-loop wall time —
    // with write_behind=true it still INCLUDES persist_wait_s (time the loop
    // blocked on a previous deferred commit). The two added fields keep the split
    // interpretable: persist_wait_s ≈ 0 means perfect overlap; persist_overlap_s
    // = persist_busy − persist_wait (clamped ≥0) is the commit work that ran
    // HIDDEN under decryption instead of serialized after it. Both are 0 with
    // the flag off. The per-chunk rows/tree/flush attribution stays inside the
    // deferred commit's own "sparse put_blocks" line (persist.rs), unchanged.
    let persist_wait_s = outcome.report.persist_wait_elapsed.as_secs_f64();
    let persist_busy_s = outcome.report.persist_busy_elapsed.as_secs_f64();
    info!(
        total_s = outcome.elapsed.as_secs_f64(),
        fetch_s = outcome.report.fetch_elapsed.as_secs_f64(),
        scan_s = outcome.report.scan_elapsed.as_secs_f64(),
        enhance_s = outcome.enhance_elapsed.as_secs_f64(),
        persist_wait_s,
        persist_overlap_s = (persist_busy_s - persist_wait_s).max(0.0),
        blocks = outcome.report.scan.blocks,
        bound = outcome.bound(),
        engine_build = ENGINE_BUILD,
        finished_at_utc = %wall_clock_utc(),
        sparse = config.sparse_persistence,
        write_behind = config.write_behind,
        "sync stage split"
    );

    // [v0.7 P0] Wire health: the server's side of the ledger. avg = pass
    // bytes over fetch wall; worst_5s = the deepest sustained trough across
    // ranges (the collapse-detection signal P2 will act on). The 2026-07-08
    // ship-day evidence this instruments: a 10× same-morning provider swing
    // (1.5 → 14.7 MB/s) with the engine's own variance at ±3%.
    let wire_fetch_s = outcome.report.fetch_elapsed.as_secs_f64();
    let wire_mbps_avg = if wire_fetch_s > 0.0 {
        outcome.report.wire_bytes as f64 / (1024.0 * 1024.0) / wire_fetch_s
    } else {
        0.0
    };
    info!(
        wire_mbps_avg = format!("{wire_mbps_avg:.2}").as_str(),
        wire_worst_5s_mbps = format!("{:.2}", outcome.report.wire_worst_window_mbps).as_str(),
        wire_mb = outcome.report.wire_bytes / (1024 * 1024),
        "wire health"
    );

    // v0.4 P0 (spec §3): shard census on the pass record — `graftable` PREDICTS
    // Plan A's ceiling for this wallet before the graft exists.
    info!(
        sapling_shards = outcome.report.census_sapling.shards(),
        sapling_noted = outcome.report.census_sapling.noted_shards(),
        sapling_graftable = outcome.report.census_sapling.graftable_fraction(),
        orchard_shards = outcome.report.census_orchard.shards(),
        orchard_noted = outcome.report.census_orchard.noted_shards(),
        orchard_graftable = outcome.report.census_orchard.graftable_fraction(),
        "shard census"
    );

    // v0.5 pacer split (plan §3): the scan lane's wall decomposed. The residue
    // (scan_s minus everything measured) is bookkeeping between the timed spans
    // — a large residue is itself a finding.
    let scan_split = &outcome.report;
    let scan_split_sum = scan_split.scan_recv_wait
        + scan_split.scan_call
        + scan_split.scan_prefetch_wait
        + scan_split.scan_interleave_drain
        + scan_split.scan_final_drain
        + scan_split.scan_absorb
        + scan_split.scan_state_prep
        + scan_split.scan_prefetch_spawn
        + scan_split.scan_submit_wait
        + scan_split.scan_submit_extra
        + scan_split.scan_reseed;
    info!(
        recv_wait_s = scan_split.scan_recv_wait.as_secs_f64(),
        scan_call_s = scan_split.scan_call.as_secs_f64(),
        prefetch_wait_s = scan_split.scan_prefetch_wait.as_secs_f64(),
        interleave_drain_s = scan_split.scan_interleave_drain.as_secs_f64(),
        final_drain_s = scan_split.scan_final_drain.as_secs_f64(),
        absorb_s = scan_split.scan_absorb.as_secs_f64(),
        // v0.6 P1: the residue named — state prep, spawn, in-loop submit
        // wait/extra, post-enhance reseed. residue_s is what remains unnamed.
        state_prep_s = scan_split.scan_state_prep.as_secs_f64(),
        prefetch_spawn_s = scan_split.scan_prefetch_spawn.as_secs_f64(),
        submit_wait_s = scan_split.scan_submit_wait.as_secs_f64(),
        submit_extra_s = scan_split.scan_submit_extra.as_secs_f64(),
        reseed_s = scan_split.scan_reseed.as_secs_f64(),
        // v0.6 P6: scan_call's two-pass interior (pass1 = feed runners,
        // pass2 = wallet-side processing; pass1 + pass2 ≈ scan_call).
        pass1_s = scan_split.scan_pass1.as_secs_f64(),
        pass2_s = scan_split.scan_pass2.as_secs_f64(),
        residue_s =
            (outcome.report.scan_elapsed.as_secs_f64() - scan_split_sum.as_secs_f64()).max(0.0),
        "scan lane split"
    );
    // v0.6 P2: the persist lane's pass delta — PERF_LEDGER #1's decomposition.
    let persist_lane = crate::persist::lane_stats::totals().delta_since(&persist_lane_start);
    info!(
        calls = persist_lane.calls,
        rows_s = persist_lane.rows_ms as f64 / 1e3,
        tree_join_s = persist_lane.tree_join_ms as f64 / 1e3,
        flush_s = persist_lane.flush_ms as f64 / 1e3,
        downgrade_s = persist_lane.downgrade_ms as f64 / 1e3,
        build_s = persist_lane.build_ms as f64 / 1e3,
        frontier_s = persist_lane.frontier_ms as f64 / 1e3,
        insert_s = persist_lane.insert_ms as f64 / 1e3,
        ensure_s = persist_lane.ensure_ms as f64 / 1e3,
        downgraded = persist_lane.downgraded,
        "persist lane split"
    );
    info!(
        fetch_wait_s = outcome.enhance.fetch_wait.as_secs_f64(),
        store_s = outcome.enhance.store.as_secs_f64(),
        address_s = outcome.enhance.address.as_secs_f64(),
        requests = outcome.enhance.requests,
        "enhance split"
    );

    // v0.5 C1 did-it-fire stats (the graft lever's lesson): calls proves the
    // batched seam is reached, kernel_lanes proves the kernel engaged, dh_s
    // is the true cross-thread production DH cost (ON/OFF pairs = real ratio).
    let (
        batch_dh_calls,
        batch_dh_lanes,
        batch_dh_kernel_lanes,
        batch_dh_nanos,
        batch_dh_wall_nanos,
        batch_epk_nanos,
    ) = crate::vendor_shim::batch_dh_stats();
    let batch_dh_s = batch_dh_nanos as f64 / 1e9;
    // v0.6 P5/P6: union wall over the DH + batch_epk brackets —
    // (dh_s + epk_s)/wall = avg busy threads inside the bracketed task core.
    let batch_dh_wall_s = batch_dh_wall_nanos as f64 / 1e9;
    let batch_epk_s = batch_epk_nanos as f64 / 1e9;
    info!(
        calls = batch_dh_calls,
        lanes = batch_dh_lanes,
        kernel_lanes = batch_dh_kernel_lanes,
        dh_s = batch_dh_s,
        dh_wall_s = batch_dh_wall_s,
        epk_s = batch_epk_s,
        endo_calls = crate::vendor_shim::endo_calls(),
        enabled = config.batch_decrypt,
        "batch_dh fire stats"
    );

    // v0.4 P0 (spec §3.1): the machine-readable bench artifact, host-opted via config.
    if let Some(path) = &config.bench_json_path {
        let bench = crate::census::BenchSummary {
            engine_build: ENGINE_BUILD,
            total_s: outcome.elapsed.as_secs_f64(),
            fetch_s: outcome.report.fetch_elapsed.as_secs_f64(),
            wire_mbps_avg,
            wire_worst_5s_mbps: outcome.report.wire_worst_window_mbps,
            wire_probe_ms,
            wire_switches: u64::from(wire_switches),
            scan_s: outcome.report.scan_elapsed.as_secs_f64(),
            enhance_s: outcome.enhance_elapsed.as_secs_f64(),
            persist_wait_s,
            persist_overlap_s: (persist_busy_s - persist_wait_s).max(0.0),
            blocks: outcome.report.scan.blocks,
            batch_dh_calls,
            batch_dh_lanes,
            batch_dh_kernel_lanes,
            batch_dh_s,
            batch_dh_wall_s,
            batch_epk_s,
            scan_recv_wait_s: outcome.report.scan_recv_wait.as_secs_f64(),
            scan_call_s: outcome.report.scan_call.as_secs_f64(),
            scan_prefetch_wait_s: outcome.report.scan_prefetch_wait.as_secs_f64(),
            scan_interleave_drain_s: outcome.report.scan_interleave_drain.as_secs_f64(),
            scan_final_drain_s: outcome.report.scan_final_drain.as_secs_f64(),
            scan_absorb_s: outcome.report.scan_absorb.as_secs_f64(),
            scan_state_prep_s: outcome.report.scan_state_prep.as_secs_f64(),
            scan_prefetch_spawn_s: outcome.report.scan_prefetch_spawn.as_secs_f64(),
            scan_submit_wait_s: outcome.report.scan_submit_wait.as_secs_f64(),
            scan_submit_extra_s: outcome.report.scan_submit_extra.as_secs_f64(),
            scan_reseed_s: outcome.report.scan_reseed.as_secs_f64(),
            scan_pass1_s: outcome.report.scan_pass1.as_secs_f64(),
            scan_pass2_s: outcome.report.scan_pass2.as_secs_f64(),
            persist_calls: persist_lane.calls,
            persist_rows_s: persist_lane.rows_ms as f64 / 1e3,
            persist_tree_join_s: persist_lane.tree_join_ms as f64 / 1e3,
            persist_flush_s: persist_lane.flush_ms as f64 / 1e3,
            persist_downgrade_s: persist_lane.downgrade_ms as f64 / 1e3,
            persist_build_s: persist_lane.build_ms as f64 / 1e3,
            persist_frontier_s: persist_lane.frontier_ms as f64 / 1e3,
            persist_insert_s: persist_lane.insert_ms as f64 / 1e3,
            persist_ensure_s: persist_lane.ensure_ms as f64 / 1e3,
            persist_downgraded: persist_lane.downgraded,
            endo_calls: crate::vendor_shim::endo_calls(),
            enhance_fetch_s: outcome.enhance.fetch_wait.as_secs_f64(),
            enhance_store_s: outcome.enhance.store.as_secs_f64(),
            enhance_address_s: outcome.enhance.address.as_secs_f64(),
            sapling: (&outcome.report.census_sapling).into(),
            orchard: (&outcome.report.census_orchard).into(),
        };
        if let Err(e) = bench.write_json(path) {
            tracing::warn!(path = %path.display(), %e, "bench JSON write failed");
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// format_utc against known epochs (no clock dependency).
    #[test]
    fn format_utc_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20Z");
        // Leap-year day: 2024-02-29 12:00:00 UTC.
        assert_eq!(format_utc(1_709_208_000), "2024-02-29 12:00:00Z");
        // End-of-year boundary: 2025-12-31 23:59:59 UTC.
        assert_eq!(format_utc(1_767_225_599), "2025-12-31 23:59:59Z");
    }

    /// wall_clock_utc returns a sane, well-formed current timestamp.
    #[test]
    fn wall_clock_utc_is_well_formed() {
        let s = wall_clock_utc();
        assert_eq!(s.len(), "2026-06-13 00:00:00Z".len());
        assert!(s.ends_with('Z'));
        assert!(s.starts_with("20"), "expected a 21st-century year, got {s}");
    }

    /// Helper to construct a minimal SyncOutcome with specified stage durations.
    fn make_outcome(fetch_s: f64, scan_s: f64, enhance_s: f64) -> SyncOutcome {
        use std::time::Duration;
        let report = crate::scheduler::SyncReport {
            fetch_elapsed: Duration::from_secs_f64(fetch_s),
            scan_elapsed: Duration::from_secs_f64(scan_s),
            ..Default::default()
        };
        SyncOutcome {
            report,
            enhance: crate::enhance::EnhanceStats::default(),
            transparent: crate::transparent::TransparentStats::default(),
            enhance_elapsed: Duration::from_secs_f64(enhance_s),
            elapsed: Duration::from_secs_f64(fetch_s + scan_s + enhance_s),
            chain_tip: 0,
        }
    }

    #[test]
    fn bound_picks_max_stage() {
        assert_eq!(make_outcome(5.0, 2.0, 1.0).bound(), "fetch");
        assert_eq!(make_outcome(2.0, 5.0, 1.0).bound(), "scan");
        assert_eq!(make_outcome(2.0, 1.0, 5.0).bound(), "enhance");
    }

    #[test]
    fn bound_returns_idle_when_all_tiny() {
        // All < 1 s → idle.
        assert_eq!(make_outcome(0.5, 0.3, 0.1).bound(), "idle");
    }

    #[test]
    fn bound_ties_prefer_fetch_then_scan() {
        // Equal fetch=scan=5s, enhance=0 → fetch wins (fetch >= scan in the branch).
        assert_eq!(make_outcome(5.0, 5.0, 0.0).bound(), "fetch");
        // Equal scan=enhance=5s, fetch=0 → scan wins.
        assert_eq!(make_outcome(0.0, 5.0, 5.0).bound(), "scan");
    }

    /// T8.1 — the follow loop's pure re-sync decision.
    #[test]
    fn follow_should_resync_only_when_tip_advances() {
        assert!(!should_resync(3_375_000, 3_374_999)); // tip behind (server lag) → no
        assert!(!should_resync(3_375_000, 3_375_000)); // tip equal → no
        assert!(should_resync(3_375_000, 3_375_001)); // tip advanced → yes
        assert!(!should_resync(0, 0));
    }

    #[test]
    fn birthday_height_zero_is_rejected() {
        // This test is hermetic: we just call validate_ufvk_birthday_guard, which
        // does not require a real network or wallet. We test the guard's logic
        // directly by checking that birthday=0 with a ufvk is a Config error.
        // The guard is inline in sync_once; exercise it via the public function
        // signature in a tokio runtime.
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime for test");
        let cfg = EngineConfig::new(
            zcash_protocol::consensus::Network::MainNetwork,
            std::path::PathBuf::from("/tmp/slipstream-engine-test-nonexistent/data.db"),
            crate::config::Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                tls: false,
            },
        );
        // birthday=0 must fail before any network call.
        let result =
            rt.block_on(async { sync_once(&cfg, Some(("dummy_ufvk", 0)), None, None).await });
        assert!(
            matches!(result, Err(SlipstreamError::Config(_))),
            "expected Config error for birthday=0, got: {result:?}"
        );
    }
}
