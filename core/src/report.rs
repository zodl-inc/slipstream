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

//! End-of-pass presentation for a completed sync pass: the operational tracing
//! summary and the machine-readable bench artifact.
//!
//! Extracted from the engine so `engine::sync_once` returns a [`SyncOutcome`] and
//! the CALLER decides what to present — keeping the sync pipeline free of
//! logging/benchmarking concerns. Everything here is a pure function of the
//! `SyncOutcome`: `session::run_pass_with_retry` calls [`log_pass_summary`] on each
//! successful pass (production/FFI + follow), and `slipstream-cli bench` calls
//! [`bench_summary`] and writes the artifact where it wants it.

use tracing::info;

use crate::census::BenchSummary;
use crate::config::EngineConfig;
use crate::engine::{ENGINE_BUILD, SyncOutcome, wall_clock_utc};
use crate::scheduler::SyncReport;

/// Average wire throughput (MB/s) over the pass's fetch wall time; 0 if no fetch.
fn wire_mbps_avg(report: &SyncReport) -> f64 {
    let fetch_s = report.fetch_elapsed.as_secs_f64();
    if fetch_s > 0.0 {
        report.wire_bytes as f64 / (1024.0 * 1024.0) / fetch_s
    } else {
        0.0
    }
}

/// Emit this pass's tracing summary: stage split, wire health, shard census,
/// scan-lane split, persist-lane split, and enhance split.
pub fn log_pass_summary(outcome: &SyncOutcome, config: &EngineConfig) {
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
        // [DEV-6] Adaptive GoAway-halving steps this pass engaged, summed
        // across every range's fetch workers. Zero in the common case.
        goaway_splits = outcome.report.fetch.goaway_splits,
        "sync stage split"
    );

    // [v0.7 P0] Wire health: the server's side of the ledger. avg = pass
    // bytes over fetch wall; worst_5s = the deepest sustained trough across
    // ranges (the collapse-detection signal P2 will act on). The 2026-07-08
    // ship-day evidence this instruments: a 10× same-morning provider swing
    // (1.5 → 14.7 MB/s) with the engine's own variance at ±3%.
    info!(
        wire_mbps_avg = format!("{:.2}", wire_mbps_avg(&outcome.report)).as_str(),
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
    let persist_lane = &outcome.persist_lane;
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
}

/// Build the machine-readable bench artifact (spec §3.1) for a completed pass.
/// The caller decides whether and where to write it (`BenchSummary::write_json`).
pub fn bench_summary(outcome: &SyncOutcome) -> BenchSummary {
    let persist_wait_s = outcome.report.persist_wait_elapsed.as_secs_f64();
    let persist_busy_s = outcome.report.persist_busy_elapsed.as_secs_f64();
    let persist_lane = &outcome.persist_lane;
    BenchSummary {
        engine_build: ENGINE_BUILD,
        total_s: outcome.elapsed.as_secs_f64(),
        fetch_s: outcome.report.fetch_elapsed.as_secs_f64(),
        wire_mbps_avg: wire_mbps_avg(&outcome.report),
        wire_worst_5s_mbps: outcome.report.wire_worst_window_mbps,
        wire_probe_ms: outcome.wire_probe_ms,
        wire_switches: u64::from(outcome.wire_switches),
        scan_s: outcome.report.scan_elapsed.as_secs_f64(),
        enhance_s: outcome.enhance_elapsed.as_secs_f64(),
        persist_wait_s,
        persist_overlap_s: (persist_busy_s - persist_wait_s).max(0.0),
        blocks: outcome.report.scan.blocks,
        batch_epk_s: 0.0,
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
        enhance_fetch_s: outcome.enhance.fetch_wait.as_secs_f64(),
        enhance_store_s: outcome.enhance.store.as_secs_f64(),
        enhance_address_s: outcome.enhance.address.as_secs_f64(),
        sapling: (&outcome.report.census_sapling).into(),
        orchard: (&outcome.report.census_orchard).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_outcome() -> SyncOutcome {
        SyncOutcome {
            report: SyncReport {
                fetch_elapsed: Duration::from_secs(2),
                scan_elapsed: Duration::from_secs(4),
                wire_bytes: 2 * 1024 * 1024, // 2 MiB over 2 s → 1.0 MB/s
                ..Default::default()
            },
            enhance: crate::enhance::EnhanceStats::default(),
            transparent: crate::transparent::TransparentStats::default(),
            enhance_elapsed: Duration::from_secs(3),
            elapsed: Duration::from_secs(10),
            chain_tip: 42,
            wire_probe_ms: 12.5,
            wire_switches: 2,
            persist_lane: crate::persist::lane_stats::Totals {
                calls: 7,
                rows_ms: 1_500,
                ..Default::default()
            },
        }
    }

    #[test]
    fn bench_summary_maps_outcome_fields() {
        let b = bench_summary(&sample_outcome());
        assert_eq!(b.engine_build, ENGINE_BUILD);
        assert_eq!(b.total_s, 10.0);
        assert_eq!(b.fetch_s, 2.0);
        assert_eq!(b.scan_s, 4.0);
        assert_eq!(b.enhance_s, 3.0);
        assert_eq!(b.wire_probe_ms, 12.5);
        assert_eq!(b.wire_switches, 2);
        assert_eq!(b.persist_calls, 7);
        assert_eq!(b.persist_rows_s, 1.5); // 1_500 ms
        assert_eq!(b.wire_mbps_avg, 1.0); // 2 MiB / 2 s
        assert_eq!(b.batch_epk_s, 0.0); // retired kernel field, held at 0
    }
}
