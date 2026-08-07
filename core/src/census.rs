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

//! v0.4 P0 — shard census + bench summary (spec: plans/2026-07-04-v04-graft-dont-grind-design.md §3).
//! Counts, per pool, which 2^16-position shards a pass touched and which of them hold
//! owned notes. `graftable_fraction` predicts Plan A's ceiling for a wallet BEFORE the
//! graft exists; the same numbers ride the `sparse … tree split` log lines and the
//! optional bench JSON (`EngineConfig::bench_json_path`) consumed by `slipstream-cli
//! bench` and bench-ios. JSON is hand-rolled (numbers + a static tag only) so the
//! published crate takes no serde dependency for one bench artifact.

use std::collections::BTreeSet;
use std::path::Path;

/// Both pools use shard height 16: shard index = position >> 16.
const SHARD_BITS: u32 = 16;

/// Per-pool, per-pass census of shard touches vs owned-note shards.
#[derive(Default, Debug, Clone)]
pub struct ShardCensus {
    touched: BTreeSet<u64>,
    noted: BTreeSet<u64>,
    /// Total commitments fed (both pools count leaves, not blocks).
    pub commitments: u64,
}

impl ShardCensus {
    /// Record `count` sequential commitments starting at `start_position`, plus the
    /// owned-note positions discovered in the same put_blocks call.
    pub fn feed(
        &mut self,
        start_position: u64,
        count: u64,
        note_positions: impl Iterator<Item = u64>,
    ) {
        if count > 0 {
            let first = start_position >> SHARD_BITS;
            let last = (start_position + count - 1) >> SHARD_BITS;
            self.touched.extend(first..=last);
            self.commitments += count;
        }
        for p in note_positions {
            self.noted.insert(p >> SHARD_BITS);
        }
    }

    /// Union another census into this one (range → pass aggregation).
    pub fn merge(&mut self, other: &ShardCensus) {
        self.touched.extend(other.touched.iter().copied());
        self.noted.extend(other.noted.iter().copied());
        self.commitments += other.commitments;
    }

    pub fn shards(&self) -> u64 {
        self.touched.len() as u64
    }

    pub fn noted_shards(&self) -> u64 {
        self.noted.len() as u64
    }

    /// Fraction of touched shards Plan A could graft: everything except noted shards
    /// and one tip shard (conservatively counted even if the tip shard is also noted).
    pub fn graftable_fraction(&self) -> f64 {
        let touched = self.touched.len() as u64;
        if touched == 0 {
            return 0.0;
        }
        let non_graftable = (self.noted.len() as u64).saturating_add(1).min(touched);
        (touched - non_graftable) as f64 / touched as f64
    }
}

/// Flat per-pool census block for the bench JSON.
#[derive(Debug, Clone, Copy)]
pub struct PoolCensusOut {
    pub shards: u64,
    pub noted_shards: u64,
    pub commitments: u64,
    pub graftable_fraction: f64,
}

impl From<&ShardCensus> for PoolCensusOut {
    fn from(c: &ShardCensus) -> Self {
        Self {
            shards: c.shards(),
            noted_shards: c.noted_shards(),
            commitments: c.commitments,
            graftable_fraction: c.graftable_fraction(),
        }
    }
}

/// End-of-pass machine-readable summary — the bench artifact (spec §3.1).
/// Field names are the contract with `slipstream-cli bench` and bench-ios.
#[derive(Debug, Clone)]
pub struct BenchSummary {
    pub engine_build: &'static str,
    pub total_s: f64,
    pub fetch_s: f64,
    /// [v0.7 P0] Pass-average wire throughput (wire bytes / fetch wall, MB/s).
    pub wire_mbps_avg: f64,
    /// [v0.7 P0] Worst sustained 5 s wire window across ranges (MB/s;
    /// 0.0 = no full window). The collapse-detection signal — interpret
    /// beside `scan_recv_wait_s` (ahead-gate caveat in fetch.rs).
    pub wire_worst_5s_mbps: f64,
    /// [v0.7 P1] Endpoint-probe wall time (0.0 = no alternates configured /
    /// Tor pass — probe skipped).
    pub wire_probe_ms: f64,
    /// [v0.7 P2] Mid-pass wire failovers performed (0 = none needed).
    pub wire_switches: u64,
    pub scan_s: f64,
    pub enhance_s: f64,
    pub persist_wait_s: f64,
    pub persist_overlap_s: f64,
    pub blocks: u64,
    /// v0.6 P6: CPU inside `batch_epk` (epk point decompression + per-epk
    /// table build). Retained in the bench JSON schema; always 0 on the
    /// current graph (the batched trial-decryption instrumentation it
    /// paired with now lives upstream).
    pub batch_epk_s: f64,
    /// v0.5 pacer split (2026-07-06 plan §3): the scan lane's wall decomposed.
    /// `scan_s ≈ recv_wait + call + prefetch_wait + interleave_drain +
    /// final_drain + persist_wait_s + residue`.
    pub scan_recv_wait_s: f64,
    pub scan_call_s: f64,
    pub scan_prefetch_wait_s: f64,
    pub scan_interleave_drain_s: f64,
    pub scan_final_drain_s: f64,
    /// v0.5 local treestate: the lever's own cost (frontier absorption).
    pub scan_absorb_s: f64,
    /// v0.6 P1 residue split — the previously-unnamed serial segments:
    /// from_state construction, prefetch spawn, in-loop submit wait/extra,
    /// post-enhance nullifier reseed. What remains is true residue.
    pub scan_state_prep_s: f64,
    pub scan_prefetch_spawn_s: f64,
    pub scan_submit_wait_s: f64,
    pub scan_submit_extra_s: f64,
    pub scan_reseed_s: f64,
    /// v0.6 P6: scan_call's interior split at the block source — upstream
    /// walks it TWICE per call: pass 1 feeds the batch runners (DH tasks
    /// spawn as thresholds fill), pass 2 re-walks doing the wallet-side
    /// processing (per-tx result extract + nullifier checks + ScannedBlock
    /// assembly). `pass1 + pass2 ≈ scan_call`. P5's verdict: the A18 wall
    /// lives in pass 2 — these two fields prove and size it on-device.
    pub scan_pass1_s: f64,
    pub scan_pass2_s: f64,
    /// v0.6 P2: the persist lane's pass totals (PERF_LEDGER #1's instrument).
    /// Bucket sums are across pools; tree_join is the rayon::join wall.
    pub persist_calls: u64,
    pub persist_rows_s: f64,
    /// v0.6 P4: the rows prologue sub-split (block-meta INSERTs / nullifier
    /// tracking / decrypted-tx section / gap-addresses + prune).
    pub persist_tree_join_s: f64,
    pub persist_flush_s: f64,
    pub persist_downgrade_s: f64,
    pub persist_build_s: f64,
    pub persist_frontier_s: f64,
    pub persist_insert_s: f64,
    pub persist_ensure_s: f64,
    pub persist_downgraded: u64,
    /// Enhancement wall split: awaiting gRPC tx fetches vs serial DB applies
    /// vs the address-window phase (explains the device enhance_s swings).
    pub enhance_fetch_s: f64,
    pub enhance_store_s: f64,
    pub enhance_address_s: f64,
    pub sapling: PoolCensusOut,
    pub orchard: PoolCensusOut,
}

impl BenchSummary {
    pub fn to_json(&self) -> String {
        fn pool(p: &PoolCensusOut) -> String {
            format!(
                "{{\"shards\":{},\"noted_shards\":{},\"commitments\":{},\"graftable_fraction\":{}}}",
                p.shards, p.noted_shards, p.commitments, p.graftable_fraction
            )
        }
        format!(
            "{{\"engine_build\":\"{}\",\"total_s\":{},\"fetch_s\":{},\"wire_mbps_avg\":{},\"wire_worst_5s_mbps\":{},\"wire_probe_ms\":{},\"wire_switches\":{},\"scan_s\":{},\"enhance_s\":{},\"persist_wait_s\":{},\"persist_overlap_s\":{},\"blocks\":{},\"batch_epk_s\":{},\"scan_recv_wait_s\":{},\"scan_call_s\":{},\"scan_prefetch_wait_s\":{},\"scan_interleave_drain_s\":{},\"scan_final_drain_s\":{},\"scan_absorb_s\":{},\"scan_state_prep_s\":{},\"scan_prefetch_spawn_s\":{},\"scan_submit_wait_s\":{},\"scan_submit_extra_s\":{},\"scan_reseed_s\":{},\"scan_pass1_s\":{},\"scan_pass2_s\":{},\"persist_calls\":{},\"persist_rows_s\":{},\"persist_tree_join_s\":{},\"persist_flush_s\":{},\"persist_downgrade_s\":{},\"persist_build_s\":{},\"persist_frontier_s\":{},\"persist_insert_s\":{},\"persist_ensure_s\":{},\"persist_downgraded\":{},\"enhance_fetch_s\":{},\"enhance_store_s\":{},\"enhance_address_s\":{},\"sapling\":{},\"orchard\":{}}}",
            self.engine_build,
            self.total_s,
            self.fetch_s,
            self.wire_mbps_avg,
            self.wire_worst_5s_mbps,
            self.wire_probe_ms,
            self.wire_switches,
            self.scan_s,
            self.enhance_s,
            self.persist_wait_s,
            self.persist_overlap_s,
            self.blocks,
            self.batch_epk_s,
            self.scan_recv_wait_s,
            self.scan_call_s,
            self.scan_prefetch_wait_s,
            self.scan_interleave_drain_s,
            self.scan_final_drain_s,
            self.scan_absorb_s,
            self.scan_state_prep_s,
            self.scan_prefetch_spawn_s,
            self.scan_submit_wait_s,
            self.scan_submit_extra_s,
            self.scan_reseed_s,
            self.scan_pass1_s,
            self.scan_pass2_s,
            self.persist_calls,
            self.persist_rows_s,
            self.persist_tree_join_s,
            self.persist_flush_s,
            self.persist_downgrade_s,
            self.persist_build_s,
            self.persist_frontier_s,
            self.persist_insert_s,
            self.persist_ensure_s,
            self.persist_downgraded,
            self.enhance_fetch_s,
            self.enhance_store_s,
            self.enhance_address_s,
            pool(&self.sapling),
            pool(&self.orchard),
        )
    }

    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn census_counts_shards_and_notes() {
        let mut c = ShardCensus::default();
        // 2 commitments at the end of shard 0, 3 into shard 1; one note in shard 1.
        c.feed(65534, 5, [65537u64].into_iter());
        assert_eq!(c.shards(), 2);
        assert_eq!(c.noted_shards(), 1);
        assert_eq!(c.commitments, 5);
        // shard 1 noted + tip discount → nothing graftable of the 2.
        assert!(c.graftable_fraction() <= 0.5);
    }

    #[test]
    fn census_graftable_fraction_typical() {
        let mut c = ShardCensus::default();
        // 10 full shards, single note in shard 0 → 10 touched, 1 noted, 1 tip → 8/10.
        c.feed(0, 65536 * 10, [5u64].into_iter());
        assert!((c.graftable_fraction() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn census_merge_unions() {
        let mut a = ShardCensus::default();
        a.feed(0, 65536, std::iter::empty());
        let mut b = ShardCensus::default();
        b.feed(65536, 65536, [65540u64].into_iter());
        a.merge(&b);
        assert_eq!(a.shards(), 2);
        assert_eq!(a.noted_shards(), 1);
        assert_eq!(a.commitments, 131_072);
    }

    #[test]
    fn census_empty_is_zero() {
        let c = ShardCensus::default();
        assert_eq!(c.shards(), 0);
        assert_eq!(c.graftable_fraction(), 0.0);
    }

    #[test]
    fn bench_summary_json_shape() {
        let pool = PoolCensusOut {
            shards: 3,
            noted_shards: 1,
            commitments: 42,
            graftable_fraction: 0.5,
        };
        let s = BenchSummary {
            engine_build: "test-build",
            total_s: 1.5,
            fetch_s: 0.25,
            wire_mbps_avg: 12.5,
            wire_worst_5s_mbps: 8.0,
            wire_probe_ms: 850.0,
            wire_switches: 1,
            scan_s: 1.0,
            enhance_s: 0.125,
            persist_wait_s: 0.0,
            persist_overlap_s: 0.5,
            blocks: 100,
            batch_epk_s: 0.05,
            scan_recv_wait_s: 0.1,
            scan_call_s: 0.8,
            scan_prefetch_wait_s: 0.05,
            scan_interleave_drain_s: 0.03,
            scan_final_drain_s: 0.02,
            scan_absorb_s: 0.07,
            scan_state_prep_s: 0.04,
            scan_prefetch_spawn_s: 0.01,
            scan_submit_wait_s: 0.02,
            scan_submit_extra_s: 0.01,
            scan_reseed_s: 0.03,
            scan_pass1_s: 0.15,
            scan_pass2_s: 0.65,
            persist_calls: 30,
            persist_rows_s: 0.5,
            persist_tree_join_s: 0.9,
            persist_flush_s: 0.1,
            persist_downgrade_s: 0.2,
            persist_build_s: 0.4,
            persist_frontier_s: 0.15,
            persist_insert_s: 0.1,
            persist_ensure_s: 0.05,
            persist_downgraded: 59000,
            enhance_fetch_s: 0.06,
            enhance_store_s: 0.04,
            enhance_address_s: 0.01,
            sapling: pool,
            orchard: pool,
        };
        let j = s.to_json();
        // Hand-rolled writer: deterministic, parseable shape.
        assert!(j.starts_with('{') && j.ends_with('}'), "json shape: {j}");
        for key in [
            "\"engine_build\":\"test-build\"",
            "\"total_s\":1.5",
            "\"wire_mbps_avg\":12.5",
            "\"wire_worst_5s_mbps\":8",
            "\"wire_probe_ms\":850",
            "\"wire_switches\":1",
            "\"blocks\":100",
            "\"batch_epk_s\":0.05",
            "\"scan_call_s\":0.8",
            "\"scan_pass1_s\":0.15",
            "\"scan_pass2_s\":0.65",
            "\"enhance_fetch_s\":0.06",
            "\"orchard\":{",
            "\"graftable_fraction\":0.5",
            "\"commitments\":42",
        ] {
            assert!(j.contains(key), "missing {key} in {j}");
        }
    }
}
