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

//! Work-unit progress accounting: blocks + shielded outputs/actions weighted
//! to match trial-decryption wall time instead of letting spam ranges crawl.

use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::NetworkUpgrade;

/// Base weight assigned to each block, regardless of its shielded outputs.
/// Added to the per-pool leaves so that even transparent blocks contribute
/// progress.
pub const BLOCK_WEIGHT: u64 = 4;

/// Per-pool work accounting: how to count leaves and query tree sizes.
#[derive(Clone, Debug)]
pub struct PoolDef {
    pub label: &'static str,
    pub activation: NetworkUpgrade,
}

impl PoolDef {
    /// Extract the shielded leaf count from a `CompactBlock` for this pool.
    pub fn leaves(&self, block: &CompactBlock) -> u64 {
        match self.label {
            "sapling" => block
                .vtx
                .iter()
                .map(|tx| tx.outputs.len() as u64)
                .sum(),
            "orchard" => block
                .vtx
                .iter()
                .map(|tx| tx.actions.len() as u64)
                .sum(),
            "ironwood" => block
                .vtx
                .iter()
                .map(|tx| tx.ironwood_actions.len() as u64)
                .sum(),
            _ => 0,
        }
    }
}

/// The three pools slipstream tracks. Adding a pool (NU7+) requires one new entry.
pub const POOLS: &[PoolDef] = &[
    PoolDef {
        label: "sapling",
        activation: NetworkUpgrade::Sapling,
    },
    PoolDef {
        label: "orchard",
        activation: NetworkUpgrade::Nu5,
    },
    PoolDef {
        label: "ironwood",
        activation: NetworkUpgrade::Nu6_3,
    },
];

/// Compute the work units for a block: `BLOCK_WEIGHT` + sum of each pool's leaves.
pub fn block_work(block: &CompactBlock) -> u64 {
    BLOCK_WEIGHT + POOLS.iter().map(|pool| pool.leaves(block)).sum::<u64>()
}

/// A height,size anchor for work estimation: the tree held this many leaves
/// at this completing height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub height: u64,
    pub size: u64,
}

/// Per-pool work estimate from subtree roots + exact chain/block metadata.
#[derive(Clone, Debug)]
pub struct PoolEstimate {
    /// Sorted anchors: (height, cumulative size). Monotone non-decreasing by construction.
    anchors: Vec<Anchor>,
}

impl PoolEstimate {
    /// Build from subtree-root completing heights + exact sizes. The first anchor
    /// is `(activation - 1, 0)` — no leaves before the pool's activation. Each
    /// subtree root `j` with completing height `e_j` adds `(e_j, (j+1) * 65536)`.
    /// Exact anchors from metadata/chain_metadata overwrite any subtree-derived
    /// anchor at the same height.
    pub fn new(
        activation_height: u64,
        subtree_ends: &[(u64, u64)],
        exact_anchors: &[(u64, u64)],
    ) -> Self {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<u64, u64> = BTreeMap::new();
        // Activation anchor: no leaves before the pool goes live.
        if activation_height > 0 {
            map.insert(activation_height - 1, 0);
        }
        // Subtree roots: each completing height anchors (j+1)*65536 leaves.
        for &(idx, end_height) in subtree_ends {
            map.insert(end_height, (idx + 1) * 65536);
        }
        // Exact anchors overwrite any subtree-derived value at the same height.
        for &(h, size) in exact_anchors {
            map.insert(h, size);
        }
        let anchors: Vec<Anchor> = map
            .into_iter()
            .map(|(height, size)| Anchor { height, size })
            .collect();
        Self { anchors }
    }

    /// Cumulative work (leaf count) at height `h`, linearly interpolated between
    /// anchors. If `h` is past the last anchor, extend with the last slope (clamped ≥ 0).
    pub fn cumulative(&self, h: u64) -> u64 {
        if self.anchors.is_empty() {
            return 0;
        }
        // Before the first anchor: extend backward at slope 0 (no leaves before activation).
        if h < self.anchors[0].height {
            return 0;
        }
        // Find the interval [left, right] that contains h, or the last anchor if h is beyond.
        let pos = self.anchors.partition_point(|a| a.height <= h);
        if pos == 0 {
            // h == anchors[0].height
            return self.anchors[0].size;
        }
        let left = &self.anchors[pos - 1];
        if pos == self.anchors.len() {
            // h is past the last anchor: extend with the last slope.
            if self.anchors.len() == 1 {
                // Only one anchor: slope is 0.
                return left.size;
            }
            let prev = &self.anchors[self.anchors.len() - 2];
            let dh = left.height.saturating_sub(prev.height);
            if dh == 0 {
                return left.size;
            }
            let ds = left.size.saturating_sub(prev.size);
            let slope = ds as f64 / dh as f64;
            let extend = ((h - left.height) as f64 * slope).round() as u64;
            return left.size.saturating_add(extend);
        }
        // h is in [left.height, right.height]
        let right = &self.anchors[pos];
        if h == right.height {
            return right.size;
        }
        // Linear interpolation
        let dh = right.height.saturating_sub(left.height);
        if dh == 0 {
            return left.size;
        }
        let ds = right.size.saturating_sub(left.size);
        let fraction = (h - left.height) as f64 / dh as f64;
        let interpolated = left.size as f64 + fraction * ds as f64;
        interpolated.round() as u64
    }

    /// Work for the range `[a, b]` inclusive. Returns 0 if `a > b`.
    pub fn range(&self, a: u64, b: u64) -> u64 {
        if a > b {
            return 0;
        }
        self.cumulative(b).saturating_sub(
            if a > 0 {
                self.cumulative(a - 1)
            } else {
                0
            },
        )
    }

    /// Whether this estimate has any real data: at least one anchor beyond activation.
    pub fn is_usable(&self) -> bool {
        // An estimate is usable if it has at least two anchors (activation + one data point),
        // or one anchor with non-zero size.
        self.anchors.len() > 1 || self.anchors.first().map_or(false, |a| a.size > 0)
    }
}

/// Multi-pool work estimator: sums each pool's estimate.
#[derive(Clone, Debug)]
pub struct WorkEstimator {
    pools: Vec<PoolEstimate>,
}

impl WorkEstimator {
    /// Build from per-pool data: activation heights, subtree-root completing heights,
    /// and exact anchors. The order of `pool_data` must match `POOLS`.
    pub fn new(pool_data: Vec<(u64, Vec<(u64, u64)>, Vec<(u64, u64)>)>) -> Self {
        let pools = pool_data
            .into_iter()
            .map(|(activation_height, subtree_ends, exact_anchors)| {
                PoolEstimate::new(activation_height, &subtree_ends, &exact_anchors)
            })
            .collect();
        Self { pools }
    }

    /// Cumulative work at height `h`: `BLOCK_WEIGHT * (h+1)` + sum of pool leaf counts.
    pub fn cumulative(&self, h: u64) -> u64 {
        let block_work = BLOCK_WEIGHT.saturating_mul(h.saturating_add(1));
        let pool_work: u64 = self.pools.iter().map(|p| p.cumulative(h)).sum();
        block_work.saturating_add(pool_work)
    }

    /// Work for the range `[a, b]` inclusive.
    pub fn range(&self, a: u64, b: u64) -> u64 {
        if a > b {
            return 0;
        }
        self.cumulative(b).saturating_sub(
            if a > 0 {
                self.cumulative(a - 1)
            } else {
                0
            },
        )
    }

    /// Whether this estimator is usable: at least one pool has real data.
    pub fn is_usable(&self) -> bool {
        self.pools.iter().any(|p| p.is_usable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_estimate_activation_anchor() {
        let est = PoolEstimate::new(100, &[], &[]);
        assert_eq!(est.cumulative(99), 0, "before activation");
        assert_eq!(est.cumulative(100), 0, "at activation with no roots");
        assert_eq!(est.cumulative(200), 0, "past activation with no data");
    }

    #[test]
    fn pool_estimate_subtree_roots() {
        // Subtree 0 completes at height 50 → 65536 leaves.
        // Subtree 1 completes at height 100 → 131072 leaves.
        let est = PoolEstimate::new(10, &[(0, 50), (1, 100)], &[]);
        assert_eq!(est.cumulative(9), 0, "before activation");
        assert_eq!(est.cumulative(50), 65536);
        assert_eq!(est.cumulative(100), 131072);
        // Interpolate between 50 and 100: halfway is (65536+131072)/2
        assert_eq!(est.cumulative(75), (65536 + 131072) / 2);
    }

    #[test]
    fn pool_estimate_exact_anchors_overwrite() {
        // Subtree 0 at 50, but exact anchor at 50 says 70000.
        let est = PoolEstimate::new(10, &[(0, 50)], &[(50, 70000)]);
        assert_eq!(est.cumulative(50), 70000, "exact overwrites subtree");
    }

    #[test]
    fn pool_estimate_extends_past_last_anchor() {
        // Two anchors: (10, 0) activation, (20, 1000).
        // Slope = 1000 / 10 = 100 leaves/block.
        let est = PoolEstimate::new(11, &[], &[(20, 1000)]);
        assert_eq!(est.cumulative(20), 1000);
        // At 30, extend by 10 blocks: 1000 + 10*100 = 2000.
        assert_eq!(est.cumulative(30), 2000);
    }

    #[test]
    fn pool_estimate_range_additive() {
        let est = PoolEstimate::new(10, &[(0, 50), (1, 100)], &[]);
        let full = est.range(50, 100);
        let left = est.range(50, 75);
        let right = est.range(76, 100);
        assert_eq!(full, left + right, "ranges must be additive");
    }

    #[test]
    fn pool_estimate_monotonic() {
        let est = PoolEstimate::new(10, &[(0, 50), (1, 100), (2, 150)], &[]);
        let mut prev = 0;
        for h in 0..200 {
            let cur = est.cumulative(h);
            assert!(
                cur >= prev,
                "cumulative must be monotone non-decreasing at h={}",
                h
            );
            prev = cur;
        }
    }

    #[test]
    fn pool_estimate_inactive_pool_contributes_zero() {
        // Pool never activated (activation_height = 0 or very high).
        let est = PoolEstimate::new(1_000_000, &[], &[]);
        assert_eq!(est.cumulative(100), 0);
        assert_eq!(est.range(0, 100), 0);
    }

    #[test]
    fn work_estimator_sums_pools() {
        // Two pools: first has 100 leaves at h=10, second has 50.
        let est = WorkEstimator::new(vec![
            (5, vec![], vec![(10, 100)]),
            (5, vec![], vec![(10, 50)]),
        ]);
        // At h=10: block_work = BLOCK_WEIGHT * 11 = 44, pool_work = 100+50 = 150.
        let expected = BLOCK_WEIGHT * 11 + 150;
        assert_eq!(est.cumulative(10), expected);
    }

    #[test]
    fn work_estimator_range_is_additive() {
        let est = WorkEstimator::new(vec![
            (5, vec![(0, 50), (1, 100)], vec![]),
            (5, vec![], vec![(100, 200)]),
        ]);
        let full = est.range(50, 100);
        let left = est.range(50, 75);
        let right = est.range(76, 100);
        assert_eq!(full, left + right);
    }

    #[test]
    fn work_estimator_is_monotonic() {
        let est = WorkEstimator::new(vec![
            (10, vec![(0, 50), (1, 100)], vec![]),
            (10, vec![(0, 60)], vec![]),
        ]);
        let mut prev = 0;
        for h in 0..200 {
            let cur = est.cumulative(h);
            assert!(cur >= prev, "monotone at h={}", h);
            prev = cur;
        }
    }

    #[test]
    fn block_work_counts_all_pools() {
        // Construct a CompactBlock with 2 sapling outputs, 3 orchard actions, 1 ironwood action.
        use zcash_client_backend::proto::compact_formats::{CompactSaplingOutput, CompactOrchardAction, CompactTx};
        let mut tx = CompactTx::default();
        tx.outputs.push(CompactSaplingOutput::default());
        tx.outputs.push(CompactSaplingOutput::default());
        tx.actions = vec![CompactOrchardAction::default(); 3];
        tx.ironwood_actions = vec![CompactOrchardAction::default(); 1];
        let mut block = CompactBlock::default();
        block.vtx.push(tx);
        let work = block_work(&block);
        // BLOCK_WEIGHT + 2 sapling + 3 orchard + 1 ironwood = 4 + 6 = 10
        assert_eq!(work, BLOCK_WEIGHT + 2 + 3 + 1);
    }

    #[test]
    fn pool_estimate_incremental_roots() {
        // Start index > 0: subtree roots [(2, 100), (3, 150)] mean indices 2 and 3.
        // Index 2 → (2+1)*65536 = 196608, index 3 → (3+1)*65536 = 262144.
        let est = PoolEstimate::new(10, &[(2, 100), (3, 150)], &[]);
        assert_eq!(est.cumulative(100), 196608);
        assert_eq!(est.cumulative(150), 262144);
    }

    #[test]
    fn pool_estimate_usable() {
        let empty = PoolEstimate::new(100, &[], &[]);
        assert!(!empty.is_usable(), "no data beyond activation");
        let with_root = PoolEstimate::new(100, &[(0, 200)], &[]);
        assert!(with_root.is_usable(), "has subtree root");
        let with_exact = PoolEstimate::new(100, &[], &[(200, 5000)]);
        assert!(with_exact.is_usable(), "has exact anchor");
    }

    #[test]
    fn work_estimator_usable() {
        let no_data = WorkEstimator::new(vec![(100, vec![], vec![]); 3]);
        assert!(!no_data.is_usable(), "no pool has data");
        let one_pool = WorkEstimator::new(vec![
            (100, vec![(0, 200)], vec![]),
            (100, vec![], vec![]),
            (100, vec![], vec![]),
        ]);
        assert!(one_pool.is_usable(), "first pool has data");
    }
}
