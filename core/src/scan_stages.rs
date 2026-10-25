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

//! Scan stage timings for diagnostic purposes (sandblasting performance analysis).
//!
//! Measures real per-thread CPU time for rayon worker threads during scan via
//! CLOCK_THREAD_CPUTIME_ID (Linux/Android only). Also captures put_blocks timing
//! (tree + rows) from persist callbacks.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-chunk scan stage timings, accumulated via atomics so multiple threads
/// can contribute (persist lane, scan thread).
#[derive(Default)]
pub struct ChunkStageTimings {
    /// Milliseconds spent in tree building (put_blocks time from persist facades).
    pub tree_ms: AtomicU64,
    /// Milliseconds spent in put_blocks' rows stage (row-level persistence).
    pub rows_ms: AtomicU64,
}

impl ChunkStageTimings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record tree building time (called from put_blocks).
    pub fn add_tree_ms(&self, ms: u64) {
        self.tree_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// Record rows stage time (called from put_blocks).
    pub fn add_rows_ms(&self, ms: u64) {
        self.rows_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// Snapshot current values.
    pub fn snapshot(&self) -> ChunkStageSnapshot {
        ChunkStageSnapshot {
            tree_ms: self.tree_ms.load(Ordering::Relaxed),
            rows_ms: self.rows_ms.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of chunk stage timings (non-atomic values for logging).
#[derive(Debug, Clone, Copy)]
pub struct ChunkStageSnapshot {
    pub tree_ms: u64,
    pub rows_ms: u64,
}

// ── Thread-local storage for chunk timings ───────────────────────────────────

thread_local! {
    /// Current chunk's stage timings, accessed by scan thread and persist callbacks.
    static CURRENT_CHUNK_TIMINGS: RefCell<Option<std::sync::Arc<ChunkStageTimings>>> =
        const { RefCell::new(None) };
}

/// Set the current chunk timings (called at chunk start by scan).
pub fn set_current_chunk_timings(timings: std::sync::Arc<ChunkStageTimings>) {
    CURRENT_CHUNK_TIMINGS.with(|cell| {
        *cell.borrow_mut() = Some(timings);
    });
}

/// Clear the current chunk timings (called at chunk end by scan).
pub fn clear_current_chunk_timings() {
    CURRENT_CHUNK_TIMINGS.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Record tree building time for the current chunk (called from put_blocks).
/// No-op if no chunk timings are active (tests, non-instrumented paths).
pub fn record_tree_ms(ms: u64) {
    CURRENT_CHUNK_TIMINGS.with(|cell| {
        if let Some(ref timings) = *cell.borrow() {
            timings.add_tree_ms(ms);
        }
    });
}

/// Record rows stage time for the current chunk (called from put_blocks).
/// No-op if no chunk timings are active.
pub fn record_rows_ms(ms: u64) {
    CURRENT_CHUNK_TIMINGS.with(|cell| {
        if let Some(ref timings) = *cell.borrow() {
            timings.add_rows_ms(ms);
        }
    });
}

// ── Rayon worker thread CPU time measurement (Linux/Android only) ─────────────

/// Per-thread CPU time sample (thread-cputime via CLOCK_THREAD_CPUTIME_ID).
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadCpuSample {
    pub cpu_ns: u64,
}

#[cfg(target_os = "linux")]
impl ThreadCpuSample {
    /// Sample current thread's CPU time (user + system) via CLOCK_THREAD_CPUTIME_ID.
    pub fn now() -> Self {
        use std::mem::MaybeUninit;
        let mut ts = MaybeUninit::<libc::timespec>::uninit();
        let ret = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, ts.as_mut_ptr()) };
        if ret == 0 {
            let ts = unsafe { ts.assume_init() };
            let cpu_ns = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
            Self { cpu_ns }
        } else {
            // clock_gettime failed (should not happen on Linux 2.6.12+)
            Self { cpu_ns: 0 }
        }
    }

    /// Compute delta in milliseconds.
    pub fn delta_ms(self, earlier: Self) -> u64 {
        self.cpu_ns.saturating_sub(earlier.cpu_ns) / 1_000_000
    }
}

#[cfg(not(target_os = "linux"))]
impl ThreadCpuSample {
    /// No-op on non-Linux platforms.
    pub fn now() -> Self {
        Self { cpu_ns: 0 }
    }

    /// No-op delta.
    pub fn delta_ms(self, _earlier: Self) -> u64 {
        0
    }
}

/// Sample all rayon worker threads' CPU time via broadcast.
/// Returns per-thread samples in worker order.
pub fn sample_rayon_workers(pool: Option<&rayon::ThreadPool>) -> Vec<ThreadCpuSample> {
    let broadcast_fn = |_ctx: rayon::BroadcastContext<'_>| ThreadCpuSample::now();

    match pool {
        Some(pool) => pool.broadcast(broadcast_fn),
        None => rayon::broadcast(broadcast_fn),
    }
}

/// Rayon worker CPU statistics from sampled deltas.
#[derive(Debug, Clone, Copy, Default)]
pub struct RayonCpuStats {
    /// Sum of all worker CPU time (milliseconds).
    pub total_cpu_ms: u64,
    /// Minimum per-thread CPU time (milliseconds).
    pub min_cpu_ms: u64,
    /// Median per-thread CPU time (milliseconds).
    pub median_cpu_ms: u64,
    /// Maximum per-thread CPU time (milliseconds).
    pub max_cpu_ms: u64,
    /// Number of worker threads.
    pub num_threads: usize,
}

impl RayonCpuStats {
    /// Compute statistics from start and end samples.
    pub fn from_samples(start: &[ThreadCpuSample], end: &[ThreadCpuSample]) -> Self {
        if start.len() != end.len() || start.is_empty() {
            return Self::default();
        }

        let mut deltas_ms: Vec<u64> = start
            .iter()
            .zip(end.iter())
            .map(|(s, e)| e.delta_ms(*s))
            .collect();

        if deltas_ms.is_empty() {
            return Self::default();
        }

        let total_cpu_ms: u64 = deltas_ms.iter().sum();
        let min_cpu_ms = *deltas_ms.iter().min().unwrap_or(&0);
        let max_cpu_ms = *deltas_ms.iter().max().unwrap_or(&0);

        deltas_ms.sort_unstable();
        let median_cpu_ms = deltas_ms[deltas_ms.len() / 2];

        Self {
            total_cpu_ms,
            min_cpu_ms,
            median_cpu_ms,
            max_cpu_ms,
            num_threads: deltas_ms.len(),
        }
    }

    /// Calculate utilization: (total CPU-ms) / (wall-ms * threads) as percentage.
    pub fn utilization_pct(&self, wall_ms: u64) -> u64 {
        if wall_ms == 0 || self.num_threads == 0 {
            return 0;
        }
        let denominator = wall_ms.saturating_mul(self.num_threads as u64);
        if denominator == 0 {
            return 0;
        }
        self.total_cpu_ms.saturating_mul(100) / denominator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_stage_timings_accumulate() {
        let timings = ChunkStageTimings::new();
        timings.add_tree_ms(100);
        timings.add_tree_ms(200);
        timings.add_rows_ms(50);

        let snap = timings.snapshot();
        assert_eq!(snap.tree_ms, 300);
        assert_eq!(snap.rows_ms, 50);
    }

    #[test]
    fn rayon_cpu_stats_from_samples() {
        let start = vec![
            ThreadCpuSample {
                cpu_ns: 1_000_000_000,
            }, // 1s
            ThreadCpuSample {
                cpu_ns: 2_000_000_000,
            }, // 2s
            ThreadCpuSample {
                cpu_ns: 1_500_000_000,
            }, // 1.5s
        ];
        let end = vec![
            ThreadCpuSample {
                cpu_ns: 1_100_000_000,
            }, // +100ms
            ThreadCpuSample {
                cpu_ns: 2_300_000_000,
            }, // +300ms
            ThreadCpuSample {
                cpu_ns: 1_700_000_000,
            }, // +200ms
        ];

        let stats = RayonCpuStats::from_samples(&start, &end);
        assert_eq!(stats.total_cpu_ms, 600); // 100+300+200
        assert_eq!(stats.min_cpu_ms, 100);
        assert_eq!(stats.max_cpu_ms, 300);
        assert_eq!(stats.median_cpu_ms, 200); // sorted: 100,200,300
        assert_eq!(stats.num_threads, 3);

        // Utilization: 600ms CPU / (200ms wall * 3 threads) = 100%
        assert_eq!(stats.utilization_pct(200), 100);
    }

    #[test]
    fn rayon_cpu_stats_empty() {
        let stats = RayonCpuStats::from_samples(&[], &[]);
        assert_eq!(stats.total_cpu_ms, 0);
        assert_eq!(stats.num_threads, 0);
    }
}
