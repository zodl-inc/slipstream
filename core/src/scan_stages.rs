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
//! Tracks per-chunk aggregated stage timing and rayon load-balance metrics to show
//! where CPU goes during scan. Cheap enough to leave on: atomics + Instants per
//! stage, never per-output instrumentation in hot loops.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Per-chunk scan stage timings, accumulated via atomics so multiple threads
/// can contribute (rayon tasks, persist lane, scan thread).
#[derive(Default)]
pub struct ChunkStageTimings {
    /// Milliseconds spent in tree building (put_blocks time from persist facades).
    pub tree_ms: AtomicU64,
    /// Milliseconds spent in put_blocks' rows stage (row-level persistence).
    pub rows_ms: AtomicU64,
    /// Number of rayon tasks spawned during this chunk's scan (estimated from
    /// rayon pool size if direct tracking unavailable).
    pub rayon_tasks: AtomicU64,
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

    /// Record rayon task count.
    pub fn add_rayon_tasks(&self, count: u64) {
        self.rayon_tasks.fetch_add(count, Ordering::Relaxed);
    }

    /// Snapshot current values.
    pub fn snapshot(&self) -> ChunkStageSnapshot {
        ChunkStageSnapshot {
            tree_ms: self.tree_ms.load(Ordering::Relaxed),
            rows_ms: self.rows_ms.load(Ordering::Relaxed),
            rayon_tasks: self.rayon_tasks.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters (called at chunk boundaries).
    pub fn reset(&self) {
        self.tree_ms.store(0, Ordering::Relaxed);
        self.rows_ms.store(0, Ordering::Relaxed);
        self.rayon_tasks.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of chunk stage timings (non-atomic values for logging).
#[derive(Debug, Clone, Copy)]
pub struct ChunkStageSnapshot {
    pub tree_ms: u64,
    pub rows_ms: u64,
    pub rayon_tasks: u64,
}

/// Rayon load-balance statistics for a chunk.
#[derive(Debug, Clone, Copy, Default)]
pub struct RayonStats {
    /// Number of rayon tasks executed.
    pub tasks: u64,
    /// Sum of all task durations (CPU-milliseconds).
    pub total_task_ms: u64,
    /// Longest task duration (milliseconds).
    pub max_task_ms: u64,
    /// Median task duration (milliseconds).
    pub median_task_ms: u64,
    /// Rayon thread pool size.
    pub pool_size: usize,
}

impl RayonStats {
    /// Calculate utilization: (total task CPU-ms) / (chunk wall-ms * threads).
    /// Returns percentage (0-100+, can exceed 100 with work stealing).
    pub fn utilization_pct(&self, chunk_wall_ms: u64) -> u64 {
        if chunk_wall_ms == 0 || self.pool_size == 0 {
            return 0;
        }
        let denominator = chunk_wall_ms.saturating_mul(self.pool_size as u64);
        if denominator == 0 {
            return 0;
        }
        self.total_task_ms.saturating_mul(100) / denominator
    }
}

/// Task timing tracker for rayon load-balance metrics.
#[derive(Debug, Default)]
pub struct TaskTimings {
    durations_ms: Vec<u64>,
}

impl TaskTimings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a task's duration.
    pub fn record(&mut self, duration: Duration) {
        self.durations_ms.push(duration.as_millis() as u64);
    }

    /// Calculate rayon statistics from recorded task durations.
    pub fn to_stats(&mut self, pool_size: usize) -> RayonStats {
        if self.durations_ms.is_empty() {
            return RayonStats {
                tasks: 0,
                total_task_ms: 0,
                max_task_ms: 0,
                median_task_ms: 0,
                pool_size,
            };
        }

        let tasks = self.durations_ms.len() as u64;
        let total_task_ms: u64 = self.durations_ms.iter().sum();
        let max_task_ms = *self.durations_ms.iter().max().unwrap_or(&0);

        // Calculate median
        self.durations_ms.sort_unstable();
        let median_task_ms = if self.durations_ms.is_empty() {
            0
        } else {
            self.durations_ms[self.durations_ms.len() / 2]
        };

        RayonStats {
            tasks,
            total_task_ms,
            max_task_ms,
            median_task_ms,
            pool_size,
        }
    }

    /// Clear recorded timings (called at chunk boundaries).
    pub fn clear(&mut self) {
        self.durations_ms.clear();
    }
}

// ── Thread-local storage for chunk timings ───────────────────────────────────

thread_local! {
    /// Current chunk's stage timings, accessed by scan thread and persist callbacks.
    static CURRENT_CHUNK_TIMINGS: RefCell<Option<std::sync::Arc<ChunkStageTimings>>> =
        RefCell::new(None);
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
    fn chunk_stage_timings_reset() {
        let timings = ChunkStageTimings::new();
        timings.add_tree_ms(100);
        timings.reset();

        let snap = timings.snapshot();
        assert_eq!(snap.tree_ms, 0);
    }

    #[test]
    fn rayon_stats_utilization() {
        let stats = RayonStats {
            tasks: 10,
            total_task_ms: 800,
            max_task_ms: 100,
            median_task_ms: 80,
            pool_size: 4,
        };

        // 800ms / (100ms * 4 threads) = 200%
        assert_eq!(stats.utilization_pct(100), 200);

        // 800ms / (400ms * 4 threads) = 50%
        assert_eq!(stats.utilization_pct(400), 50);
    }

    #[test]
    fn task_timings_median() {
        let mut timings = TaskTimings::new();
        timings.record(Duration::from_millis(10));
        timings.record(Duration::from_millis(50));
        timings.record(Duration::from_millis(30));
        timings.record(Duration::from_millis(40));
        timings.record(Duration::from_millis(20));

        let stats = timings.to_stats(4);
        assert_eq!(stats.tasks, 5);
        assert_eq!(stats.total_task_ms, 150);
        assert_eq!(stats.max_task_ms, 50);
        assert_eq!(stats.median_task_ms, 30); // sorted: 10,20,30,40,50
    }

    #[test]
    fn task_timings_empty() {
        let mut timings = TaskTimings::new();
        let stats = timings.to_stats(4);
        assert_eq!(stats.tasks, 0);
        assert_eq!(stats.total_task_ms, 0);
    }
}
