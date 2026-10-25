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

/// Per-chunk scan stage timings, accumulated via atomics so multiple threads
/// can contribute (rayon tasks, persist lane, scan thread).
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
}
