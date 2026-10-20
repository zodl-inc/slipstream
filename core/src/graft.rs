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

//! v0.4 Plan A — the graft buffer (spec §4, plan Task 5).
//!
//! `ext_slipstream_graft_buffer` holds the raw commitments of still-open,
//! note-free shards so their build can be deferred to the shard-close verdict
//! (graft the server root / build). It is a slipstream-owned `ext_` table in
//! `data.db` — created by the engine's schemerz migration (`migrations.rs`,
//! issue #4), written over a SIDE connection (upstream `WalletDb` never
//! exposes its connection).
//!
//! ## Restart-safety contract (ordering + idempotency, NOT shared-transaction)
//! Appends run BEFORE the chunk's main `put_blocks` transaction commits, keyed
//! `(pool, shard_index, position)` with INSERT OR REPLACE:
//! - crash between append and main-commit → the range is still unscanned →
//!   rescan re-appends byte-identical rows onto the same keys — harmless;
//! - crash after main-commit, before a close-verdict cleanup → rows of a built
//!   shard stay buffered → a range that later seeds in that shard resumes only
//!   the contiguous run ending right before its start, on its own frontier's
//!   leaf (`graft_accumulator::resumable_run`), and deletes every other row; a
//!   run it resumes on a shard the store already holds content for is built
//!   again with its first span (same leaves at the same positions) — self-healing;
//! - stop after a range's last commit, before its range-end build (a host abort
//!   landing in the final drain) → the range is scanned, but its range-end shard's
//!   rows stay buffered and no later range resumes them (Historic ranges run newest
//!   first) → the next pass's start sweep (`persist::sweep_stranded_graft_rows`)
//!   builds them, or deletes them and queues a rescan of their blocks.
//!
//! The invariant "block marked scanned ⇒ its commitments are in the shard store
//! OR in this buffer" therefore holds at every crash point. After a pass's start
//! sweep, a buffered run of scanned blocks is one the first range to seed in its
//! shard resumes, unless the wallet's block metadata cannot place it (the sweep
//! then leaves it, with a warning).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Range, RangeInclusive};

use incrementalmerkletree::{Marking, Retention};
use rusqlite::{Connection, params};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::{ShieldedPool, consensus::BlockHeight};

/// log2 of the shard size both pools share (`graft_accumulator::SHARD_BITS`).
const SHARD_BITS: u32 = 16;

/// One buffered commitment row.
pub(crate) type BufferRow<H> = (u64, H, Retention<BlockHeight>);

fn pool_code(pool: ShieldedPool) -> i64 {
    match pool {
        ShieldedPool::Sapling => 2,
        ShieldedPool::Orchard => 3,
        // [IW-6] the graft never runs for ironwood today (tiny tree, serial
        // lane, no lwd subtree roots) but the mapping is real.
        ShieldedPool::Ironwood => 4,
    }
}

fn corrupt(msg: impl Into<String>) -> SqliteClientError {
    SqliteClientError::CorruptedData(msg.into())
}

/// DDL of the graft buffer. Executed ONLY by the `ext_slipstream_*` schema
/// migration ([`crate::migrations`]) — production code may assume the table
/// exists in any opened wallet database.
pub(crate) const GRAFT_BUFFER_DDL: &str = "CREATE TABLE ext_slipstream_graft_buffer (
    pool INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    position INTEGER NOT NULL,
    commitment BLOB NOT NULL,
    retention_kind INTEGER NOT NULL,
    checkpoint_height INTEGER,
    marking INTEGER,
    PRIMARY KEY (pool, shard_index, position)
) WITHOUT ROWID";

fn encode_retention(r: &Retention<BlockHeight>) -> (i64, Option<i64>, Option<i64>) {
    match r {
        Retention::Ephemeral => (0, None, None),
        Retention::Marked => (1, None, None),
        Retention::Checkpoint { id, marking } => {
            let m = match marking {
                Marking::None => 0,
                Marking::Marked => 1,
                Marking::Reference => 2,
            };
            (2, Some(i64::from(u32::from(*id))), Some(m))
        }
        Retention::Reference => (3, None, None),
    }
}

fn decode_retention(
    kind: i64,
    checkpoint_height: Option<i64>,
    marking: Option<i64>,
) -> Result<Retention<BlockHeight>, SqliteClientError> {
    Ok(match kind {
        0 => Retention::Ephemeral,
        1 => Retention::Marked,
        2 => {
            let h = checkpoint_height
                .ok_or_else(|| corrupt("graft buffer: checkpoint row without height"))?;
            let h = u32::try_from(h).map_err(|_| corrupt("graft buffer: height out of range"))?;
            let marking = match marking.unwrap_or(0) {
                0 => Marking::None,
                1 => Marking::Marked,
                2 => Marking::Reference,
                other => return Err(corrupt(format!("graft buffer: bad marking {other}"))),
            };
            Retention::Checkpoint {
                id: BlockHeight::from(h),
                marking,
            }
        }
        3 => Retention::Reference,
        other => return Err(corrupt(format!("graft buffer: bad retention kind {other}"))),
    })
}

/// Append rows for one shard (INSERT OR REPLACE — idempotent under rescan).
pub(crate) fn append_rows<H: HashSer>(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
    rows: &[BufferRow<H>],
) -> Result<(), SqliteClientError> {
    if rows.is_empty() {
        return Ok(());
    }
    // ONE transaction per append (first live-fire lesson, 2026-07-04): autocommit
    // meant one implicit txn+fsync PER ROW — ~18k/chunk — and persist_wait went
    // 16.6s → 96.5s on the reference restore. unchecked: the side conn never
    // holds another open txn (all its other uses are single statements).
    let tx = conn.unchecked_transaction()?;
    let mut stmt = tx.prepare_cached(
        "INSERT OR REPLACE INTO ext_slipstream_graft_buffer
         (pool, shard_index, position, commitment, retention_kind, checkpoint_height, marking)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (position, hash, retention) in rows {
        let mut bytes = vec![];
        hash.write(&mut bytes)
            .map_err(|e| corrupt(format!("graft buffer: hash ser: {e}")))?;
        let (kind, height, marking) = encode_retention(retention);
        stmt.execute(params![
            pool_code(pool),
            shard_index as i64,
            *position as i64,
            bytes,
            kind,
            height,
            marking
        ])?;
    }
    drop(stmt);
    tx.commit()?;
    Ok(())
}

/// Load one shard's buffered rows, ordered by position. Empty vec when the
/// buffer holds nothing for the shard.
pub(crate) fn load_shard<H: HashSer>(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
) -> Result<Vec<BufferRow<H>>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT position, commitment, retention_kind, checkpoint_height, marking
         FROM ext_slipstream_graft_buffer
         WHERE pool = ?1 AND shard_index = ?2
         ORDER BY position ASC",
    )?;
    let rows = stmt.query_map(params![pool_code(pool), shard_index as i64], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
        ))
    })?;
    let mut out = vec![];
    for row in rows {
        let (position, bytes, kind, height, marking) = row?;
        let hash =
            H::read(&bytes[..]).map_err(|e| corrupt(format!("graft buffer: hash de: {e}")))?;
        out.push((
            position as u64,
            hash,
            decode_retention(kind, height, marking)?,
        ));
    }
    Ok(out)
}

/// Drop one shard's buffer (close-verdict cleanup — graft installed or built).
pub(crate) fn delete_shard(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ext_slipstream_graft_buffer WHERE pool = ?1 AND shard_index = ?2",
        params![pool_code(pool), shard_index as i64],
    )?;
    Ok(())
}

/// Drop one shard's rows outside `keep`: what a resumed range's seed leaves out
/// once it has kept the run it continues (`graft_accumulator::resumable_run`).
pub(crate) fn delete_shard_outside(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
    keep: std::ops::Range<u64>,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ext_slipstream_graft_buffer
         WHERE pool = ?1 AND shard_index = ?2 AND (position < ?3 OR position >= ?4)",
        params![
            pool_code(pool),
            shard_index as i64,
            keep.start as i64,
            keep.end as i64
        ],
    )?;
    Ok(())
}

/// The shards of `pool` the buffer holds rows for, ascending.
pub(crate) fn buffered_shards(
    conn: &Connection,
    pool: ShieldedPool,
) -> Result<Vec<u64>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT shard_index FROM ext_slipstream_graft_buffer
         WHERE pool = ?1 ORDER BY shard_index",
    )?;
    let shards = stmt
        .query_map(params![pool_code(pool)], |row| row.get::<_, i64>(0))?
        .map(|shard| shard.map(|s| s as u64))
        .collect::<Result<_, _>>()?;
    Ok(shards)
}

/// One shard's buffered positions, ascending, without decoding the rows.
pub(crate) fn buffered_positions(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
) -> Result<Vec<u64>, SqliteClientError> {
    let mut stmt = conn.prepare_cached(
        "SELECT position FROM ext_slipstream_graft_buffer
         WHERE pool = ?1 AND shard_index = ?2 ORDER BY position ASC",
    )?;
    let positions = stmt
        .query_map(params![pool_code(pool), shard_index as i64], |row| {
            row.get::<_, i64>(0)
        })?
        .map(|position| position.map(|p| p as u64))
        .collect::<Result<_, _>>()?;
    Ok(positions)
}

/// Drop one shard's rows inside `run`: a stranded run the pass-start sweep has built
/// or queued for a rescan.
pub(crate) fn delete_rows_in(
    conn: &Connection,
    pool: ShieldedPool,
    shard_index: u64,
    run: Range<u64>,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ext_slipstream_graft_buffer
         WHERE pool = ?1 AND shard_index = ?2 AND position >= ?3 AND position < ?4",
        params![
            pool_code(pool),
            shard_index as i64,
            run.start as i64,
            run.end as i64
        ],
    )?;
    Ok(())
}

// ── The pass-start sweep's decisions (`persist::sweep_stranded_graft_rows`) ──────

/// The contiguous runs of `positions`, which must be ascending (as `load_shard`
/// returns them).
pub(crate) fn contiguous_runs(positions: &[u64]) -> Vec<RangeInclusive<u64>> {
    let mut runs: Vec<RangeInclusive<u64>> = vec![];
    for &p in positions {
        match runs.last_mut() {
            Some(run) if *run.end() + 1 == p => *run = *run.start()..=p,
            _ => runs.push(p..=p),
        }
    }
    runs
}

/// The start position of the first range to seed in each shard, from the start
/// positions of the pending Historic ranges in the order the scheduler scans them
/// (`None` where a start is unknown: the wallet holds no metadata for the block
/// below the range).
///
/// A range seeds in the shard its start position falls in, and that seed deletes
/// the shard's rows outside the run it continues
/// (`graft_accumulator::resumable_run`), so only the first range to seed in a
/// shard can resume one of its runs. A shard first claimed after a range whose
/// start is unknown is left out: that range may seed in the same shard first.
pub(crate) fn first_seeders(starts: impl IntoIterator<Item = Option<u64>>) -> BTreeMap<u64, u64> {
    let mut claimed: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    let mut unknown_start_before = false;
    for start in starts {
        match start {
            Some(position) => {
                claimed
                    .entry(position >> SHARD_BITS)
                    .or_insert((!unknown_start_before).then_some(position));
            }
            None => unknown_start_before = true,
        }
    }
    claimed
        .into_iter()
        .filter_map(|(shard, start)| Some((shard, start?)))
        .collect()
}

/// The runs of one shard's rows (ascending `positions`) that nothing will resume.
///
/// `resume_at` is the start position of the shard's first seeder
/// ([`first_seeders`]). The run holding `resume_at - 1` is the one that seed
/// continues; its rows at or above `resume_at` lie in the seeding range's own
/// blocks, which it scans again, so that run is left whole. Every other run is
/// stranded.
pub(crate) fn stranded_runs(positions: &[u64], resume_at: Option<u64>) -> Vec<RangeInclusive<u64>> {
    let resumed = resume_at.and_then(|start| start.checked_sub(1));
    contiguous_runs(positions)
        .into_iter()
        .filter(|run| resumed.is_none_or(|last| !run.contains(&last)))
        .collect()
}

/// Whether a stranded run can be built as it is, because where it ends is known.
///
/// - `last_leaf_in_tree`: the commitment tree already holds a leaf at the run's last
///   position, and it is the run's last row. A range scanned above the run inserted
///   it, as its `from_state` frontier: the next commitment on the chain is that
///   range's.
/// - `pending_starts`: the start positions of the pending ranges, from the metadata
///   of the block below each. A run that ends right below one is a committed prefix
///   whose remainder is still queued.
/// - A run that reaches the end of its shard has nothing in the shard after it.
pub(crate) fn can_build(
    run: &RangeInclusive<u64>,
    last_leaf_in_tree: bool,
    pending_starts: &BTreeSet<u64>,
) -> bool {
    let next = *run.end() + 1;
    last_leaf_in_tree || pending_starts.contains(&next) || next.is_multiple_of(1 << SHARD_BITS)
}

/// The stretches of `floor..end` that no `pending` range covers, ascending: the
/// heights the scan queue counts as scanned.
pub(crate) fn scanned_stretches(
    pending: impl IntoIterator<Item = Range<BlockHeight>>,
    floor: BlockHeight,
    end: BlockHeight,
) -> Vec<Range<BlockHeight>> {
    let mut pending: Vec<Range<BlockHeight>> = pending.into_iter().collect();
    pending.sort_by_key(|range| range.start);
    let mut stretches = vec![];
    let mut next = floor;
    for range in pending {
        if range.start > next {
            stretches.push(next..range.start.min(end));
        }
        next = next.max(range.end);
        if next >= end {
            break;
        }
    }
    if next < end {
        stretches.push(next..end);
    }
    stretches.retain(|stretch| !stretch.is_empty());
    stretches
}

/// Rewind support (plan Task 9): drop every buffered row at or above `min_position`.
///
/// Upstream's rewinds never see this engine-owned table, so the engine calls this
/// after its own: the reorg recovery's truncation and an account import's rewind
/// (`WalletSession::truncate_to_height`, `WalletSession::import_account`). The blocks
/// they queue again hold exactly the rows at or above the rewind's tree size.
pub(crate) fn delete_from_position(
    conn: &Connection,
    pool: ShieldedPool,
    min_position: u64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "DELETE FROM ext_slipstream_graft_buffer WHERE pool = ?1 AND position >= ?2",
        params![pool_code(pool), min_position as i64],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::Hashable as _;
    use orchard::tree::MerkleHashOrchard;

    fn mem_conn() -> Connection {
        Connection::open_in_memory().expect("in-memory conn")
    }

    fn h(n: u8) -> MerkleHashOrchard {
        // Distinct valid nodes: hash the empty leaf up n levels.
        let mut v = MerkleHashOrchard::empty_leaf();
        for level in 0..n {
            v = MerkleHashOrchard::combine(incrementalmerkletree::Level::from(level), &v, &v);
        }
        v
    }

    fn all_retentions() -> Vec<Retention<BlockHeight>> {
        vec![
            Retention::Ephemeral,
            Retention::Marked,
            Retention::Reference,
            Retention::Checkpoint {
                id: BlockHeight::from(123),
                marking: Marking::None,
            },
            Retention::Checkpoint {
                id: BlockHeight::from(456),
                marking: Marking::Marked,
            },
            Retention::Checkpoint {
                id: BlockHeight::from(789),
                marking: Marking::Reference,
            },
        ]
    }

    #[test]
    fn append_load_round_trip_ordered_all_retentions() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = all_retentions()
            .into_iter()
            .enumerate()
            .map(|(i, r)| (1000 + i as u64, h(i as u8), r))
            .collect();
        // Append out of order to prove ORDER BY, not insertion order.
        let mut shuffled = rows.clone();
        shuffled.reverse();
        append_rows(&conn, ShieldedPool::Orchard, 7, &shuffled).expect("append");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 7).expect("load");
        assert_eq!(loaded, rows);
    }

    #[test]
    fn append_is_idempotent_under_rescan() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = vec![
            (5, h(1), Retention::Ephemeral),
            (6, h(2), Retention::Marked),
        ];
        append_rows(&conn, ShieldedPool::Orchard, 0, &rows).expect("append 1");
        append_rows(&conn, ShieldedPool::Orchard, 0, &rows).expect("append 2 (rescan)");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 0).expect("load");
        assert_eq!(
            loaded, rows,
            "REPLACE semantics — no duplicates, same content"
        );
    }

    #[test]
    fn pools_and_shards_are_disjoint_and_delete_is_scoped() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let row = |p: u64| vec![(p, h(0), Retention::Ephemeral)];
        append_rows(&conn, ShieldedPool::Orchard, 1, &row(10)).expect("o1");
        append_rows(&conn, ShieldedPool::Orchard, 2, &row(70_000)).expect("o2");
        append_rows(&conn, ShieldedPool::Sapling, 1, &row(11)).expect("s1");
        delete_shard(&conn, ShieldedPool::Orchard, 1).expect("delete o1");
        let o1: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 1).expect("load o1");
        let o2: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 2).expect("load o2");
        let s1: Vec<BufferRow<sapling::Node>> =
            load_shard(&conn, ShieldedPool::Sapling, 1).expect("load s1");
        assert!(o1.is_empty());
        assert_eq!(o2.len(), 1);
        assert_eq!(s1.len(), 1, "sapling shard 1 untouched by orchard delete");
    }

    #[test]
    fn rewind_deletes_at_and_above_position() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = (0..4u64)
            .map(|i| (100 + i, h(0), Retention::Ephemeral))
            .collect();
        append_rows(&conn, ShieldedPool::Orchard, 0, &rows).expect("append");
        delete_from_position(&conn, ShieldedPool::Orchard, 102).expect("rewind");
        let loaded: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 0).expect("load");
        assert_eq!(
            loaded.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![100, 101]
        );
    }

    #[test]
    fn buffered_shards_positions_and_run_deletes_are_scoped() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let rows = |positions: Range<u64>| -> Vec<BufferRow<MerkleHashOrchard>> {
            positions.map(|p| (p, h(0), Retention::Ephemeral)).collect()
        };
        append_rows(&conn, ShieldedPool::Orchard, 1, &rows(65_536..65_546)).expect("o1");
        append_rows(&conn, ShieldedPool::Orchard, 3, &rows(196_608..196_610)).expect("o3");
        append_rows(&conn, ShieldedPool::Sapling, 1, &rows(65_536..65_540)).expect("s1");
        assert_eq!(
            buffered_shards(&conn, ShieldedPool::Orchard).expect("shards"),
            vec![1, 3]
        );
        delete_rows_in(&conn, ShieldedPool::Orchard, 1, 65_538..65_541).expect("delete");
        assert_eq!(
            buffered_positions(&conn, ShieldedPool::Orchard, 1).expect("positions"),
            [65_536, 65_537]
                .into_iter()
                .chain(65_541..65_546)
                .collect::<Vec<_>>(),
            "only the run's rows are deleted"
        );
        assert_eq!(
            buffered_positions(&conn, ShieldedPool::Orchard, 3).expect("positions"),
            vec![196_608, 196_609],
            "another shard is untouched"
        );
        assert_eq!(
            buffered_positions(&conn, ShieldedPool::Sapling, 1)
                .expect("positions")
                .len(),
            4,
            "the other pool is untouched"
        );
    }

    #[test]
    fn contiguous_runs_split_at_gaps() {
        assert_eq!(
            contiguous_runs(&[1, 2, 3, 7, 8, 10]),
            vec![1..=3, 7..=8, 10..=10]
        );
        assert!(contiguous_runs(&[]).is_empty());
    }

    #[test]
    fn first_seeders_trusts_the_first_range_to_seed_a_shard_before_any_unknown_start() {
        const S: u64 = 1 << SHARD_BITS;
        // In scan order: shard 2, shard 1, shard 2 again, a range with an unknown start,
        // shard 0.
        let seeders = first_seeders([Some(2 * S + 5), Some(S + 9), Some(2 * S + 1), None, Some(7)]);
        assert_eq!(
            seeders,
            BTreeMap::from([(1, S + 9), (2, 2 * S + 5)]),
            "only the first range seeds a shard, and shard 0 is first claimed after an unknown start"
        );
    }

    #[test]
    fn stranded_runs_leave_the_run_the_first_seeder_continues() {
        let positions: Vec<u64> = (10..20).chain(30..45).collect();
        assert_eq!(stranded_runs(&positions, Some(45)), vec![10..=19]);
        assert_eq!(
            stranded_runs(&positions, Some(40)),
            vec![10..=19],
            "the seed trims the run's rows from its own start on; the run is still its own"
        );
        assert_eq!(
            stranded_runs(&positions, Some(50)),
            vec![10..=19, 30..=44],
            "a start that continues no run strands every run"
        );
        assert_eq!(stranded_runs(&positions, None), vec![10..=19, 30..=44]);
    }

    #[test]
    fn can_build_needs_a_known_end() {
        let pending_starts = BTreeSet::from([100]);
        assert!(
            can_build(&(10..=50), true, &pending_starts),
            "the tree's leaf at the run's end is its last row"
        );
        assert!(
            can_build(&(10..=99), false, &pending_starts),
            "a pending range starts right after it"
        );
        assert!(
            can_build(&(65_000..=65_535), false, &pending_starts),
            "it reaches the end of its shard"
        );
        assert!(!can_build(&(10..=50), false, &pending_starts));
    }

    #[test]
    fn scanned_stretches_are_the_heights_no_pending_range_covers() {
        let h = BlockHeight::from;
        assert_eq!(
            scanned_stretches(
                [h(50)..h(60), h(20)..h(30), h(0)..h(15), h(90)..h(200)],
                h(10),
                h(100)
            ),
            vec![h(15)..h(20), h(30)..h(50), h(60)..h(90)]
        );
        assert_eq!(scanned_stretches([], h(10), h(100)), vec![h(10)..h(100)]);
    }

    #[test]
    fn delete_shard_outside_keeps_only_the_range_in_that_shard() {
        let conn = mem_conn();
        conn.execute_batch(GRAFT_BUFFER_DDL).expect("table");
        let rows: Vec<BufferRow<MerkleHashOrchard>> = (0..6u64)
            .map(|i| (100 + i, h(0), Retention::Ephemeral))
            .collect();
        append_rows(&conn, ShieldedPool::Orchard, 0, &rows).expect("append o0");
        append_rows(&conn, ShieldedPool::Sapling, 0, &rows).expect("append s0");
        delete_shard_outside(&conn, ShieldedPool::Orchard, 0, 101..104).expect("delete");
        let orchard: Vec<BufferRow<MerkleHashOrchard>> =
            load_shard(&conn, ShieldedPool::Orchard, 0).expect("load o0");
        assert_eq!(
            orchard.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![101, 102, 103],
            "only the kept range survives"
        );
        let sapling: Vec<BufferRow<sapling::Node>> =
            load_shard(&conn, ShieldedPool::Sapling, 0).expect("load s0");
        assert_eq!(sapling.len(), 6, "the other pool is untouched");
    }
}
