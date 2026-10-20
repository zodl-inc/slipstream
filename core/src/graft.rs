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
//!   leaf (`graft_accumulator::resumable_run`), and deletes only the rows at the
//!   positions it scans again; a run it resumes on a shard the store already
//!   holds content for is built again with its first span (same leaves at the
//!   same positions) — self-healing; any other row of the shard is left to the
//!   next pass's start sweep;
//! - stop after a range's last commit, before its range-end build (a host abort
//!   landing in the final drain) → the range is scanned, but its range-end shard's
//!   rows stay buffered and no later range resumes them (Historic ranges run newest
//!   first) → the next pass's start sweep (`persist::sweep_stranded_graft_rows`)
//!   builds them when data the wallet already holds checks where they end (the
//!   tree's leaf there, or the stored root of the shard they complete), and
//!   otherwise deletes them and queues a rescan of their blocks.
//!
//! The invariant "block marked scanned ⇒ its commitments are in the shard store
//! OR in this buffer" therefore holds at every crash point. After a pass's start
//! sweep, a buffered run of scanned blocks is one the first range to seed in its
//! shard resumes, unless the sweep could not read its shard or the wallet's block
//! metadata cannot place it (the sweep then leaves it, with a warning). A shard
//! whose rows will not decode is swept by position: each run whose blocks the
//! metadata places is queued for a rescan and then deleted, and any other run
//! stays, with a warning. A seed that still meets such a shard seeds without a
//! resume and builds what its range scans there, instead of failing. Only a
//! decode failure counts ([`will_not_decode`]): any other error reading a shard
//! fails the seed's range for the pass, and the sweep leaves that shard's rows.
//!
//! No seed or cleanup deletes a row at a position its own range does not feed:
//! a seed deletes the rows at the positions its call feeds again, and a build or
//! graft deletes the rows of the row set it built. So when the sweep's forecast
//! goes stale during a pass (it did not run, or the queue changed and another
//! range seeds in a shard first), the runs no range continues stay buffered for
//! the next pass's sweep, which builds them or rescans their blocks.
//!
//! No range buffers a row right after a run it rejects: when the run that ends
//! right before a seed's start is not on that range's frontier leaf (another
//! chain's rows, as a reorg's truncation can leave them), the range builds what
//! it scans in that shard instead. A resume takes every row contiguous below the
//! start, and the sweep's last-leaf check reads only a run's last row, so either
//! would otherwise take the rejected run with the range's own rows.

use std::collections::BTreeMap;
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

/// Whether `e`, an error of [`load_shard`], says that the shard's rows will not
/// decode: a row's commitment or retention cannot be read back. `load_shard`
/// reports exactly those as `CorruptedData`; any other error is SQLite's own (a
/// busy database past the timeout, an I/O error), which says nothing about the
/// rows.
pub(crate) fn will_not_decode(e: &SqliteClientError) -> bool {
    matches!(e, SqliteClientError::CorruptedData(_))
}

/// Drop one shard's buffer. Only tests drop a whole shard: every production delete
/// covers just the positions its caller fed, built or queued for a rescan
/// ([`delete_rows_in`], [`delete_from_position`]).
#[cfg(test)]
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

/// Drop one shard's rows inside `run`: the positions a range's seed feeds again, a row
/// set a range built or grafted, or a stranded run the pass-start sweep has built or
/// queued for a rescan.
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
/// A range seeds in the shard its start position falls in, and only the first
/// range to seed in a shard is trusted to resume one of its runs
/// (`graft_accumulator::resumable_run`): it is the next range to meet the shard,
/// while what a later one meets depends on the ranges before it, and its start can
/// still change as the pass goes on (a found note, a rescan queued after the
/// sweep). Every other run is the sweep's to build or rescan now. A run this
/// forecast still gets wrong stays buffered for the next sweep, since no range
/// deletes rows at positions it does not feed. A shard first claimed after a range
/// whose start is unknown is left out: that range may seed in the same shard first.
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
/// continues; its rows at or above `resume_at` are at positions of the seeding
/// range's blocks, which it scans again (its seed deletes those its first call
/// feeds, and any its range does not reach stay for the next sweep), so that run
/// is left whole. Every other run is stranded.
pub(crate) fn stranded_runs(positions: &[u64], resume_at: Option<u64>) -> Vec<RangeInclusive<u64>> {
    let resumed = resume_at.and_then(|start| start.checked_sub(1));
    contiguous_runs(positions)
        .into_iter()
        .filter(|run| resumed.is_none_or(|last| !run.contains(&last)))
        .collect()
}

/// What the wallet already holds that checks where a stranded run ends ([`end_check`]).
/// The pass-start sweep builds only a run it can check this way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndCheck<H> {
    /// The commitment tree holds a leaf at the run's last position, and it is the run's
    /// last row. A range scanned above the run inserted it as its `from_state` frontier,
    /// so the next commitment on the chain is that range's.
    LastLeaf,
    /// The run completes its shard, and the wallet stores a root for that shard: the
    /// server's, which every pass start ingests before the sweep. Once the run is in the
    /// tree, the shard's root computed from it must be this one.
    ShardRoot(H),
}

/// How a stranded run's end can be checked against data the wallet already holds, or
/// `None` when nothing does (the sweep then rescans the run's blocks).
///
/// `last_leaf_matches`: the tree holds a leaf at the run's last position, and it is the
/// run's last row; it is preferred. `stored_root`: the root the wallet stores for the
/// run's shard, which checks only a run that completes the shard. Positions alone never
/// check a run: neither a pending range that starts right after it nor the end of its
/// shard says whether its rows are the chain's, and rows a reorg left buffered before
/// the engine cleaned the buffer on rewinds may be another chain's.
pub(crate) fn end_check<H>(
    run: &RangeInclusive<u64>,
    last_leaf_matches: bool,
    stored_root: Option<H>,
) -> Option<EndCheck<H>> {
    if last_leaf_matches {
        Some(EndCheck::LastLeaf)
    } else if (*run.end() + 1).is_multiple_of(1 << SHARD_BITS) {
        stored_root.map(EndCheck::ShardRoot)
    } else {
        None
    }
}

/// Whether `rows` are exactly the rows of `run`: one per position, ascending and
/// contiguous from its first position to its last. A build lays rows out from the
/// first row's position, so rows that miss a position or hold one twice would put
/// every later leaf at the wrong position; the pass-start sweep then treats the run
/// as one nothing checks, and rescans its blocks.
pub(crate) fn rows_cover_run<H>(rows: &[BufferRow<H>], run: &RangeInclusive<u64>) -> bool {
    rows.len() as u64 == *run.end() - *run.start() + 1
        && rows.first().is_some_and(|row| row.0 == *run.start())
        && rows.windows(2).all(|pair| pair[0].0 + 1 == pair[1].0)
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

/// The block ranges to rescan so that every scanned block holding a position of `run`
/// is scanned again: in each scanned stretch the run reaches, from the block holding its
/// first position (or the stretch's first block) to the block holding its last (or the
/// stretch's last block). Positions in blocks a pending range covers need nothing.
/// `size_at(height)` is the pool's tree size at the end of block `height`, when the
/// wallet holds that block's metadata; `None` (the result) when the metadata cannot
/// place the run.
///
/// Two walks over the `stretches` (ascending, as [`scanned_stretches`] returns them)
/// find these ranges, and a block without its size stops either. The walk from the
/// newest stretch down ([`walk_from_newest`]) stops as soon as it sees where the run
/// begins, so old stretches without a pool's tree sizes (blocks scanned before the
/// wallet recorded them) stop it only where the run may begin in the first block of the
/// stretch above them; but it reads the end of every stretch above the run. When one of
/// those has no size, the walk from the oldest stretch up ([`walk_from_oldest`]), which
/// stops at the stretch the run ends in, places the run instead. Neither guesses a size
/// it lacks, so both place a run as they would with every size known. `None` means
/// neither can: a block on the walks' path through the run's own stretches has no size,
/// or each walk meets a stretch without sizes on its way to the run.
pub(crate) fn rescans_for<E>(
    mut size_at: impl FnMut(BlockHeight) -> Result<Option<u64>, E>,
    run: &RangeInclusive<u64>,
    stretches: &[Range<BlockHeight>],
) -> Result<Option<Vec<Range<BlockHeight>>>, E> {
    match walk_from_newest(&mut size_at, run, stretches)? {
        Some(rescans) => Ok(Some(rescans)),
        None => walk_from_oldest(&mut size_at, run, stretches),
    }
}

/// [`rescans_for`]'s walk from the newest stretch down. It stops at the first stretch
/// that ends at or before the run's first position, or as soon as the run is seen to
/// begin inside a stretch: positions only grow with heights, so no older stretch holds any
/// of it. An older stretch is read only when the run may begin in the first block of the
/// one above it, which nothing but the older stretch's end can tell. Every stretch above
/// the run is read on the way down, so one whose last block has no size stops the walk:
/// with stretches [10, 20), [30, 40) and [50, 60), sizes missing on 50..60 and the run
/// 32..=35, it returns `None`, and [`walk_from_oldest`] places the run.
fn walk_from_newest<E>(
    size_at: &mut impl FnMut(BlockHeight) -> Result<Option<u64>, E>,
    run: &RangeInclusive<u64>,
    stretches: &[Range<BlockHeight>],
) -> Result<Option<Vec<Range<BlockHeight>>>, E> {
    let (first, last) = (*run.start(), *run.end());
    let mut rescans = vec![];
    // The rescan in the lowest stretch seen so far that ends past the run: of the
    // stretches that do, only the lowest can hold any of it.
    let mut past_last = None;
    for stretch in stretches.iter().rev() {
        let Some(end_size) = size_at(stretch.end - 1)? else {
            return Ok(None);
        };
        if end_size <= first {
            break;
        }
        let Some(from) = first_block_past(size_at, first, stretch)? else {
            return Ok(None);
        };
        if end_size > last {
            let Some(to) = first_block_past(size_at, last, stretch)? else {
                return Ok(None);
            };
            past_last = Some(from..to + 1);
        } else {
            rescans.extend(past_last.take());
            rescans.push(from..stretch.end);
        }
        // The block before `from` ends at or before the run's first position: the run
        // begins in this stretch.
        if from > stretch.start {
            break;
        }
    }
    rescans.extend(past_last);
    rescans.reverse();
    Ok(Some(rescans))
}

/// [`rescans_for`]'s walk from the oldest stretch up. It stops at the first stretch that
/// ends past the run's last position: positions only grow with heights, so no newer
/// stretch holds any of it. It reads the end of every stretch below the run on the way
/// up, so an old stretch whose last block has no size stops the walk.
fn walk_from_oldest<E>(
    size_at: &mut impl FnMut(BlockHeight) -> Result<Option<u64>, E>,
    run: &RangeInclusive<u64>,
    stretches: &[Range<BlockHeight>],
) -> Result<Option<Vec<Range<BlockHeight>>>, E> {
    let (first, last) = (*run.start(), *run.end());
    let mut rescans = vec![];
    for stretch in stretches {
        let Some(end_size) = size_at(stretch.end - 1)? else {
            return Ok(None);
        };
        if end_size <= first {
            continue;
        }
        let Some(from) = first_block_past(size_at, first, stretch)? else {
            return Ok(None);
        };
        if end_size > last {
            let Some(to) = first_block_past(size_at, last, stretch)? else {
                return Ok(None);
            };
            rescans.push(from..to + 1);
            break;
        }
        rescans.push(from..stretch.end);
    }
    Ok(Some(rescans))
}

/// The lowest height in `stretch` whose block ends with more than `position`
/// commitments: the block holding `position`, or the stretch's first block when
/// `position` lies below the stretch. `None` when the stretch's metadata does not decide
/// it (a block without metadata, or `position` at or past the stretch's end).
fn first_block_past<E>(
    size_at: &mut impl FnMut(BlockHeight) -> Result<Option<u64>, E>,
    position: u64,
    stretch: &Range<BlockHeight>,
) -> Result<Option<BlockHeight>, E> {
    let (mut lo, mut hi) = (u32::from(stretch.start), u32::from(stretch.end) - 1);
    if size_at(BlockHeight::from(hi))?.is_none_or(|size| size <= position) {
        return Ok(None);
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match size_at(BlockHeight::from(mid))? {
            Some(size) if size > position => hi = mid,
            Some(_) => lo = mid + 1,
            None => return Ok(None),
        }
    }
    Ok(Some(BlockHeight::from(lo)))
}

/// The rewind delete of [`delete_from_position`] and [`delete_from_position_in`].
const DELETE_FROM_POSITION: &str =
    "DELETE FROM ext_slipstream_graft_buffer WHERE pool = ?1 AND position >= ?2";

/// Rewind support (plan Task 9): drop every buffered row at or above `min_position`.
///
/// Upstream's rewinds never see this engine-owned table, so the engine drops the rows
/// with its own: after an account import's rewind (`WalletSession::import_account`),
/// and inside the reorg recovery's truncation ([`delete_from_position_in`]). The
/// blocks they queue again hold exactly the rows at or above the rewind's tree size.
pub(crate) fn delete_from_position(
    conn: &Connection,
    pool: ShieldedPool,
    min_position: u64,
) -> Result<(), SqliteClientError> {
    conn.execute(
        DELETE_FROM_POSITION,
        params![pool_code(pool), min_position as i64],
    )?;
    Ok(())
}

/// [`delete_from_position`] inside a wallet transaction, through its extension handle
/// (`WalletDb::transactionally_with_extension`): `WalletSession::truncate_to_height`
/// drops the rows in upstream's own truncation transaction, so both commit or neither.
pub(crate) fn delete_from_position_in(
    ext: &zcash_client_sqlite::ExtensionTransaction<'_>,
    pool: ShieldedPool,
    min_position: u64,
) -> Result<(), SqliteClientError> {
    ext.execute(
        DELETE_FROM_POSITION,
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
    fn end_check_needs_data_the_wallet_holds() {
        let shard_end = 65_000..=65_535;
        assert_eq!(
            end_check(&(10..=50), true, Some(h(3))),
            Some(EndCheck::LastLeaf),
            "the tree's leaf at the run's end is its last row"
        );
        assert_eq!(
            end_check(&shard_end, true, Some(h(3))),
            Some(EndCheck::LastLeaf),
            "the tree's leaf is preferred to the shard's root"
        );
        assert_eq!(
            end_check(&shard_end, false, Some(h(3))),
            Some(EndCheck::ShardRoot(h(3))),
            "the run completes its shard, whose root the wallet stores"
        );
        assert_eq!(
            end_check::<MerkleHashOrchard>(&shard_end, false, None),
            None,
            "reaching the end of its shard does not check a run"
        );
        assert_eq!(
            end_check(&(10..=99), false, Some(h(3))),
            None,
            "a stored root checks only a run that completes the shard, and nothing checks \
             a run by the pending range that starts right after it"
        );
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
    fn rows_cover_run_only_with_one_row_per_position() {
        let rows = |positions: &[u64]| -> Vec<BufferRow<MerkleHashOrchard>> {
            positions
                .iter()
                .map(|&p| (p, h(0), Retention::Ephemeral))
                .collect()
        };
        assert!(rows_cover_run(&rows(&[10, 11, 12]), &(10..=12)));
        assert!(
            !rows_cover_run(&rows(&[10, 12]), &(10..=12)),
            "a position is missing"
        );
        assert!(
            !rows_cover_run(&rows(&[10, 11, 11]), &(10..=12)),
            "a position is held twice"
        );
        assert!(
            !rows_cover_run(&rows(&[11, 12, 13]), &(10..=12)),
            "the rows start past the run"
        );
        assert!(
            !rows_cover_run(&rows(&[10, 11, 12, 13]), &(10..=12)),
            "a row lies past the run"
        );
        assert!(!rows_cover_run(&rows(&[]), &(10..=12)), "no rows");
    }

    /// One commitment per block, at the block's own height, except in `missing`, whose
    /// blocks carry no tree size: `size_at(h) = h + 1`.
    fn sizes(missing: Range<u32>) -> impl FnMut(BlockHeight) -> Result<Option<u64>, ()> {
        move |height| {
            let height = u32::from(height);
            Ok((!missing.contains(&height)).then_some(u64::from(height) + 1))
        }
    }

    /// The walk this module replaced (oldest stretch first), kept as the reference the
    /// newest-first walk must agree with wherever every block has its tree size.
    fn rescans_oldest_first(
        mut size_at: impl FnMut(BlockHeight) -> Result<Option<u64>, ()>,
        run: &RangeInclusive<u64>,
        stretches: &[Range<BlockHeight>],
    ) -> Option<Vec<Range<BlockHeight>>> {
        let (first, last) = (*run.start(), *run.end());
        let mut rescans = vec![];
        for stretch in stretches {
            let end_size = size_at(stretch.end - 1).ok()??;
            if end_size <= first {
                continue;
            }
            let from = first_block_past(&mut size_at, first, stretch).ok()??;
            let to = if end_size > last {
                first_block_past(&mut size_at, last, stretch).ok()??
            } else {
                stretch.end - 1
            };
            rescans.push(from..to + 1);
            if end_size > last {
                break;
            }
        }
        Some(rescans)
    }

    #[test]
    fn rescans_for_finds_the_scanned_blocks_holding_a_run() {
        let h = BlockHeight::from;
        let stretches = [h(10)..h(20), h(30)..h(40), h(50)..h(60)];
        let rescans =
            |run: RangeInclusive<u64>| rescans_for(sizes(0..0), &run, &stretches).expect("sizes");
        assert_eq!(
            rescans(32..=35),
            Some(vec![h(32)..h(36)]),
            "a run inside one stretch"
        );
        assert_eq!(
            rescans(15..=55),
            Some(vec![h(15)..h(20), h(30)..h(40), h(50)..h(56)]),
            "a run across stretches"
        );
        assert_eq!(
            rescans(70..=75),
            Some(vec![]),
            "positions of pending blocks need nothing"
        );
        assert_eq!(
            rescans(22..=25),
            Some(vec![h(30)..h(31)]),
            "a run below a stretch's first block: nothing tells whether that block holds it"
        );
        // Wherever every block has its tree size, the walk agrees with the oldest-first one.
        for first in 0..70u64 {
            for last in first..70 {
                assert_eq!(
                    rescans(first..=last),
                    rescans_oldest_first(sizes(0..0), &(first..=last), &stretches),
                    "run {first}..={last}"
                );
            }
        }
    }

    #[test]
    fn rescans_for_never_reads_the_stretches_below_a_run() {
        let h = BlockHeight::from;
        let stretches = [h(10)..h(20), h(30)..h(40), h(50)..h(60)];
        // The oldest stretch's blocks carry no tree size (scanned before the wallet
        // recorded the pool's sizes); the oldest-first walk could place no run at all.
        let old_gap = || sizes(10..20);
        assert_eq!(
            rescans_oldest_first(old_gap(), &(32..=35), &stretches),
            None,
            "the oldest-first walk stops at the old stretch"
        );
        assert_eq!(
            rescans_for(old_gap(), &(32..=35), &stretches),
            Ok(Some(vec![h(32)..h(36)])),
            "a run beginning inside a newer stretch is placed"
        );
        assert_eq!(
            rescans_for(old_gap(), &(45..=55), &stretches),
            Ok(Some(vec![h(50)..h(56)])),
            "the stretch ending below the run ends the walk"
        );
        assert_eq!(
            rescans_for(sizes(30..40), &(52..=55), &stretches),
            Ok(Some(vec![h(52)..h(56)])),
            "a run beginning inside the newest stretch reads nothing older"
        );
        assert_eq!(
            rescans_for(sizes(30..40), &(32..=35), &stretches),
            Ok(None),
            "a run in blocks without sizes still cannot be placed"
        );
        assert_eq!(
            rescans_for(old_gap(), &(30..=35), &stretches),
            Ok(None),
            "nor one that may begin below its stretch's first block, where only the old \
             stretch's end could tell"
        );
    }

    /// A stretch ABOVE the run has no sizes. The walk from the newest stretch reads that
    /// stretch's end on its way down and cannot place the run; the walk from the oldest
    /// stretch stops at the stretch the run ends in and never reads it, so the run is placed.
    #[test]
    fn rescans_for_places_a_run_below_a_stretch_without_sizes() {
        let h = BlockHeight::from;
        let stretches = [h(10)..h(20), h(30)..h(40), h(50)..h(60)];
        let new_gap = || sizes(50..60);
        assert_eq!(
            rescans_for(new_gap(), &(32..=35), &stretches),
            Ok(Some(vec![h(32)..h(36)])),
            "a run below the stretch without sizes is placed"
        );
        assert_eq!(
            rescans_for(new_gap(), &(15..=35), &stretches),
            Ok(Some(vec![h(15)..h(20), h(30)..h(36)])),
            "so is one across the stretches below it"
        );
        assert_eq!(
            rescans_for(new_gap(), &(52..=55), &stretches),
            Ok(None),
            "a run in the stretch without sizes is not"
        );
        assert_eq!(
            rescans_for(new_gap(), &(35..=52), &stretches),
            Ok(None),
            "nor is one reaching into it"
        );
    }

    /// Neither walk guesses a size it lacks: each places a run as it would with every size
    /// known, or not at all, and `rescans_for` places it whenever either walk does. Checked
    /// over runs of every span and sizes missing in each place, against the answer with
    /// every size known.
    #[test]
    fn rescans_for_places_a_run_whenever_either_walk_does() {
        let h = BlockHeight::from;
        let stretches = [h(10)..h(20), h(30)..h(40), h(50)..h(60)];
        assert_eq!(
            walk_from_newest(&mut sizes(50..60), &(32..=35), &stretches),
            Ok(None),
            "the walk from the newest stops at the stretch without sizes above the run"
        );
        let gaps = [
            10..20,
            30..40,
            50..60,
            12..13,
            17..18,
            33..35,
            39..40,
            50..51,
            55..57,
            10..40,
            30..60,
            19..51,
        ];
        let mut only_from_oldest = 0;
        for first in 0..70u64 {
            for last in first..70 {
                let run = first..=last;
                let known = rescans_for(sizes(0..0), &run, &stretches).expect("sizes");
                assert!(
                    known.is_some(),
                    "every size known places run {first}..={last}"
                );
                for gap in &gaps {
                    let newest =
                        walk_from_newest(&mut sizes(gap.clone()), &run, &stretches).expect("sizes");
                    let oldest =
                        walk_from_oldest(&mut sizes(gap.clone()), &run, &stretches).expect("sizes");
                    for (walk, placed) in [("newest", &newest), ("oldest", &oldest)] {
                        assert!(
                            placed.is_none() || *placed == known,
                            "the walk from the {walk} places run {first}..={last} as with \
                             every size known (sizes missing on {gap:?})"
                        );
                    }
                    assert_eq!(
                        rescans_for(sizes(gap.clone()), &run, &stretches).expect("sizes"),
                        newest.clone().or(oldest.clone()),
                        "run {first}..={last}, sizes missing on {gap:?}"
                    );
                    if newest.is_none() && oldest.is_some() {
                        only_from_oldest += 1;
                    }
                }
            }
        }
        assert!(
            only_from_oldest > 0,
            "some runs only the walk from the oldest places"
        );
    }
}
