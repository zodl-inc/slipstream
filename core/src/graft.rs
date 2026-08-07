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
//! - crash after main-commit, before a close-verdict cleanup → stale rows for a
//!   built shard → the accumulator's seed rule ("store already has internals →
//!   passthrough") drops + deletes them — self-healing.
//!
//! The invariant "block marked scanned ⇒ its commitments are in the shard store
//! OR in this buffer" therefore holds at every crash point.

use incrementalmerkletree::{Marking, Retention};
use rusqlite::{Connection, params};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::{ShieldedPool, consensus::BlockHeight};

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

/// Rewind support (plan Task 9): drop every buffered row at or above `min_position`.
///
/// NOT currently called from any production path — the scheduler's reorg-recovery
/// arm (`scheduler.rs`) truncates the wallet DB via upstream's
/// `truncate_to_height`, which has no visibility into this engine-owned table.
/// Exercised only by this module's own tests. Kept (not deleted) because it is
/// real, tested rewind support the recovery arm appears to need but does not yet
/// call — flagged separately rather than wired up here, since fixing the gap
/// itself is out of scope for a dead-code cleanup pass.
#[allow(dead_code)]
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
}
