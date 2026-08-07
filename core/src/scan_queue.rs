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

//! Slipstream-owned scan-queue hygiene (additive; the upstream data model is untouched).
//!
//! [B4-16] Upstream `WalletWrite::delete_account` removes the account row and the
//! transaction data solely linked to it — but it NEVER touches `scan_queue`. The historic
//! ranges a deep-birthday import queued survive the deletion, so the engine would grind a
//! full deep restore for viewing keys that no longer exist: hours of wasted scan on a
//! wallet whose remaining accounts cannot have notes down there (an account has no notes
//! below its birthday).
//!
//! [`prune_orphaned_historic_ranges`] restores the queue to the shape it would have if the
//! deleted account had never been imported: work queued ENTIRELY below every remaining
//! account's birthday is cancelled and straddlers are trimmed to start at that floor,
//! RETAINING `OpenAdjacent` and greater. Per the trait's contiguity contract, cancelled
//! ranges are demoted in place to `Ignored` (merging adjacent demotions) wherever a
//! retained row lies beneath them; only coverage below the lowest retained row is deleted
//! outright, since that merely raises the queue's floor:
//!
//! - `Historic` work below the wallet birthday can only have been justified by a
//!   now-deleted account — upstream never queues Historic ranges below the wallet
//!   birthday, and [`WalletRead::get_wallet_birthday`] is exactly that floor.
//! - `OpenAdjacent`/`FoundNote`/`ChainTip`/`Verify` rows are kept even below the floor: a
//!   REMAINING account's shard-completion range (needed for witnesses) may legitimately
//!   start below its birthday — a found note's subtree spans earlier blocks. A stale one
//!   left by the deleted account is bounded by shard size: seconds of scan, not hours.
//! - `Scanned`/`Ignored` rows are bookkeeping, not work — upstream itself maintains them
//!   (e.g. the canonical `Ignored` range spanning activation → wallet birthday), so
//!   `prune_scan_queue_below` retains them unconditionally in its `Some(_)` form; pruning
//!   them would make the queue shape diverge from upstream's (the golden oracle's
//!   restart-equivalence test catches exactly that).
//!
//! Issue #4: the whole operation is expressed through the upstream storage traits
//! ([`WalletRead::get_wallet_birthday`] for the floor,
//! [`WalletWrite::prune_scan_queue_below`] for the demote/trim — whose no-op fast path
//! stays read-only, taking no write lock).
//!
//! Called from [`crate::wallet_session::WalletSession::open`] — i.e. at host open AND at
//! every pass start (`engine::sync_once` opens a fresh session) — so a wallet wedged by an
//! earlier delete heals at the next launch, and an in-app delete → restart heals
//! immediately, with no FFI surface. No accounts ⇒ no floor ⇒ no-op. Idempotent.
//!
//! [`WalletRead::get_wallet_birthday`]: zcash_client_backend::data_api::WalletRead::get_wallet_birthday
//! [`WalletWrite::prune_scan_queue_below`]: zcash_client_backend::data_api::WalletWrite::prune_scan_queue_below

use zcash_client_backend::data_api::{WalletRead, WalletWrite, scanning::ScanPriority};

use crate::error::SlipstreamError;
use crate::wallet_session::Db;

/// Cancel scan work queued below EVERY remaining account's birthday (demoting to
/// `Ignored`, or deleting where the trait's contiguity contract permits), retaining the
/// witness-relevant priorities (`OpenAdjacent` and greater). Returns the number of rows
/// changed (deleted, demoted, or trimmed); `Ok(0)` when there are no accounts or nothing
/// qualifies (the common case — a read-only probe, no write lock).
pub fn prune_orphaned_historic_ranges(db: &mut Db) -> Result<u64, SlipstreamError> {
    let err = |context: &str, e: &dyn std::fmt::Display| {
        SlipstreamError::Wallet(format!("scan-queue prune {context}: {e}"))
    };
    let Some(floor) = db
        .get_wallet_birthday()
        .map_err(|e| err("wallet birthday", &e))?
    else {
        return Ok(0);
    };
    db.prune_scan_queue_below(floor, Some(ScanPriority::OpenAdjacent))
        .map_err(|e| err("prune", &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_session::{TEST_UFVK, WalletSession};
    use rusqlite::{Connection, params};
    use zcash_protocol::consensus::Network;

    /// Migrated wallet with ONE account (birthday 663_150 — the treestate is at 663_149),
    /// then the scan queue cleared so tests insert controlled rows only. The session stays
    /// open (the prune runs through its WalletDb); the side connection serves the test's
    /// own fixture inserts and assertions (WAL permits both).
    fn fixture_with_account() -> (tempfile::TempDir, WalletSession, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let ts = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(TEST_UFVK, ts).expect("import account");
        let conn = Connection::open(&path).expect("conn");
        conn.execute("DELETE FROM scan_queue", [])
            .expect("clear queue");
        (dir, s, conn)
    }

    fn insert_range(conn: &Connection, start: i64, end: i64, priority: i64) {
        conn.execute(
            "INSERT INTO scan_queue (block_range_start, block_range_end, priority) \
             VALUES (?1, ?2, ?3)",
            params![start, end, priority],
        )
        .expect("insert scan_queue row");
    }

    fn ranges(conn: &Connection) -> Vec<(i64, i64, i64)> {
        let mut stmt = conn
            .prepare(
                "SELECT block_range_start, block_range_end, priority FROM scan_queue \
                 ORDER BY block_range_start",
            )
            .expect("prepare");
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    }

    /// The core B4-16 shape: a deleted deep-birthday account left Historic ranges below
    /// the remaining account's birthday (663_150). Fully-below rows sit above the
    /// retained FoundNote row, so contiguity demotes them (merged with the straddler's
    /// vacated span) to a single `Ignored` row rather than deleting them; the straddler
    /// is trimmed to the floor, and Historic-above plus the witness-class FoundNote and
    /// bookkeeping Scanned rows below the floor are kept. Rows are non-overlapping
    /// (queue invariant).
    #[test]
    fn prune_drops_orphaned_historic_keeps_justified_rows() {
        let (_dir, mut s, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 550_000, 20); // Historic, fully below → deleted
        insert_range(&conn, 550_000, 600_000, 20); // Historic, fully below → deleted
        insert_range(&conn, 600_000, 700_000, 20); // Historic straddler → trimmed
        insert_range(&conn, 700_000, 710_000, 20); // Historic above floor → kept
        insert_range(&conn, 450_000, 460_000, 40); // FoundNote below floor → kept
        insert_range(&conn, 460_000, 470_000, 10); // Scanned below floor → kept (bookkeeping)

        let changed = prune_orphaned_historic_ranges(s.db_mut()).expect("prune");
        assert_eq!(changed, 3, "2 demoted + 1 trimmed");
        assert_eq!(
            ranges(&conn),
            vec![
                (450_000, 460_000, 40),
                (460_000, 470_000, 10),
                (500_000, 663_150, 0),
                (663_150, 700_000, 20),
                (700_000, 710_000, 20),
            ]
        );
    }

    /// `block_range_end` is EXCLUSIVE: a row ending exactly at the floor covers only
    /// heights strictly below every birthday, so it is dropped whole (not trimmed to an
    /// empty range, which the schema's `start < end` CHECK would reject).
    #[test]
    fn prune_treats_end_at_floor_as_fully_below() {
        let (_dir, mut s, conn) = fixture_with_account();
        insert_range(&conn, 600_000, 663_150, 20);
        assert_eq!(
            prune_orphaned_historic_ranges(s.db_mut()).expect("prune"),
            1
        );
        assert!(ranges(&conn).is_empty());
    }

    /// No accounts ⇒ no floor ⇒ strict no-op (a fresh wallet's queue is never touched).
    #[test]
    fn prune_without_accounts_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let conn = Connection::open(&path).expect("conn");
        insert_range(&conn, 100_000, 200_000, 20);

        assert_eq!(
            prune_orphaned_historic_ranges(s.db_mut()).expect("prune"),
            0
        );
        assert_eq!(ranges(&conn), vec![(100_000, 200_000, 20)]);
    }

    /// A second run finds nothing (and, per the fast path, takes no write transaction).
    #[test]
    fn prune_is_idempotent() {
        let (_dir, mut s, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 600_000, 20);
        assert_eq!(
            prune_orphaned_historic_ranges(s.db_mut()).expect("first"),
            1
        );
        assert_eq!(
            prune_orphaned_historic_ranges(s.db_mut()).expect("second"),
            0
        );
    }

    /// End-to-end proof of the hook: `WalletSession::open` itself heals a wedged wallet —
    /// the exact field path (app relaunch after a mid-restore account delete).
    #[test]
    fn open_prunes_orphaned_ranges() {
        let (dir, s, conn) = fixture_with_account();
        insert_range(&conn, 500_000, 600_000, 20);
        drop(conn);
        drop(s);

        let path = dir.path().join("data.db");
        let _s = WalletSession::open(Network::MainNetwork, &path).expect("re-open");
        let conn = Connection::open(&path).expect("conn");
        let below: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_queue WHERE priority = 20 AND block_range_start < 663_150",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(below, 0, "open() must prune the orphaned historic range");
    }
}
