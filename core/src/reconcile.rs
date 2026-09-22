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

//! Slipstream-owned, read-side transaction reconciliation view (additive).
//!
//! During a recent-first restore the scheduler scans a recent block that spends
//! an older note BEFORE the block where that note was received. Until the older
//! block is scanned, upstream's `v_transactions` has no `*_received_note_spends`
//! row for the spend, so the spend contributes 0 to `account_balance_delta` and
//! a self-send's change reads as a phantom "+receive" (the delta is transiently
//! positive, then flips negative once the spent note is linked). The evidence
//! that a spend exists but is not yet linked lives in `nullifier_map` (the
//! observed nullifier) with no matching `*_received_notes.nf`.
//!
//! `ext_slipstream_v_tx_reconciled` exposes, per wallet txid, whether the tx
//! still has such a dangling shielded spend. A consumer (the SDK) can hold an
//! unreconciled tx out of the Activity list until its delta is final, then
//! reveal it — surfacing genuine receives and already-linked sends *sooner*
//! while keeping the ambiguous change-vs-receive tx hidden until it is *correct*.
//!
//! This is a VIEW (computed on read): it adds NO rows to `data.db`, never runs
//! on the scan/persist hot path, and is invisible to the golden oracle (which
//! diffs `type='table'` only — see `oracle::semantic_diff`). It is created by
//! the `ext_slipstream_*` schema migration (`migrations.rs`, issue #4), so any
//! host of the engine (iOS, Android, CLI) inherits it with no FFI surface
//! change. A fully-synced wallet has no dangling spends, so every tx reads
//! `reconciled = 1` — correct at cold start with the engine not even running.

/// Name of the reconciliation view (kept in sync with [`RECONCILE_VIEW_SQL`]).
pub const RECONCILE_VIEW_NAME: &str = "ext_slipstream_v_tx_reconciled";

/// `CREATE VIEW` for the per-tx reconciliation signal (run by the
/// `ext_slipstream_*` schema migration).
///
/// `reconciled = 0` iff the tx has an observed shielded spend (a `nullifier_map`
/// row at the tx's locator) whose note has not yet been received (no
/// `*_received_notes` row carries that nullifier). `spend_pool` follows upstream
/// `pool_code` (zcash_client_sqlite `wallet/encoding.rs:34`): 2 = Sapling,
/// 3 = Orchard, 4 = Ironwood. Every shielded pool needs its own arm: a
/// `spend_pool` value with no arm matches nothing, so the tx would read
/// `reconciled = 1` with that spend still unlinked — and after NU6.3 activation
/// essentially every received note lands in Ironwood, so an Ironwood-blind view
/// degrades toward "always reconciled" exactly for the wallets it protects
/// (issue #9). Transparent spends never produce this transient (their inputs are
/// linked by outpoint at scan time, not by a later-scanned origin block), so they
/// are intentionally not considered here.
///
/// The `FROM transactions t` anchor keeps the result to *our* wallet's txs:
/// `nullifier_map` records every nullifier in a scanned block (including other
/// parties' spends), but only our txs have a row in `transactions`, so a
/// non-wallet `tl.txid` simply has no `t` to match. The test is "is the note
/// received yet", NOT "is the nullifier still tracked", so it is robust to
/// `prune_tracked_nullifiers` timing.
///
/// KNOWN INVARIANT — the view is APPROXIMATE mid-restore and MUST stay
/// recovery-scoped on the read side ([audit P0-B, verified against a field
/// data.db 2026-07-01]): a nullifier at *our* tx's locator is not necessarily
/// *our* spend. Two classes can never link and stay `reconciled = 0` forever:
///   1. an external RECEIVE — the tx that pays us also carries the SENDER's
///      spends, whose notes are never ours;
///   2. spends of pre-birthday notes — the origin block is below the wallet
///      birthday and will never be scanned.
///
/// Mid-restore these are indistinguishable (from the DB alone) from "our note,
/// origin not yet scanned" — the case this view exists for. Consumers must
/// therefore apply the unreconciled set only WHILE recovery is active (the SDK
/// gates on `isRecovering`); after the backfill completes, nothing more can
/// link, and permanently-dangling rows are expected residue, not an error.
/// (nf-NULL on imported/UFVK accounts was ruled out on the same field DB: all
/// notes, including the hardware-wallet account's, had `nf` populated.)
pub const RECONCILE_VIEW_SQL: &str = "CREATE VIEW ext_slipstream_v_tx_reconciled AS
SELECT t.txid AS txid,
       t.mined_height AS mined_height,
       NOT EXISTS (
           SELECT 1
           FROM nullifier_map nm
           JOIN tx_locator_map tl
               ON tl.block_height = nm.block_height
              AND tl.tx_index = nm.tx_index
           WHERE tl.txid = t.txid
             AND (
                 (nm.spend_pool = 2
                  AND NOT EXISTS (SELECT 1 FROM sapling_received_notes s WHERE s.nf = nm.nf))
                 OR
                 (nm.spend_pool = 3
                  AND NOT EXISTS (SELECT 1 FROM orchard_received_notes o WHERE o.nf = nm.nf))
                 OR
                 (nm.spend_pool = 4
                  AND NOT EXISTS (SELECT 1 FROM ironwood_received_notes i WHERE i.nf = nm.nf))
             )
       ) AS reconciled
FROM transactions t";

/// [API v2 §4.2] Per-account as-recovered balance: Σ `account_balance_delta` over MINED
/// transactions whose delta is FINAL (reconciled — no dangling shielded spend). This is the
/// field-validated SDK query (`TransactionRepository.recoveryBalances()`, the "Direction B"
/// fix from the 2026-06-30 balance-recovery postmortem) moved down into the
/// engine so EVERY host gets a never-over-showing restore balance by SELECTing one view.
/// Guarantees (tested below): excludes a tx while its delta is transiently wrong (dangling
/// spend), includes it the moment it links; never over-counts; consistent with the
/// reconciled Activity list by construction. `v_transactions` is upstream's stable view
/// (account_uuid, account_balance_delta, mined_height are the columns the shipped SDK
/// query already depends on).
pub const RECOVERY_BALANCE_VIEW_SQL: &str = "CREATE VIEW ext_slipstream_v_recovery_balance AS
SELECT vt.account_uuid AS account_uuid,
       SUM(vt.account_balance_delta) AS balance_zat
FROM v_transactions vt
WHERE vt.mined_height IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM ext_slipstream_v_tx_reconciled r
                  WHERE r.txid = vt.txid AND r.reconciled = 0)
GROUP BY vt.account_uuid";

/// Install both read-side views on a bare test fixture (stub upstream tables,
/// no migrator). Production databases get them from the `ext_slipstream_*`
/// schema migration ([`crate::migrations`]) instead.
#[cfg(test)]
pub(crate) fn create_reconcile_view(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(RECONCILE_VIEW_SQL)?;
    conn.execute_batch(RECOVERY_BALANCE_VIEW_SQL)
}

/// Per-account recovery balances: every row of `ext_slipstream_v_recovery_balance`
/// as `(account_uuid bytes, balance_zat)`. The read side of [API v2 §4.2] for hosts
/// (the CLI monitor) — reads ONLY the slipstream-owned view.
pub fn recovery_balances(
    conn: &rusqlite::Connection,
) -> Result<Vec<(Vec<u8>, i64)>, rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT account_uuid, balance_zat FROM ext_slipstream_v_recovery_balance")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

/// Count of MINED wallet transactions under the host display rule
/// ("visible = reconciled OR NOT recovering", mined txs only): all mined txs, or —
/// with `reconciled_only` — just those with no dangling shielded spend. Reads ONLY
/// the slipstream-owned view.
pub fn visible_mined_tx_count(
    conn: &rusqlite::Connection,
    reconciled_only: bool,
) -> Result<u64, rusqlite::Error> {
    let sql = if reconciled_only {
        "SELECT COUNT(*) FROM ext_slipstream_v_tx_reconciled
         WHERE mined_height IS NOT NULL AND reconciled = 1"
    } else {
        "SELECT COUNT(*) FROM ext_slipstream_v_tx_reconciled
         WHERE mined_height IS NOT NULL"
    };
    conn.query_row(sql, [], |r| r.get::<_, i64>(0))
        .map(|n| u64::try_from(n).unwrap_or(0))
}

// NOTE: an earlier `slipstream_v_balance_overcount` view (subtract a per-account nf-based
// over-count from the live balance during recovery) was removed — it was structurally
// inert: during the recent-first gap the spend's block is unscanned, so its nullifier is
// not yet in `nullifier_map`, so the view found nothing while the balance still read ~2×.
// The working recovery balance (Σ reconciled deltas) was first shipped SDK-side and is now
// engine-owned as `ext_slipstream_v_recovery_balance` above (API v2 §4.2); the SDK's copy
// retires in boundary-review Phase D.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_session::WalletSession;
    use rusqlite::{Connection, OptionalExtension, params};
    use zcash_protocol::consensus::Network;

    /// Open a migrated wallet DB (which also installs the reconcile view), and
    /// hand back a plain connection with foreign-key enforcement OFF so the test
    /// can insert only the columns the view reads.
    fn fixture() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let _session = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let conn = Connection::open(&path).expect("conn");
        conn.pragma_update(None, "foreign_keys", false)
            .expect("fk off");
        (dir, conn)
    }

    fn reconciled(conn: &Connection, txid: &[u8]) -> Option<i64> {
        conn.query_row(
            "SELECT reconciled FROM ext_slipstream_v_tx_reconciled WHERE txid = ?1",
            params![txid],
            |r| r.get(0),
        )
        .optional()
        .expect("query view")
    }

    /// Record our spending tx `txid` at locator (height, 0) plus the observed
    /// shielded spend of `nf` in pool `spend_pool`. The spent note is NOT yet
    /// received — the recent-first "dangling" state.
    fn insert_dangling_spend(
        conn: &Connection,
        id_tx: i64,
        txid: &[u8],
        height: i64,
        spend_pool: i64,
        nf: &[u8],
    ) {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (?1, ?2, ?3, 0, ?3)",
            params![id_tx, txid, height],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (?1, 0, ?2)",
            params![height, txid],
        )
        .expect("insert tx_locator_map");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (?1, ?2, ?3, 0)",
            params![spend_pool, nf, height],
        )
        .expect("insert nullifier_map");
    }

    #[test]
    fn sapling_spend_dangling_then_linked() {
        let (_dir, conn) = fixture();
        let txid = vec![0xAAu8; 32];
        let nf = vec![0xBBu8; 32];

        insert_dangling_spend(&conn, 1, &txid, 200, 2, &nf);
        assert_eq!(
            reconciled(&conn, &txid),
            Some(0),
            "sapling dangling spend -> unreconciled"
        );

        // The older block is scanned: the note carrying `nf` is received -> the
        // spend links -> the tx's delta is now final.
        conn.execute(
            "INSERT INTO sapling_received_notes
                (transaction_id, output_index, account_id, diversifier, value, rcm, nf, is_change)
             VALUES (1, 0, 1, x'00', 0, x'00', ?1, 0)",
            params![nf],
        )
        .expect("insert sapling_received_notes");
        assert_eq!(
            reconciled(&conn, &txid),
            Some(1),
            "sapling linked spend -> reconciled"
        );
    }

    #[test]
    fn orchard_spend_dangling_then_linked() {
        let (_dir, conn) = fixture();
        let txid = vec![0xCCu8; 32];
        let nf = vec![0xDDu8; 32];

        insert_dangling_spend(&conn, 1, &txid, 300, 3, &nf);
        assert_eq!(
            reconciled(&conn, &txid),
            Some(0),
            "orchard dangling spend -> unreconciled"
        );

        conn.execute(
            "INSERT INTO orchard_received_notes
                (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change)
             VALUES (1, 0, 1, x'00', 0, x'00', x'00', ?1, 0)",
            params![nf],
        )
        .expect("insert orchard_received_notes");
        assert_eq!(
            reconciled(&conn, &txid),
            Some(1),
            "orchard linked spend -> reconciled"
        );
    }

    /// [issue #9] Ironwood ([ZIP 2005], NU6.3) is the pool every note lands in after
    /// activation, so this is the arm a post-activation restore leans on hardest.
    ///
    /// [ZIP 2005]: https://zips.z.cash/zip-2005
    #[test]
    fn ironwood_spend_dangling_then_linked() {
        let (_dir, conn) = fixture();
        let txid = vec![0x77u8; 32];
        let nf = vec![0x88u8; 32];

        insert_dangling_spend(&conn, 1, &txid, 350, 4, &nf);
        assert_eq!(
            reconciled(&conn, &txid),
            Some(0),
            "ironwood dangling spend -> unreconciled"
        );

        conn.execute(
            "INSERT INTO ironwood_received_notes
                (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change, note_version)
             VALUES (1, 0, 1, x'00', 0, x'00', x'00', ?1, 0, 3)",
            params![nf],
        )
        .expect("insert ironwood_received_notes");
        assert_eq!(
            reconciled(&conn, &txid),
            Some(1),
            "ironwood linked spend -> reconciled"
        );
    }

    #[test]
    fn pure_receive_with_no_spends_is_reconciled_immediately() {
        let (_dir, conn) = fixture();
        let txid = vec![0xEEu8; 32];
        // A genuine incoming receive: tx recorded, but no nullifier_map row (it
        // spends nothing of ours). Must read reconciled from the first scan.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 400, 0, 400)",
            params![txid],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (400, 0, ?1)",
            params![txid],
        )
        .expect("insert tx_locator_map");
        assert_eq!(
            reconciled(&conn, &txid),
            Some(1),
            "pure receive -> reconciled"
        );
    }

    #[test]
    fn unrelated_nullifier_does_not_taint_our_tx() {
        // A dangling spend that belongs to a DIFFERENT (non-wallet) tx position
        // must not mark our reconciled receive as unreconciled.
        let (_dir, conn) = fixture();
        let ours = vec![0x11u8; 32];
        let theirs_nf = vec![0x22u8; 32];

        // Our pure receive at (500, 0).
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 500, 0, 500)",
            params![ours],
        )
        .expect("insert transaction");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 0, ?1)",
            params![ours],
        )
        .expect("insert tx_locator_map");
        // A nullifier observed at a different locator (500, 7) that has no row in
        // `transactions` (not our tx). It must not affect our (500, 0) tx.
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 7, x'99')",
            [],
        )
        .expect("insert other tx_locator_map");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (2, ?1, 500, 7)",
            params![theirs_nf],
        )
        .expect("insert other nullifier_map");

        assert_eq!(
            reconciled(&conn, &ours),
            Some(1),
            "unrelated dangling spend must not taint our tx"
        );
    }

    // ── [API v2 §4.2] recovery-balance view ─────────────────────────────────────────────

    /// Hermetic stub DB: the minimal base tables the reconcile view reads, plus a STUB
    /// `v_transactions` TABLE standing in for upstream's view (only the three columns the
    /// recovery-balance view depends on). Real-schema CREATE-compatibility is covered
    /// separately: `fixture()` opens a fully-migrated wallet DB, where `WalletSession::open`
    /// now installs BOTH views over upstream's real `v_transactions` — every fixture-based
    /// test would fail if the SQL didn't apply there.
    fn stub_fixture() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB, mined_height INTEGER, tx_index INTEGER, min_observed_height INTEGER);
             CREATE TABLE tx_locator_map (block_height INTEGER, tx_index INTEGER, txid BLOB);
             CREATE TABLE nullifier_map (spend_pool INTEGER, nf BLOB, block_height INTEGER, tx_index INTEGER);
             CREATE TABLE sapling_received_notes (id INTEGER PRIMARY KEY, tx INTEGER, account_id INTEGER, nf BLOB);
             CREATE TABLE orchard_received_notes (id INTEGER PRIMARY KEY, tx INTEGER, account_id INTEGER, nf BLOB);
             CREATE TABLE ironwood_received_notes (id INTEGER PRIMARY KEY, tx INTEGER, account_id INTEGER, nf BLOB);
             CREATE TABLE v_transactions (txid BLOB, account_uuid BLOB, account_balance_delta INTEGER, mined_height INTEGER);",
        )
        .expect("stub schema");
        create_reconcile_view(&conn).expect("create views");
        conn
    }

    fn recovery_balance(conn: &Connection, account: &[u8]) -> Option<i64> {
        conn.query_row(
            "SELECT balance_zat FROM ext_slipstream_v_recovery_balance WHERE account_uuid = ?1",
            params![account],
            |r| r.get(0),
        )
        .optional()
        .expect("query recovery balance")
    }

    /// The postmortem replay (4→8→4 class): a mined receive counts immediately; a mined
    /// spend with a DANGLING nullifier is excluded (its delta is transiently wrong) — the
    /// balance never over-shows — and is included the moment the spent note links.
    #[test]
    fn recovery_balance_excludes_dangling_then_includes_linked() {
        let conn = stub_fixture();
        let acct = vec![0xAAu8; 16];
        let receive_tx = vec![0x01u8; 32];
        let spend_tx = vec![0x02u8; 32];
        let nf = vec![0xBBu8; 32];

        // Mined receive: +400, immediately reconciled (no spends).
        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, 400, 100)",
            params![receive_tx, acct],
        )
        .expect("receive row");
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 100, 0, 100)",
            params![receive_tx],
        )
        .expect("receive tx row");
        assert_eq!(
            recovery_balance(&conn, &acct),
            Some(400),
            "reconciled receive counts"
        );

        // Mined spend −100 whose spent note hasn't been scanned yet (dangling nullifier):
        // the tx is unreconciled → EXCLUDED → balance holds at 400, never over/under-shows.
        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, -100, 200)",
            params![spend_tx, acct],
        )
        .expect("spend row");
        insert_dangling_spend(&conn, 2, &spend_tx, 200, 3, &nf);
        assert_eq!(
            recovery_balance(&conn, &acct),
            Some(400),
            "dangling spend excluded while its delta is provisional"
        );

        // The backfill scans the note's origin → nf links → the spend reconciles → included.
        conn.execute(
            "INSERT INTO orchard_received_notes (tx, account_id, nf) VALUES (1, 1, ?1)",
            params![nf],
        )
        .expect("link note");
        assert_eq!(
            recovery_balance(&conn, &acct),
            Some(300),
            "linked spend folds into the balance"
        );
    }

    /// [issue #9] The same replay with the spend in IRONWOOD — the pool every note a
    /// wallet receives after NU6.3 lands in, so post-activation this is the ordinary
    /// case, not an edge case. Before the Ironwood arm existed the tx read
    /// `reconciled = 1` and its provisional delta was counted, so the restore balance
    /// over-showed and then dropped when the origin block was scanned.
    #[test]
    fn recovery_balance_excludes_dangling_ironwood_spend() {
        let conn = stub_fixture();
        let acct = vec![0xA7u8; 16];
        let receive_tx = vec![0x05u8; 32];
        let spend_tx = vec![0x06u8; 32];
        let nf = vec![0xEEu8; 32];

        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, 400, 100)",
            params![receive_tx, acct],
        )
        .expect("receive row");
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 100, 0, 100)",
            params![receive_tx],
        )
        .expect("receive tx row");
        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, -100, 200)",
            params![spend_tx, acct],
        )
        .expect("spend row");
        insert_dangling_spend(&conn, 2, &spend_tx, 200, 4, &nf);
        assert_eq!(
            recovery_balance(&conn, &acct),
            Some(400),
            "dangling ironwood spend excluded while its delta is provisional"
        );

        conn.execute(
            "INSERT INTO ironwood_received_notes (tx, account_id, nf) VALUES (1, 1, ?1)",
            params![nf],
        )
        .expect("link note");
        assert_eq!(
            recovery_balance(&conn, &acct),
            Some(300),
            "linked ironwood spend folds into the balance"
        );
    }

    /// Per-account isolation: one account's dangling spend must not hold back another's balance.
    #[test]
    fn recovery_balance_is_per_account() {
        let conn = stub_fixture();
        let acct_a = vec![0xA1u8; 16];
        let acct_b = vec![0xB1u8; 16];
        let a_receive = vec![0x03u8; 32];
        let b_spend = vec![0x04u8; 32];
        let nf = vec![0xCCu8; 32];

        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, 500, 100)",
            params![a_receive, acct_a],
        )
        .expect("a receive");
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 100, 0, 100)",
            params![a_receive],
        )
        .expect("a tx row");
        conn.execute(
            "INSERT INTO v_transactions VALUES (?1, ?2, -50, 200)",
            params![b_spend, acct_b],
        )
        .expect("b spend");
        insert_dangling_spend(&conn, 2, &b_spend, 200, 2, &nf);

        assert_eq!(
            recovery_balance(&conn, &acct_a),
            Some(500),
            "A unaffected by B's dangle"
        );
        assert_eq!(
            recovery_balance(&conn, &acct_b),
            None,
            "B has no reconciled rows yet"
        );
    }

    /// The CLI display rule reads: all-mined vs reconciled-only counts and the
    /// per-account recovery balances — all served by the slipstream-owned views.
    #[test]
    fn visible_counts_and_recovery_balances_read_the_views() {
        let conn = stub_fixture();
        // txid1: mined, reconciled (no observed spends).
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (1, ?1, 400, 0, 400)",
            params![vec![0x01u8; 32]],
        )
        .expect("tx1");
        // txid2: mined, dangling shielded spend (nullifier observed, note not received).
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (2, ?1, 500, 0, 500)",
            params![vec![0x02u8; 32]],
        )
        .expect("tx2");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 0, ?1)",
            params![vec![0x02u8; 32]],
        )
        .expect("locator");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (2, ?1, 500, 0)",
            params![vec![0xBBu8; 32]],
        )
        .expect("nullifier");
        // txid3: UNMINED — excluded from both counts.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height) VALUES (3, ?1, NULL, 0, 600)",
            params![vec![0x03u8; 32]],
        )
        .expect("tx3");

        assert_eq!(
            visible_mined_tx_count(&conn, false).expect("all mined"),
            2,
            "not recovering: every mined tx is visible"
        );
        assert_eq!(
            visible_mined_tx_count(&conn, true).expect("reconciled only"),
            1,
            "recovering: the dangling-spend tx is held back"
        );

        // Recovery balance rows surface via the view (v_transactions stub).
        conn.execute(
            "INSERT INTO v_transactions (txid, account_uuid, account_balance_delta, mined_height) VALUES (?1, ?2, 700, 400)",
            params![vec![0x01u8; 32], vec![0xAAu8; 16]],
        )
        .expect("vtx");
        assert_eq!(
            recovery_balances(&conn).expect("balances"),
            vec![(vec![0xAAu8; 16], 700)]
        );
    }
}
