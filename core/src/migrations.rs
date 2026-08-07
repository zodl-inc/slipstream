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

//! Slipstream-owned schemerz migrations for the `ext_slipstream_*` schema (issue #4).
//!
//! `zcash_client_sqlite` reserves the `ext_` name prefix for application-owned
//! schema and requires that such schema be created by external migrations
//! registered with the wallet DB's own migrator
//! ([`WalletMigrator::with_external_migrations`]) — never ad-hoc by the engine.
//! Slipstream's prefix is `ext_slipstream_`. Every table, view, or index the
//! engine owns is created and evolved HERE, anchored against upstream's
//! released migration graph, and recorded in the shared `schemer_migrations`
//! table like any other migration.
//!
//! [`WalletMigrator::with_external_migrations`]: zcash_client_sqlite::wallet::init::WalletMigrator::with_external_migrations

use std::collections::HashSet;

use rusqlite::Transaction;
use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::{WalletMigrationError, migrations as upstream_migrations};

/// Identifier of the initial `ext_slipstream_*` schema migration.
pub const MIGRATION_ID_EXT_SCHEMA_INIT: Uuid =
    Uuid::from_u128(0x5903e190_57c4_4a45_8701_1edd943a4330);

/// Initial `ext_slipstream_*` schema: the graft buffer table and the two
/// read-side reconciliation views, adopting (copy-then-drop) any objects a
/// pre-migration build created ad-hoc under the un-prefixed legacy names.
struct ExtSchemaInit;

impl schemerz::Migration<Uuid> for ExtSchemaInit {
    fn id(&self) -> Uuid {
        MIGRATION_ID_EXT_SCHEMA_INIT
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        // Anchor after the newest RELEASED upstream leaf set. Everything the
        // views read (`transactions`, `nullifier_map`, `tx_locator_map`,
        // `{sapling,orchard}_received_notes`, `v_transactions`) long predates
        // 0.19, and SQLite resolves view bodies lazily besides — so this
        // anchor is stable across upstream rev bumps.
        upstream_migrations::V_0_19_0.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Creates the ext_slipstream_* schema (graft buffer, reconciliation views), \
         adopting any pre-migration ad-hoc slipstream_* objects."
    }
}

impl RusqliteMigration for ExtSchemaInit {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(crate::graft::GRAFT_BUFFER_DDL)?;
        // Adopt a legacy ad-hoc buffer: its rows are real engine state (open
        // shards' commitments pending a graft verdict) that internal users'
        // wallets carry — copy, then drop.
        let legacy_buffer: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'slipstream_graft_buffer'",
            [],
            |r| r.get(0),
        )?;
        if legacy_buffer > 0 {
            transaction.execute_batch(
                "INSERT INTO ext_slipstream_graft_buffer
                     (pool, shard_index, position, commitment,
                      retention_kind, checkpoint_height, marking)
                 SELECT pool, shard_index, position, commitment,
                        retention_kind, checkpoint_height, marking
                 FROM slipstream_graft_buffer;
                 DROP TABLE slipstream_graft_buffer;",
            )?;
        }
        // The legacy views carry no state — drop and recreate under ext_ names.
        transaction.execute_batch(
            "DROP VIEW IF EXISTS slipstream_v_recovery_balance;
             DROP VIEW IF EXISTS slipstream_v_tx_reconciled;",
        )?;
        transaction.execute_batch(crate::reconcile::RECONCILE_VIEW_SQL)?;
        transaction.execute_batch(crate::reconcile::RECOVERY_BALANCE_VIEW_SQL)?;
        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(
            MIGRATION_ID_EXT_SCHEMA_INIT,
        ))
    }
}

/// Identifier of the migration that rebuilds the reconciliation views with an
/// Ironwood arm (issue #9).
pub const MIGRATION_ID_EXT_RECONCILE_IRONWOOD: Uuid =
    Uuid::from_u128(0x9b1c2f04_7d3a_4c58_bf16_2a0e5c8d41e7);

/// Rebuilds both read-side reconciliation views so that a dangling **Ironwood**
/// spend (`nullifier_map.spend_pool = 4`) is detected like its Sapling and
/// Orchard siblings ([`crate::reconcile::RECONCILE_VIEW_SQL`], issue #9).
///
/// The views hold no state, so the fix is a plain drop-and-recreate; wallets
/// created before this migration carry the two-pool view and are corrected in
/// place on the next open.
struct ExtReconcileIronwood;

impl schemerz::Migration<Uuid> for ExtReconcileIronwood {
    fn id(&self) -> Uuid {
        MIGRATION_ID_EXT_RECONCILE_IRONWOOD
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        // Our own initial migration, plus the newest RELEASED upstream leaf set
        // that has `ironwood_received_notes` — the table this migration's view
        // names. 0.22.0-rc.2 is the first state whose leaves (`note_locking`,
        // `orchard_ironwood_migration_tables`) both descend from it, so the table
        // is guaranteed to exist before the view is created rather than merely
        // likely to: SQLite resolves view bodies lazily, so an earlier anchor
        // would leave the view referencing a table that upstream had not created
        // yet, and only upstream's convention of wrapping table renames in
        // `PRAGMA legacy_alter_table = ON` (which suppresses the re-parse that
        // would then fail) would keep the migration run working.
        //
        // Release constants are the anchor to prefer: they name states of the
        // graph that a published crate release exposed, so they are unaffected by
        // the migrations later releases add.
        upstream_migrations::V_0_22_0_RC2
            .iter()
            .copied()
            .chain([MIGRATION_ID_EXT_SCHEMA_INIT])
            .collect()
    }

    fn description(&self) -> &'static str {
        "Rebuilds the ext_slipstream_* reconciliation views to detect dangling Ironwood spends."
    }
}

impl RusqliteMigration for ExtReconcileIronwood {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &Transaction) -> Result<(), WalletMigrationError> {
        transaction.execute_batch(
            "DROP VIEW IF EXISTS ext_slipstream_v_recovery_balance;
             DROP VIEW IF EXISTS ext_slipstream_v_tx_reconciled;",
        )?;
        transaction.execute_batch(crate::reconcile::RECONCILE_VIEW_SQL)?;
        transaction.execute_batch(crate::reconcile::RECOVERY_BALANCE_VIEW_SQL)?;
        Ok(())
    }

    fn down(&self, _transaction: &Transaction) -> Result<(), WalletMigrationError> {
        Err(WalletMigrationError::CannotRevert(
            MIGRATION_ID_EXT_RECONCILE_IRONWOOD,
        ))
    }
}

/// The slipstream external migration graph, for registration via
/// [`WalletMigrator::with_external_migrations`] by any opener of a slipstream
/// wallet database (the engine's own `WalletSession::open`, or a host that
/// manages the wallet file itself).
///
/// [`WalletMigrator::with_external_migrations`]: zcash_client_sqlite::wallet::init::WalletMigrator::with_external_migrations
pub fn external_migrations() -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    vec![Box::new(ExtSchemaInit), Box::new(ExtReconcileIronwood)]
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use zcash_protocol::consensus::Network;

    use crate::wallet_session::WalletSession;

    fn object_exists(conn: &Connection, kind: &str, name: &str) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
                [kind, name],
                |r| r.get(0),
            )
            .expect("sqlite_master query");
        n > 0
    }

    fn legacy_object_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'slipstream_%'",
            [],
            |r| r.get(0),
        )
        .expect("legacy name query")
    }

    #[test]
    fn fresh_open_creates_ext_schema_via_migrations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("data.db");
        WalletSession::open(Network::MainNetwork, &db_path).expect("open");

        let conn = Connection::open(&db_path).expect("conn");
        assert!(
            object_exists(&conn, "table", "ext_slipstream_graft_buffer"),
            "graft buffer table must be created by the migration"
        );
        assert!(
            object_exists(&conn, "view", "ext_slipstream_v_tx_reconciled"),
            "reconcile view must be created by the migration"
        );
        assert!(
            object_exists(&conn, "view", "ext_slipstream_v_recovery_balance"),
            "recovery balance view must be created by the migration"
        );
        // Recorded in the shared schemerz migrations table, not created ad-hoc.
        let registered: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schemer_migrations WHERE id = ?1",
                [super::MIGRATION_ID_EXT_SCHEMA_INIT.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("schemer_migrations query");
        assert_eq!(registered, 1, "migration id must be recorded");
        // No un-prefixed legacy objects remain.
        assert_eq!(legacy_object_count(&conn), 0);
    }

    fn view_sql(conn: &Connection, name: &str) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = ?1",
            [name],
            |r| r.get(0),
        )
        .expect("view sql")
    }

    fn migration_applied(conn: &Connection, id: super::Uuid) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schemer_migrations WHERE id = ?1",
                [id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("schemer_migrations query");
        n > 0
    }

    /// [issue #9] The reconcile view must name every shielded pool's notes table —
    /// against the REAL upstream schema, so this also pins that the view body
    /// resolves after a full migration run at the pinned upstream revision.
    #[test]
    fn fresh_open_installs_the_ironwood_aware_views() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("data.db");
        WalletSession::open(Network::MainNetwork, &db_path).expect("open");

        let conn = Connection::open(&db_path).expect("conn");
        assert!(migration_applied(
            &conn,
            super::MIGRATION_ID_EXT_RECONCILE_IRONWOOD
        ));
        let sql = view_sql(&conn, "ext_slipstream_v_tx_reconciled");
        for table in [
            "sapling_received_notes",
            "orchard_received_notes",
            "ironwood_received_notes",
        ] {
            assert!(sql.contains(table), "view must test {table}");
        }
        // The body resolves against the real schema (a view over a missing table
        // only fails when queried).
        conn.query_row(
            "SELECT COUNT(*) FROM ext_slipstream_v_tx_reconciled",
            [],
            |r| r.get::<_, i64>(0),
        )
        .expect("reconcile view resolves");
        conn.query_row(
            "SELECT COUNT(*) FROM ext_slipstream_v_recovery_balance",
            [],
            |r| r.get::<_, i64>(0),
        )
        .expect("recovery balance view resolves");
    }

    /// [issue #9] A wallet migrated by a build that predates the fix carries the
    /// two-pool view; reopening with this build must rebuild it. Simulated by
    /// restoring the old view bodies and un-recording the new migration.
    #[test]
    fn stale_two_pool_views_are_rebuilt_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("data.db");
        WalletSession::open(Network::MainNetwork, &db_path).expect("open");
        {
            let conn = Connection::open(&db_path).expect("conn");
            conn.execute_batch(
                "DROP VIEW ext_slipstream_v_recovery_balance;
                 DROP VIEW ext_slipstream_v_tx_reconciled;
                 CREATE VIEW ext_slipstream_v_tx_reconciled AS
                     SELECT t.txid AS txid, t.mined_height AS mined_height,
                            NOT EXISTS (
                                SELECT 1 FROM nullifier_map nm
                                JOIN tx_locator_map tl
                                    ON tl.block_height = nm.block_height
                                   AND tl.tx_index = nm.tx_index
                                WHERE tl.txid = t.txid
                                  AND ((nm.spend_pool = 2
                                        AND NOT EXISTS (SELECT 1 FROM sapling_received_notes s WHERE s.nf = nm.nf))
                                    OR (nm.spend_pool = 3
                                        AND NOT EXISTS (SELECT 1 FROM orchard_received_notes o WHERE o.nf = nm.nf)))
                            ) AS reconciled
                     FROM transactions t;
                 CREATE VIEW ext_slipstream_v_recovery_balance AS SELECT NULL AS account_uuid, 0 AS balance_zat;",
            )
            .expect("restore pre-fix views");
            conn.execute(
                "DELETE FROM schemer_migrations WHERE id = ?1",
                [super::MIGRATION_ID_EXT_RECONCILE_IRONWOOD
                    .as_bytes()
                    .as_slice()],
            )
            .expect("un-record migration");
        }

        WalletSession::open(Network::MainNetwork, &db_path).expect("reopen");

        let conn = Connection::open(&db_path).expect("conn");
        assert!(
            view_sql(&conn, "ext_slipstream_v_tx_reconciled").contains("ironwood_received_notes"),
            "the stale two-pool view must be rebuilt with the Ironwood arm"
        );
        assert!(
            view_sql(&conn, "ext_slipstream_v_recovery_balance")
                .contains("ext_slipstream_v_tx_reconciled"),
            "the recovery-balance view must be rebuilt over the reconcile view"
        );
    }

    #[test]
    fn legacy_ad_hoc_objects_are_adopted_then_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("data.db");
        // Simulate a wallet produced by a pre-migration build: upstream
        // migrations applied (as any old build did at open), then the ad-hoc
        // graft buffer holding rows, plus the two ad-hoc views. The legacy
        // objects must post-date the upstream schema — upstream `ALTER TABLE`
        // migrations re-parse every view body, so views referencing
        // not-yet-created tables would break them (impossible in a real legacy
        // wallet, where the old build migrated first and added views after).
        {
            let conn = Connection::open(&db_path).expect("pre-create");
            rusqlite::vtab::array::load_module(&conn).expect("array vtab");
            let mut db = zcash_client_sqlite::WalletDb::from_connection(
                conn,
                crate::network::SlipstreamNetwork::from(Network::MainNetwork),
                zcash_client_sqlite::util::SystemClock,
                rand::rngs::OsRng,
            );
            zcash_client_sqlite::wallet::init::WalletMigrator::new()
                .init_or_migrate(&mut db)
                .expect("upstream-only migrations (pre-migration build)");
        }
        {
            let conn = Connection::open(&db_path).expect("pre-create");
            conn.execute_batch(
                "CREATE TABLE slipstream_graft_buffer (
                    pool INTEGER NOT NULL,
                    shard_index INTEGER NOT NULL,
                    position INTEGER NOT NULL,
                    commitment BLOB NOT NULL,
                    retention_kind INTEGER NOT NULL,
                    checkpoint_height INTEGER,
                    marking INTEGER,
                    PRIMARY KEY (pool, shard_index, position)
                ) WITHOUT ROWID;
                INSERT INTO slipstream_graft_buffer
                    VALUES (3, 7, 100, x'01', 0, NULL, NULL);
                INSERT INTO slipstream_graft_buffer
                    VALUES (3, 7, 101, x'02', 2, 123, 1);
                CREATE VIEW slipstream_v_tx_reconciled AS
                    SELECT txid, 1 AS reconciled FROM transactions;
                CREATE VIEW slipstream_v_recovery_balance AS
                    SELECT 'none' AS account_uuid, 0 AS balance_zat;",
            )
            .expect("legacy schema");
        }
        WalletSession::open(Network::MainNetwork, &db_path).expect("open");

        let conn = Connection::open(&db_path).expect("conn");
        let rows: Vec<(i64, i64, i64, Vec<u8>)> = conn
            .prepare(
                "SELECT pool, shard_index, position, commitment
                 FROM ext_slipstream_graft_buffer ORDER BY position",
            )
            .expect("prepare")
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![(3, 7, 100, vec![0x01]), (3, 7, 101, vec![0x02]),],
            "legacy buffer rows must be carried into the ext_ table"
        );
        assert_eq!(
            legacy_object_count(&conn),
            0,
            "legacy table and views must be dropped after adoption"
        );
    }
}
