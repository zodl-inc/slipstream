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

/// The slipstream external migration graph, for registration via
/// [`WalletMigrator::with_external_migrations`] by any opener of a slipstream
/// wallet database (the engine's own `WalletSession::open`, or a host that
/// manages the wallet file itself).
///
/// [`WalletMigrator::with_external_migrations`]: zcash_client_sqlite::wallet::init::WalletMigrator::with_external_migrations
pub fn external_migrations() -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    vec![Box::new(ExtSchemaInit)]
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
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![
                (3, 7, 100, vec![0x01]),
                (3, 7, 101, vec![0x02]),
            ],
            "legacy buffer rows must be carried into the ext_ table"
        );
        assert_eq!(
            legacy_object_count(&conn),
            0,
            "legacy table and views must be dropped after adoption"
        );
    }
}
