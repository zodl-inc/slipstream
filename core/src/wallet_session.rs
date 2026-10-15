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

//! Persistent wallet session: ONE WalletDb for the whole sync (decision D2/D3 —
//! unchanged zcash_client_sqlite data model), WAL set on the file before open,
//! migrations run once, chain-state ops (subtree roots, chain tip, scan ranges)
//! and keyless account import (UFVK only, decision D6).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use shardtree::{error::ShardTreeError, store::ShardStore};
use tracing::info;
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, WalletCommitmentTrees, WalletRead, WalletWrite,
    scanning::{ScanPriority, ScanRange},
};
use zcash_client_backend::proto::service::TreeState;
use zcash_client_sqlite::{WalletDb, error::SqliteClientError};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{ShieldedPool, consensus::BlockHeight};

use crate::{
    error::SlipstreamError,
    grpc::{SubtreeRootStart, SubtreeRoots},
};

use crate::network::SlipstreamNetwork;

// Mirror rust/src/lib.rs:132 — same generics, same clock/rng — except the params
// type: the engine session is generic-capable via [`SlipstreamNetwork`] (IW-0.5,
// custom chains), while the FFI's own WalletDb stays stock-`Network` typed.
pub(crate) type Db = WalletDb<
    Connection,
    SlipstreamNetwork,
    zcash_client_sqlite::util::SystemClock,
    rand::rand_core::UnwrapErr<rand::rngs::SysRng>,
>;

pub struct WalletSession {
    pub network: SlipstreamNetwork,
    db: Db,
    // Used by seed_block_metadata (cfg(any(test, feature = "darkside")) only).
    #[cfg_attr(not(any(test, feature = "darkside")), allow(dead_code))]
    db_path: PathBuf,
}

fn wallet_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Wallet(format!("{context}: {e}"))
}

/// The first subtree index to request for a pool whose store holds shards at `stored`
/// (ascending, as `ShardStore::get_shard_roots` lists them).
///
/// Mirrors upstream's `next_subtree_index` (zcash_client_sqlite): the last stored shard is
/// usually the incomplete one at the tip, so the request restarts at the second-to-last and
/// overlaps the last complete shard — the only one whose root can still change. Unlike
/// upstream, the stored indices must also be the complete range `0..=last`. A pool seeded
/// only near the tip, or with a gap, starts at 0 instead, and the full download makes its
/// indices a complete range again: an older-birthday scan crossing Ironwood activation relies
/// on that (0.3.0, Fixed).
pub(crate) fn next_subtree_root_index(stored: &[u64]) -> u64 {
    let complete_from_zero = stored.iter().copied().eq(0..stored.len() as u64);
    if complete_from_zero {
        stored.len().saturating_sub(2) as u64
    } else {
        0
    }
}

/// The indices of the shards `store` holds, ascending.
fn shard_indices<S: ShardStore>(store: &S) -> Result<Vec<u64>, ShardTreeError<S::Error>> {
    Ok(store
        .get_shard_roots()
        .map_err(ShardTreeError::Storage)?
        .iter()
        .map(|addr| addr.index())
        .collect())
}

impl WalletSession {
    /// Sets WAL (a persistent file property) via a plain connection, then opens
    /// the WalletDb ONCE and runs migrations (seedless — keyless engine).
    pub fn open(
        network: impl Into<SlipstreamNetwork>,
        db_path: &Path,
    ) -> Result<Self, SlipstreamError> {
        let network = network.into();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| wallet_err("create wallet dir", e))?;
        }
        {
            let conn = Connection::open(db_path).map_err(|e| wallet_err("pre-open", e))?;
            // [audit ENG-1] busy_timeout is per-CONNECTION (never persisted in the file): set it on
            // every connection we open, so a WAL checkpoint or the Swift SDK's concurrent reader
            // (which carries its own 5s timeout) surfaces as a short wait, never an instant
            // SQLITE_BUSY error. The main WalletDb connection is opened internally by
            // zcash_client_sqlite (no public conn access); single-writer discipline makes writer
            // contention impossible there — these side connections are the ones that can race.
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .map_err(|e| wallet_err("set busy_timeout", e))?;
            // Note 1: pragma_update_and_check in rusqlite 0.37 takes Option<&str> for schema_name
            // (not Option<DatabaseName> as in older versions) — plan code compiles as-written.
            let mode: String = conn
                .pragma_update_and_check(None, "journal_mode", "wal", |row| row.get(0))
                .map_err(|e| wallet_err("set WAL", e))?;
            info!(%mode, "journal mode");
            conn.pragma_update(None, "synchronous", "NORMAL")
                .map_err(|e| wallet_err("set synchronous", e))?;
        }
        // [B4-12 / ZRUST0096] Open the MAIN wallet connection ourselves so it gets a
        // busy_timeout — upstream's `for_path` sets NONE, so any competing writer (a host
        // `importAccount` landing mid-pass, or a restart's orphaned write-behind commit:
        // `spawn_blocking` is uncancellable by abort, so it can outlive the pass that
        // spawned it) surfaced as an immediate SQLITE_BUSY → non-transient Wallet error →
        // Error state (the Keystone delete→re-import field failure, 2026-07-02). 15 s —
        // the worst observed device commit is a few seconds (A10): WAITING beats dying.
        // Mirrors upstream `for_path` otherwise (array vtab module, then wrap).
        let wallet_conn = Connection::open(db_path).map_err(|e| wallet_err("open wallet db", e))?;
        wallet_conn
            .busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| wallet_err("set busy_timeout (wallet)", e))?;
        rusqlite::vtab::array::load_module(&wallet_conn)
            .map_err(|e| wallet_err("load array vtab", e))?;
        let mut db = WalletDb::from_connection(
            wallet_conn,
            network,
            zcash_client_sqlite::util::SystemClock,
            rand::rand_core::UnwrapErr(rand::rngs::SysRng),
        );
        // Issue #4: the engine's own `ext_slipstream_*` schema (graft buffer,
        // reconciliation views — see `migrations.rs`) rides the wallet's
        // migrator as external schemerz migrations, so it is created and
        // versioned exactly like the upstream schema (seedless — keyless engine).
        zcash_client_sqlite::wallet::init::WalletMigrator::new()
            .with_external_migrations(crate::migrations::external_migrations())
            .init_or_migrate(&mut db)
            .map_err(|e| wallet_err("init/migrations", e))?;
        // [B4-16] Queue hygiene: drop Historic ranges no remaining account justifies.
        // An account deleted mid-restore leaves its deep ranges queued (upstream
        // `delete_account` never touches scan_queue) — without this, the engine grinds
        // a full deep restore for keys that no longer exist. Runs at every open (= every
        // pass start too), so wedged wallets heal at launch and an in-app delete →
        // restart heals immediately. Warn-and-continue: a failed prune must not block
        // opening — sync still runs correctly without it, just wastefully.
        match crate::scan_queue::prune_orphaned_historic_ranges(&mut db) {
            Ok(0) => {}
            Ok(n) => info!(
                pruned = n,
                "scan queue: dropped orphaned historic ranges (below every account birthday)"
            ),
            Err(e) => tracing::warn!(%e, "scan queue prune failed (non-fatal) — continuing"),
        }
        // Sandblasting-era flood heal (2026-07-06): wallets that scanned the
        // spam era on a pre-fix build carry thousands of deep-history
        // checkpoint rows that panic every subsequent pass — remove them at
        // open (via the pools' own checkpoint stores) so damaged wallets
        // self-repair without a reset. No-op on healthy wallets.
        // Warn-and-continue, same policy as the prune above.
        match crate::persist::heal_flooded_checkpoints(&mut db) {
            Ok(0) => {}
            Ok(n) => info!(
                healed = n,
                "checkpoint store: removed flooded deep-history checkpoints (pre-fix sandblasting damage)"
            ),
            Err(e) => {
                tracing::warn!(%e, "checkpoint flood heal failed (non-fatal) — continuing")
            }
        }
        Ok(Self {
            network,
            db,
            db_path: db_path.to_path_buf(),
        })
    }

    /// [API v2 §4.4] The wallet's recovery ceiling, or `None` when no account has one
    /// (new wallets / fully non-restore imports). The scheduler compares suggested ranges
    /// against this once per suggest round to drive the snapshot's `is_recovering`.
    /// Issue #4: reads via [`WalletRead::get_wallet_recover_until`] — no direct SQL.
    pub fn max_recover_until(&self) -> Result<Option<u64>, SlipstreamError> {
        Ok(self
            .db
            .get_wallet_recover_until()
            .map_err(|e| wallet_err("wallet recover_until", e))?
            .map(|h| u64::from(u32::from(h))))
    }

    /// [API v2 §4.4 / Phase E] The wallet's oldest account birthday, or `None` when no
    /// accounts exist. With the chain tip and the remaining scan queue it seeds the
    /// global permille floor once per suggest round (`scheduler::global_floor_permille`).
    /// Issue #4: reads via [`WalletRead::get_wallet_birthday`] (whose contract is exactly
    /// the minimum account birthday) — no direct SQL.
    pub fn min_birthday(&self) -> Result<Option<u64>, SlipstreamError> {
        Ok(self
            .db
            .get_wallet_birthday()
            .map_err(|e| wallet_err("wallet birthday", e))?
            .map(|h| u64::from(u32::from(h))))
    }

    /// Whether the wallet already tracks an account for `ufvk`.
    ///
    /// The engine's per-account import guard: `sync_once` imports each provided key only
    /// when this returns `false`, so a re-run — or a wallet a host already provisioned —
    /// neither re-imports the key nor spends a `GetTreeState` RPC on it.
    pub fn has_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<bool, SlipstreamError> {
        Ok(self
            .db
            .get_account_for_ufvk(ufvk)
            .map_err(|e| wallet_err("get_account_for_ufvk", e))?
            .is_some())
    }

    /// Imports `ufvk` as a view-only account with the given birthday treestate
    /// (server-provided at birthday-1).
    ///
    /// The import is UNCONDITIONAL: the caller must first confirm the account is absent
    /// (see [`has_account_for_ufvk`](Self::has_account_for_ufvk)). The engine keeps the
    /// treestate fetch and the presence check together so a key already present costs
    /// neither an RPC nor a redundant import.
    pub fn import_account(
        &mut self,
        ufvk: &UnifiedFullViewingKey,
        birthday_treestate: TreeState,
    ) -> Result<(), SlipstreamError> {
        let birthday = AccountBirthday::from_treestate(birthday_treestate, None).map_err(|e| {
            use zcash_client_backend::data_api::BirthdayError;
            let detail = match e {
                BirthdayError::HeightInvalid(ie) => format!("height invalid: {ie}"),
                BirthdayError::Decode(io) => format!("decode: {io}"),
                // `BirthdayError` is `#[non_exhaustive]` and implements neither `Debug` nor
                // `Display`, so a variant added upstream can only be reported generically.
                _ => "unrecognized birthday error".to_string(),
            };
            SlipstreamError::Wallet(format!("invalid birthday treestate: {detail}"))
        })?;
        self.import_account_with_birthday(ufvk, &birthday)
    }

    /// Imports `ufvk` as a view-only account with `birthday`
    /// ([`import_account`](Self::import_account) once the treestate is decoded).
    ///
    /// A new account rewinds the wallet to the chain state below its birthday and queues
    /// every later block again (upstream `add_account` → `rewind_to_chain_state`), so the
    /// graft-buffer rows of those blocks, every row at or above the birthday's tree sizes,
    /// are dropped: the rescan scans them again, and a range must only resume rows of
    /// blocks that stay scanned. An import that upgrades an existing account's viewing key
    /// adds no account and rewinds nothing, so it leaves the buffer alone.
    pub(crate) fn import_account_with_birthday(
        &mut self,
        ufvk: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
    ) -> Result<(), SlipstreamError> {
        let accounts = self
            .db
            .get_account_ids()
            .map_err(|e| wallet_err("get_account_ids", e))?
            .len();
        self.db
            .import_account_ufvk("slipstream", ufvk, birthday, AccountPurpose::ViewOnly, None)
            .map_err(|e| wallet_err("import_account_ufvk", e))?;
        info!("account imported (view-only)");
        let added = self
            .db
            .get_account_ids()
            .map_err(|e| wallet_err("get_account_ids", e))?
            .len()
            > accounts;
        if added {
            self.drop_graft_rows_from(
                Some(birthday.sapling_frontier().tree_size()),
                Some(birthday.orchard_frontier().tree_size()),
            )?;
        }
        Ok(())
    }

    /// Truncates the wallet to at most `height` (upstream
    /// [`WalletWrite::truncate_to_height`]; the scheduler's reorg recovery), and drops the
    /// graft-buffer rows of the blocks the truncation removed: every row at or above the
    /// tree sizes at the end of the highest block the wallet still holds. Those blocks are
    /// queued again and may come back from another chain, so a range must not resume rows
    /// scanned from the one the wallet left. Both run in upstream's truncation transaction
    /// ([`WalletDb::transactionally_with_extension`]): a crash or an error undoes both, so
    /// the wallet is never left truncated with those rows buffered. A pool whose tree size
    /// the highest remaining block does not record keeps its rows, with a warning: no other
    /// size bounds them (a lower block's would also drop rows of blocks the wallet keeps).
    /// Returns the height the wallet was truncated to.
    pub fn truncate_to_height(
        &mut self,
        height: BlockHeight,
    ) -> Result<BlockHeight, SlipstreamError> {
        self.db
            .transactionally_with_extension(|wdb, ext| {
                let truncated_to = wdb.truncate_to_height(height)?;
                let (sapling, orchard) = match wdb.block_max_scanned()? {
                    Some(highest) => (
                        highest.sapling_tree_size().map(u64::from),
                        highest.orchard_tree_size().map(u64::from),
                    ),
                    // No block left: every buffered row is a removed block's.
                    None => (Some(0), Some(0)),
                };
                for (pool, from) in [
                    (ShieldedPool::Sapling, sapling),
                    (ShieldedPool::Orchard, orchard),
                ] {
                    match from {
                        Some(from) => crate::graft::delete_from_position_in(ext, pool, from)?,
                        None => tracing::warn!(
                            ?pool,
                            %truncated_to,
                            "truncation: the highest remaining block records no tree size for this pool; its graft-buffer rows stay"
                        ),
                    }
                }
                Ok::<_, zcash_client_sqlite::error::SqliteClientError>(truncated_to)
            })
            .map_err(|e| wallet_err("truncate_to_height", e))
    }

    /// Drops every graft-buffer row at or above these tree sizes (Sapling, Orchard;
    /// `None` leaves that pool's rows), over a side connection: upstream `WalletDb` never
    /// exposes its own. An account import's rewind uses it, after the import commits.
    fn drop_graft_rows_from(
        &self,
        sapling: Option<u64>,
        orchard: Option<u64>,
    ) -> Result<(), SlipstreamError> {
        let conn =
            Connection::open(&self.db_path).map_err(|e| wallet_err("graft buffer open", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| wallet_err("graft buffer busy_timeout", e))?;
        for (pool, from) in [
            (ShieldedPool::Sapling, sapling),
            (ShieldedPool::Orchard, orchard),
        ] {
            if let Some(from) = from {
                crate::graft::delete_from_position(&conn, pool, from)
                    .map_err(|e| wallet_err("graft buffer cleanup", e))?;
            }
        }
        Ok(())
    }

    /// Test/darkside bootstrap convenience: import `ufvk_str` (decoded here) as the
    /// wallet's single view-only account, but NO-OP if the wallet already has ANY account.
    ///
    /// The whole-wallet guard exists because fixtures may pre-seed a *spending* account and
    /// then expect this to defer (see the oracle synthetic-window harness). Production goes
    /// through [`import_account`](Self::import_account) with an already-decoded key and a
    /// per-account presence check; this string-decoding, single-account shape is only for
    /// tests that pass the `TEST_UFVK` constant directly.
    #[cfg(any(test, feature = "darkside"))]
    pub fn ensure_account(
        &mut self,
        ufvk_str: &str,
        birthday_treestate: TreeState,
    ) -> Result<(), SlipstreamError> {
        let existing = self
            .db
            .get_account_ids()
            .map_err(|e| wallet_err("get_account_ids", e))?;
        if !existing.is_empty() {
            return Ok(());
        }
        let ufvk = UnifiedFullViewingKey::decode(&self.network, ufvk_str)
            .map_err(|e| wallet_err("ufvk decode", e))?;
        self.import_account(&ufvk, birthday_treestate)
    }

    /// Where this pass's subtree-root requests start, per pool (see
    /// `next_subtree_root_index`).
    pub fn next_subtree_root_start(&mut self) -> Result<SubtreeRootStart, SlipstreamError> {
        let (sapling, orchard, ironwood) = self.stored_shard_indices()?;
        Ok(SubtreeRootStart {
            sapling: next_subtree_root_index(&sapling),
            orchard: next_subtree_root_index(&orchard),
            ironwood: next_subtree_root_index(&ironwood),
        })
    }

    /// The shard indices each pool's note commitment tree stores, ascending:
    /// `(sapling, orchard, ironwood)`. Read through `WalletCommitmentTrees`, with no SQL
    /// against upstream tables (Issue #4).
    #[allow(clippy::type_complexity)]
    fn stored_shard_indices(&mut self) -> Result<(Vec<u64>, Vec<u64>, Vec<u64>), SlipstreamError> {
        let sapling = self
            .db
            .with_sapling_tree_mut::<_, _, SqliteClientError>(|tree| {
                shard_indices(tree.store()).map_err(SqliteClientError::CommitmentTree)
            })
            .map_err(|e| wallet_err("sapling shard indices", e))?;
        let orchard = self
            .db
            .with_orchard_tree_mut::<_, _, SqliteClientError>(|tree| {
                shard_indices(tree.store()).map_err(SqliteClientError::CommitmentTree)
            })
            .map_err(|e| wallet_err("orchard shard indices", e))?;
        let ironwood = self
            .db
            .with_ironwood_tree_mut::<_, _, SqliteClientError>(|tree| {
                shard_indices(tree.store()).map_err(SqliteClientError::CommitmentTree)
            })
            .map_err(|e| wallet_err("ironwood shard indices", e))?
            .unwrap_or_default();
        Ok((sapling, orchard, ironwood))
    }

    /// Stores `roots`, each pool's first root at its index in `start` — the `start` they were
    /// requested from (`grpc::get_subtree_roots_from`).
    pub fn put_subtree_roots_at(
        &mut self,
        start: SubtreeRootStart,
        roots: &SubtreeRoots,
    ) -> Result<(), SlipstreamError> {
        self.db
            .put_sapling_subtree_roots(start.sapling, &roots.sapling)
            .map_err(|e| wallet_err("put_sapling_subtree_roots", e))?;
        self.db
            .put_orchard_subtree_roots(start.orchard, &roots.orchard)
            .map_err(|e| wallet_err("put_orchard_subtree_roots", e))?;
        self.db
            .put_ironwood_subtree_roots(start.ironwood, &roots.ironwood)
            .map_err(|e| wallet_err("put_ironwood_subtree_roots", e))?;
        Ok(())
    }

    /// Stores `roots` downloaded from index 0 (`grpc::get_subtree_roots`).
    pub fn put_subtree_roots(&mut self, roots: &SubtreeRoots) -> Result<(), SlipstreamError> {
        self.put_subtree_roots_at(SubtreeRootStart::default(), roots)
    }

    pub fn update_chain_tip(&mut self, height: u64) -> Result<(), SlipstreamError> {
        let height = u32::try_from(height)
            .map_err(|_| SlipstreamError::Wallet(format!("height {height} exceeds u32")))?;
        self.db
            .update_chain_tip(BlockHeight::from(height))
            .map_err(|e| wallet_err("update_chain_tip", e))
    }

    pub fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, SlipstreamError> {
        self.db
            .suggest_scan_ranges()
            .map_err(|e| wallet_err("suggest_scan_ranges", e))
    }

    /// Whether the scan queue holds a `Historic` range: a restore under way, or the rescan an
    /// account import below the tip queues. Only such a range grafts note-free shards against
    /// the stored subtree roots, and a graft install or a fully pruned note-free shard leaves
    /// its row without a stored root, which a download restores only for the shards it reaches.
    /// So a pass with `Historic` work fetches every root again (`engine::sync_once`).
    pub fn has_historic_scan_ranges(&self) -> Result<bool, SlipstreamError> {
        Ok(self
            .suggest_scan_ranges()?
            .iter()
            .any(|range| range.priority() == ScanPriority::Historic))
    }

    /// [API v2.1 E-3] The wallet's PERSISTED view of the chain tip (`WalletRead::chain_height`,
    /// scan-queue derived), or `None` when the wallet has never seen a tip (fresh DB). Used by
    /// the open-time snapshot seed: it is the tip the last `update_chain_tip` recorded, so the
    /// truthful-from-open snapshot can report a real height before any network call.
    pub fn chain_height(&self) -> Result<Option<u64>, SlipstreamError> {
        Ok(self
            .db
            .chain_height()
            .map_err(|e| wallet_err("chain_height", e))?
            .map(|h| u64::from(u32::from(h))))
    }

    /// [API v2.1 E-4] Cheap signature of the wallet's transaction set:
    /// `(COUNT(tx rows), COUNT(unreconciled))`, both read from the slipstream-owned
    /// `ext_slipstream_v_tx_reconciled` view (one row per wallet tx by construction).
    /// The scheduler compares it across range boundaries and bumps `tx_set_version` when it
    /// moved — catching set changes that arrive WITHOUT an enhancement write (the classic
    /// case: scanning a historic block stores the received note that LINKS an
    /// already-stored dangling spend, flipping it reconciled). Same short-side-connection
    /// pattern as `max_recover_until`; the counts are over wallet-sized tables (cheap).
    pub fn tx_set_signature(&self) -> Result<(u64, u64), SlipstreamError> {
        let conn = Connection::open(&self.db_path).map_err(|e| wallet_err("tx sig open", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| wallet_err("tx sig busy_timeout", e))?;
        let (total, unreconciled): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN reconciled = 0 THEN 1 ELSE 0 END), 0)
                 FROM ext_slipstream_v_tx_reconciled",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| wallet_err("tx sig counts", e))?;
        Ok((
            u64::try_from(total).unwrap_or(0),
            u64::try_from(unreconciled).unwrap_or(0),
        ))
    }

    /// Exclusive access for the scan driver (scan_cached_blocks needs &mut).
    pub fn db_mut(&mut self) -> &mut Db {
        &mut self.db
    }

    /// Path of the wallet DB file — used by the write-behind test driver
    /// (`scan_chunks_from_treestate`) to open the persist lane's second
    /// connection. Production `scan_chunks` takes the path from `EngineConfig`.
    #[cfg(any(test, feature = "darkside"))]
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Pre-seed the `blocks` table with a record at `height` carrying `block_hash` and
    /// `sapling_commitment_tree_size`.
    ///
    /// **FOR DARKSIDE TESTS ONLY.** The real `put_block` in zcash_client_sqlite is
    /// `pub(crate)` and goes through the full `put_blocks` pipeline (which requires
    /// already-scanned `ScannedBlock` values). For our darkside workaround we need a
    /// pre-existing block record so that `scan_cached_blocks` finds a non-None
    /// `prior_block_metadata` for the very first block, enabling it to determine the
    /// Sapling note commitment tree size without relying on `chain_metadata` in the
    /// compact blocks (lightwalletd v0.4.9 does not set this field).
    ///
    /// The `block_hash` must equal the `prev_hash` of the first block that will be
    /// scanned, or the chain-continuity check inside `scan_block_with_runners` will
    /// raise `PrevHashMismatch`. Callers should fetch the first block and read its
    /// `prev_hash` to populate this parameter.
    ///
    /// Opens a separate `rusqlite::Connection` to the DB path (WAL mode allows this
    /// concurrently with the WalletDb connection) and upserts the block record.
    #[cfg(any(test, feature = "darkside"))]
    pub fn seed_block_metadata(
        &self,
        height: u64,
        sapling_commitment_tree_size: u32,
        block_hash: &[u8],
    ) -> Result<(), SlipstreamError> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| wallet_err("seed_block_metadata open", e))?;
        let h = u32::try_from(height)
            .map_err(|_| SlipstreamError::Wallet(format!("height {height} exceeds u32")))?;
        // orchard_commitment_tree_size and counts are 0 (Sapling-only test chain).
        conn.execute(
            "INSERT INTO blocks (
                height, hash, time,
                sapling_commitment_tree_size, sapling_output_count, sapling_tree,
                orchard_commitment_tree_size, orchard_action_count
             ) VALUES (?1, ?2, 0, ?3, 0, x'00', 0, 0)
             ON CONFLICT (height) DO UPDATE
             SET hash = excluded.hash,
                 sapling_commitment_tree_size = excluded.sapling_commitment_tree_size",
            rusqlite::params![h, block_hash, sapling_commitment_tree_size],
        )
        .map_err(|e| wallet_err("seed_block_metadata insert", e))?;
        Ok(())
    }
}

/// TEST_UFVK: mainnet UFVK for the canonical darkside seed used in this repo's test suite.
/// Derived from seed phrase: "still champion voice habit trend flight..." (Tests/TestUtils/Tests+Utils.swift:19)
/// seed bytes base64: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg=="
/// Verified in Tests/OfflineTests/DerivationToolTests/DerivationToolMainnetTests.swift:32-39
/// as `expectedViewingKey` derived from the same `seedData`.
///
/// Re-exported here (not just in #[cfg(test)]) for the darkside integration test in
/// tests/darkside_sync.rs which is an integration test binary (not a unit test module)
/// and therefore cannot access items gated behind `#[cfg(test)]`.
#[cfg(any(test, feature = "darkside"))]
pub const TEST_UFVK: &str = concat!(
    "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
    "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
    "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
    "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
);

#[cfg(test)]
mod tests {
    use super::*;
    // [IW-2b] IW-0.5 moved the session onto SlipstreamNetwork; the consensus
    // Network literal the fixtures use converts via `From<Network>`.
    use zcash_protocol::consensus::Network;

    use incrementalmerkletree::{Hashable, Level};
    use zcash_client_backend::data_api::chain::CommitmentTreeRoot;

    #[test]
    fn open_sets_wal_and_initializes_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let _session = WalletSession::open(Network::MainNetwork, &path).expect("open");
        // WAL must persist on the file.
        let conn = Connection::open(&path).expect("reopen");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(mode.to_lowercase(), "wal");
    }

    /// [API v2.1 E-4] The tx-set signature moves on INSERTS (count) and on reconcile-LINKAGE
    /// transitions (unreconciled count) — the two classes the boundary check must catch.
    #[test]
    fn open_heals_flooded_deep_history_checkpoints() {
        // 2026-07-06 sandblasting-era P0: wallets that scanned the spam era on
        // a pre-fix build carry thousands of deep-history checkpoint rows that
        // panic every later pass. Opening the session must delete everything
        // deeper than the margin below each pool's max checkpoint id — and be
        // a no-op within the retained window.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        // First open creates the schema.
        drop(WalletSession::open(Network::MainNetwork, &path).expect("open"));
        {
            let conn = Connection::open(&path).expect("reopen");
            // The poisoned shape: a flood spanning the era + a healthy tip window.
            let mut stmt = conn
                .prepare("INSERT INTO orchard_tree_checkpoints (checkpoint_id, position) VALUES (?1, ?2)")
                .expect("prepare");
            for id in (1_687_103..1_990_103).step_by(100) {
                stmt.execute(rusqlite::params![id, 1_000])
                    .expect("insert flood");
            }
            for id in 3_402_885..3_402_985 {
                stmt.execute(rusqlite::params![id, 2_000_000])
                    .expect("insert window");
            }
        }
        // Second open runs the heal.
        drop(WalletSession::open(Network::MainNetwork, &path).expect("open heals"));
        let conn = Connection::open(&path).expect("reopen");
        let (n, min_id): (u64, i64) = conn
            .query_row(
                "SELECT COUNT(*), MIN(checkpoint_id) FROM orchard_tree_checkpoints",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("count");
        assert_eq!(n, 100, "only the tip window survives the heal");
        assert!(
            min_id >= 3_402_985 - 10_000,
            "flood rows below the margin are gone"
        );
    }

    #[test]
    fn tx_set_signature_tracks_inserts_and_linkage() {
        use rusqlite::params;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        assert_eq!(s.tx_set_signature().expect("sig"), (0, 0), "fresh wallet");

        let conn = Connection::open(&path).expect("side conn");
        // Same as reconcile.rs's fixture: raw fixture rows without full FK graphs.
        conn.pragma_update(None, "foreign_keys", false)
            .expect("fk off");
        // A pure receive (no observed spends) is reconciled immediately: count moves, not unreconciled.
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height)
             VALUES (1, ?1, 400, 0, 400)",
            params![vec![0x01u8; 32]],
        )
        .expect("insert pure receive");
        assert_eq!(
            s.tx_set_signature().expect("sig"),
            (1, 0),
            "insert moves the count"
        );

        // A dangling shielded spend (nullifier observed, note not yet received) flips unreconciled.
        let txid2 = vec![0x02u8; 32];
        let nf = vec![0xBBu8; 32];
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, min_observed_height)
             VALUES (2, ?1, 500, 0, 500)",
            params![txid2],
        )
        .expect("insert spend tx");
        conn.execute(
            "INSERT INTO tx_locator_map (block_height, tx_index, txid) VALUES (500, 0, ?1)",
            params![vec![0x02u8; 32]],
        )
        .expect("insert locator");
        conn.execute(
            "INSERT INTO nullifier_map (spend_pool, nf, block_height, tx_index) VALUES (2, ?1, 500, 0)",
            params![nf],
        )
        .expect("insert nullifier");
        assert_eq!(
            s.tx_set_signature().expect("sig"),
            (2, 1),
            "dangling spend flips unreconciled"
        );

        // Scanning the origin block receives the note -> the spend LINKS with NO new tx row:
        // exactly the change class only the signature (not the enhance counter) can see.
        conn.execute(
            "INSERT INTO sapling_received_notes
                (transaction_id, output_index, account_id, diversifier, value, rcm, nf, is_change)
             VALUES (1, 0, 1, x'00', 0, x'00', ?1, 0)",
            params![nf],
        )
        .expect("link note");
        assert_eq!(
            s.tx_set_signature().expect("sig"),
            (2, 0),
            "linkage moves the signature"
        );
    }

    #[test]
    fn ensure_account_imports_once_with_empty_treestate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        // TreeState with height + valid hex hash (32 zero bytes) and empty tree strings.
        // to_chain_state() requires a non-empty hex hash; "00" * 32 = 64 chars is accepted.
        // Note: empty sapling_tree / orchard_tree strings decode to empty frontiers — valid for
        // a wallet at or before sapling activation where no notes have been committed yet.
        let ts = TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(TEST_UFVK, ts.clone())
            .expect("first import");
        s.ensure_account(TEST_UFVK, ts).expect("idempotent");
        // Note 4: assert on account count (simpler than range-suggestion check on fresh wallet)
        let ids = s.db.get_account_ids().expect("get_account_ids");
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn import_account_is_guarded_by_per_ufvk_presence_check() {
        // The typed production path: `has_account_for_ufvk` flips false→true across an
        // `import_account`, which is how the engine imports each key at most once.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("data.db");
        let mut s = WalletSession::open(Network::MainNetwork, &path).expect("open");
        let net = SlipstreamNetwork::from(Network::MainNetwork);
        let ufvk = UnifiedFullViewingKey::decode(&net, TEST_UFVK).expect("decode TEST_UFVK");
        let ts = TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        assert!(
            !s.has_account_for_ufvk(&ufvk).expect("presence"),
            "absent before import"
        );
        s.import_account(&ufvk, ts).expect("import");
        assert!(
            s.has_account_for_ufvk(&ufvk).expect("presence"),
            "present after import"
        );
        assert_eq!(s.db.get_account_ids().expect("get_account_ids").len(), 1);
    }

    // ── Incremental subtree roots ────────────────────────────────────────────

    /// Roots `start..start + count` of every pool. A root's hash depends only on its index,
    /// so an overlapping re-download stores identical roots.
    fn roots(start: u64, count: u64) -> SubtreeRoots {
        let height = |i: u64| BlockHeight::from_u32(1_000 + u32::try_from(i).expect("small"));
        let level = |i: u64| Level::from(u8::try_from(i).expect("small"));
        SubtreeRoots {
            sapling: (start..start + count)
                .map(|i| {
                    CommitmentTreeRoot::from_parts(height(i), sapling::Node::empty_root(level(i)))
                })
                .collect(),
            orchard: (start..start + count)
                .map(|i| {
                    CommitmentTreeRoot::from_parts(
                        height(i),
                        orchard::tree::MerkleHashOrchard::empty_root(level(i)),
                    )
                })
                .collect(),
            ironwood: (start..start + count)
                .map(|i| {
                    CommitmentTreeRoot::from_parts(
                        height(i),
                        orchard::tree::MerkleHashOrchard::empty_root(level(i)),
                    )
                })
                .collect(),
        }
    }

    /// Only the Ironwood roots of `roots(start, count)`.
    fn ironwood_only(start: u64, count: u64) -> SubtreeRoots {
        let mut r = roots(start, count);
        r.sapling.clear();
        r.orchard.clear();
        r
    }

    #[test]
    fn next_subtree_root_index_overlaps_the_last_complete_shard() {
        assert_eq!(
            next_subtree_root_index(&[]),
            0,
            "nothing stored: everything"
        );
        assert_eq!(next_subtree_root_index(&[0]), 0);
        assert_eq!(next_subtree_root_index(&[0, 1]), 0);
        assert_eq!(
            next_subtree_root_index(&[0, 1, 2, 3, 4, 5]),
            4,
            "second-to-last"
        );
        assert_eq!(
            next_subtree_root_index(&[5]),
            0,
            "seeded near the tip: everything"
        );
        assert_eq!(next_subtree_root_index(&[5, 6]), 0);
        assert_eq!(
            next_subtree_root_index(&[0, 1, 3, 4]),
            0,
            "a gap: everything"
        );
    }

    /// A fresh wallet stores no shards, so every pool asks from index 0.
    #[test]
    fn subtree_roots_start_at_zero_on_a_fresh_wallet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s =
            WalletSession::open(Network::MainNetwork, &dir.path().join("data.db")).expect("open");
        assert_eq!(
            s.next_subtree_root_start().expect("start"),
            SubtreeRootStart::default()
        );
    }

    /// With roots stored, a pass asks from the second-to-last stored shard — the last
    /// complete one overlaps — and every pool's indices stay one complete range.
    #[test]
    fn subtree_roots_resume_with_overlap_and_stay_contiguous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s =
            WalletSession::open(Network::MainNetwork, &dir.path().join("data.db")).expect("open");
        s.put_subtree_roots_at(SubtreeRootStart::default(), &roots(0, 6))
            .expect("the first pass downloads everything");
        let start = s.next_subtree_root_start().expect("start");
        assert_eq!(
            start,
            SubtreeRootStart {
                sapling: 4,
                orchard: 4,
                ironwood: 4
            }
        );
        // The next pass: the server answers from 4 — the overlap (4, 5) plus two new roots.
        s.put_subtree_roots_at(start, &roots(4, 4))
            .expect("an incremental download is continuous");
        let all: Vec<u64> = (0..8).collect();
        assert_eq!(
            s.stored_shard_indices().expect("indices"),
            (all.clone(), all.clone(), all)
        );
        assert_eq!(
            s.next_subtree_root_start().expect("start"),
            SubtreeRootStart {
                sapling: 6,
                orchard: 6,
                ironwood: 6
            }
        );
    }

    /// A pool whose stored shards do not start at 0 — Ironwood seeded only near the tip —
    /// downloads every root again, and its indices become one complete range, so a later
    /// older-birthday scan cannot hit `SubtreeDiscontinuity`.
    #[test]
    fn a_pool_seeded_only_near_the_tip_downloads_everything_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s =
            WalletSession::open(Network::MainNetwork, &dir.path().join("data.db")).expect("open");
        let at = |ironwood: u64| SubtreeRootStart {
            ironwood,
            ..SubtreeRootStart::default()
        };
        s.put_subtree_roots_at(at(5), &ironwood_only(5, 2))
            .expect("seeded near the tip");
        assert_eq!(s.stored_shard_indices().expect("indices").2, vec![5, 6]);
        // Why it matters: below a near-tip seed, a lower root is refused.
        let err = s
            .put_subtree_roots_at(at(2), &ironwood_only(2, 1))
            .expect_err("a gap below the stored shards");
        assert!(err.to_string().contains("discontinuous"), "got: {err}");

        let start = s.next_subtree_root_start().expect("start");
        assert_eq!(
            start.ironwood, 0,
            "not a complete range from 0: download everything"
        );
        s.put_subtree_roots_at(start, &roots(0, 8))
            .expect("the full download overlaps the seeded shards");
        assert_eq!(
            s.stored_shard_indices().expect("indices").2,
            (0..8).collect::<Vec<u64>>()
        );
        s.put_subtree_roots_at(at(2), &ironwood_only(2, 1))
            .expect("inside the complete range now");
        assert_eq!(s.next_subtree_root_start().expect("start").ironwood, 6);
    }

    // ── Historic scan work ───────────────────────────────────────────────────

    /// Imports `TEST_UFVK` with a mainnet birthday far below the tips these tests use, and
    /// below any NU7 activation.
    fn import_old_account(s: &mut WalletSession) {
        let birthday = TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        s.ensure_account(TEST_UFVK, birthday).expect("import");
    }

    /// A fresh wallet has no `Historic` scan work. An account whose birthday is far below
    /// the tip queues some: the rescan from the birthday up to the tip.
    #[test]
    fn historic_scan_work_appears_with_an_account_imported_below_the_tip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s =
            WalletSession::open(Network::MainNetwork, &dir.path().join("data.db")).expect("open");
        assert!(
            !s.has_historic_scan_ranges().expect("query"),
            "a fresh wallet has nothing to scan"
        );

        import_old_account(&mut s);
        s.update_chain_tip(700_000).expect("tip");
        assert!(
            s.has_historic_scan_ranges().expect("query"),
            "the birthday is far below the tip"
        );
    }

    /// Only `Historic` ranges count. With roots stored, the range up to the tip is queued as
    /// `ChainTip` work instead, so a pass that has only that keeps its incremental start.
    #[test]
    fn scan_ranges_of_other_priorities_are_not_historic_work() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s =
            WalletSession::open(Network::MainNetwork, &dir.path().join("data.db")).expect("open");
        s.put_subtree_roots_at(SubtreeRootStart::default(), &roots(0, 6))
            .expect("roots");
        import_old_account(&mut s);
        s.update_chain_tip(700_000).expect("tip");

        let ranges = s.suggest_scan_ranges().expect("ranges");
        assert!(
            !ranges.is_empty()
                && ranges
                    .iter()
                    .all(|range| range.priority() == ScanPriority::ChainTip),
            "premise: scan work is queued, and none of it is Historic: {ranges:?}"
        );
        assert!(
            !s.has_historic_scan_ranges().expect("query"),
            "a queue of ChainTip ranges is not Historic work"
        );
    }
}
