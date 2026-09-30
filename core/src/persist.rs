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

//! Sparse/batched persistence (P6): upstream-identical `put_blocks` semantics
//! with the shardtree state held in memory per scan range and flushed to SQLite
//! once per chunk. The scan kernel (`scan_cached_blocks`) is untouched — this
//! module only swaps the `WalletWrite::put_blocks` target via `SparseFacade`.
//! Flag-gated by `EngineConfig::sparse_persistence`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU32;
use std::ops::Range;
use std::time::SystemTime;

use incrementalmerkletree::{Address, Level, Marking, Position, Retention};
use secrecy::SecretVec;
use shardtree::{
    LocatedPrunableTree, LocatedTree, PrunableTree, RetentionFlags, ShardTree, Tree,
    error::ShardTreeError,
    store::{Checkpoint, ShardStore},
};
use tracing::info;
use transparent::address::TransparentAddress;
use zip32::DiversifierIndex;

use zcash_client_backend::data_api::anchor_retention::AnchorRetention;
pub(crate) use zcash_client_backend::data_api::ll::wallet::build_subtrees;
use zcash_client_backend::data_api::ll::wallet::{
    batch_ensure_heights, ensure_checkpoints, put_blocks_rows,
};
use zcash_client_backend::data_api::{
    AccountBirthday, AccountPurpose, AddressInfo, BlockMetadata, DecryptedTransaction,
    NullifierQuery, ORCHARD_SHARD_HEIGHT, OutputLockStore, ReceivedTransactionOutput,
    SAPLING_SHARD_HEIGHT, ScannedBlock, SeedRelevance, SentTransaction, TransactionDataRequest,
    TransactionStatus, TransactionsInvolvingAddress, TransparentBalances, WalletCommitmentTrees,
    WalletRead, WalletSummary, WalletWrite, Zip32Derivation,
    chain::ChainState,
    error::{FindAccountForAddressError, LockError},
    ll::{LowLevelWalletWrite, wallet::PutBlocksError},
    scanning::ScanRange,
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_client_backend::wallet::{
    LockOwner, NoteId, OutputRef, TransparentAddressMetadata, WalletTransparentOutput,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::transparent::gap_limits::GapLimits;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::Memo;

use crate::wallet_session::Db;

/// Mirror of upstream's checkpoint retention bound
/// (zcash_client_backend ll/wallet.rs:52 PRUNING_DEPTH = 100, used as
/// max_checkpoints at zcash_client_sqlite lib.rs:2213).
const MAX_CHECKPOINTS: usize = 100;

/// Subtree build chunk size — mirror of ll/wallet.rs:467 CHUNK_SIZE.
pub(crate) const BUILD_CHUNK_SIZE: usize = 1024;

/// T6.3b checkpoint-downgrade window, mirroring upstream PRUNING_DEPTH = 100
/// (zcash_client_backend ll/wallet.rs:52, plumbed into the trees as
/// `max_checkpoints` — see MAX_CHECKPOINTS above).
///
/// Upstream's scan stream carries a `Retention::Checkpoint { id }` for EVERY
/// scanned block, but `prune_excess_checkpoints` (shardtree lib.rs:550-660)
/// trims the checkpoint set back to the newest 100 ids on every `insert_tree`
/// call — so within one `put_blocks` call all but the newest ~100 checkpoints
/// are created, walked, and destroyed (≈9,900 create/destroy cycles per
/// 10k-block chunk). The downgrade computes the surviving window up front
/// (per pool, per put_blocks call) and never creates the doomed ones.
///
/// For a pool that checkpoints every block of the batch this is the
/// controller-prescribed `cutoff = last_scanned_block_height - 100`; the exact
/// per-pool form (see [`doomed_checkpoint_cutoff`]) is required because
/// upstream retains the newest 100 ids *of the pool's checkpoint id stream*,
/// which reaches below `last - 100` when a pool checkpoints fewer than 100
/// blocks in that window.
const SPARSE_CHECKPOINT_WINDOW: u64 = 100;
const _: () = assert!(
    SPARSE_CHECKPOINT_WINDOW as usize == MAX_CHECKPOINTS,
    "window must mirror upstream PRUNING_DEPTH / max_checkpoints"
);

/// Batches whose last height sits at least this far below the chain tip carry
/// NO per-block checkpoints at all (every `Retention::Checkpoint` in the
/// stream is downgraded up front; only the per-chunk `from_state` frontier
/// checkpoint — `Marking::Reference`, materialized by `insert_frontier` —
/// survives).
///
/// Correctness (the sandblasting-era panic, 2026-07-06, traced live): the
/// v0.4 graft accumulator BUFFERS note-free historic rows instead of
/// inserting them, which breaks TWO assumptions at once. (1) The cross-pool
/// `ensure_checkpoints` maps are deliberately taken PRE-dooming
/// (upstream-identical inputs), and the add loops' `height > min_cp` filter
/// assumed built-segment insertion keeps the store's min checkpoint at the
/// window cutoff — with everything buffered nothing inserts, `min_cp` stays
/// ancient, and the filter admits THOUSANDS of cross-pool checkpoint adds
/// per era chunk (traced: 319 after chunk 1, 3,174 by chunk 2 vs max 100).
/// (2) The pass-start subtree-root ingest has installed a ROOT-ONLY leaf for
/// every chain-wide-completed shard, and the buffered rows' retention never
/// materializes — so when the next `insert_frontier`'s
/// `prune_excess_checkpoints` mass-evicts that flood in per-shard
/// `clear_flags` batches, it descends into a root-only leaf with thousands
/// of positions and hits shardtree's "Tree state inconsistent with
/// checkpoints" panic arm. Dooming the stream up front empties the cp_pos
/// maps, so the flood never happens and there is nothing to evict; the
/// surviving per-chunk frontier checkpoints sit on leaves `insert_frontier`
/// materialized, and their single-position clears are handled gracefully.
///
/// Equivalence: upstream's own serial scan prunes every checkpoint deeper
/// than `PRUNING_DEPTH` (100) as it goes, so the final `data.db` checkpoint
/// set — the newest window near the tip — is unchanged; deep-history
/// checkpoints are pure churn in both worlds. Rewinds deeper than the margin
/// re-anchor from a server `TreeState` exactly as upstream does. The margin
/// is deliberately enormous next to the reorg depth (100).
const DEEP_HISTORY_CHECKPOINT_MARGIN: u32 = 10_000;

/// \[B6\] Whether the checkpoint at `height` must be retained as a durable
/// anchor, delegated to upstream's [`AnchorRetention::retains`].
///
/// The grid used to be mirrored here as a local `ANCHOR_RETENTION_INTERVAL`
/// constant, because upstream declared its own `pub(crate)`. That mirror was a
/// standing correctness hazard and did in fact drift — it sat at 288 while
/// upstream was 144, so this engine retained only every OTHER upstream anchor,
/// and a transfer pre-signed against an odd multiple of 144 would have lost
/// the checkpoint it proves against. Upstream now publishes the grid as a type
/// that owns the arithmetic, so there is one implementation and nothing left to
/// drift.
///
/// Every exemption in the sparse mirror (checkpoint downgrade, deep-history
/// dooming, shardtree's retention-aware prune via `ensure_retained`) keys on
/// THIS predicate, so the surviving anchor set equals upstream's retained set
/// (upstream records the same predicate's hits imperatively via
/// `ensure_retained`). Note the deliberate asymmetry vs upstream's
/// `remove_retained_checkpoint` release API: we re-derive from the predicate
/// at seed time and never release, which retains a SUPERSET — the safe
/// direction (a few extra checkpoint rows; never a destroyed anchor).
fn should_retain_anchor(anchor_retention: Option<&AnchorRetention>, height: BlockHeight) -> bool {
    anchor_retention.is_some_and(|retention| retention.retains(height))
}

/// v0.6 P4c/P4d (subsumes T6.9b): the persist lane's dedicated rayon pool —
/// THE one pool policy for all persist-side rayon work. Installed at the
/// sap∥orch `rayon::join` in `sparse_put_blocks`, which rayon-scopes ALL
/// nested parallelism (the join arms AND upstream `build_subtrees`'
/// `par_chunks`) onto these threads, never the global pool's decrypt workers.
///
/// Why dedicated — three generations of field evidence:
/// - A10 4-core (T6.9, 2026-06-13): sharing the global pool queued the lane's
///   tree work behind decrypt — tree wall 12.9 s vs 6.7 s of work on one
///   chunk, persist_wait 259 s over the pass. Isolation was worth ≈200 s.
/// - A18 6-core (P4c, 2026-07-07): same pathology at production scale once
///   the nfskip diet exposed it — tree_join wall 17.7–28.8 s on ~6.5 s of
///   work. A dedicated pool made tree_join equal its bucket sum again.
/// - The retired T6.9b2 core-count branch ("isolate only on ≤4 cores; a
///   2-thread pool DOUBLED Mac scan_s 5.58→11.23 s") was measured against the
///   PRE-diet lane (rows ~15 s/pass + checkpoint churn); post-nfskip the Mac
///   lane is ~4 s/pass and the 2-thread sanity run showed no regression
///   (tree_join 3.35→2.52 s). Always isolate now.
///
/// Why `cores − 2` clamped to [2, 4] (P4d): the lane's cost is burst-shaped —
/// the big shard-crossing builds land exactly while the scan lane is blocked
/// in submit_wait, i.e. while the DH threads are IDLE. A 2-thread pool left
/// 4 of the A18's 6 cores unused during the only windows that bind the wall
/// (measured: build doubled 5.2→10.9 s, submit_wait stuck at ~5.8 s). The
/// floor of 2 keeps the sap∥orch join genuinely parallel within the A10's
/// 4-thread budget (2 lane + 2 decrypt — the T6.9b tuning); the cap of 4
/// keeps overlap-time competition with DH negligible.
///
/// Process-global (OnceLock): concurrent sessions share one bounded pool
/// rather than stacking per-lane threads. The inline (write_behind=false)
/// path routes through it too — it never overlaps decrypt, so isolation
/// costs it nothing at these thread counts, and one mechanism beats two.
/// Falls back to the global pool if construction ever fails (never
/// observed — but a perf lever must not become a crash).
fn persist_pool() -> Option<&'static rayon::ThreadPool> {
    use std::sync::OnceLock;
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(2, usize::from);
        rayon::ThreadPoolBuilder::new()
            .num_threads(cores.saturating_sub(2).clamp(2, 4))
            .thread_name(|i| format!("slipstream-persist-{i}"))
            .build()
            .map_err(|e| tracing::warn!(%e, "persist pool build failed — global pool fallback"))
            .ok()
    })
    .as_ref()
}

/// Open-time self-heal for wallets damaged by the pre-fix sandblasting-era
/// checkpoint flood (see `DEEP_HISTORY_CHECKPOINT_MARGIN`): builds that ran
/// v0.4/v0.5 before the fix persisted THOUSANDS of deep-history checkpoint
/// rows (a poisoned specimen: 3,174 orchard rows spanning the whole spam era
/// vs the healthy 100-row tip window). Every later pass — even a 10-block tip
/// verify — then mass-evicts them into root-only ingested shard leaves and
/// dies in shardtree's "Tree state inconsistent with checkpoints" panic arm,
/// wedging the wallet in the revival loop.
///
/// The heal removes checkpoints (their marks-removed satellites cascade in
/// the store) deeper than the margin below each pool's own max checkpoint id.
/// For healthy wallets this is a no-op (upstream-equivalent pruning never
/// leaves deep rows); for flooded wallets it restores exactly the state
/// upstream's own `prune_excess_checkpoints` would have converged to. The
/// flooded rows' retention flags were never materialized in the tree (their
/// commitments were buffered), so store-row deletion needs no tree-side flag
/// cleanup; stale flags from any legitimately-built deep checkpoints merely
/// keep a node alive (bloat, not breakage).
///
/// Issue #4: runs through `WalletCommitmentTrees` + the pool stores' own
/// checkpoint API — the engine holds no direct SQL against upstream tables.
///
/// Returns checkpoints removed across all pools.
// The heal_pool_checkpoints closures below look redundant, but a bare fn item
// is "not general enough" for the for<'a> callback lifetime these methods need.
#[allow(clippy::redundant_closure)]
pub fn heal_flooded_checkpoints(db: &mut Db) -> Result<u64, crate::error::SlipstreamError> {
    let heal_err = |pool: &str, e: &dyn std::fmt::Display| {
        crate::error::SlipstreamError::Wallet(format!("checkpoint heal ({pool}): {e}"))
    };
    // [IW-2c]/[B6] third pool included (absent stores heal zero); durable
    // anchors are spared by consulting each store's RETAINED checkpoint set.
    let mut removed = 0u64;
    removed += db
        .with_sapling_tree_mut::<_, _, ShardTreeError<_>>(|t| heal_pool_checkpoints(t))
        .map_err(|e| heal_err("sapling", &e))?;
    removed += db
        .with_orchard_tree_mut::<_, _, ShardTreeError<_>>(|t| heal_pool_checkpoints(t))
        .map_err(|e| heal_err("orchard", &e))?;
    removed += db
        .with_ironwood_tree_mut::<_, _, ShardTreeError<_>>(|t| heal_pool_checkpoints(t))
        .map_err(|e| heal_err("ironwood", &e))?
        .unwrap_or(0);
    Ok(removed)
}

/// One pool's flood heal: drop every checkpoint deeper than
/// `DEEP_HISTORY_CHECKPOINT_MARGIN` below the pool's max checkpoint id, except
/// those the store records as RETAINED durable anchors.
///
/// The retained set is read from the store rather than re-derived from the
/// anchor grid. The heal has no retention-floor context at open time, so it
/// used to spare every height on a hard-coded grid — which stops being possible
/// once the grid is configurable, and was in any case a guess. `ensure_retained`
/// has already recorded exactly which checkpoints are durable anchors, so
/// reading that set spares precisely the right ones at whatever interval they
/// were established under, including an interval a previous run was configured
/// with. The flooded rows were never retained (their commitments were
/// buffered), so they are unaffected by the exemption and still swept.
fn heal_pool_checkpoints<S, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &mut ShardTree<S, DEPTH, SHARD_HEIGHT>,
) -> Result<u64, ShardTreeError<S::Error>>
where
    S: ShardStore<CheckpointId = BlockHeight>,
    S::H: incrementalmerkletree::Hashable + Clone + PartialEq,
{
    let store = tree.store_mut();
    let Some((max_id, _)) = store
        .get_checkpoint_at_depth(0)
        .map_err(ShardTreeError::Storage)?
    else {
        return Ok(0);
    };
    let cutoff = u32::from(max_id).saturating_sub(DEEP_HISTORY_CHECKPOINT_MARGIN);
    let retained = store
        .retained_checkpoints()
        .map_err(ShardTreeError::Storage)?;
    // The store binds `limit` as an SQL parameter (i64), so `usize::MAX` is
    // NOT a valid "no limit" sentinel — pass the actual row count.
    let count = store.checkpoint_count().map_err(ShardTreeError::Storage)?;
    let mut doomed = vec![];
    store
        .for_each_checkpoint(count, |id, _| {
            if u32::from(*id) < cutoff && !retained.contains(id) {
                doomed.push(*id);
            }
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
    for id in &doomed {
        store
            .remove_checkpoint(id)
            .map_err(ShardTreeError::Storage)?;
    }
    Ok(doomed.len() as u64)
}

// ── In-memory shard store ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SparseStoreError {
    /// A shard exists in SQLite but was not preloaded — preload-set bug.
    /// Failing loudly here is a D3 guard: silently treating it as absent would
    /// diverge from upstream pruning behavior.
    #[error("shard index {0} exists in the database but was not preloaded")]
    NotPreloaded(u64),
    #[error("operation not supported by the in-memory sparse store: {0}")]
    Unsupported(&'static str),
}

/// ShardStore over BTreeMaps with read-miss policy and dirty tracking.
/// Semantics inherited: all mutations come from upstream's own ShardTree logic.
pub struct SparseShardStore<H> {
    shard_level: Level,
    /// Shard indices present in SQLite at seed time.
    db_shard_indices: BTreeSet<u64>,
    shards: BTreeMap<u64, LocatedPrunableTree<H>>,
    dirty_shards: BTreeSet<u64>,
    cap: PrunableTree<H>,
    cap_dirty: bool,
    checkpoints: BTreeMap<BlockHeight, Checkpoint>,
    /// Mirror of the checkpoint rows in SQLite (for flush diffing).
    db_checkpoints: BTreeMap<BlockHeight, Checkpoint>,
    /// \[B6\] Checkpoint ids pinned against automatic pruning (the migration
    /// crate's 288-block durable anchors). In-memory only: re-derived at seed
    /// time from the retention predicate — see `should_retain_anchor`.
    retained: BTreeSet<BlockHeight>,
}

impl<H> SparseShardStore<H> {
    /// v0.4 T10b: does the store hold REAL interior content for this shard —
    /// anything beyond the root-only leaf that upstream's `put_shard_roots`
    /// caches for every server-ingested subtree root (and that a graft installs)?
    /// The accumulator's seed passthrough must key on THIS, not row presence:
    /// after the pass-start root ingest EVERY completed shard has a row, so a
    /// presence check silently forfeits the graft of any shard a range starts
    /// exactly on. Root-only leaves are graft/build-eligible; only a built
    /// interior means "already have it" (the crash-heal case).
    pub fn shard_has_interior(&self, idx: u64) -> bool {
        match self.shards.get(&idx) {
            Some(t) => !t.root().is_leaf(),
            // Not in memory (seed loads every known shard, so effectively
            // unreachable) — stay conservative: presence ⇒ interior.
            None => self.db_shard_indices.contains(&idx),
        }
    }

    pub fn new(shard_height: u8) -> Self {
        Self {
            shard_level: Level::new(shard_height),
            db_shard_indices: BTreeSet::new(),
            shards: BTreeMap::new(),
            dirty_shards: BTreeSet::new(),
            cap: PrunableTree::empty(),
            cap_dirty: false,
            checkpoints: BTreeMap::new(),
            db_checkpoints: BTreeMap::new(),
            retained: BTreeSet::new(),
        }
    }

    /// Checkpoint diff vs the SQLite mirror: (to_remove, to_add).
    /// A checkpoint whose state changed appears in both (remove + re-add),
    /// matching add_checkpoint's CheckpointConflict contract
    /// (zcash_client_sqlite commitment_tree.rs:654-740).
    fn checkpoint_delta(&self) -> (Vec<BlockHeight>, Vec<(BlockHeight, Checkpoint)>) {
        let mut remove = vec![];
        let mut add = vec![];
        for (h, db_cp) in &self.db_checkpoints {
            match self.checkpoints.get(h) {
                None => remove.push(*h),
                Some(mem_cp)
                    if mem_cp.tree_state() != db_cp.tree_state()
                        || mem_cp.marks_removed() != db_cp.marks_removed() =>
                {
                    remove.push(*h);
                    add.push((*h, mem_cp.clone()));
                }
                Some(_) => {}
            }
        }
        for (h, cp) in &self.checkpoints {
            if !self.db_checkpoints.contains_key(h) {
                add.push((*h, cp.clone()));
            }
        }
        (remove, add)
    }
}

impl<H: Clone> ShardStore for SparseShardStore<H> {
    type H = H;
    type CheckpointId = BlockHeight;
    type Error = SparseStoreError;

    fn get_shard(&self, addr: Address) -> Result<Option<LocatedPrunableTree<H>>, Self::Error> {
        let idx = addr.index();
        if let Some(s) = self.shards.get(&idx) {
            return Ok(Some(s.clone()));
        }
        if self.db_shard_indices.contains(&idx) {
            return Err(SparseStoreError::NotPreloaded(idx));
        }
        Ok(None)
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<H>>, Self::Error> {
        // Invariant: the frontier shard (true last) is always preloaded at seed,
        // so the max loaded/created index is the true last shard.
        Ok(self.shards.values().next_back().cloned())
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<H>) -> Result<(), Self::Error> {
        let idx = subtree.root_addr().index();
        self.shards.insert(idx, subtree);
        self.dirty_shards.insert(idx);
        Ok(())
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        let mut all: BTreeSet<u64> = self.db_shard_indices.clone();
        all.extend(self.shards.keys().copied());
        Ok(all
            .into_iter()
            .map(|i| Address::from_parts(self.shard_level, i))
            .collect())
    }

    fn truncate_shards(&mut self, _shard_index: u64) -> Result<(), Self::Error> {
        // Never reached on the insert path; reorg truncation goes through the
        // REAL WalletDb (scheduler reorg arm) and the sparse state is discarded
        // per range. Fail loudly if shardtree internals ever call this.
        Err(SparseStoreError::Unsupported("truncate_shards"))
    }

    fn get_cap(&self) -> Result<PrunableTree<H>, Self::Error> {
        Ok(self.cap.clone())
    }

    fn put_cap(&mut self, cap: PrunableTree<H>) -> Result<(), Self::Error> {
        self.cap = cap;
        self.cap_dirty = true;
        Ok(())
    }

    fn min_checkpoint_id(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.checkpoints.keys().next().copied())
    }

    fn max_checkpoint_id(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Ok(self.checkpoints.keys().next_back().copied())
    }

    fn add_checkpoint(
        &mut self,
        id: BlockHeight,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        self.checkpoints.insert(id, checkpoint);
        Ok(())
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        Ok(self.checkpoints.len())
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(BlockHeight, Checkpoint)>, Self::Error> {
        // Matches SQLite: ORDER BY checkpoint_id DESC LIMIT 1 OFFSET depth.
        Ok(self
            .checkpoints
            .iter()
            .rev()
            .nth(checkpoint_depth)
            .map(|(id, c)| (*id, c.clone())))
    }

    fn get_checkpoint(&self, id: &BlockHeight) -> Result<Option<Checkpoint>, Self::Error> {
        Ok(self.checkpoints.get(id).cloned())
    }

    fn with_checkpoints<F>(&mut self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Self::Error>,
    {
        for (id, cp) in self.checkpoints.iter().take(limit) {
            callback(id, cp)?;
        }
        Ok(())
    }

    fn for_each_checkpoint<F>(&self, limit: usize, mut callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), Self::Error>,
    {
        for (id, cp) in self.checkpoints.iter().take(limit) {
            callback(id, cp)?;
        }
        Ok(())
    }

    fn update_checkpoint_with<F>(
        &mut self,
        id: &BlockHeight,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        if let Some(cp) = self.checkpoints.get_mut(id) {
            update(cp)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_checkpoint(&mut self, id: &BlockHeight) -> Result<(), Self::Error> {
        self.checkpoints.remove(id);
        Ok(())
    }

    // [B6] Retention overrides — shardtree's retention-aware prune exempts
    // these ids (the migration crate's durable anchors) from the budget.
    fn add_retained_checkpoint(&mut self, id: BlockHeight) -> Result<(), Self::Error> {
        self.retained.insert(id);
        Ok(())
    }

    fn remove_retained_checkpoint(&mut self, id: &BlockHeight) -> Result<(), Self::Error> {
        self.retained.remove(id);
        Ok(())
    }

    fn retained_checkpoints(&self) -> Result<BTreeSet<BlockHeight>, Self::Error> {
        Ok(self.retained.clone())
    }

    fn truncate_checkpoints_retaining(&mut self, _id: &BlockHeight) -> Result<(), Self::Error> {
        Err(SparseStoreError::Unsupported(
            "truncate_checkpoints_retaining",
        ))
    }
}

// ── Per-range sparse tree state ────────────────────────────────────────────────

type SaplingSparseTree = ShardTree<
    SparseShardStore<sapling::Node>,
    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
    SAPLING_SHARD_HEIGHT,
>;
type OrchardSparseTree = ShardTree<
    SparseShardStore<orchard::tree::MerkleHashOrchard>,
    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    ORCHARD_SHARD_HEIGHT,
>;
// [IW-2c] Ironwood shares Orchard's curve/hash (MerkleHashOrchard, same depth
// and shard height) — a distinct TREE over identical kernels.
type IronwoodSparseTree = OrchardSparseTree;

/// In-memory tree state for ONE scan range (created per scan_chunks call,
/// dropped at range end / on error — reorg truncation therefore never has to
/// invalidate it explicitly).
#[derive(Default)]
pub struct SparseTreeState {
    sapling: Option<SaplingSparseTree>,
    orchard: Option<OrchardSparseTree>,
    /// \[B6\] Anchor-retention policy (upstream put_blocks' `anchor_retention`):
    /// when `Some`, checkpoints the policy retains — those at or above its floor
    /// that fall on its grid — are durable anchors, exempt from the T6.3b
    /// downgrade, the deep-history dooming, and (via `ensure_retained`)
    /// shardtree's excess-checkpoint pruning. `None` (the default) = today's
    /// behavior byte-for-byte.
    pub(crate) anchor_retention: Option<AnchorRetention>,
    /// [IW-2c] Third pool. No graft/census/GPU lane: the ironwood tree starts
    /// at activation (tiny for years), stock lightwalletd serves no ironwood
    /// subtree roots to graft from, and the build cost is microseconds.
    ironwood: Option<IronwoodSparseTree>,
    /// B0: route the Orchard subtree build to the GPU (feature `gpu`). Default false;
    /// set from `EngineConfig::gpu_subtree` at the scan-path construction site.
    pub(crate) gpu_subtree: bool,
    /// v0.4 Plan A (spec §4): defer note-free shard builds through the graft
    /// accumulator. Set ONLY for Historic-priority ranges when
    /// `EngineConfig::graft_subtree` is on (accumulator safety rule 2 — the
    /// ChainTip range always runs today's passthrough path verbatim).
    pub(crate) graft_buffering: bool,
    /// Live graft machinery (side connection + per-pool accumulators), opened by
    /// the persist lane when `graft_buffering` (plan Task 7b rev 2). `None` on
    /// every other path — and the closure then runs byte-for-byte today's code.
    pub(crate) graft: Option<GraftCtx>,
    /// v0.4 Plan B: route Orchard builds through the batch-affine lookup path
    /// (byte-identical; the KAT + lookup_build gate adjudicate).
    pub(crate) batch_combine: bool,
    /// v0.4 census (spec §3.2): shard-touch vs owned-note-shard counts, fed by every
    /// `sparse_put_blocks` call on this state and read out at range end (ScanStats).
    pub(crate) census_sapling: crate::census::ShardCensus,
    pub(crate) census_orchard: crate::census::ShardCensus,
    /// v0.4 T10b: cumulative graft verdicts — ((sap_grafted, sap_fallback),
    /// (orch_grafted, orch_fallback)). The per-call values feed the "graft
    /// verdicts" log; this sum is the in-band DID-IT-FIRE signal (build-then-prune
    /// and graft converge to identical final bytes, so the DB can't tell).
    pub(crate) graft_verdict_totals: ((u64, u64), (u64, u64)),
}

impl SparseTreeState {
    /// \[B6\] Set the anchor-retention policy (see the field docs). Public for
    /// integration tests and direct hosts; production plumbs it from
    /// `EngineConfig::anchor_retention`.
    pub fn set_anchor_retention(&mut self, anchor_retention: Option<AnchorRetention>) {
        self.anchor_retention = anchor_retention;
    }

    /// v0.4 census read-out (spec §3.2) — (sapling, orchard). Production reads
    /// travel via `ScanStats`; this accessor serves tests and direct hosts.
    pub fn census(&self) -> (&crate::census::ShardCensus, &crate::census::ShardCensus) {
        (&self.census_sapling, &self.census_orchard)
    }
}

// ── v0.4 Plan A: graft machinery (plan Task 7b rev 2) ──────────────────────────

/// Live graft state for one lane/range: the side connection for the buffer
/// table (pre-txn appends, post-txn cleanup — graft.rs's ordering+idempotency
/// contract) + the per-pool accumulators.
pub(crate) struct GraftCtx {
    conn: rusqlite::Connection,
    /// Task 10: verify every Nth graftable shard by building it anyway and
    /// root-comparing against the server (0 = off, 1 = audit every graft).
    verify_sample: u32,
    acc_sapling: Option<crate::graft_accumulator::ShardAccumulator<sapling::Node>>,
    acc_orchard:
        Option<crate::graft_accumulator::ShardAccumulator<orchard::tree::MerkleHashOrchard>>,
}

impl GraftCtx {
    pub(crate) fn open(
        wallet_db_path: &std::path::Path,
        verify_sample: u32,
    ) -> Result<Self, crate::error::SlipstreamError> {
        // Same wait-not-die posture as every other engine connection.
        let conn = rusqlite::Connection::open(wallet_db_path).map_err(|e| {
            crate::error::SlipstreamError::Wallet(format!("graft side conn open: {e}"))
        })?;
        conn.busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!("graft side conn busy_timeout: {e}"))
            })?;
        Ok(Self {
            conn,
            verify_sample,
            acc_sapling: None,
            acc_orchard: None,
        })
    }
}

/// One contiguous build segment: its start position and per-row payload
/// (`None` = a passthrough gap; `Some((hash, retention))` = a row to build).
type BuildSegment<H> = (Position, Vec<Option<(H, Retention<BlockHeight>)>>);

/// One pool's build plan for one put_blocks call: contiguous row segments to
/// build inside the main txn (passthrough spans, eager note flushes, and — in
/// Task 7, where the verdict is still always-build — closed clean shards), plus
/// the shards whose buffer rows die once the txn commits.
struct PoolPlan<H> {
    segments: Vec<BuildSegment<H>>,
    /// Task 8: clean shards with a server root — installed as root-only shards
    /// (upstream's own put_shard_roots shape), ZERO combines.
    grafts: Vec<(u64, H)>,
    cleanup_shards: Vec<u64>,
    /// Clean shards with NO server root (tip lag / server gap) — built instead.
    fallbacks: u64,
    /// Task 10 sampling verify: shards built ANYWAY (their rows ride
    /// `segments`) whose computed root must equal this server root.
    verify_roots: Vec<(u64, H)>,
}

/// Retentions travel VERBATIM into deferred builds (fixture-proven, 7b rev 2.1):
/// own-pool checkpoint TABLE entries come exclusively from the
/// `from_iter → insert_tree(subtree, checkpoints)` path — buffered rows'
/// checkpoints were never inserted at their origin chunk, so a deferred build
/// MUST carry them. Stale (below-window) ones are handled by the SAME
/// doomed-cutoff downgrade every build already applies (the first fixture run
/// stripped them instead and lost 97 of 100 checkpoint rows vs the OFF path).
fn rows_to_segment<H>(rows: Vec<crate::graft_accumulator::AccRow<H>>) -> Option<BuildSegment<H>> {
    let first = rows.first()?.0;
    let seg = rows.into_iter().map(|(_, h, r)| Some((h, r))).collect();
    Some((Position::from(first), seg))
}

/// Pre-txn planner for one pool: lazily seed the accumulator (buffer resume +
/// conservative store-presence probe), feed this call's stream, persist Buffer
/// rows on the side connection, and return the build plan. Runs BEFORE the main
/// transaction opens — no lock conflict, and a crash after these appends is the
/// benign "rescan re-appends identical rows" window (graft.rs header).
#[allow(clippy::too_many_arguments)]
fn plan_pool<H: Clone + zcash_primitives::merkle_tree::HashSer>(
    conn: &rusqlite::Connection,
    verify_sample: u32,
    acc: &mut Option<crate::graft_accumulator::ShardAccumulator<H>>,
    pool: ShieldedPool,
    start_position: u64,
    stream: Vec<(H, Retention<BlockHeight>)>,
    note_positions: &[u64],
    store_has_shard: impl Fn(u64) -> bool,
    mut server_root: impl FnMut(u64) -> Result<Option<H>, SqliteClientError>,
    anchor_retention: Option<&AnchorRetention>,
) -> Result<PoolPlan<H>, SqliteClientError> {
    use crate::graft_accumulator::{FeedAction, ShardAccumulator};

    if acc.is_none() {
        let shard = start_position >> 16;
        let mut resume = crate::graft::load_shard::<H>(conn, pool, shard)?;
        let has_internals = store_has_shard(shard);
        if has_internals && !resume.is_empty() {
            // Stale rows for a shard the store already holds (crash between a
            // build-commit and its cleanup) — the documented self-heal path.
            crate::graft::delete_shard(conn, pool, shard)?;
            resume = vec![];
        }
        *acc = Some(ShardAccumulator::seed(
            start_position,
            resume,
            has_internals,
        ));
    }
    let acc = acc.as_mut().unwrap_or_else(|| unreachable!("seeded above"));

    let mut plan = PoolPlan {
        segments: vec![],
        grafts: vec![],
        cleanup_shards: vec![],
        fallbacks: 0,
        verify_roots: vec![],
    };
    for action in acc.feed(start_position, stream, note_positions) {
        match action {
            FeedAction::Build(rows) => {
                if let Some(first) = rows.first() {
                    plan.cleanup_shards.push(first.0 >> 16);
                }
                plan.segments.extend(rows_to_segment(rows));
            }
            FeedAction::CloseCleanShard { shard_index, rows } => {
                // Task 8 — THE verdict: note-free shard + server root ⇒ graft
                // (zero combines); no root ⇒ build these exact rows (fallback).
                plan.cleanup_shards.push(shard_index);
                // [B6] A graft installs a root-only leaf: the shard's interior —
                // INCLUDING its checkpoint rows — never materializes. Pre-B6 that
                // was free (the downgrade doomed those checkpoints anyway); a
                // durable anchor inside the span must LIVE, so the shard falls
                // back to the built path (retentions travel, anchors exempted).
                let contains_anchor = rows.iter().any(|(_, _, r)| {
                    matches!(r, Retention::Checkpoint { id, .. }
                        if should_retain_anchor(anchor_retention, *id))
                });
                if contains_anchor {
                    plan.fallbacks += 1;
                    plan.segments.extend(rows_to_segment(rows));
                    continue;
                }
                match server_root(shard_index)? {
                    Some(root) => {
                        // Task 10: deterministic 1-in-N audit — build it anyway
                        // and compare roots after insertion (reproducible; the
                        // built content wins on mismatch, so audit ⊇ correct).
                        let audit = verify_sample > 0
                            && shard_index.is_multiple_of(u64::from(verify_sample));
                        if audit {
                            plan.verify_roots.push((shard_index, root));
                            plan.segments.extend(rows_to_segment(rows));
                        } else {
                            plan.grafts.push((shard_index, root));
                        }
                    }
                    None => {
                        plan.fallbacks += 1;
                        plan.segments.extend(rows_to_segment(rows));
                    }
                }
            }
            FeedAction::Buffer(rows) => {
                if let Some(first) = rows.first() {
                    crate::graft::append_rows(conn, pool, first.0 >> 16, &rows)?;
                }
            }
        }
    }
    Ok(plan)
}

fn seed_sapling(
    db: &mut Db,
    _from_state: &ChainState,
    anchor_floor: Option<&AnchorRetention>,
) -> Result<SaplingSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<sapling::Node>::new(SAPLING_SHARD_HEIGHT);
    db.with_sapling_tree_mut::<_, _, SqliteClientError>(|tree| {
        let s = tree.store();
        let roots = s.get_shard_roots().map_err(ShardTreeError::Storage)?;
        store.db_shard_indices = roots.iter().map(|a| a.index()).collect();
        let count = s.checkpoint_count().map_err(ShardTreeError::Storage)?;
        let mut cps = BTreeMap::new();
        s.for_each_checkpoint(count, |id, cp| {
            cps.insert(*id, cp.clone());
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
        // Load ALL shards from SQLite into memory: the scan may access any shard
        // in the scan range (e.g. when a complete subtree boundary is crossed), and
        // returning NotPreloaded for an unloaded-but-known shard would abort the scan.
        // Complete subtrees are stored as a single root-hash node, so the total
        // preload cost is modest even for large trees (≈N * ~100 bytes per shard).
        for addr in &roots {
            let idx = addr.index();
            if let Some(shard) = s.get_shard(*addr).map_err(ShardTreeError::Storage)? {
                store.shards.insert(idx, shard);
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        // [B6] Retention is in-memory: re-pin loaded anchor rows from the
        // predicate every seed (see should_retain_anchor — deliberate superset
        // vs upstream's imperative set; never destroys, may over-retain).
        for id in store.checkpoints.keys() {
            if should_retain_anchor(anchor_floor, *id) {
                store.retained.insert(*id);
            }
        }
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

fn seed_orchard(
    db: &mut Db,
    _from_state: &ChainState,
    anchor_floor: Option<&AnchorRetention>,
) -> Result<OrchardSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<orchard::tree::MerkleHashOrchard>::new(ORCHARD_SHARD_HEIGHT);
    db.with_orchard_tree_mut::<_, _, SqliteClientError>(|tree| {
        let s = tree.store();
        let roots = s.get_shard_roots().map_err(ShardTreeError::Storage)?;
        store.db_shard_indices = roots.iter().map(|a| a.index()).collect();
        let count = s.checkpoint_count().map_err(ShardTreeError::Storage)?;
        let mut cps = BTreeMap::new();
        s.for_each_checkpoint(count, |id, cp| {
            cps.insert(*id, cp.clone());
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
        // Load ALL shards from SQLite into memory: same reasoning as seed_sapling —
        // the scan range may cross shard boundaries for any protocol, and returning
        // NotPreloaded for an unloaded-but-known shard would abort the scan.
        for addr in &roots {
            let idx = addr.index();
            if let Some(shard) = s.get_shard(*addr).map_err(ShardTreeError::Storage)? {
                store.shards.insert(idx, shard);
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        // [B6] Retention is in-memory: re-pin loaded anchor rows from the
        // predicate every seed (see should_retain_anchor — deliberate superset
        // vs upstream's imperative set; never destroys, may over-retain).
        for id in store.checkpoints.keys() {
            if should_retain_anchor(anchor_floor, *id) {
                store.retained.insert(*id);
            }
        }
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

// [IW-2c] Ironwood mirror of seed_orchard — same node type/shard height, the
// fork's `with_ironwood_tree_mut` is the SQLite bridge.
fn seed_ironwood(
    db: &mut Db,
    _from_state: &ChainState,
    anchor_floor: Option<&AnchorRetention>,
) -> Result<IronwoodSparseTree, SqliteClientError> {
    let mut store = SparseShardStore::<orchard::tree::MerkleHashOrchard>::new(ORCHARD_SHARD_HEIGHT);
    db.with_ironwood_tree_mut::<_, _, SqliteClientError>(|tree| {
        let s = tree.store();
        let roots = s.get_shard_roots().map_err(ShardTreeError::Storage)?;
        store.db_shard_indices = roots.iter().map(|a| a.index()).collect();
        let count = s.checkpoint_count().map_err(ShardTreeError::Storage)?;
        let mut cps = BTreeMap::new();
        s.for_each_checkpoint(count, |id, cp| {
            cps.insert(*id, cp.clone());
            Ok(())
        })
        .map_err(ShardTreeError::Storage)?;
        // Preload all shards — same reasoning as seed_sapling/seed_orchard.
        for addr in &roots {
            let idx = addr.index();
            if let Some(shard) = s.get_shard(*addr).map_err(ShardTreeError::Storage)? {
                store.shards.insert(idx, shard);
            }
        }
        store.cap = s.get_cap().map_err(ShardTreeError::Storage)?;
        store.checkpoints = cps.clone();
        store.db_checkpoints = cps;
        // [B6] Retention is in-memory: re-pin loaded anchor rows from the
        // predicate every seed (see should_retain_anchor — deliberate superset
        // vs upstream's imperative set; never destroys, may over-retain).
        for id in store.checkpoints.keys() {
            if should_retain_anchor(anchor_floor, *id) {
                store.retained.insert(*id);
            }
        }
        Ok(())
    })?;
    Ok(ShardTree::new(store, MAX_CHECKPOINTS))
}

/// Flush dirty in-memory sapling tree state into the live transaction's SQLite store,
/// via `WalletCommitmentTrees::put_sapling_shards` (this engine's flush pattern,
/// upstreamed in zcash/librustzcash#2600; runs inside the live transaction as its
/// atomicity contract requires).
/// Shards ascending (check_shard_discontinuity, commitment_tree.rs:444-481);
/// checkpoint changes as remove+add (CheckpointConflict contract).
fn flush_sapling<P, CL, R>(
    wdb: &mut zcash_client_sqlite::WalletDb<zcash_client_sqlite::SqlTransaction<'_>, P, CL, R>,
    tree: &mut SaplingSparseTree,
) -> Result<(), SqliteClientError>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (remove, add) = tree.store().checkpoint_delta();
    let mut shards = Vec::with_capacity(tree.store().dirty_shards.len());
    for idx in &tree.store().dirty_shards {
        shards.push(tree.store().shards.get(idx).cloned().ok_or_else(|| {
            ShardTreeError::Storage(
                zcash_client_sqlite::wallet::commitment_tree::Error::Serialization(
                    std::io::Error::other(format!("dirty shard {idx} missing from memory")),
                ),
            )
        })?);
    }
    let cap = tree.store().cap_dirty.then(|| tree.store().cap.clone());
    wdb.put_sapling_shards(&shards, cap.as_ref(), &remove, &add)?;
    // [B6, flush half] Persist the retained-anchor marks alongside the checkpoint rows they
    // protect, inside the same transaction. The in-memory `retained` set (predicate-derived
    // at seed time and during the batch) shields boundary checkpoints from the IN-MEMORY
    // excess-checkpoint prune, but until now it died with the buffer: the sqlite store never
    // learned the marks, so the open-time deep-history heal — which spares exactly the ids
    // the SQLITE store's retained set names — would doom every boundary anchor older than
    // its margin, leaving pre-signed migration transfers permanently unprovable
    // (AnchorNotFound on every prove, forever). Add-delta only: a height flushed earlier got
    // its mark in its own flush, and a removed checkpoint was never retained (retained ids
    // are exempt from the prune, and a state-changed re-add reappears in `add`), so there is
    // nothing to unmark. Wallets whose checkpoints predate this fix are backfilled by the
    // consumer's open-time reconcile.
    let marks: Vec<BlockHeight> = add
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| tree.store().retained.contains(h))
        .collect();
    if !marks.is_empty() {
        wdb.with_sapling_tree_mut::<_, _, SqliteClientError>(|db_tree| {
            for h in &marks {
                db_tree.ensure_retained(*h)?;
            }
            Ok(())
        })?;
    }
    let store = tree.store_mut();
    store.db_checkpoints = store.checkpoints.clone();
    // NOTE: do NOT insert dirty shard indices into db_shard_indices here.
    // Flushed shards remain in `shards` (we never clear the in-memory map), so
    // get_shard() finds them via the first check (shards.get(idx)).
    // db_shard_indices must only track shards loaded from SQLite at seed time
    // ("known-but-unloaded" guard); adding flushed shards would cause
    // NotPreloaded errors on the next chunk if shardtree internally calls
    // get_shard for a shard that is now in db_shard_indices but has been
    // evicted or not yet re-populated in `shards`.
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}

/// Flush dirty in-memory orchard tree state into the live transaction's SQLite store,
/// via `WalletCommitmentTrees::put_orchard_shards` (see flush_sapling).
fn flush_orchard<P, CL, R>(
    wdb: &mut zcash_client_sqlite::WalletDb<zcash_client_sqlite::SqlTransaction<'_>, P, CL, R>,
    tree: &mut OrchardSparseTree,
) -> Result<(), SqliteClientError>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (remove, add) = tree.store().checkpoint_delta();
    let mut shards = Vec::with_capacity(tree.store().dirty_shards.len());
    for idx in &tree.store().dirty_shards {
        shards.push(tree.store().shards.get(idx).cloned().ok_or_else(|| {
            ShardTreeError::Storage(
                zcash_client_sqlite::wallet::commitment_tree::Error::Serialization(
                    std::io::Error::other(format!("dirty shard {idx} missing from memory")),
                ),
            )
        })?);
    }
    let cap = tree.store().cap_dirty.then(|| tree.store().cap.clone());
    wdb.put_orchard_shards(&shards, cap.as_ref(), &remove, &add)?;
    // [B6, flush half] Persist retained-anchor marks for the added checkpoints — see the
    // flush_sapling comment for the full reasoning; same transaction, add-delta only.
    let marks: Vec<BlockHeight> = add
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| tree.store().retained.contains(h))
        .collect();
    if !marks.is_empty() {
        wdb.with_orchard_tree_mut::<_, _, SqliteClientError>(|db_tree| {
            for h in &marks {
                db_tree.ensure_retained(*h)?;
            }
            Ok(())
        })?;
    }
    let store = tree.store_mut();
    store.db_checkpoints = store.checkpoints.clone();
    // NOTE: do NOT insert dirty shard indices into db_shard_indices here.
    // See flush_sapling comment — same reasoning applies.
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}

// [IW-2c] Ironwood mirror of flush_orchard, over `with_ironwood_tree_mut`.
fn flush_ironwood<P, CL, R>(
    wdb: &mut zcash_client_sqlite::WalletDb<zcash_client_sqlite::SqlTransaction<'_>, P, CL, R>,
    tree: &mut IronwoodSparseTree,
) -> Result<(), SqliteClientError>
where
    P: zcash_protocol::consensus::Parameters,
{
    let (remove, add) = tree.store().checkpoint_delta();
    let mut shards = Vec::with_capacity(tree.store().dirty_shards.len());
    for idx in &tree.store().dirty_shards {
        shards.push(tree.store().shards.get(idx).cloned().ok_or_else(|| {
            ShardTreeError::Storage(
                zcash_client_sqlite::wallet::commitment_tree::Error::Serialization(
                    std::io::Error::other(format!("dirty shard {idx} missing from memory")),
                ),
            )
        })?);
    }
    let cap = tree.store().cap_dirty.then(|| tree.store().cap.clone());
    wdb.put_ironwood_shards(&shards, cap.as_ref(), &remove, &add)?;
    // [B6, flush half] Persist retained-anchor marks for the added checkpoints — see the
    // flush_sapling comment for the full reasoning; same transaction, add-delta only.
    let marks: Vec<BlockHeight> = add
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| tree.store().retained.contains(h))
        .collect();
    if !marks.is_empty() {
        wdb.with_ironwood_tree_mut::<_, _, SqliteClientError>(|db_tree| {
            for h in &marks {
                db_tree.ensure_retained(*h)?;
            }
            Ok(())
        })?;
    }
    let store = tree.store_mut();
    store.db_checkpoints = store.checkpoints.clone();
    // NOTE: do NOT insert dirty shard indices into db_shard_indices here.
    // See flush_sapling comment — same reasoning applies.
    store.dirty_shards.clear();
    store.cap_dirty = false;
    Ok(())
}

/// Upstream-equivalent put_blocks with in-memory tree accumulation.
/// The rows stage IS upstream's `put_blocks_rows` (#2586 extraction; #2604 moved
/// the nullifier-tracking floor inside it); the tree stage substitutes the tree
/// target (SparseShardStore vs SqliteShardStore) and flushes the dirty tree
/// delta inside the same transaction.
#[allow(clippy::too_many_lines)]
// sapling::Note / orchard::Note do not implement Copy; clippy false-positive on .clone()
#[allow(clippy::clone_on_copy)]
pub fn sparse_put_blocks(
    inner: &mut Db,
    sparse: &mut SparseTreeState,
    from_state: &ChainState,
    blocks: Vec<ScannedBlock<<Db as WalletRead>::AccountId>>,
) -> Result<(), SqliteClientError> {
    // ll/wallet.rs:245-247.
    let Some(initial_block) = blocks.first() else {
        return Ok(());
    };

    // ── Validation — ll/wallet.rs:249-267 ────────────────────────────────────
    // (usize → u64 is lossless on every supported target; upstream unwraps here.)
    let mut seq = from_state.block_height() + 1 == initial_block.height();
    seq &= from_state.final_sapling_tree().tree_size()
        + initial_block.sapling().commitments().len() as u64
        == u64::from(initial_block.sapling().final_tree_size());
    seq &= from_state.final_orchard_tree().tree_size()
        + initial_block.orchard().commitments().len() as u64
        == u64::from(initial_block.orchard().final_tree_size());
    // [IW-2c] ll/wallet.rs:228-230 — third-pool continuity guard.
    seq &= from_state.final_ironwood_tree().tree_size()
        + initial_block.ironwood().commitments().len() as u64
        == u64::from(initial_block.ironwood().final_tree_size());
    if !seq {
        return Err(SqliteClientError::from(PutBlocksError::<
            SqliteClientError,
            zcash_client_sqlite::wallet::commitment_tree::Error,
        >::NonSequentialBlocks {
            prev_height: from_state.block_height(),
            block_height: initial_block.height(),
        }));
    }

    // Seed per-range trees lazily (first chunk of the range), then destructure
    // once — disjoint &mut borrows for the transactionally closure, no expect().
    if sparse.sapling.is_none() {
        sparse.sapling = Some(seed_sapling(
            inner,
            from_state,
            sparse.anchor_retention.as_ref(),
        )?);
    }
    if sparse.orchard.is_none() {
        sparse.orchard = Some(seed_orchard(
            inner,
            from_state,
            sparse.anchor_retention.as_ref(),
        )?);
    }
    if sparse.ironwood.is_none() {
        sparse.ironwood = Some(seed_ironwood(
            inner,
            from_state,
            sparse.anchor_retention.as_ref(),
        )?);
    }
    let gpu_on = sparse.gpu_subtree;
    let batch_on = sparse.batch_combine;
    // [B6] Copy the retention floor out before the split-borrow: every downgrade
    // site and the per-lane ensure_retained calls key on it.
    let anchor_floor = sparse.anchor_retention.as_ref();
    let SparseTreeState {
        sapling: Some(sap_tree),
        orchard: Some(orch_tree),
        ironwood: Some(iw_tree),
        census_sapling,
        census_orchard,
        graft,
        graft_verdict_totals,
        ..
    } = sparse
    else {
        return Err(SqliteClientError::CorruptedData(
            "sparse tree state missing after seed".into(),
        ));
    };

    // ── v0.4 Plan A pre-txn phase (Task 7b rev 2) — graft-ON lanes only ────────
    // Borrow-extract this call's per-pool streams + note positions, feed the
    // accumulators, persist Buffer rows on the side connection (the main txn is
    // not open yet — no lock conflict; ordering+idempotency per graft.rs), and
    // hand the closure a build plan. `None` plans = today's path verbatim.
    let (sap_plan, orch_plan, graft_cleanup) = if let Some(ctx) = graft.as_mut() {
        let sap_start_u64 = from_state.final_sapling_tree().tree_size();
        let orch_start_u64 = from_state.final_orchard_tree().tree_size();
        let mut sap_stream = vec![];
        let mut orch_stream = vec![];
        let mut sap_notes = vec![];
        let mut orch_notes = vec![];
        for block in &blocks {
            sap_stream.extend(block.sapling().commitments().iter().cloned());
            orch_stream.extend(block.orchard().commitments().iter().cloned());
            for wtx in block.transactions() {
                sap_notes.extend(
                    wtx.sapling_outputs()
                        .iter()
                        .map(|o| u64::from(o.note_commitment_tree_position())),
                );
                orch_notes.extend(
                    wtx.orchard_outputs()
                        .iter()
                        .map(|o| u64::from(o.note_commitment_tree_position())),
                );
            }
        }
        let sp = plan_pool(
            &ctx.conn,
            ctx.verify_sample,
            &mut ctx.acc_sapling,
            ShieldedPool::Sapling,
            sap_start_u64,
            sap_stream,
            &sap_notes,
            |s| sap_tree.store().shard_has_interior(s),
            |s| {
                inner
                    .get_sapling_subtree_root(s)
                    .map_err(SqliteClientError::CommitmentTree)
            },
            anchor_floor,
        )?;
        let op = plan_pool(
            &ctx.conn,
            ctx.verify_sample,
            &mut ctx.acc_orchard,
            ShieldedPool::Orchard,
            orch_start_u64,
            orch_stream,
            &orch_notes,
            |s| orch_tree.store().shard_has_interior(s),
            |s| {
                inner
                    .get_orchard_subtree_root(s)
                    .map_err(SqliteClientError::CommitmentTree)
            },
            anchor_floor,
        )?;
        let cleanup = (sp.cleanup_shards.clone(), op.cleanup_shards.clone());
        let verdicts = (
            (sp.grafts.len() as u64, sp.fallbacks),
            (op.grafts.len() as u64, op.fallbacks),
        );
        (Some(sp), Some(op), Some((cleanup, verdicts)))
    } else {
        (None, None, None)
    };

    let t_rows = std::time::Instant::now();
    let mut rows_ms = 0u128;
    let mut tree_ms = 0u128;
    let mut sap_tree_ms = 0u128;
    let mut orch_tree_ms = 0u128;
    let mut sap_split = PoolTimers::default();
    let mut orch_split = PoolTimers::default();
    let mut flush_ms = 0u128;
    let mut downgraded = 0u64;

    inner.transactionally::<_, _, SqliteClientError>(|wdb| {
        // ── Rows stage — upstream verbatim (#2586 extraction + #2604 nfskip) ──
        // `put_blocks_rows` persists every row-level artifact (block meta, tx
        // and note rows, spend marking, nullifier tracking with the
        // frontier-gated below-window skip that #2604 moved upstream,
        // transparent gap addresses, and the trailing-window prune) and returns
        // exactly what the tree stage needs. GapLimits: the engine opens
        // `WalletDb` without `with_gap_limits`, so `default()` is the same
        // value upstream's own `put_blocks` passes; thread the configured
        // value through here if the engine ever customizes gap limits.
        let rows = put_blocks_rows::<
            _,
            SqliteClientError,
            zcash_client_sqlite::wallet::commitment_tree::Error,
        >(wdb, GapLimits::default(), from_state, blocks)
        .map_err(SqliteClientError::from)?;
        rows_ms = t_rows.elapsed().as_millis();

        let mut sapling_commitments = rows.sapling_commitments;
        let mut orchard_commitments = rows.orchard_commitments;
        let mut ironwood_commitments = rows.ironwood_commitments;
        let note_positions = rows.note_positions;
        let last_scanned_height = rows.last_scanned_height;

        if let Some(last_scanned_height) = last_scanned_height {
            let t_tree = std::time::Instant::now();

            // ── T6.3b checkpoint downgrade — cross-pool dependency boundary ───
            // The two cp_pos maps MUST be computed serially before the per-pool
            // pipeline: ensure_checkpoints is CROSS-POOL (missing_sapling uses
            // orchard_cp_pos.keys(); missing_orchard uses sapling_cp_pos.keys()).
            // Both maps come from immutable commitment slices so the two
            // stream_checkpoint_positions calls are independent, but their results
            // must both exist before we can compute the cross-pool ensure-heights.
            // Everything below (downgrade → build_subtrees → insert_frontier →
            // insert_tree loops → ensure_add) is fully per-pool and runs in
            // parallel via rayon::join.
            //
            // Full (pre-downgrade) checkpoint position maps, computed straight
            // from the commitment streams. These are EXACTLY the maps upstream's
            // `checkpoint_positions(&subtrees)` would extract (from_iter records
            // every Checkpoint retention as id → position, shardtree
            // batch.rs:204) — but they must be taken BEFORE the downgrade:
            // `ensure_checkpoints` below needs upstream-identical inputs, since
            // a filtered `existing` map would remap an ensure-height whose
            // nearest own-pool checkpoint lies below the cutoff onto the
            // frontier position instead of that checkpoint's position.
            // Deep-history batches carry no per-block checkpoints at all — see
            // DEEP_HISTORY_CHECKPOINT_MARGIN for the full why (the
            // sandblasting-era prune-into-root-only-leaf panic) and the
            // upstream-equivalence argument. Dooming the stream BEFORE the
            // cp_pos extraction starves the entire pipeline consistently:
            // empty maps → ensure_checkpoints adds nothing → no store
            // checkpoints → nothing for prune_excess_checkpoints to evict
            // into an unmaterialized (buffered/root-only) shard.
            let deep_history = wdb.chain_height()?.is_some_and(|tip| {
                last_scanned_height + DEEP_HISTORY_CHECKPOINT_MARGIN < tip
            });
            if deep_history {
                let doom_all = BlockHeight::from(u32::MAX);
                downgrade_doomed_checkpoints(&mut sapling_commitments, doom_all, anchor_floor);
                downgrade_doomed_checkpoints(&mut orchard_commitments, doom_all, anchor_floor);
                // [IW-2c] third pool dooms with the others — the deep-history
                // starvation argument is pool-independent.
                downgrade_doomed_checkpoints(&mut ironwood_commitments, doom_all, anchor_floor);
            }

            let sapling_cp_pos = stream_checkpoint_positions(
                Position::from(from_state.final_sapling_tree().tree_size()),
                &sapling_commitments,
            );
            let orchard_cp_pos = stream_checkpoint_positions(
                Position::from(from_state.final_orchard_tree().tree_size()),
                &orchard_commitments,
            );
            // [IW-2c] third pool's checkpoint positions.
            let ironwood_cp_pos = stream_checkpoint_positions(
                Position::from(from_state.final_ironwood_tree().tree_size()),
                &ironwood_commitments,
            );

            // ll/wallet.rs:484-501 — cross-pool checkpoint reconciliation, on
            // the FULL pre-downgrade maps (upstream-identical). Computed here,
            // before the per-pool parallel section, because each pool's
            // ensure_checkpoints call needs the OTHER pool's cp_pos map.
            // The `height > min_cp` filter in the add loops below keeps the
            // surviving add-set identical to upstream's: with the downgrade, the
            // post-insert min checkpoint id equals upstream's post-prune min (the
            // cutoff computation above is that same retained-set minimum), so
            // only ids ≥ cutoff can reach the checkpoint tables.
            // [IW-2c] ll/wallet.rs:496-517 — three-way: each pool ensures at the
            // OTHER TWO pools' checkpoint heights so anchors align across trees.
            //
            // [B6-fix, field-caught 2026-08-01] This set is TWO obligations, and
            // this lane long carried only the first. The second — every height
            // `anchor_retention` retains in this batch's range — is what makes a
            // ZIP 318 boundary exist at all: scanning checkpoints a block at its
            // LAST note commitment, so a grid boundary landing on a block with no
            // shielded output in any pool is not supplied by the cross-pool union
            // either, and `ensure_retained` (which this lane does call, six times
            // over) only PROMISES to preserve a checkpoint — it never creates one.
            // The engine therefore marked boundary heights that never materialized,
            // and every committed migration transfer anchored to one was permanently
            // unprovable: `prove_transfer` -> AnchorNotFound -> transient defer ->
            // retried forever. Invisible to the dual-path byte-equality seals, too,
            // since a missing checkpoint at a commitment-free height changes no shard
            // bytes. `batch_ensure_heights` is upstream's composition of both, so
            // this lane can no longer half-implement the rule.
            let [ensure_sapling, ensure_orchard, ensure_ironwood] = batch_ensure_heights(
                &sapling_cp_pos.keys().copied().collect(),
                &orchard_cp_pos.keys().copied().collect(),
                &ironwood_cp_pos.keys().copied().collect(),
                anchor_floor,
                from_state.block_height() + 1..=last_scanned_height,
            );
            let missing_sapling = ensure_checkpoints(
                ensure_sapling.iter(),
                &sapling_cp_pos,
                from_state.final_sapling_tree(),
            );
            let missing_orchard = ensure_checkpoints(
                ensure_orchard.iter(),
                &orchard_cp_pos,
                from_state.final_orchard_tree(),
            );
            let missing_ironwood = ensure_checkpoints(
                ensure_ironwood.iter(),
                &ironwood_cp_pos,
                from_state.final_ironwood_tree(),
            );

            // ── T6.8 parallel per-pool tree work ──────────────────────────────
            // sapling and orchard operate on completely disjoint state:
            //   - separate SparseShardStore/ShardTree fields (sap_tree / orch_tree)
            //   - separate commitment Vecs (sapling_commitments / orchard_commitments)
            //   - pre-computed, pool-independent ensure-checkpoint Vecs above
            // rayon::join uses work-stealing from the global pool; nested rayon
            // is safe (upstream's build_subtrees already uses par_chunks internally).
            // Each side returns Result — both results are checked after join
            // (no unwrap/expect).
            //
            // Cutoff per pool, per put_blocks call: the minimum of the newest
            // SPARSE_CHECKPOINT_WINDOW checkpoint ids that will exist at the end
            // of this call (already-stored ids ∪ the frontier id ∪ this batch's
            // new ids) — i.e. exactly the post-prune retained set upstream's
            // iterative oldest-first pruning leaves behind. Every Checkpoint
            // retention below it is doomed and gets downgraded to the residue
            // prune_excess_checkpoints would leave anyway (Marked survives the
            // CHECKPOINT-flag clear; everything else becomes Ephemeral).
            let frontier_id = from_state.block_height();

            // Capture immutable per-pool inputs before the split-borrow.
            let sap_start = Position::from(from_state.final_sapling_tree().tree_size());
            let orch_start = Position::from(from_state.final_orchard_tree().tree_size());
            let sap_frontier = from_state.final_sapling_tree().clone();
            let orch_frontier = from_state.final_orchard_tree().clone();
            // [IW-2c] third-pool captures.
            let iw_start = Position::from(from_state.final_ironwood_tree().tree_size());
            let iw_frontier = from_state.final_ironwood_tree().clone();
            let frontier_checkpoint_id = frontier_id;

            // v0.4 census (spec §3.2): record shard touches + owned-note shards for
            // this call BEFORE the per-pool parallel section (serial, trivial cost).
            census_sapling.feed(
                u64::from(sap_start),
                sapling_commitments.len() as u64,
                note_positions
                    .iter()
                    .filter(|(p, _)| *p == zcash_protocol::ShieldedPool::Sapling)
                    .map(|(_, pos)| u64::from(*pos)),
            );
            census_orchard.feed(
                u64::from(orch_start),
                orchard_commitments.len() as u64,
                note_positions
                    .iter()
                    .filter(|(p, _)| *p == zcash_protocol::ShieldedPool::Orchard)
                    .map(|(_, pos)| u64::from(*pos)),
            );

            fn map_sparse_err<E: std::fmt::Debug>(e: E) -> SqliteClientError {
                SqliteClientError::CorruptedData(format!("sparse tree: {e:?}"))
            }

            // v0.6 P4c: run the per-pool join in the lane's OWN small pool.
            // On the shared global pool the join's tasks queue behind the scan's
            // DH saturation — measured on the A18 as ~20 s of tree_join wall
            // over ~6.5 s of real work (and it GREW when the rows fix freed the
            // lane: the bottleneck moved from disk to queueing). `install`
            // scopes nested rayon too (upstream `build_subtrees`' par_chunks +
            // the batch-affine combine), so the whole tree pipeline stops
            // waiting on the scanner. This removes a priority-inversion
            // artifact rather than adding parallelism: the lane's real work is
            // small and already off the critical path — it just needs to RUN.
            let join_pools = || rayon::join(
                || -> Result<(u64, PoolTimers, (u64, u64)), SqliteClientError> {
                    let t_pool = std::time::Instant::now();
                    let mut timers = PoolTimers::default();
                    // Task 10: pull the audit list out before the plan is consumed.
                    let (sap_plan, sap_verify_roots) = match sap_plan {
                        Some(mut plan) => {
                            let v = std::mem::take(&mut plan.verify_roots);
                            (Some(plan), v)
                        }
                        None => (None, vec![]),
                    };
                    // Downgrade doomed checkpoints (T6.3b).
                    let t = std::time::Instant::now();
                    let sap_cutoff = doomed_checkpoint_cutoff(
                        sap_tree.store().checkpoints.keys().copied(),
                        frontier_id,
                        sapling_cp_pos.keys().copied(),
                    );
                    let mut sap_downgraded = match (&sap_plan, sap_cutoff) {
                        // Plan mode: the closure's own stream is never built —
                        // segments get their downgrade below.
                        (Some(_), _) | (None, None) => 0,
                        (None, Some(cutoff)) => {
                            downgrade_doomed_checkpoints(&mut sapling_commitments, cutoff, anchor_floor)
                        }
                    };
                    timers.downgrade_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:466-481 — build subtrees (rayon par_chunks, same chunk size).
                    // v0.4 plan mode: build the accumulator's contiguous SEGMENTS instead
                    // (current-chunk spans + carried prefixes; graft-OFF path unchanged).
                    let t = std::time::Instant::now();
                    let sapling_subtrees = match sap_plan {
                        None => build_subtrees::<_, SAPLING_SHARD_HEIGHT>(sap_start, &mut sapling_commitments, BUILD_CHUNK_SIZE),
                        Some(plan) => {
                            let mut out = vec![];
                            for (seg_start, mut rows) in plan.segments {
                                if let Some(cutoff) = sap_cutoff {
                                    sap_downgraded += downgrade_doomed_checkpoints(&mut rows, cutoff, anchor_floor);
                                }
                                out.extend(build_subtrees::<_, SAPLING_SHARD_HEIGHT>(seg_start, &mut rows, BUILD_CHUNK_SIZE));
                            }
                            // Task 8 installs: upstream's own root-only shape
                            // (put_shard_roots, commitment_tree.rs:1105) — put_shard
                            // replaces any partial content (frontier remnants) wholesale.
                            for (idx, root) in plan.grafts {
                                let located = LocatedTree::from_parts(
                                    Address::from_parts(Level::from(SAPLING_SHARD_HEIGHT), idx),
                                    Tree::leaf((root, RetentionFlags::EPHEMERAL)),
                                )
                                .map_err(|addr| {
                                    SqliteClientError::CorruptedData(format!(
                                        "graft install: bad shard address {addr:?}"
                                    ))
                                })?;
                                sap_tree.store_mut().put_shard(located).map_err(map_sparse_err)?;
                            }
                            out
                        }
                    };
                    timers.build_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:503-537 update_tree — IN MEMORY (the substitution).
                    let t = std::time::Instant::now();
                    sap_tree
                        .insert_frontier(
                            sap_frontier,
                            Retention::Checkpoint {
                                id: frontier_checkpoint_id,
                                marking: Marking::Reference,
                            },
                        )
                        .map_err(map_sparse_err)?;
                    // [B6] upstream update_tree: retain the frontier checkpoint when it
                    // lands on the anchor grid, and each subtree's anchor-grid heights.
                    if should_retain_anchor(anchor_floor, frontier_checkpoint_id) {
                        sap_tree.ensure_retained(frontier_checkpoint_id).map_err(map_sparse_err)?;
                    }
                    timers.frontier_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    for (subtree, checkpoints) in sapling_subtrees {
                        // [B6] PRE-register the anchors: shardtree's excess-checkpoint
                        // prune runs INSIDE insert_tree, so retaining after the insert
                        // loses anchors that age out within one 10k-block call (the
                        // ShardStore contract explicitly allows recording an id before
                        // its checkpoint exists). Upstream retains after — safe there
                        // only because its tip-time batches are small.
                        for h in checkpoints
                            .keys()
                            .copied()
                            .filter(|h| should_retain_anchor(anchor_floor, *h))
                        {
                            sap_tree.ensure_retained(h).map_err(map_sparse_err)?;
                        }
                        sap_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                    }
                    timers.insert_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    let min_cp = sap_tree
                        .store()
                        .min_checkpoint_id()
                        .map_err(map_sparse_err)?
                        .ok_or_else(|| SqliteClientError::CorruptedData(
                            "no sapling checkpoint after insert_frontier".into(),
                        ))?;
                    for (height, checkpoint) in missing_sapling {
                        if height > min_cp {
                            sap_tree
                                .store_mut()
                                .add_checkpoint(height, checkpoint)
                                .map_err(map_sparse_err)?;
                        }
                    }
                    timers.ensure_ms = t.elapsed().as_millis();
                    // Task 10 audit: sampled grafts were built + inserted above —
                    // recompute each audited shard's root and compare to the server's.
                    let mut sap_audit = (0u64, 0u64); // (verified, mismatched)
                    for (idx, server_root) in &sap_verify_roots {
                        let addr = Address::from_parts(Level::from(SAPLING_SHARD_HEIGHT), *idx);
                        let end = Position::from((idx + 1) << 16);
                        match sap_tree.store().get_shard(addr) {
                            Ok(Some(shard)) => match shard.root_hash(end) {
                                Ok(computed) if &computed == server_root => sap_audit.0 += 1,
                                Ok(_) => {
                                    sap_audit.1 += 1;
                                    tracing::error!(
                                        shard = idx,
                                        "GRAFT AUDIT MISMATCH (sapling): server root != computed — built content installed, server suspect"
                                    );
                                }
                                Err(_) => tracing::warn!(shard = idx, "graft audit inconclusive (sapling): shard incomplete"),
                            },
                            _ => tracing::warn!(shard = idx, "graft audit: sapling shard missing post-insert"),
                        }
                    }
                    timers.total_ms = t_pool.elapsed().as_millis();
                    Ok((sap_downgraded, timers, sap_audit))
                },
                || -> Result<(u64, PoolTimers, (u64, u64)), SqliteClientError> {
                    let t_pool = std::time::Instant::now();
                    let mut timers = PoolTimers::default();
                    let (orch_plan, orch_verify_roots) = match orch_plan {
                        Some(mut plan) => {
                            let v = std::mem::take(&mut plan.verify_roots);
                            (Some(plan), v)
                        }
                        None => (None, vec![]),
                    };
                    // Downgrade doomed checkpoints (T6.3b).
                    let t = std::time::Instant::now();
                    let orch_cutoff = doomed_checkpoint_cutoff(
                        orch_tree.store().checkpoints.keys().copied(),
                        frontier_id,
                        orchard_cp_pos.keys().copied(),
                    );
                    let mut orch_downgraded = match (&orch_plan, orch_cutoff) {
                        (Some(_), _) | (None, None) => 0,
                        (None, Some(cutoff)) => {
                            downgrade_doomed_checkpoints(&mut orchard_commitments, cutoff, anchor_floor)
                        }
                    };
                    timers.downgrade_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:466-481 — build subtrees (rayon par_chunks, same chunk size).
                    // v0.4 plan mode: segments; ALWAYS the CPU path (the banked GPU offload
                    // targets exactly the work grafting removes — combining them is
                    // unsupported and pointless).
                    let t = std::time::Instant::now();
                    let orchard_subtrees = match orch_plan {
                        None => build_orchard_subtrees(gpu_on, batch_on, orch_start, &mut orchard_commitments),
                        Some(plan) => {
                            let mut out = vec![];
                            for (seg_start, mut rows) in plan.segments {
                                if let Some(cutoff) = orch_cutoff {
                                    orch_downgraded += downgrade_doomed_checkpoints(&mut rows, cutoff, anchor_floor);
                                }
                                // Plan B applies to the combines that SURVIVE grafting
                                // (noted/fallback/audit shards) — graft+batch compose.
                                out.extend(build_orchard_subtrees(false, batch_on, seg_start, &mut rows));
                            }
                            for (idx, root) in plan.grafts {
                                let located = LocatedTree::from_parts(
                                    Address::from_parts(Level::from(ORCHARD_SHARD_HEIGHT), idx),
                                    Tree::leaf((root, RetentionFlags::EPHEMERAL)),
                                )
                                .map_err(|addr| {
                                    SqliteClientError::CorruptedData(format!(
                                        "graft install: bad shard address {addr:?}"
                                    ))
                                })?;
                                orch_tree.store_mut().put_shard(located).map_err(map_sparse_err)?;
                            }
                            out
                        }
                    };
                    timers.build_ms = t.elapsed().as_millis();

                    // ll/wallet.rs:503-537 update_tree — IN MEMORY (the substitution).
                    let t = std::time::Instant::now();
                    orch_tree
                        .insert_frontier(
                            orch_frontier,
                            Retention::Checkpoint {
                                id: frontier_checkpoint_id,
                                marking: Marking::Reference,
                            },
                        )
                        .map_err(map_sparse_err)?;
                    // [B6] upstream update_tree: retain the frontier checkpoint when it
                    // lands on the anchor grid, and each subtree's anchor-grid heights.
                    if should_retain_anchor(anchor_floor, frontier_checkpoint_id) {
                        orch_tree.ensure_retained(frontier_checkpoint_id).map_err(map_sparse_err)?;
                    }
                    timers.frontier_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    for (subtree, checkpoints) in orchard_subtrees {
                        // [B6] PRE-register the anchors: shardtree's excess-checkpoint
                        // prune runs INSIDE insert_tree, so retaining after the insert
                        // loses anchors that age out within one 10k-block call (the
                        // ShardStore contract explicitly allows recording an id before
                        // its checkpoint exists). Upstream retains after — safe there
                        // only because its tip-time batches are small.
                        for h in checkpoints
                            .keys()
                            .copied()
                            .filter(|h| should_retain_anchor(anchor_floor, *h))
                        {
                            orch_tree.ensure_retained(h).map_err(map_sparse_err)?;
                        }
                        orch_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                    }
                    timers.insert_ms = t.elapsed().as_millis();
                    let t = std::time::Instant::now();
                    let min_cp = orch_tree
                        .store()
                        .min_checkpoint_id()
                        .map_err(map_sparse_err)?
                        .ok_or_else(|| SqliteClientError::CorruptedData(
                            "no orchard checkpoint after insert_frontier".into(),
                        ))?;
                    for (height, checkpoint) in missing_orchard {
                        if height > min_cp {
                            orch_tree
                                .store_mut()
                                .add_checkpoint(height, checkpoint)
                                .map_err(map_sparse_err)?;
                        }
                    }
                    timers.ensure_ms = t.elapsed().as_millis();
                    let mut orch_audit = (0u64, 0u64);
                    for (idx, server_root) in &orch_verify_roots {
                        let addr = Address::from_parts(Level::from(ORCHARD_SHARD_HEIGHT), *idx);
                        let end = Position::from((idx + 1) << 16);
                        match orch_tree.store().get_shard(addr) {
                            Ok(Some(shard)) => match shard.root_hash(end) {
                                Ok(computed) if &computed == server_root => orch_audit.0 += 1,
                                Ok(_) => {
                                    orch_audit.1 += 1;
                                    tracing::error!(
                                        shard = idx,
                                        "GRAFT AUDIT MISMATCH (orchard): server root != computed — built content installed, server suspect"
                                    );
                                }
                                Err(_) => tracing::warn!(shard = idx, "graft audit inconclusive (orchard): shard incomplete"),
                            },
                            _ => tracing::warn!(shard = idx, "graft audit: orchard shard missing post-insert"),
                        }
                    }
                    timers.total_ms = t_pool.elapsed().as_millis();
                    Ok((orch_downgraded, timers, orch_audit))
                },
            );
            let (sap_result, orch_result) = if let Some(pool) = persist_pool() {
                pool.install(join_pools)
            } else {
                join_pools()
            };
            // Propagate errors from both sides after join (no unwrap/expect).
            let (sap_downgraded, sap_timers, sap_audit) = sap_result?;
            let (orch_downgraded, orch_timers, orch_audit) = orch_result?;
            if sap_audit != (0, 0) || orch_audit != (0, 0) {
                info!(
                    sap_verified = sap_audit.0,
                    sap_mismatched = sap_audit.1,
                    orch_verified = orch_audit.0,
                    orch_mismatched = orch_audit.1,
                    "graft audit (this call)"
                );
            }
            // ── [IW-2c] ironwood lane — SERIAL, after the join ────────────────
            // Same pipeline as orchard minus graft/census/GPU: the tree starts
            // at NU6.3 activation (tiny for years), stock lightwalletd serves no
            // ironwood subtree roots, and the build cost is microseconds — a
            // third rayon lane would buy nothing.
            let iw_downgraded = {
                let iw_cutoff = doomed_checkpoint_cutoff(
                    iw_tree.store().checkpoints.keys().copied(),
                    frontier_id,
                    ironwood_cp_pos.keys().copied(),
                );
                let iw_downgraded = match iw_cutoff {
                    None => 0,
                    Some(cutoff) => {
                        downgrade_doomed_checkpoints(&mut ironwood_commitments, cutoff, anchor_floor)
                    }
                };
                let ironwood_subtrees = build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(
                    iw_start,
                    &mut ironwood_commitments,
                    BUILD_CHUNK_SIZE,
                );
                iw_tree
                    .insert_frontier(
                        iw_frontier,
                        Retention::Checkpoint {
                            id: frontier_checkpoint_id,
                            marking: Marking::Reference,
                        },
                    )
                    .map_err(map_sparse_err)?;
                // [B6] same retention as the other lanes.
                if should_retain_anchor(anchor_floor, frontier_checkpoint_id) {
                    iw_tree.ensure_retained(frontier_checkpoint_id).map_err(map_sparse_err)?;
                }
                for (subtree, checkpoints) in ironwood_subtrees {
                    // [B6] PRE-register the anchors: shardtree's excess-checkpoint
                    // prune runs INSIDE insert_tree, so retaining after the insert
                    // loses anchors that age out within one 10k-block call (the
                    // ShardStore contract explicitly allows recording an id before
                    // its checkpoint exists). Upstream retains after — safe there
                    // only because its tip-time batches are small.
                    for h in checkpoints
                        .keys()
                        .copied()
                        .filter(|h| should_retain_anchor(anchor_floor, *h))
                    {
                        iw_tree.ensure_retained(h).map_err(map_sparse_err)?;
                    }
                    iw_tree.insert_tree(subtree, checkpoints).map_err(map_sparse_err)?;
                }
                let min_cp = iw_tree
                    .store()
                    .min_checkpoint_id()
                    .map_err(map_sparse_err)?
                    .ok_or_else(|| SqliteClientError::CorruptedData(
                        "no ironwood checkpoint after insert_frontier".into(),
                    ))?;
                for (height, checkpoint) in missing_ironwood {
                    if height > min_cp {
                        iw_tree
                            .store_mut()
                            .add_checkpoint(height, checkpoint)
                            .map_err(map_sparse_err)?;
                    }
                }
                iw_downgraded
            };

            downgraded = sap_downgraded + orch_downgraded + iw_downgraded;
            sap_tree_ms = sap_timers.total_ms;
            orch_tree_ms = orch_timers.total_ms;
            sap_split = sap_timers;
            orch_split = orch_timers;

            tree_ms = t_tree.elapsed().as_millis();

            // Flush the dirty tree delta + scan-queue update in the SAME txn.
            let t_flush = std::time::Instant::now();
            flush_sapling(wdb, sap_tree)?;
            flush_orchard(wdb, orch_tree)?;
            // [IW-2c] third pool flushes in the SAME txn as the others.
            flush_ironwood(wdb, iw_tree)?;
            // ll/wallet.rs:539-547.
            wdb.notify_scan_complete(
                Range { start: from_state.block_height() + 1, end: last_scanned_height + 1 },
                &note_positions,
            )?;
            flush_ms = t_flush.elapsed().as_millis();
        }
        Ok(())
    })?;

    // v0.4 Plan A: buffer rows for shards built/closed this call are dead now the
    // txn committed. POST-commit on purpose (graft.rs contract): a crash before
    // this point leaves stale rows that the store-has-internals seed rule heals.
    if let (Some(ctx), Some(((sap_cleanup, orch_cleanup), verdicts))) =
        (graft.as_ref(), graft_cleanup)
    {
        for shard in sap_cleanup {
            crate::graft::delete_shard(&ctx.conn, ShieldedPool::Sapling, shard)?;
        }
        for shard in orch_cleanup {
            crate::graft::delete_shard(&ctx.conn, ShieldedPool::Orchard, shard)?;
        }
        let ((sap_grafted, sap_fallback), (orch_grafted, orch_fallback)) = verdicts;
        if sap_grafted + sap_fallback + orch_grafted + orch_fallback > 0 {
            info!(
                sap_grafted,
                sap_fallback, orch_grafted, orch_fallback, "graft verdicts (this call)"
            );
        }
        // v0.4 T10b: cumulative totals — the in-band DID-IT-FIRE signal (final
        // DB bytes can't distinguish graft from build-then-prune).
        graft_verdict_totals.0.0 += sap_grafted;
        graft_verdict_totals.0.1 += sap_fallback;
        graft_verdict_totals.1.0 += orch_grafted;
        graft_verdict_totals.1.1 += orch_fallback;
    }

    // sap_tree_ms/orch_tree_ms are the per-pool closure wall times INSIDE the join:
    // tree_ms ≈ max(sap, orch) when the join truly runs in parallel, ≈ sap + orch when
    // it degenerates to serial (single-thread rayon pool) — this distinguishes
    // "lopsided pools" from "no parallelism" directly in device logs.
    info!(
        rows_ms,
        tree_ms,
        sap_tree_ms,
        orch_tree_ms,
        flush_ms,
        downgraded,
        // [B6] retention observability: the active floor and grid, plus how many
        // anchors the orchard store currently pins (None = retention off).
        anchor_floor = anchor_floor.map(|r| u32::from(r.from_height())),
        anchor_grid = anchor_floor
            .map(|r| {
                r.intervals()
                    .iter()
                    .map(|i| i.block_count().get())
                    .collect::<Vec<_>>()
            })
            .map(|g| format!("{g:?}")),
        retained = orch_tree.store().retained.len(),
        "sparse put_blocks"
    );
    // v0.6 P2: feed the pass-level lane totals (bucket sums across pools).
    lane_stats::record(
        rows_ms as u64,
        tree_ms as u64,
        flush_ms as u64,
        downgraded,
        (sap_split.downgrade_ms + orch_split.downgrade_ms) as u64,
        (sap_split.build_ms + orch_split.build_ms) as u64,
        (sap_split.frontier_ms + orch_split.frontier_ms) as u64,
        (sap_split.insert_ms + orch_split.insert_ms) as u64,
        (sap_split.ensure_ms + orch_split.ensure_ms) as u64,
    );
    // T6.8-L3b sub-attribution: per-pool pipeline split (one line per pool, per chunk).
    // The dominant orchard sub-bucket decides the L3b optimization target.
    info!(
        downgrade_ms = orch_split.downgrade_ms,
        build_ms = orch_split.build_ms,
        frontier_ms = orch_split.frontier_ms,
        insert_ms = orch_split.insert_ms,
        ensure_ms = orch_split.ensure_ms,
        total_ms = orch_split.total_ms,
        "sparse orchard tree split"
    );
    info!(
        downgrade_ms = sap_split.downgrade_ms,
        build_ms = sap_split.build_ms,
        frontier_ms = sap_split.frontier_ms,
        insert_ms = sap_split.insert_ms,
        ensure_ms = sap_split.ensure_ms,
        total_ms = sap_split.total_ms,
        "sparse sapling tree split"
    );
    Ok(())
}

// ── Deliberate variants of upstream helpers (the verbatim replicas were deleted
// when zcash/librustzcash#2586 made the originals pub — see the imports above) ──

/// Orchard subtree build routing. Priority: batch-affine (v0.4 Plan B, always
/// available, ~12× the scalar combine) > GPU offload (banked B0, feature `gpu`)
/// > scalar. Output is byte-identical on every path (lookup_build gate + the
/// > gpu equality test + the engine oracle).
fn build_orchard_subtrees(
    gpu: bool,
    batch: bool,
    start: Position,
    commitments: &mut [Option<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>],
) -> Vec<(
    LocatedPrunableTree<orchard::tree::MerkleHashOrchard>,
    BTreeMap<BlockHeight, Position>,
)> {
    if batch {
        return crate::lookup_build::build_subtrees_lookup::<ORCHARD_SHARD_HEIGHT>(
            crate::batch_sinsemilla::orchard_combine_batch_cpu,
            start,
            commitments,
        );
    }
    #[cfg(feature = "gpu")]
    if gpu {
        return crate::gpu_subtree::build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(start, commitments);
    }
    #[cfg(not(feature = "gpu"))]
    let _ = gpu;
    build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(start, commitments, BUILD_CHUNK_SIZE)
}

/// Equivalent of ll/wallet.rs:1173-1183 `checkpoint_positions`, computed
/// directly from a commitment stream instead of from the built subtrees:
/// `LocatedTree::from_iter` records every `Retention::Checkpoint` it consumes
/// as id → leaf position (shardtree batch.rs:204), and positions are assigned
/// sequentially from the start position — so this map is identical to the one
/// upstream extracts post-build. Needed pre-build so the T6.3b downgrade can
/// run between map extraction and subtree construction.
fn stream_checkpoint_positions<H>(
    start: Position,
    commitments: &[Option<(H, Retention<BlockHeight>)>],
) -> BTreeMap<BlockHeight, Position> {
    commitments
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            c.as_ref().and_then(|(_, retention)| match retention {
                Retention::Checkpoint { id, .. } => Some((*id, start + i as u64)),
                _ => None,
            })
        })
        .collect()
}

/// T6.3b: the cutoff id below which a `Retention::Checkpoint` created in this
/// `sparse_put_blocks` call is doomed — i.e. cannot survive upstream's
/// `prune_excess_checkpoints` (oldest-first removal down to
/// [`SPARSE_CHECKPOINT_WINDOW`] entries, re-run on every `insert_tree` call).
///
/// The retained set at the end of the call is the newest
/// `SPARSE_CHECKPOINT_WINDOW` distinct ids out of (already-stored checkpoint
/// ids ∪ the from_state frontier checkpoint id ∪ this batch's new checkpoint
/// ids); the cutoff is that set's minimum. `None` when the union fits inside
/// the window (nothing is doomed — e.g. sub-100-block batches).
fn doomed_checkpoint_cutoff(
    existing: impl Iterator<Item = BlockHeight>,
    frontier_id: BlockHeight,
    new_ids: impl Iterator<Item = BlockHeight>,
) -> Option<BlockHeight> {
    let mut union: BTreeSet<BlockHeight> = existing.collect();
    union.insert(frontier_id);
    union.extend(new_ids);
    union
        .iter()
        .rev()
        .nth(SPARSE_CHECKPOINT_WINDOW as usize - 1)
        .copied()
}

/// v0.6 P2 (PERF_LEDGER #1's instrument): pass-level persist-lane totals.
/// Process-cumulative cross-thread atomics (the write-behind lane runs the
/// put_blocks closures on its own thread); the engine snapshots at pass start
/// and logs the delta at pass end ("persist lane split") + bench JSON.
/// Bucket sums are ACROSS pools (sap + orch); `tree_join_ms` is the join's
/// wall time (≈ max(pools) when parallel, ≈ sum when serial).
pub mod lane_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    static CALLS: AtomicU64 = AtomicU64::new(0);
    static ROWS_MS: AtomicU64 = AtomicU64::new(0);
    static TREE_JOIN_MS: AtomicU64 = AtomicU64::new(0);
    static FLUSH_MS: AtomicU64 = AtomicU64::new(0);
    static DOWNGRADE_MS: AtomicU64 = AtomicU64::new(0);
    static BUILD_MS: AtomicU64 = AtomicU64::new(0);
    static FRONTIER_MS: AtomicU64 = AtomicU64::new(0);
    static INSERT_MS: AtomicU64 = AtomicU64::new(0);
    static ENSURE_MS: AtomicU64 = AtomicU64::new(0);
    static DOWNGRADED: AtomicU64 = AtomicU64::new(0);
    // v0.6 P4: the rows prologue sub-split.

    #[derive(Debug, Default, Clone, Copy)]
    pub struct Totals {
        pub calls: u64,
        pub rows_ms: u64,
        pub tree_join_ms: u64,
        pub flush_ms: u64,
        pub downgrade_ms: u64,
        pub build_ms: u64,
        pub frontier_ms: u64,
        pub insert_ms: u64,
        pub ensure_ms: u64,
        pub downgraded: u64,
    }

    impl Totals {
        /// This-pass delta against a pass-start snapshot.
        pub fn delta_since(&self, start: &Totals) -> Totals {
            Totals {
                calls: self.calls.saturating_sub(start.calls),
                rows_ms: self.rows_ms.saturating_sub(start.rows_ms),
                tree_join_ms: self.tree_join_ms.saturating_sub(start.tree_join_ms),
                flush_ms: self.flush_ms.saturating_sub(start.flush_ms),
                downgrade_ms: self.downgrade_ms.saturating_sub(start.downgrade_ms),
                build_ms: self.build_ms.saturating_sub(start.build_ms),
                frontier_ms: self.frontier_ms.saturating_sub(start.frontier_ms),
                insert_ms: self.insert_ms.saturating_sub(start.insert_ms),
                ensure_ms: self.ensure_ms.saturating_sub(start.ensure_ms),
                downgraded: self.downgraded.saturating_sub(start.downgraded),
            }
        }
    }

    pub fn totals() -> Totals {
        Totals {
            calls: CALLS.load(Ordering::Relaxed),
            rows_ms: ROWS_MS.load(Ordering::Relaxed),
            tree_join_ms: TREE_JOIN_MS.load(Ordering::Relaxed),
            flush_ms: FLUSH_MS.load(Ordering::Relaxed),
            downgrade_ms: DOWNGRADE_MS.load(Ordering::Relaxed),
            build_ms: BUILD_MS.load(Ordering::Relaxed),
            frontier_ms: FRONTIER_MS.load(Ordering::Relaxed),
            insert_ms: INSERT_MS.load(Ordering::Relaxed),
            ensure_ms: ENSURE_MS.load(Ordering::Relaxed),
            downgraded: DOWNGRADED.load(Ordering::Relaxed),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        rows_ms: u64,
        tree_join_ms: u64,
        flush_ms: u64,
        downgraded: u64,
        downgrade_ms: u64,
        build_ms: u64,
        frontier_ms: u64,
        insert_ms: u64,
        ensure_ms: u64,
    ) {
        CALLS.fetch_add(1, Ordering::Relaxed);
        ROWS_MS.fetch_add(rows_ms, Ordering::Relaxed);
        TREE_JOIN_MS.fetch_add(tree_join_ms, Ordering::Relaxed);
        FLUSH_MS.fetch_add(flush_ms, Ordering::Relaxed);
        DOWNGRADE_MS.fetch_add(downgrade_ms, Ordering::Relaxed);
        BUILD_MS.fetch_add(build_ms, Ordering::Relaxed);
        FRONTIER_MS.fetch_add(frontier_ms, Ordering::Relaxed);
        INSERT_MS.fetch_add(insert_ms, Ordering::Relaxed);
        ENSURE_MS.fetch_add(ensure_ms, Ordering::Relaxed);
        DOWNGRADED.fetch_add(downgraded, Ordering::Relaxed);
    }
}

/// T6.8-L3b sub-attribution: wall-time split of one pool's in-memory tree
/// pipeline inside its rayon::join closure. All values are milliseconds;
/// `total_ms` is the whole-closure wall time (≈ sum of the buckets).
#[derive(Debug, Default, Clone, Copy)]
struct PoolTimers {
    /// `doomed_checkpoint_cutoff` + `downgrade_doomed_checkpoints`.
    downgrade_ms: u128,
    /// `build_subtrees` (upstream's par_chunks subtree construction).
    build_ms: u128,
    /// `insert_frontier`.
    frontier_ms: u128,
    /// The `insert_tree` loop over built subtrees.
    insert_ms: u128,
    /// `min_checkpoint_id` + the missing-checkpoint add loop.
    ensure_ms: u128,
    /// Whole-closure wall time.
    total_ms: u128,
}

/// T6.3b: downgrade doomed checkpoint retentions in place (ids strictly below
/// `cutoff`) to the exact residue upstream's prune cycle would leave on the
/// leaf: clearing the CHECKPOINT flag preserves MARKED and leaves everything
/// else EPHEMERAL (shardtree lib.rs:550-660 + RetentionFlags at
/// prunable.rs:55-67). The from_state frontier insert's checkpoint
/// (`Marking::Reference`, applied by the update_tree mirror, never present in
/// these streams — scanning.rs:777-786 emits only `Marked`/`None` markings)
/// and all ids at/above the cutoff are untouched. Returns the downgrade count.
fn downgrade_doomed_checkpoints<H>(
    commitments: &mut [Option<(H, Retention<BlockHeight>)>],
    cutoff: BlockHeight,
    anchor_retention: Option<&AnchorRetention>,
) -> u64 {
    let mut downgraded = 0u64;
    for slot in commitments.iter_mut().flatten() {
        if let Retention::Checkpoint { id, marking } = &slot.1
            && *id < cutoff
            && !should_retain_anchor(anchor_retention, *id)
        {
            slot.1 = match marking {
                Marking::Marked => Retention::Marked,
                _ => Retention::Ephemeral,
            };
            downgraded += 1;
        }
    }
    downgraded
}

// ── WalletWrite facade ─────────────────────────────────────────────────────────

/// Borrows the real WalletDb + the per-range sparse tree state; passes
/// scan_cached_blocks' put_blocks call to sparse_put_blocks and delegates
/// EVERYTHING else verbatim. Error type = SqliteClientError → upstream error
/// shapes (incl. continuity ScanErrors) are preserved bit-for-bit.
pub struct SparseFacade<'a> {
    pub inner: &'a mut Db,
    pub sparse: &'a mut SparseTreeState,
}

impl WalletRead for SparseFacade<'_> {
    type Error = SqliteClientError;
    type AccountId = <Db as WalletRead>::AccountId;
    type Account = <Db as WalletRead>::Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        self.inner.get_account_ids()
    }
    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.inner.get_account(account_id)
    }
    fn get_derived_account(
        &self,
        derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.inner.get_derived_account(derivation)
    }
    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        self.inner.validate_seed(account_id, seed)
    }
    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        self.inner.seed_relevance_to_derived_accounts(seed)
    }
    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.inner.get_account_for_ufvk(ufvk)
    }
    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        self.inner.list_addresses(account)
    }
    fn find_account_for_address<P: zcash_protocol::consensus::Parameters>(
        &self,
        params: &P,
        address: &zcash_keys::address::Address,
    ) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> {
        self.inner.find_account_for_address(params, address)
    }
    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.inner
            .get_last_generated_address_matching(account, address_filter)
    }
    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.inner.get_account_birthday(account)
    }
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.inner.get_wallet_birthday()
    }
    fn get_wallet_recover_until(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.inner.get_wallet_recover_until()
    }
    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        self.inner.get_wallet_summary(confirmations_policy)
    }
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.inner.chain_height()
    }
    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.inner.get_block_hash(block_height)
    }
    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        self.inner.block_metadata(height)
    }
    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.inner.block_fully_scanned()
    }
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.inner.get_max_height_hash()
    }
    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.inner.block_max_scanned()
    }
    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        self.inner.suggest_scan_ranges()
    }
    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        self.inner.get_target_and_anchor_heights(min_confirmations)
    }
    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.inner.get_tx_height(txid)
    }
    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        self.inner.get_unified_full_viewing_keys()
    }
    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        self.inner.get_memo(note_id)
    }
    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        self.inner.get_transaction(txid)
    }
    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        self.inner.get_sapling_nullifiers(query)
    }
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.inner.get_orchard_nullifiers(query)
    }
    fn get_ironwood_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.inner.get_ironwood_nullifiers(query)
    }
    fn get_transparent_receivers(
        &self,
        account: Self::AccountId,
        include_change: bool,
        include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.inner
            .get_transparent_receivers(account, include_change, include_standalone)
    }
    fn get_ephemeral_transparent_receivers(
        &self,
        account: Self::AccountId,
        exposure_depth: u32,
        exclude_used: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.inner
            .get_ephemeral_transparent_receivers(account, exposure_depth, exclude_used)
    }
    fn get_transparent_balances(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentBalances, Self::Error> {
        self.inner
            .get_transparent_balances(account, target_height, confirmations_policy)
    }
    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        self.inner
            .get_transparent_address_metadata(account, address)
    }
    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.inner.utxo_query_height(account)
    }
    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        self.inner.transaction_data_requests()
    }
    fn get_received_outputs(
        &self,
        txid: TxId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        self.inner
            .get_received_outputs(txid, target_height, confirmations_policy)
    }
}

// Output locking is a `WalletWrite` supertrait rather than part of `WalletWrite` itself;
// the facade holds no lock state of its own, so every method delegates verbatim.
impl OutputLockStore for SparseFacade<'_> {
    type Error = SqliteClientError;
    type AccountId = <Db as WalletRead>::AccountId;

    fn lock_outputs(
        &mut self,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<usize, LockError<Self::Error>> {
        self.inner.lock_outputs(outputs, owner, lock_expiry_height)
    }
    fn unlock_output(&mut self, output: &OutputRef, owner: LockOwner) -> Result<bool, Self::Error> {
        self.inner.unlock_output(output, owner)
    }
    fn clear_locked_outputs(&mut self, account: Self::AccountId) -> Result<usize, Self::Error> {
        self.inner.clear_locked_outputs(account)
    }
    fn get_locked_outputs(&self, account: Self::AccountId) -> Result<Vec<OutputRef>, Self::Error> {
        self.inner.get_locked_outputs(account)
    }
}

impl WalletWrite for SparseFacade<'_> {
    type UtxoRef = <Db as WalletWrite>::UtxoRef;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(<Self as WalletRead>::AccountId, UnifiedSpendingKey), <Self as WalletRead>::Error>
    {
        self.inner
            .create_account(account_name, seed, birthday, key_source)
    }
    fn import_account_hd(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), <Self as WalletRead>::Error> {
        self.inner
            .import_account_hd(account_name, seed, account_index, birthday, key_source)
    }
    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, <Self as WalletRead>::Error> {
        self.inner
            .import_account_ufvk(account_name, unified_key, birthday, purpose, key_source)
    }
    fn delete_account(
        &mut self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.delete_account(account)
    }
    fn get_next_available_address(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, <Self as WalletRead>::Error> {
        self.inner.get_next_available_address(account, request)
    }
    fn get_address_for_index(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, <Self as WalletRead>::Error> {
        self.inner
            .get_address_for_index(account, diversifier_index, request)
    }
    fn update_chain_tip(
        &mut self,
        tip_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        WalletWrite::update_chain_tip(self.inner, tip_height)
    }

    fn prune_scan_queue_below(
        &mut self,
        height: BlockHeight,
        retain_with_priority: Option<zcash_client_backend::data_api::scanning::ScanPriority>,
    ) -> Result<u64, <Self as WalletRead>::Error> {
        WalletWrite::prune_scan_queue_below(self.inner, height, retain_with_priority)
    }

    // THE INTERCEPT.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        sparse_put_blocks(self.inner, self.sparse, from_state, blocks)
    }

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput<<Self as WalletRead>::AccountId>,
    ) -> Result<Self::UtxoRef, <Self as WalletRead>::Error> {
        self.inner.put_received_transparent_utxo(output)
    }
    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<Transaction, <Self as WalletRead>::AccountId>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.store_decrypted_tx(received_tx)
    }
    fn set_tx_trust(
        &mut self,
        txid: TxId,
        trusted: bool,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.set_tx_trust(txid, trusted)
    }
    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<<Self as WalletRead>::AccountId>],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.store_transactions_to_be_sent(transactions)
    }
    fn truncate_to_height(
        &mut self,
        max_height: BlockHeight,
    ) -> Result<BlockHeight, <Self as WalletRead>::Error> {
        self.inner.truncate_to_height(max_height)
    }
    fn truncate_to_chain_state(
        &mut self,
        chain_state: ChainState,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.truncate_to_chain_state(chain_state)
    }
    fn rewind_to_chain_state(
        &mut self,
        chain_state: ChainState,
        reset_account_birthdays: std::collections::HashSet<<Self as WalletRead>::AccountId>,
    ) -> Result<
        (),
        zcash_client_backend::data_api::error::RewindError<
            <Self as WalletRead>::AccountId,
            <Self as WalletRead>::Error,
        >,
    > {
        self.inner
            .rewind_to_chain_state(chain_state, reset_account_birthdays)
    }
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: <Self as WalletRead>::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        self.inner.reserve_next_n_ephemeral_addresses(account_id, n)
    }
    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), <Self as WalletRead>::Error> {
        WalletWrite::set_transaction_status(self.inner, txid, status)
    }
    fn schedule_next_check(
        &mut self,
        address: &TransparentAddress,
        offset_seconds: u32,
    ) -> Result<Option<SystemTime>, <Self as WalletRead>::Error> {
        self.inner.schedule_next_check(address, offset_seconds)
    }
    fn mark_transparent_addresses_exposed(
        &mut self,
        exposures: &[(TransparentAddress, BlockHeight)],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.mark_transparent_addresses_exposed(exposures)
    }
    fn notify_address_checked(
        &mut self,
        request: TransactionsInvolvingAddress,
        as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.inner.notify_address_checked(request, as_of_height)
    }
}

// ── T6.9 L4b: write-behind persistence pipelining ──────────────────────────────
//
// Depth-1 pipeline: chunk N's commit (the EXACT `sparse_put_blocks` logic — rows
// + in-memory tree mutation + flush, one atomic `transactionally` per put_blocks
// call, strictly serial N before N+1) runs on a persist lane while the scan task
// decrypts chunk N+1. With chunk N uncommitted, chunk N+1's `scan_cached_blocks`
// reads the wallet DB — its COMPLETE read surface (recon 2026-06-12, every call
// site cited on the methods below) is served by `WriteBehindFacade` from a
// pending-aware merged view; every read OUTSIDE that surface fails loudly
// (`unvirtualized`) so upstream read-surface drift can never become a silent
// stale read. Tree-state ownership: the per-range `SparseTreeState` lives in the
// `PersistLane` (insert + flush stay together inside each deferred commit); the
// scan side never touches it.

/// Account id alias of the production wallet DB (zcash_client_sqlite AccountUuid).
type DbAccountId = <Db as WalletRead>::AccountId;

/// One deferred persist unit: everything `sparse_put_blocks` needs, captured at
/// `put_blocks` time. `from_state` is the server-provided treestate for this
/// unit's lower boundary (independent of DB state — unaffected by deferral).
pub struct PendingPersist {
    pub from_state: ChainState,
    pub blocks: Vec<ScannedBlock<DbAccountId>>,
    /// First/last block height of the unit (log attribution only).
    pub first_height: u64,
    pub last_height: u64,
}

/// Mirror of upstream `Nullifiers::update_with` for ONE block's worth of deltas
/// (zcash_client_backend-0.23.0/src/scanning.rs:435-464): retain-then-extend,
/// applied per block in block order. Generic so the semantics are unit-testable
/// without `ScannedBlock` values (which are not publicly constructible).
pub(crate) fn apply_nullifier_delta<A: Copy, Nf: PartialEq + Copy>(
    set: &mut Vec<(A, Nf)>,
    spent: &[Nf],
    found: &[(A, Nf)],
) {
    set.retain(|(_, nf)| !spent.contains(nf));
    set.extend_from_slice(found);
}

fn unvirtualized(name: &str) -> SqliteClientError {
    SqliteClientError::CorruptedData(format!(
        "write-behind facade: `{name}` is not part of the scan_cached_blocks read surface \
         (T6.9 recon) — refusing to serve a possibly-stale read while a commit is pending"
    ))
}

/// Pending-aware wallet facade for the write-behind scan path. Holds NO database
/// connection: the four reads `scan_cached_blocks` performs are served from
/// state seeded once per range (under the no-pending barrier) and rolled forward
/// at each `put_blocks` stash — the same in-memory threading upstream itself
/// uses BETWEEN BLOCKS of a single call (chain.rs:652-653), extended across one
/// call boundary.
///
/// Read surface of `scan_cached_blocks` (zcash_client_backend-0.23.0
/// data_api/chain.rs:586-664), enumerated:
/// 1. `get_unified_full_viewing_keys` — chain.rs:603-605. Never changed by
///    `put_blocks` (accounts/UFVKs mutate only via account import/create, which
///    cannot run during a range) → served from a per-range cache. EXACT.
/// 2. `block_metadata(from_height - 1)` — chain.rs:614-620, consumed by
///    `check_hash_continuity` (scanning/compact.rs:191-221: prev-height +
///    prev-hash reorg detection) and `PositionTracker::for_compact_block`
///    (compact.rs:400-516: prior tree sizes). With chunk N pending this row is
///    exactly chunk N's last scanned block → served from the stashed tail via
///    `ScannedBlock::to_block_metadata()` — the IDENTICAL value upstream threads
///    between blocks within one call (chain.rs:653). Any other height = loud error.
/// 3. `get_sapling_nullifiers(NullifierQuery::Unspent)` — via
///    `Nullifiers::unspent`, scanning.rs:360-368 ← chain.rs:623. Served from a
///    running unspent view: seeded from the DB at range start, advanced per
///    stashed block by `apply_nullifier_delta` (upstream's own `update_with`
///    semantics, scanning.rs:435-464 — upstream relies on this equivalence for
///    every multi-block call; the SQLite Unspent query at
///    zcash_client_sqlite-0.21.0 wallet/common.rs:155-189 returns the same set
///    for committed scan output: nf NOT NULL ∧ tx mined ∧ not spent by a mined
///    tx). A note FOUND in pending chunk N is therefore visible to chunk N+1's
///    spend detection. Re-seeded from the DB after every enhancement barrier
///    (enhancement may store full txs that add/spend notes).
/// 4. `get_orchard_nullifiers(NullifierQuery::Unspent)` — same as (3),
///    scanning.rs:366.
///
/// Everything else a `WalletRead`/`WalletWrite` impl must provide is NOT called
/// by `scan_cached_blocks`; each such method returns `unvirtualized` (loud
/// fail-fast, exercised by oracle + darkside suites) instead of an approximate
/// or stale answer.
pub struct WriteBehindFacade {
    ufvks: HashMap<DbAccountId, UnifiedFullViewingKey>,
    /// The single height `block_metadata` is allowed to answer for
    /// (= the next scan call's `from_height - 1`).
    prior_meta_height: BlockHeight,
    /// The metadata at `prior_meta_height` (None = known-absent row, e.g. the
    /// first range after birthday — upstream returns None there too).
    prior_meta: Option<BlockMetadata>,
    sapling_nfs: Vec<(DbAccountId, sapling::Nullifier)>,
    orchard_nfs: Vec<(DbAccountId, orchard::note::Nullifier)>,
    // [IW-6] ironwood nullifiers share the orchard domain but live in their own
    // tracking tables on main; the running view splits accordingly.
    ironwood_nfs: Vec<(DbAccountId, orchard::note::Nullifier)>,
    stash: Option<PendingPersist>,
}

impl WriteBehindFacade {
    /// Seed the virtualized read state from the committed DB. MUST be called
    /// under the no-pending barrier (range start: nothing stashed or in
    /// flight), so the committed DB is the complete wallet state.
    pub fn seed(db: &Db, range_start: u64) -> Result<Self, SqliteClientError> {
        let prior_height = range_start
            .checked_sub(1)
            .and_then(|h| u32::try_from(h).ok())
            .ok_or_else(|| {
                SqliteClientError::CorruptedData(format!(
                    "write-behind facade: invalid range_start {range_start}"
                ))
            })?;
        let prior_meta_height = BlockHeight::from(prior_height);
        Ok(Self {
            ufvks: db.get_unified_full_viewing_keys()?,
            prior_meta_height,
            prior_meta: db.block_metadata(prior_meta_height)?,
            sapling_nfs: db.get_sapling_nullifiers(NullifierQuery::Unspent)?,
            orchard_nfs: db.get_orchard_nullifiers(NullifierQuery::Unspent)?,
            ironwood_nfs: db.get_ironwood_nullifiers(NullifierQuery::Unspent)?,
            stash: None,
        })
    }

    /// Re-read both running nullifier views from the committed DB. MUST be
    /// called under a drained barrier (no stash, no in-flight commit) — used
    /// after enhancement runs, which may store fully-decrypted transactions
    /// that add received notes or mark notes spent outside `put_blocks`.
    /// `prior_meta` and the UFVK cache are deliberately NOT re-read:
    /// enhancement never writes the `blocks` table or the accounts table.
    pub fn reseed_nullifiers(&mut self, db: &Db) -> Result<(), SqliteClientError> {
        if self.stash.is_some() {
            return Err(SqliteClientError::CorruptedData(
                "write-behind facade: reseed_nullifiers with an occupied stash".into(),
            ));
        }
        self.sapling_nfs = db.get_sapling_nullifiers(NullifierQuery::Unspent)?;
        self.orchard_nfs = db.get_orchard_nullifiers(NullifierQuery::Unspent)?;
        self.ironwood_nfs = db.get_ironwood_nullifiers(NullifierQuery::Unspent)?;
        Ok(())
    }

    /// Take the pending unit stashed by the last `put_blocks` call (if any).
    pub fn take_stash(&mut self) -> Option<PendingPersist> {
        self.stash.take()
    }

    #[cfg(test)]
    fn test_new(prior_meta_height: BlockHeight, prior_meta: Option<BlockMetadata>) -> Self {
        Self {
            ufvks: HashMap::new(),
            prior_meta_height,
            prior_meta,
            sapling_nfs: vec![],
            orchard_nfs: vec![],
            ironwood_nfs: vec![],
            stash: None,
        }
    }
}

impl WalletRead for WriteBehindFacade {
    type Error = SqliteClientError;
    type AccountId = DbAccountId;
    type Account = <Db as WalletRead>::Account;

    // ── The virtualized read surface (see struct docs for citations) ──────────
    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        Ok(self.ufvks.clone())
    }
    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        if height == self.prior_meta_height {
            Ok(self.prior_meta)
        } else {
            Err(SqliteClientError::CorruptedData(format!(
                "write-behind facade: block_metadata({height}) outside the virtualized tail (expected {})",
                self.prior_meta_height
            )))
        }
    }
    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => Ok(self.sapling_nfs.clone()),
            NullifierQuery::All => Err(unvirtualized("get_sapling_nullifiers(All)")),
        }
    }
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => Ok(self.orchard_nfs.clone()),
            NullifierQuery::All => Err(unvirtualized("get_orchard_nullifiers(All)")),
        }
    }
    fn get_ironwood_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        match query {
            NullifierQuery::Unspent => Ok(self.ironwood_nfs.clone()),
            NullifierQuery::All => Err(unvirtualized("get_ironwood_nullifiers(All)")),
        }
    }

    // ── Outside the scan read surface: fail loudly, never approximate ─────────
    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        Err(unvirtualized("get_account_ids"))
    }
    fn get_account(
        &self,
        _account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Err(unvirtualized("get_account"))
    }
    fn get_derived_account(
        &self,
        _derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Err(unvirtualized("get_derived_account"))
    }
    fn validate_seed(
        &self,
        _account_id: Self::AccountId,
        _seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        Err(unvirtualized("validate_seed"))
    }
    fn seed_relevance_to_derived_accounts(
        &self,
        _seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        Err(unvirtualized("seed_relevance_to_derived_accounts"))
    }
    fn get_account_for_ufvk(
        &self,
        _ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        Err(unvirtualized("get_account_for_ufvk"))
    }
    fn list_addresses(&self, _account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        Err(unvirtualized("list_addresses"))
    }
    fn find_account_for_address<P: zcash_protocol::consensus::Parameters>(
        &self,
        _params: &P,
        _address: &zcash_keys::address::Address,
    ) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> {
        Err(FindAccountForAddressError::Backend(unvirtualized(
            "find_account_for_address",
        )))
    }
    fn get_last_generated_address_matching(
        &self,
        _account: Self::AccountId,
        _address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        Err(unvirtualized("get_last_generated_address_matching"))
    }
    fn get_account_birthday(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Err(unvirtualized("get_account_birthday"))
    }
    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Err(unvirtualized("get_wallet_birthday"))
    }
    fn get_wallet_recover_until(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Err(unvirtualized("get_wallet_recover_until"))
    }
    fn get_wallet_summary(
        &self,
        _confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        Err(unvirtualized("get_wallet_summary"))
    }
    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        Err(unvirtualized("chain_height"))
    }
    fn get_block_hash(&self, _block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        Err(unvirtualized("get_block_hash"))
    }
    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Err(unvirtualized("block_fully_scanned"))
    }
    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        Err(unvirtualized("get_max_height_hash"))
    }
    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        Err(unvirtualized("block_max_scanned"))
    }
    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        Err(unvirtualized("suggest_scan_ranges"))
    }
    fn get_target_and_anchor_heights(
        &self,
        _min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        Err(unvirtualized("get_target_and_anchor_heights"))
    }
    fn get_tx_height(&self, _txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        Err(unvirtualized("get_tx_height"))
    }
    fn get_memo(&self, _note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        Err(unvirtualized("get_memo"))
    }
    fn get_transaction(&self, _txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        Err(unvirtualized("get_transaction"))
    }
    fn get_transparent_receivers(
        &self,
        _account: Self::AccountId,
        _include_change: bool,
        _include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        Err(unvirtualized("get_transparent_receivers"))
    }
    fn get_ephemeral_transparent_receivers(
        &self,
        _account: Self::AccountId,
        _exposure_depth: u32,
        _exclude_used: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        Err(unvirtualized("get_ephemeral_transparent_receivers"))
    }
    fn get_transparent_balances(
        &self,
        _account: Self::AccountId,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentBalances, Self::Error> {
        Err(unvirtualized("get_transparent_balances"))
    }
    fn get_transparent_address_metadata(
        &self,
        _account: Self::AccountId,
        _address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        Err(unvirtualized("get_transparent_address_metadata"))
    }
    fn utxo_query_height(&self, _account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        Err(unvirtualized("utxo_query_height"))
    }
    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        Err(unvirtualized("transaction_data_requests"))
    }
    fn get_received_outputs(
        &self,
        _txid: TxId,
        _target_height: TargetHeight,
        _confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        Err(unvirtualized("get_received_outputs"))
    }
}

// Outside the virtualized read surface (see the module note above): the write-behind
// facade never serves lock state, so every method fails loudly rather than silently
// answering from the un-merged view.
impl OutputLockStore for WriteBehindFacade {
    type Error = SqliteClientError;
    type AccountId = <Db as WalletRead>::AccountId;

    fn lock_outputs(
        &mut self,
        _outputs: &[OutputRef],
        _owner: LockOwner,
        _lock_expiry_height: BlockHeight,
    ) -> Result<usize, LockError<Self::Error>> {
        Err(LockError::Storage(unvirtualized("lock_outputs")))
    }
    fn unlock_output(
        &mut self,
        _output: &OutputRef,
        _owner: LockOwner,
    ) -> Result<bool, Self::Error> {
        Err(unvirtualized("unlock_output"))
    }
    fn clear_locked_outputs(&mut self, _account: Self::AccountId) -> Result<usize, Self::Error> {
        Err(unvirtualized("clear_locked_outputs"))
    }
    fn get_locked_outputs(&self, _account: Self::AccountId) -> Result<Vec<OutputRef>, Self::Error> {
        Err(unvirtualized("get_locked_outputs"))
    }
}

impl WalletWrite for WriteBehindFacade {
    type UtxoRef = <Db as WalletWrite>::UtxoRef;

    // THE INTERCEPT: stash instead of committing; advance the virtualized reads.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<<Self as WalletRead>::AccountId>>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        // Depth-1 invariant FIRST: an occupied stash means the scan loop failed
        // to submit the previous unit — a loop bug, never tolerated silently.
        if self.stash.is_some() {
            return Err(SqliteClientError::CorruptedData(
                "write-behind facade: put_blocks with an occupied stash — depth-1 invariant violated".into(),
            ));
        }
        // Upstream parity: empty input is a no-op (ll/wallet.rs:245-247).
        let (Some(first), Some(last)) = (blocks.first(), blocks.last()) else {
            return Ok(());
        };
        let first_height = u64::from(u32::from(first.height()));
        let last_height = u64::from(u32::from(last.height()));

        // Advance the virtualized prior-block metadata to this unit's tail —
        // identical to upstream's intra-call threading (chain.rs:653).
        self.prior_meta_height = last.height();
        self.prior_meta = Some(last.to_block_metadata());

        // Advance both running nullifier views per block, in block order
        // (upstream update_with parity: retain spends, then extend with found
        // notes whose nullifiers are known — scanning.rs:435-464).
        for b in &blocks {
            let sap_spent: Vec<sapling::Nullifier> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.sapling_spends().iter().map(|s| *s.nf()))
                .collect();
            let sap_found: Vec<(<Self as WalletRead>::AccountId, sapling::Nullifier)> = b
                .transactions()
                .iter()
                .flat_map(|tx| {
                    tx.sapling_outputs()
                        .iter()
                        .filter_map(|o| o.nf().map(|nf| (*o.account_id(), *nf)))
                })
                .collect();
            apply_nullifier_delta(&mut self.sapling_nfs, &sap_spent, &sap_found);

            let orch_spent: Vec<orchard::note::Nullifier> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.orchard_spends().iter().map(|s| *s.nf()))
                .collect();
            let orch_found: Vec<(<Self as WalletRead>::AccountId, orchard::note::Nullifier)> = b
                .transactions()
                .iter()
                .flat_map(|tx| {
                    tx.orchard_outputs()
                        .iter()
                        .filter_map(|o| o.nf().map(|nf| (*o.account_id(), *nf)))
                })
                .collect();
            apply_nullifier_delta(&mut self.orchard_nfs, &orch_spent, &orch_found);

            // [IW-6] the ironwood view advances from the pool's own accessors.
            let iw_spent: Vec<orchard::note::Nullifier> = b
                .transactions()
                .iter()
                .flat_map(|tx| tx.ironwood_spends().iter().map(|s| *s.nf()))
                .collect();
            let iw_found: Vec<(<Self as WalletRead>::AccountId, orchard::note::Nullifier)> = b
                .transactions()
                .iter()
                .flat_map(|tx| {
                    tx.ironwood_outputs()
                        .iter()
                        .filter_map(|o| o.nf().map(|nf| (*o.account_id(), *nf)))
                })
                .collect();
            apply_nullifier_delta(&mut self.ironwood_nfs, &iw_spent, &iw_found);
        }

        self.stash = Some(PendingPersist {
            from_state: from_state.clone(),
            blocks,
            first_height,
            last_height,
        });
        Ok(())
    }

    // ── Outside the scan write surface: fail loudly ────────────────────────────
    fn create_account(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(<Self as WalletRead>::AccountId, UnifiedSpendingKey), <Self as WalletRead>::Error>
    {
        Err(unvirtualized("create_account"))
    }
    fn import_account_hd(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _account_index: zip32::AccountId,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), <Self as WalletRead>::Error> {
        Err(unvirtualized("import_account_hd"))
    }
    fn import_account_ufvk(
        &mut self,
        _account_name: &str,
        _unified_key: &UnifiedFullViewingKey,
        _birthday: &AccountBirthday,
        _purpose: AccountPurpose,
        _key_source: Option<&str>,
    ) -> Result<Self::Account, <Self as WalletRead>::Error> {
        Err(unvirtualized("import_account_ufvk"))
    }
    fn delete_account(
        &mut self,
        _account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("delete_account"))
    }
    fn get_next_available_address(
        &mut self,
        _account: <Self as WalletRead>::AccountId,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, <Self as WalletRead>::Error> {
        Err(unvirtualized("get_next_available_address"))
    }
    fn get_address_for_index(
        &mut self,
        _account: <Self as WalletRead>::AccountId,
        _diversifier_index: DiversifierIndex,
        _request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, <Self as WalletRead>::Error> {
        Err(unvirtualized("get_address_for_index"))
    }
    fn update_chain_tip(
        &mut self,
        _tip_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("update_chain_tip"))
    }
    fn prune_scan_queue_below(
        &mut self,
        _height: BlockHeight,
        _retain_with_priority: Option<zcash_client_backend::data_api::scanning::ScanPriority>,
    ) -> Result<u64, <Self as WalletRead>::Error> {
        Err(unvirtualized("prune_scan_queue_below"))
    }
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput<<Self as WalletRead>::AccountId>,
    ) -> Result<Self::UtxoRef, <Self as WalletRead>::Error> {
        Err(unvirtualized("put_received_transparent_utxo"))
    }
    fn store_decrypted_tx(
        &mut self,
        _received_tx: DecryptedTransaction<Transaction, <Self as WalletRead>::AccountId>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("store_decrypted_tx"))
    }
    fn set_tx_trust(
        &mut self,
        _txid: TxId,
        _trusted: bool,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("set_tx_trust"))
    }
    fn store_transactions_to_be_sent(
        &mut self,
        _transactions: &[SentTransaction<<Self as WalletRead>::AccountId>],
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("store_transactions_to_be_sent"))
    }
    fn truncate_to_height(
        &mut self,
        _max_height: BlockHeight,
    ) -> Result<BlockHeight, <Self as WalletRead>::Error> {
        Err(unvirtualized("truncate_to_height"))
    }
    fn truncate_to_chain_state(
        &mut self,
        _chain_state: ChainState,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("truncate_to_chain_state"))
    }
    fn rewind_to_chain_state(
        &mut self,
        _chain_state: ChainState,
        _reset_account_birthdays: std::collections::HashSet<<Self as WalletRead>::AccountId>,
    ) -> Result<
        (),
        zcash_client_backend::data_api::error::RewindError<
            <Self as WalletRead>::AccountId,
            <Self as WalletRead>::Error,
        >,
    > {
        Err(
            zcash_client_backend::data_api::error::RewindError::DataSource(unvirtualized(
                "rewind_to_chain_state",
            )),
        )
    }
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        _account_id: <Self as WalletRead>::AccountId,
        _n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        Err(unvirtualized("reserve_next_n_ephemeral_addresses"))
    }
    fn set_transaction_status(
        &mut self,
        _txid: TxId,
        _status: TransactionStatus,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("set_transaction_status"))
    }
    fn schedule_next_check(
        &mut self,
        _address: &TransparentAddress,
        _offset_seconds: u32,
    ) -> Result<Option<SystemTime>, <Self as WalletRead>::Error> {
        Err(unvirtualized("schedule_next_check"))
    }
    fn mark_transparent_addresses_exposed(
        &mut self,
        _exposures: &[(TransparentAddress, BlockHeight)],
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("mark_transparent_addresses_exposed"))
    }
    fn notify_address_checked(
        &mut self,
        _request: TransactionsInvolvingAddress,
        _as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        Err(unvirtualized("notify_address_checked"))
    }
}

// ── Persist lane ───────────────────────────────────────────────────────────────

/// A deferred-commit job: runs against the lane's Db + tree state on a blocking
/// thread. Boxed so lane mechanics (serial order, depth-1 backpressure, error
/// propagation, drain) are unit-testable without `ScannedBlock` values.
pub(crate) type PersistJob =
    Box<dyn FnOnce(&mut Db, &mut SparseTreeState) -> Result<(), SqliteClientError> + Send>;

/// What a finished commit task hands back: lane ownership (Db + tree state)
/// plus the commit's wall time (or its error).
type PersistTaskOutput = (
    Db,
    SparseTreeState,
    Result<std::time::Duration, SqliteClientError>,
);

/// The write-behind persist lane: owns a SECOND `WalletDb` connection to the
/// same wallet file (WAL) and the per-range `SparseTreeState`. Runs at most
/// ONE deferred commit at a time via `spawn_blocking` (ownership ping-pongs
/// through the task — serialization is structural, not advisory).
///
/// Thread-pool isolation: the lane's rayon work runs on the dedicated
/// `persist_pool`, installed at the sap∥orch join inside
/// `sparse_put_blocks` itself (v0.6 P4c/P4d — the policy, sizing, and full
/// A10/A18/Mac evidence live on that fn). Write-behind and inline
/// (write_behind=false) paths both route through it, since the install site
/// is inside the shared commit logic.
///
/// No concurrent-writer hazard by design: while a commit is in flight the scan
/// side performs ZERO database work (all its reads are virtualized by
/// `WriteBehindFacade`), and every other DB user (enhancement, reorg truncate,
/// suggest, summary) runs only behind a `drain()` barrier.
///
/// Failure semantics: a commit error is returned by the NEXT `submit` (or by
/// `drain`), always BEFORE another unit is submitted — the range aborts with
/// the last successful commit fully durable (atomic per-unit transactions).
/// A panic inside a commit task loses the lane connection (`db: None`); any
/// further use errors loudly and the pass fails — the wallet file itself stays
/// consistent (SQLite rolls back the open transaction when the connection drops).
pub struct PersistLane {
    db: Option<Db>,
    sparse: Option<SparseTreeState>,
    /// [B4-16 drain] When attached (production scan path), every deferred commit holds a
    /// [`crate::events::WalletWriterGate`] for its WHOLE life (tree compute + DB txn), so
    /// the FFI stop()/start() drain can wait out an orphan commit that `task.abort()`
    /// cannot cancel — field-caught landing its Scanned-mark AFTER an importAccount's
    /// force-rescan re-queue, and colliding with the next pass's first writes.
    progress: Option<crate::events::ProgressArc>,
    in_flight: Option<tokio::task::JoinHandle<PersistTaskOutput>>,
    /// (first_height, last_height) of the in-flight unit, for log attribution.
    in_flight_span: (u64, u64),
    /// Depth-N write-behind buffer: pending units not yet spawned. At most ONE
    /// runs at a time (`in_flight`); up to `depth` total may be unpersisted
    /// (in_flight + queued) before the scan side blocks at `submit`. Persist stays
    /// serial + in-order, so deepening this NEVER changes the committed `data.db` —
    /// it only lets scan run further ahead, hiding more persist behind scan.
    queue: std::collections::VecDeque<((u64, u64), PersistJob)>,
    /// Max unpersisted units (in_flight + queued) before `submit` blocks the scan
    /// side. 1 = strict depth-1 backpressure (legacy, byte-for-byte identical
    /// behaviour); higher = scan runs further ahead (memory cost: ≤`depth` buffered
    /// units, each ≈ one chunk's scanned blocks + commitments).
    depth: usize,
    /// Σ scan-side blocked time across all awaits (0 ≈ perfect overlap).
    total_wait: std::time::Duration,
    /// Σ commit wall time measured inside the deferred closures.
    total_busy: std::time::Duration,
}

impl PersistLane {
    /// Open the lane's own connection to the (already-migrated) wallet file.
    /// `graft_buffering`: v0.4 Plan A — this range defers note-free shard builds
    /// (Historic ranges with `graft_subtree` on; see SparseTreeState field doc).
    #[allow(clippy::too_many_arguments)] // lane tuning mirrors EngineConfig 1:1
    pub fn open(
        wallet_db_path: &std::path::Path,
        network: crate::network::SlipstreamNetwork,
        depth: usize,
        graft_buffering: bool,
        graft_verify_sample: u32,
        batch_combine: bool,
        anchor_retention: Option<AnchorRetention>,
    ) -> Result<Self, crate::error::SlipstreamError> {
        // [B4-16] Same wait-not-die posture as the main connection (wallet_session.rs): a
        // host write (importAccount landing mid-pass) holding the lock made the lane's
        // deferred commit die with an instant SQLITE_BUSY — a NON-transient pass error.
        // Mirror `for_path` (open + array vtab + wrap) with a 15 s busy_timeout.
        let lane_conn = rusqlite::Connection::open(wallet_db_path).map_err(|e| {
            crate::error::SlipstreamError::Wallet(format!("persist lane open: {e}"))
        })?;
        lane_conn
            .busy_timeout(std::time::Duration::from_secs(15))
            .map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!("persist lane busy_timeout: {e}"))
            })?;
        rusqlite::vtab::array::load_module(&lane_conn).map_err(|e| {
            crate::error::SlipstreamError::Wallet(format!("persist lane array module: {e}"))
        })?;
        let db = zcash_client_sqlite::WalletDb::from_connection(
            lane_conn,
            network,
            zcash_client_sqlite::util::SystemClock,
            rand::rngs::OsRng,
        );
        let graft = if graft_buffering {
            Some(GraftCtx::open(wallet_db_path, graft_verify_sample)?)
        } else {
            None
        };
        let sparse = SparseTreeState {
            graft_buffering,
            graft,
            batch_combine,
            anchor_retention,
            ..Default::default()
        };
        Ok(Self {
            db: Some(db),
            sparse: Some(sparse),
            progress: None,
            in_flight: None,
            in_flight_span: (0, 0),
            queue: std::collections::VecDeque::new(),
            depth: depth.max(1),
            total_wait: std::time::Duration::ZERO,
            total_busy: std::time::Duration::ZERO,
        })
    }

    /// [B4-16 drain] Attach the handle's shared progress so every deferred commit holds
    /// the writer gate for its whole life. The production scan path attaches; oracle and
    /// test drivers (no stop()/start() drain to serve) may skip.
    pub fn attach_writer_gate(&mut self, progress: crate::events::ProgressArc) {
        self.progress = Some(progress);
    }

    pub fn total_wait(&self) -> std::time::Duration {
        self.total_wait
    }

    pub fn total_busy(&self) -> std::time::Duration {
        self.total_busy
    }

    /// v0.4 census (spec §3.2): per-pool shard census accumulated by this lane's
    /// sparse state — (sapling, orchard). Meaningful after `drain()` (lane
    /// quiescent); zeros if the state is checked out mid-commit or never used.
    pub fn census(&self) -> (crate::census::ShardCensus, crate::census::ShardCensus) {
        match &self.sparse {
            Some(s) => (s.census_sapling.clone(), s.census_orchard.clone()),
            None => Default::default(),
        }
    }

    /// v0.4 T10b: cumulative graft verdicts this lane rendered —
    /// ((sap_grafted, sap_fallback), (orch_grafted, orch_fallback)).
    /// Meaningful after `drain()`, same caveats as [`Self::census`].
    pub fn graft_verdict_totals(&self) -> ((u64, u64), (u64, u64)) {
        match &self.sparse {
            Some(s) => s.graft_verdict_totals,
            None => Default::default(),
        }
    }

    /// v0.4 Plan A (Task 7b rev 2): build whatever the graft accumulators still
    /// hold — the range-end / tip shard, which NEVER grafts (accumulator rule 1)
    /// — inside one small transaction, then drop its buffer rows. Call after
    /// `drain()` on the success path only (on error exits the buffered rows stay
    /// for the restart-resume path). Blocking — wrap in `block_in_place`.
    pub fn finish_graft_blocking(&mut self) -> Result<(), crate::error::SlipstreamError> {
        use crate::graft_accumulator::FeedAction;
        let werr = |c: &str, e: String| {
            crate::error::SlipstreamError::Wallet(format!("finish_graft {c}: {e}"))
        };

        let Some(sparse) = self.sparse.as_mut() else {
            return Ok(());
        };
        let SparseTreeState {
            sapling,
            orchard,
            graft: Some(ctx),
            anchor_retention: anchor_floor,
            ..
        } = sparse
        else {
            return Ok(());
        };
        fn take_rows<H>(f: Option<FeedAction<H>>) -> Vec<crate::graft_accumulator::AccRow<H>> {
            match f {
                Some(FeedAction::Build(r)) => r,
                _ => Vec::new(),
            }
        }
        let sap_rows = take_rows(ctx.acc_sapling.as_mut().and_then(|a| a.finish()));
        let orch_rows = take_rows(ctx.acc_orchard.as_mut().and_then(|a| a.finish()));
        if sap_rows.is_empty() && orch_rows.is_empty() {
            return Ok(());
        }
        fn shard_ids<H>(rows: &[crate::graft_accumulator::AccRow<H>]) -> Vec<u64> {
            let mut v: Vec<u64> = rows.iter().map(|r| r.0 >> 16).collect();
            v.dedup();
            v
        }
        let sap_shards = shard_ids(&sap_rows);
        let orch_shards = shard_ids(&orch_rows);

        let (Some(sap_tree), Some(orch_tree)) = (sapling.as_mut(), orchard.as_mut()) else {
            // Rows only exist if put_blocks ran, which seeds the trees first.
            return Err(werr("trees", "finish rows without seeded trees".into()));
        };
        let db = self
            .db
            .as_mut()
            .ok_or_else(|| werr("db", "lane connection lost (prior commit panic)".into()))?;

        // Same doomed-checkpoint policy as every build (fixture-proven, rev 2.1):
        // retentions travel verbatim; the cutoff — computed from existing ids ∪
        // this build's own checkpoint ids (no NEW frontier at finish) — downgrades
        // exactly what upstream's per-chunk pruning would have.
        fn finish_cutoff<H>(
            existing: impl Iterator<Item = BlockHeight>,
            rows: &[Option<(H, Retention<BlockHeight>)>],
        ) -> Option<BlockHeight> {
            let existing: Vec<BlockHeight> = existing.collect();
            let frontier_id = existing.iter().max().copied()?;
            let new_ids = rows.iter().flatten().filter_map(|(_, r)| match r {
                Retention::Checkpoint { id, .. } => Some(*id),
                _ => None,
            });
            doomed_checkpoint_cutoff(existing.iter().copied(), frontier_id, new_ids)
        }
        db.transactionally::<_, _, SqliteClientError>(|wdb| {
            if let Some((seg_start, mut rows)) = rows_to_segment(sap_rows) {
                if let Some(cutoff) =
                    finish_cutoff(sap_tree.store().checkpoints.keys().copied(), &rows)
                {
                    downgrade_doomed_checkpoints(&mut rows, cutoff, anchor_floor.as_ref());
                }
                for (subtree, checkpoints) in build_subtrees::<_, SAPLING_SHARD_HEIGHT>(
                    seg_start,
                    &mut rows,
                    BUILD_CHUNK_SIZE,
                ) {
                    sap_tree.insert_tree(subtree, checkpoints).map_err(|e| {
                        SqliteClientError::CorruptedData(format!("finish sapling insert: {e:?}"))
                    })?;
                }
                flush_sapling(wdb, sap_tree)?;
            }
            if let Some((seg_start, mut rows)) = rows_to_segment(orch_rows) {
                if let Some(cutoff) =
                    finish_cutoff(orch_tree.store().checkpoints.keys().copied(), &rows)
                {
                    downgrade_doomed_checkpoints(&mut rows, cutoff, anchor_floor.as_ref());
                }
                for (subtree, checkpoints) in build_subtrees::<_, ORCHARD_SHARD_HEIGHT>(
                    seg_start,
                    &mut rows,
                    BUILD_CHUNK_SIZE,
                ) {
                    orch_tree.insert_tree(subtree, checkpoints).map_err(|e| {
                        SqliteClientError::CorruptedData(format!("finish orchard insert: {e:?}"))
                    })?;
                }
                flush_orchard(wdb, orch_tree)?;
            }
            Ok(())
        })
        .map_err(|e: SqliteClientError| werr("txn", e.to_string()))?;

        // Post-commit cleanup (ordering contract — crash before this self-heals).
        for shard in sap_shards {
            crate::graft::delete_shard(&ctx.conn, ShieldedPool::Sapling, shard)
                .map_err(|e| werr("cleanup sapling", e.to_string()))?;
        }
        for shard in orch_shards {
            crate::graft::delete_shard(&ctx.conn, ShieldedPool::Orchard, shard)
                .map_err(|e| werr("cleanup orchard", e.to_string()))?;
        }
        info!("graft finish: range-end shards built + buffer cleaned");
        Ok(())
    }

    /// Await the in-flight commit, if any (the full barrier when called alone —
    /// see `drain`). Accounts `persist_wait` (scan-side blocked time) and
    /// `persist_busy` (commit wall time), restores Db + tree ownership to the
    /// lane, and propagates the commit's error.
    async fn await_in_flight(&mut self) -> Result<(), crate::error::SlipstreamError> {
        if let Some(handle) = self.in_flight.take() {
            let (first_height, last_height) = self.in_flight_span;
            let waited = std::time::Instant::now();
            let (db, sparse, result) = handle.await.map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!(
                    "write-behind persist task died (panic/cancel): {e}"
                ))
            })?;
            let persist_wait_ms = waited.elapsed().as_millis();
            self.total_wait += waited.elapsed();
            self.db = Some(db);
            self.sparse = Some(sparse);
            let busy = result.map_err(|e| {
                crate::error::SlipstreamError::Wallet(format!(
                    "write-behind deferred put_blocks [{first_height}..={last_height}]: {e}"
                ))
            })?;
            self.total_busy += busy;
            info!(
                persist_wait_ms,
                persist_busy_ms = busy.as_millis(),
                first_height,
                last_height,
                "write-behind persist awaited"
            );
        }
        Ok(())
    }

    /// Total unpersisted units: the in-flight commit (if any) + the queued ones.
    fn pending_count(&self) -> usize {
        usize::from(self.in_flight.is_some()) + self.queue.len()
    }

    /// Spawn the head of the queue IF the lane is idle. No-op when a commit is
    /// already in flight or the queue is empty. Errors loudly if the lane
    /// connection was lost (poisoned by an earlier panic).
    ///
    /// Rayon isolation happens INSIDE the job (`sparse_put_blocks` installs
    /// [`persist_pool`] at its sap∥orch join) — the closure itself just runs
    /// on the blocking thread.
    fn spawn_next(&mut self) -> Result<(), crate::error::SlipstreamError> {
        if self.in_flight.is_some() {
            return Ok(());
        }
        let Some((span, job)) = self.queue.pop_front() else {
            return Ok(());
        };
        let (Some(mut db), Some(mut sparse)) = (self.db.take(), self.sparse.take()) else {
            return Err(crate::error::SlipstreamError::Wallet(
                "write-behind persist lane unusable (connection lost by an earlier failure)".into(),
            ));
        };
        // [B4-16 drain] Acquired BEFORE the spawn (no window where the commit exists but
        // the counter reads 0) and moved into the closure — held across compute + txn,
        // released by Drop on completion or panic.
        let gate = self
            .progress
            .clone()
            .map(crate::events::WalletWriterGate::hold);
        self.in_flight_span = span;
        let liveness = self.progress.clone();
        self.in_flight = Some(tokio::task::spawn_blocking(move || {
            let _gate = gate;
            let started = std::time::Instant::now();
            let result = job(&mut db, &mut sparse).map(|()| started.elapsed());
            // Liveness: a finished commit is forward progress for the stall clock
            // even though no counter moves.
            if result.is_ok()
                && let Some(p) = &liveness
            {
                p.touch();
            }
            (db, sparse, result)
        }));
        Ok(())
    }

    /// Submit one deferred commit job into the depth-N buffer. Persist stays
    /// serial + IN-ORDER (one commit at a time) — so deepening the buffer never
    /// changes the committed `data.db`. The scan side blocks ONLY once `depth`
    /// units are unpersisted (in_flight + queued). At `depth == 1` this is the
    /// legacy strict depth-1 backpressure: submit(N+1) awaits (and error-propagates)
    /// unit N before spawning N+1 — byte-for-byte identical to the pre-queue lane.
    ///
    /// A commit error aborts the pipeline: the in-flight error is propagated and
    /// the remaining queued units are DROPPED (the range fails; never spawned).
    pub(crate) async fn submit_job(
        &mut self,
        span: (u64, u64),
        job: PersistJob,
    ) -> Result<(), crate::error::SlipstreamError> {
        self.queue.push_back((span, job));
        // Start the next unit immediately if the lane is idle.
        self.spawn_next()?;
        // Backpressure: await + reap + spawn-next until we are at/under `depth`.
        while self.pending_count() > self.depth {
            if let Err(e) = self.await_in_flight().await {
                self.queue.clear();
                return Err(e);
            }
            self.spawn_next()?;
        }
        Ok(())
    }

    /// Submit one pending scan unit: the deferred commit runs the EXACT
    /// `sparse_put_blocks` logic (rows + tree + flush in one transaction).
    pub async fn submit(
        &mut self,
        pending: PendingPersist,
    ) -> Result<(), crate::error::SlipstreamError> {
        let span = (pending.first_height, pending.last_height);
        self.submit_job(
            span,
            Box::new(move |db, sparse| {
                sparse_put_blocks(db, sparse, &pending.from_state, pending.blocks)
            }),
        )
        .await
    }

    /// Full barrier: drain the ENTIRE pending queue (await each in-flight commit,
    /// spawn the next, in order) and propagate the first error. After `drain`
    /// returns Ok, every submitted unit is durably committed — required before
    /// enhancement, reorg recovery, suggest, summary, and at range end. A commit
    /// error drops the remaining queued units and propagates. At `depth == 1` (and
    /// any time ≤1 unit is pending) this is exactly the legacy single await.
    pub async fn drain(&mut self) -> Result<(), crate::error::SlipstreamError> {
        while self.pending_count() > 0 {
            if let Err(e) = self.await_in_flight().await {
                self.queue.clear();
                return Err(e);
            }
            self.spawn_next()?;
        }
        Ok(())
    }
}

// ── Contract tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod store_tests {
    use super::*;
    use incrementalmerkletree::{Address, Hashable as _};
    use zcash_client_backend::data_api::anchor_retention::AnchorRetentionInterval;

    type Store = SparseShardStore<sapling::Node>;

    #[test]
    fn miss_on_unknown_index_is_none_but_known_unloaded_errors() {
        let mut s = Store::new(16);
        let addr9 = Address::from_parts(Level::new(16), 9);
        assert!(matches!(s.get_shard(addr9), Ok(None)));
        s.db_shard_indices.insert(9);
        assert!(matches!(
            s.get_shard(addr9),
            Err(SparseStoreError::NotPreloaded(9))
        ));
    }

    #[test]
    fn put_shard_marks_dirty_and_serves_reads() {
        let mut s = Store::new(16);
        let addr = Address::from_parts(Level::new(16), 3);
        let tree = LocatedPrunableTree::empty(addr);
        s.put_shard(tree).expect("put");
        assert!(s.dirty_shards.contains(&3));
        assert!(matches!(s.get_shard(addr), Ok(Some(_))));
        assert_eq!(
            s.last_shard().expect("last").map(|t| t.root_addr().index()),
            Some(3)
        );
    }

    #[test]
    fn checkpoint_delta_computes_remove_add_change() {
        let mut s = Store::new(16);
        let h = |n: u32| BlockHeight::from(n);
        s.db_checkpoints.insert(h(10), Checkpoint::tree_empty());
        s.db_checkpoints.insert(h(11), Checkpoint::tree_empty());
        s.db_checkpoints
            .insert(h(12), Checkpoint::at_position(Position::from(5u64)));
        // mem: 10 kept identical, 11 removed, 12 changed, 13 added
        s.checkpoints.insert(h(10), Checkpoint::tree_empty());
        s.checkpoints
            .insert(h(12), Checkpoint::at_position(Position::from(7u64)));
        s.checkpoints
            .insert(h(13), Checkpoint::at_position(Position::from(9u64)));
        let (remove, add) = s.checkpoint_delta();
        assert_eq!(remove, vec![h(11), h(12)]);
        let add_ids: Vec<u32> = add.iter().map(|(h, _)| u32::from(*h)).collect();
        assert_eq!(add_ids, vec![12, 13]);
    }

    #[test]
    fn checkpoint_at_depth_matches_desc_offset_semantics() {
        let mut s = Store::new(16);
        for n in [5u32, 7, 9] {
            s.add_checkpoint(BlockHeight::from(n), Checkpoint::tree_empty())
                .unwrap();
        }
        let (id, _) = s.get_checkpoint_at_depth(0).unwrap().unwrap();
        assert_eq!(u32::from(id), 9);
        let (id, _) = s.get_checkpoint_at_depth(2).unwrap().unwrap();
        assert_eq!(u32::from(id), 5);
        assert!(s.get_checkpoint_at_depth(3).unwrap().is_none());
    }

    // ── T6.3b checkpoint-downgrade helpers ─────────────────────────────────────

    fn heights(range: std::ops::RangeInclusive<u32>) -> impl Iterator<Item = BlockHeight> {
        range.map(BlockHeight::from)
    }

    #[test]
    fn doomed_cutoff_none_when_window_not_exceeded() {
        // 50 existing + frontier + 40 new = 91 distinct ids ≤ 100 → nothing doomed.
        let cutoff =
            doomed_checkpoint_cutoff(heights(1..=50), BlockHeight::from(50), heights(51..=90));
        assert_eq!(cutoff, None);
    }

    #[test]
    fn doomed_cutoff_is_upstream_retained_min_for_dense_stream() {
        // 100 existing (heights 1..=100, frontier = 100) + 10_000 new
        // (101..=10_100): upstream retains the newest 100 = 10_001..=10_100,
        // i.e. the controller cutoff last_scanned − (WINDOW − 1).
        let cutoff = doomed_checkpoint_cutoff(
            heights(1..=100),
            BlockHeight::from(100),
            heights(101..=10_100),
        );
        assert_eq!(cutoff, Some(BlockHeight::from(10_001)));
    }

    #[test]
    fn doomed_cutoff_reaches_below_window_for_sparse_stream() {
        // A pool with only 30 new checkpoints: upstream's newest-100 keeps 70
        // older ids alive — the cutoff must NOT be last_scanned − 100.
        let cutoff = doomed_checkpoint_cutoff(
            heights(1..=100),
            BlockHeight::from(100),
            heights(10_071..=10_100),
        );
        // union = {1..=100} ∪ {10_071..=10_100} (130 ids); newest 100 =
        // {31..=100} ∪ {10_071..=10_100} → min = 31.
        assert_eq!(cutoff, Some(BlockHeight::from(31)));
    }

    #[test]
    fn downgrade_maps_marked_to_marked_and_plain_to_ephemeral() {
        let h = |n: u32| BlockHeight::from(n);
        let node = sapling::Node::empty_leaf();
        let mut commitments: Vec<Option<(sapling::Node, Retention<BlockHeight>)>> = vec![
            Some((
                node,
                Retention::Checkpoint {
                    id: h(10),
                    marking: Marking::Marked,
                },
            )),
            Some((
                node,
                Retention::Checkpoint {
                    id: h(11),
                    marking: Marking::None,
                },
            )),
            Some((
                node,
                Retention::Checkpoint {
                    id: h(50),
                    marking: Marking::None,
                },
            )),
            Some((node, Retention::Marked)),
            Some((node, Retention::Ephemeral)),
        ];
        let n = downgrade_doomed_checkpoints(&mut commitments, h(50), None);
        assert_eq!(n, 2);
        assert!(matches!(
            commitments[0].as_ref().unwrap().1,
            Retention::Marked
        ));
        assert!(matches!(
            commitments[1].as_ref().unwrap().1,
            Retention::Ephemeral
        ));
        // id == cutoff survives (only ids strictly below are doomed).
        assert!(matches!(
            commitments[2].as_ref().unwrap().1,
            Retention::Checkpoint { .. }
        ));
        assert!(matches!(
            commitments[3].as_ref().unwrap().1,
            Retention::Marked
        ));
        assert!(matches!(
            commitments[4].as_ref().unwrap().1,
            Retention::Ephemeral
        ));
    }

    /// [B6] The migration crate's durable anchors (288-block grid at or above the
    /// retention floor) must survive the doomed-checkpoint downgrade; the same id
    /// with retention OFF (`None`) or BELOW the floor is doomed like any other.
    #[test]
    fn retained_anchors_survive_checkpoint_downgrade() {
        let h = |n: u32| BlockHeight::from(n);
        let node = sapling::Node::empty_leaf();
        // 1152 and 1440 sit on the 288 grid; 1300 does not.
        let fresh = |ids: &[u32]| -> Vec<Option<(sapling::Node, Retention<BlockHeight>)>> {
            ids.iter()
                .map(|&id| {
                    Some((
                        node,
                        Retention::Checkpoint {
                            id: h(id),
                            marking: Marking::None,
                        },
                    ))
                })
                .collect()
        };

        // Retention ON, floor below the anchors: grid ids survive, off-grid is doomed.
        let zip318 = |floor: u32| AnchorRetention::new(h(floor), AnchorRetentionInterval::ZIP_318);
        let mut commitments = fresh(&[1152, 1300, 1440]);
        let n = downgrade_doomed_checkpoints(&mut commitments, h(2000), Some(&zip318(1000)));
        assert_eq!(n, 1, "only the off-grid checkpoint is doomed");
        assert!(matches!(
            commitments[0].as_ref().unwrap().1,
            Retention::Checkpoint { .. }
        ));
        assert!(matches!(
            commitments[1].as_ref().unwrap().1,
            Retention::Ephemeral
        ));
        assert!(matches!(
            commitments[2].as_ref().unwrap().1,
            Retention::Checkpoint { .. }
        ));

        // Retention OFF: the grid buys nothing — pre-B6 behavior byte-for-byte.
        let mut commitments = fresh(&[1152, 1300, 1440]);
        let n = downgrade_doomed_checkpoints(&mut commitments, h(2000), None);
        assert_eq!(n, 3);

        // Grid id BELOW the floor: retention is not active there — doomed.
        let mut commitments = fresh(&[1152]);
        let n = downgrade_doomed_checkpoints(&mut commitments, h(2000), Some(&zip318(1200)));
        assert_eq!(n, 1);

        // A CONFIGURED grid, not a compiled-in one: under a 12-block interval the
        // off-ZIP-318 height 1300 is itself a boundary and survives. This is what a
        // test network needs, and what a mirrored constant could never express.
        let short = AnchorRetention::new(
            h(1000),
            AnchorRetentionInterval::custom(NonZeroU32::new(12).expect("nonzero")),
        );
        let mut commitments = fresh(&[1152, 1300, 1440]);
        let n = downgrade_doomed_checkpoints(&mut commitments, h(2000), Some(&short));
        assert_eq!(n, 1, "1300 is off the 12-grid; 1152 and 1440 are on it");
        assert!(matches!(
            commitments[1].as_ref().unwrap().1,
            Retention::Ephemeral
        ));
    }

    /// [B6] The predicate delegates to upstream's `AnchorRetention::retains`, so
    /// this engine's surviving anchor set is upstream's by construction rather
    /// than by a mirrored constant that has to be kept in step by hand.
    #[test]
    fn should_retain_anchor_matches_upstream_predicate() {
        let h = |n: u32| BlockHeight::from(n);
        let at = |floor: u32| AnchorRetention::new(h(floor), AnchorRetentionInterval::ZIP_318);
        assert!(should_retain_anchor(Some(&at(1000)), h(1152)));
        assert!(
            should_retain_anchor(Some(&at(1152)), h(1152)),
            "at the floor"
        );
        assert!(!should_retain_anchor(Some(&at(1000)), h(1300)), "off-grid");
        assert!(
            !should_retain_anchor(Some(&at(1200)), h(1152)),
            "below the floor"
        );
        assert!(!should_retain_anchor(None, h(1152)), "retention off");

        // The grid is whatever was configured. 1308 is a 12-block boundary but not
        // a ZIP 318 one, so a host on a shortened test-network grid retains a
        // height the default grid discards — which is the entire point of making
        // the interval configurable rather than mirroring a constant.
        let short = AnchorRetention::new(
            h(1000),
            AnchorRetentionInterval::custom(NonZeroU32::new(12).expect("nonzero")),
        );
        assert!(should_retain_anchor(Some(&short), h(1308)));
        assert!(!should_retain_anchor(Some(&at(1000)), h(1308)));
    }

    #[test]
    fn stream_checkpoint_positions_matches_from_iter_extraction() {
        let h = |n: u32| BlockHeight::from(n);
        let node = sapling::Node::empty_leaf();
        let commitments: Vec<Option<(sapling::Node, Retention<BlockHeight>)>> = vec![
            Some((node, Retention::Ephemeral)),
            Some((
                node,
                Retention::Checkpoint {
                    id: h(7),
                    marking: Marking::None,
                },
            )),
            Some((node, Retention::Marked)),
            Some((
                node,
                Retention::Checkpoint {
                    id: h(8),
                    marking: Marking::Marked,
                },
            )),
        ];
        let map = stream_checkpoint_positions(Position::from(100u64), &commitments);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&h(7)), Some(&Position::from(101u64)));
        assert_eq!(map.get(&h(8)), Some(&Position::from(103u64)));
    }
}

// ── T6.9 write-behind tests ────────────────────────────────────────────────────

#[cfg(test)]
mod write_behind_tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::*;
    use incrementalmerkletree::frontier::Frontier;

    // ── apply_nullifier_delta: upstream update_with parity (scanning.rs:435-464) ──

    #[test]
    fn nullifier_delta_removes_spent_and_adds_found() {
        let mut set: Vec<(u32, [u8; 4])> = vec![(1, *b"aaaa"), (1, *b"bbbb")];
        // Block: spends "aaaa", finds "cccc".
        apply_nullifier_delta(&mut set, &[*b"aaaa"], &[(1, *b"cccc")]);
        assert_eq!(set, vec![(1, *b"bbbb"), (1, *b"cccc")]);
    }

    /// THE pending-spend case: a note FOUND in (pending) chunk N must be
    /// spendable-detectable in chunk N+1 — its nullifier enters the view at the
    /// stash of N (found), and the spend in N+1 removes it.
    #[test]
    fn nullifier_found_in_pending_block_is_visible_then_spendable() {
        let mut set: Vec<(u32, [u8; 4])> = vec![];
        // Chunk N stash: note found.
        apply_nullifier_delta(&mut set, &[], &[(7, *b"note")]);
        assert_eq!(
            set,
            vec![(7, *b"note")],
            "found note must enter the unspent view"
        );
        // Chunk N+1 stash: the same nullifier spent.
        apply_nullifier_delta(&mut set, &[*b"note"], &[]);
        assert!(set.is_empty(), "spent note must leave the unspent view");
    }

    /// Per-block ordering parity: retain happens BEFORE extend within one block,
    /// so a found-then-spent sequence across two block deltas behaves like
    /// upstream's per-block update_with stream.
    #[test]
    fn nullifier_delta_is_retain_then_extend_per_block() {
        let mut set: Vec<(u32, [u8; 4])> = vec![(1, *b"xxxx")];
        // Same block spends "xxxx" and finds "xxxx" again (degenerate, but
        // order-defining): retain removes first, extend re-adds.
        apply_nullifier_delta(&mut set, &[*b"xxxx"], &[(1, *b"xxxx")]);
        assert_eq!(set, vec![(1, *b"xxxx")]);
    }

    // ── WriteBehindFacade virtualized reads ────────────────────────────────────

    fn test_meta(height: u32) -> BlockMetadata {
        BlockMetadata::from_parts(
            BlockHeight::from(height),
            BlockHash([0xAB; 32]),
            Some(123),
            Some(45),
            // [IW-2b] ironwood tree size — fixture chain has none.
            Some(0),
        )
    }

    #[test]
    fn facade_block_metadata_serves_the_virtualized_tail_only() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(999u32), Some(test_meta(999)));
        let got = f
            .block_metadata(BlockHeight::from(999u32))
            .expect("tail height must serve");
        let got = got.expect("metadata present");
        assert_eq!(got.block_height(), BlockHeight::from(999u32));
        assert_eq!(got.block_hash(), BlockHash([0xAB; 32]));
        assert_eq!(got.sapling_tree_size(), Some(123));
        assert_eq!(got.orchard_tree_size(), Some(45));
        // Any other height is a loud error, never a stale read.
        let err = f.block_metadata(BlockHeight::from(998u32)).unwrap_err();
        assert!(
            err.to_string().contains("outside the virtualized tail"),
            "got: {err}"
        );
    }

    #[test]
    fn facade_block_metadata_known_absent_returns_none() {
        // Fresh wallet, first range: the seeded row at range_start-1 may be
        // absent — upstream returns None there and skips the continuity check.
        let f = WriteBehindFacade::test_new(BlockHeight::from(500u32), None);
        let got = f
            .block_metadata(BlockHeight::from(500u32))
            .expect("seeded height");
        assert!(got.is_none());
    }

    #[test]
    fn facade_unspent_nullifiers_serve_the_running_view_and_all_is_loud() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        assert!(
            f.get_sapling_nullifiers(NullifierQuery::Unspent)
                .expect("unspent")
                .is_empty()
        );
        assert!(
            f.get_orchard_nullifiers(NullifierQuery::Unspent)
                .expect("unspent")
                .is_empty()
        );
        let err = f.get_sapling_nullifiers(NullifierQuery::All).unwrap_err();
        assert!(
            err.to_string()
                .contains("not part of the scan_cached_blocks read surface")
        );
    }

    #[test]
    fn facade_ufvk_cache_is_served() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        assert!(
            f.get_unified_full_viewing_keys()
                .expect("cached")
                .is_empty()
        );
    }

    #[test]
    fn facade_reads_outside_the_surface_fail_loudly() {
        let f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        let err = f.chain_height().unwrap_err();
        assert!(
            err.to_string()
                .contains("not part of the scan_cached_blocks read surface")
        );
        let err = f.get_max_height_hash().unwrap_err();
        assert!(err.to_string().contains("get_max_height_hash"));
        let err = f.suggest_scan_ranges().unwrap_err();
        assert!(err.to_string().contains("suggest_scan_ranges"));
    }

    fn empty_chain_state(height: u32) -> ChainState {
        ChainState::new(
            BlockHeight::from(height),
            BlockHash([0u8; 32]),
            Frontier::empty(),
            Frontier::empty(),
            Frontier::empty(),
        )
    }

    #[test]
    fn facade_put_blocks_rejects_occupied_stash() {
        let mut f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        // Occupy the stash (empty blocks Vec — ScannedBlock is not publicly
        // constructible; the guard fires before the empty-input early return).
        f.stash = Some(PendingPersist {
            from_state: empty_chain_state(1),
            blocks: vec![],
            first_height: 2,
            last_height: 2,
        });
        let err = f.put_blocks(&empty_chain_state(1), vec![]).unwrap_err();
        assert!(
            err.to_string().contains("depth-1 invariant violated"),
            "got: {err}"
        );
        // Draining the stash restores put_blocks (empty input = upstream no-op).
        assert!(f.take_stash().is_some());
        f.put_blocks(&empty_chain_state(1), vec![])
            .expect("empty input is a no-op");
        assert!(f.take_stash().is_none(), "empty input must not stash");
    }

    #[test]
    fn facade_writes_outside_put_blocks_fail_loudly() {
        let mut f = WriteBehindFacade::test_new(BlockHeight::from(1u32), None);
        let err = WalletWrite::update_chain_tip(&mut f, BlockHeight::from(5u32)).unwrap_err();
        assert!(err.to_string().contains("update_chain_tip"));
        let err = f.truncate_to_height(BlockHeight::from(5u32)).unwrap_err();
        assert!(err.to_string().contains("truncate_to_height"));
    }

    // ── PersistLane: serial order, depth-1 backpressure, errors, drain ─────────

    fn lane(dir: &std::path::Path) -> PersistLane {
        PersistLane::open(
            &dir.join("lane.db"),
            crate::network::SlipstreamNetwork::MAIN,
            1,
            false,
            0,
            false,
            None,
        )
        .expect("lane open")
    }

    /// v0.6 P4c/P4d: the dedicated persist pool must exist and carry the
    /// policy thread count for this machine — `cores − 2` clamped to [2, 4] —
    /// and `install` must actually scope work onto it.
    #[test]
    fn persist_pool_policy() {
        let pool = persist_pool().expect("dedicated persist pool builds");
        let cores = std::thread::available_parallelism().map_or(2, usize::from);
        assert_eq!(
            pool.current_num_threads(),
            cores.saturating_sub(2).clamp(2, 4),
            "pool size must follow the cores−2 [2,4] clamp"
        );
        let inside = pool.install(rayon::current_num_threads);
        assert_eq!(
            inside,
            pool.current_num_threads(),
            "install() must run closures inside the dedicated pool"
        );
    }

    /// Depth-1 backpressure: submit(N+1) must complete unit N first — N+1's
    /// job can never start before N's job finished.
    #[tokio::test]
    async fn lane_submit_awaits_previous_before_spawning_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(vec![]));

        let l1 = Arc::clone(&log);
        lane.submit_job(
            (1, 1),
            Box::new(move |_db, _sparse| {
                l1.lock().expect("lock").push("job1-start");
                std::thread::sleep(Duration::from_millis(150));
                l1.lock().expect("lock").push("job1-end");
                Ok(())
            }),
        )
        .await
        .expect("submit 1");

        let submitted = Instant::now();
        let l2 = Arc::clone(&log);
        lane.submit_job(
            (2, 2),
            Box::new(move |_db, _sparse| {
                l2.lock().expect("lock").push("job2-start");
                Ok(())
            }),
        )
        .await
        .expect("submit 2");
        // submit(2) returned only after job1 completed (≥150ms blocked).
        assert!(
            submitted.elapsed() >= Duration::from_millis(140),
            "submit must block on the previous unit (depth-1), elapsed {:?}",
            submitted.elapsed()
        );
        lane.drain().await.expect("drain");

        let order = log.lock().expect("lock").clone();
        assert_eq!(
            order,
            vec!["job1-start", "job1-end", "job2-start"],
            "strictly serial"
        );
        assert!(
            lane.total_wait() >= Duration::from_millis(140),
            "wait accounted"
        );
        assert!(
            lane.total_busy() >= Duration::from_millis(140),
            "busy accounted"
        );
    }

    /// Liveness: a finished deferred commit is forward progress for the stall
    /// clock even though no counter moves (a slow device finishing a range).
    #[tokio::test]
    async fn lane_successful_commit_touches_attached_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let progress: crate::events::ProgressArc = Arc::new(crate::events::Progress::default());
        progress
            .last_progress_unix
            .store(0, std::sync::atomic::Ordering::Relaxed);
        lane.attach_writer_gate(Arc::clone(&progress));
        lane.submit_job((1, 1), Box::new(|_db, _sparse| Ok(())))
            .await
            .expect("submit");
        lane.drain().await.expect("drain");
        assert!(
            progress.last_progress_unix_secs() > 0,
            "a completed commit must stamp the stall clock"
        );
    }

    /// Liveness counterpart: a commit that FAILS is not forward progress — the
    /// stall clock must stay untouched so a genuinely stuck pass still stalls.
    #[tokio::test]
    async fn lane_failed_commit_does_not_touch_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let progress: crate::events::ProgressArc = Arc::new(crate::events::Progress::default());
        progress
            .last_progress_unix
            .store(0, std::sync::atomic::Ordering::Relaxed);
        lane.attach_writer_gate(Arc::clone(&progress));
        lane.submit_job(
            (1, 1),
            Box::new(|_db, _sparse| {
                Err(SqliteClientError::CorruptedData(
                    "synthetic commit failure".into(),
                ))
            }),
        )
        .await
        .expect("submit of the failing unit itself succeeds");
        let err = lane.drain().await.unwrap_err();
        assert!(
            err.to_string().contains("synthetic commit failure"),
            "got: {err}"
        );
        assert_eq!(
            progress.last_progress_unix_secs(),
            0,
            "a failed commit must not stamp the stall clock"
        );
    }

    /// A failed commit aborts the pipeline: the NEXT submit returns the error
    /// and never spawns its own job.
    #[tokio::test]
    async fn lane_error_propagates_before_next_submit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let ran2 = Arc::new(Mutex::new(false));

        lane.submit_job(
            (10, 19),
            Box::new(|_db, _sparse| {
                Err(SqliteClientError::CorruptedData(
                    "synthetic commit failure".into(),
                ))
            }),
        )
        .await
        .expect("submit of the failing unit itself succeeds");

        let r2 = Arc::clone(&ran2);
        let err = lane
            .submit_job(
                (20, 29),
                Box::new(move |_db, _sparse| {
                    *r2.lock().expect("lock") = true;
                    Ok(())
                }),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("synthetic commit failure"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("10..=19"),
            "error names the failed unit: {err}"
        );
        assert!(
            !*ran2.lock().expect("lock"),
            "unit N+1 must never run after N failed"
        );
        lane.drain()
            .await
            .expect("drain after error is a no-op (lane restored)");
    }

    /// drain() is the full barrier: it returns only after the in-flight commit
    /// finished, and propagates its error.
    #[tokio::test]
    async fn lane_drain_awaits_in_flight_and_propagates_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        let done = Arc::new(Mutex::new(false));
        let d = Arc::clone(&done);
        lane.submit_job(
            (1, 5),
            Box::new(move |_db, _sparse| {
                std::thread::sleep(Duration::from_millis(120));
                *d.lock().expect("lock") = true;
                Ok(())
            }),
        )
        .await
        .expect("submit");
        lane.drain().await.expect("drain");
        assert!(
            *done.lock().expect("lock"),
            "drain returned before the commit finished"
        );

        // Error path.
        lane.submit_job(
            (6, 9),
            Box::new(|_db, _sparse| Err(SqliteClientError::CorruptedData("late failure".into()))),
        )
        .await
        .expect("submit");
        let err = lane.drain().await.unwrap_err();
        assert!(err.to_string().contains("late failure"));
    }

    #[tokio::test]
    async fn lane_drain_when_idle_is_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        lane.drain().await.expect("idle drain");
        assert_eq!(lane.total_wait(), Duration::ZERO);
    }

    /// A panicking commit task surfaces as an error and poisons the lane
    /// (connection moved into the dead task) — further submits fail loudly.
    #[tokio::test]
    async fn lane_panic_is_an_error_and_poisons_the_lane() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lane = lane(dir.path());
        lane.submit_job((1, 1), Box::new(|_db, _sparse| panic!("synthetic panic")))
            .await
            .expect("submit");
        let err = lane.drain().await.unwrap_err();
        assert!(err.to_string().contains("persist task died"), "got: {err}");
        let err = lane
            .submit_job((2, 2), Box::new(|_db, _sparse| Ok(())))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("lane unusable"), "got: {err}");
    }
}

/// [B6, flush half] The retained-anchor marks a flush persists — see the fix in
/// `flush_sapling`/`flush_orchard`/`flush_ironwood`: the in-memory store's `retained` set
/// protects boundary checkpoints from the in-memory prune, but the sqlite store must learn the
/// marks too, or the open-time deep-history heal (which spares exactly the ids the SQLITE
/// retained set names) dooms every boundary anchor older than its margin.
#[cfg(test)]
mod flush_retained_tests {
    use super::*;
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_client_sqlite::wallet::init::init_wallet_db;

    fn fresh_db(
        dir: &std::path::Path,
    ) -> WalletDb<
        rusqlite::Connection,
        crate::network::SlipstreamNetwork,
        SystemClock,
        rand::rngs::OsRng,
    > {
        let conn = rusqlite::Connection::open(dir.join("wallet.sqlite")).expect("opens");
        rusqlite::vtab::array::load_module(&conn).expect("array vtab");
        let mut db = WalletDb::from_connection(
            conn,
            crate::network::SlipstreamNetwork::MAIN,
            SystemClock,
            rand::rngs::OsRng,
        );
        init_wallet_db(&mut db, None).expect("initializes the wallet schema");
        db
    }

    fn table_heights(dir: &std::path::Path, table: &str) -> Vec<u32> {
        let conn = rusqlite::Connection::open(dir.join("wallet.sqlite")).expect("re-opens");
        let mut stmt = conn
            .prepare(&format!(
                "SELECT checkpoint_id FROM {table} ORDER BY checkpoint_id"
            ))
            .expect("prepares");
        stmt.query_map([], |r| r.get::<_, u32>(0))
            .expect("queries")
            .collect::<Result<Vec<_>, _>>()
            .expect("collects")
    }

    /// The flush persists a retained mark for every ADDED checkpoint the in-memory store
    /// retains — in the same transaction as the checkpoint rows — and no mark for an added
    /// checkpoint that is not retained.
    #[test]
    fn flush_persists_retained_marks_for_added_checkpoints() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = fresh_db(dir.path());

        let mut store = SparseShardStore::<sapling::Node>::new(SAPLING_SHARD_HEIGHT);
        store
            .checkpoints
            .insert(BlockHeight::from(1_000u32), Checkpoint::tree_empty());
        store
            .checkpoints
            .insert(BlockHeight::from(1_002u32), Checkpoint::tree_empty());
        store.retained.insert(BlockHeight::from(1_000u32));
        let mut tree = ShardTree::new(store, MAX_CHECKPOINTS);

        db.transactionally::<_, _, SqliteClientError>(|wdb| flush_sapling(wdb, &mut tree))
            .expect("flushes");
        drop(db);

        assert_eq!(
            table_heights(dir.path(), "sapling_tree_checkpoints"),
            vec![1_000, 1_002],
            "both added checkpoints land as rows"
        );
        assert_eq!(
            table_heights(dir.path(), "sapling_tree_retained_checkpoints"),
            vec![1_000],
            "exactly the retained added checkpoint is marked durable in sqlite"
        );
    }

    /// Orchard and ironwood mirror the sapling behavior into their own tables.
    #[test]
    fn flush_marks_mirror_in_orchard_and_ironwood() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = fresh_db(dir.path());

        let mut orch_store =
            SparseShardStore::<orchard::tree::MerkleHashOrchard>::new(ORCHARD_SHARD_HEIGHT);
        orch_store
            .checkpoints
            .insert(BlockHeight::from(2_000u32), Checkpoint::tree_empty());
        orch_store.retained.insert(BlockHeight::from(2_000u32));
        let mut orch_tree: OrchardSparseTree = ShardTree::new(orch_store, MAX_CHECKPOINTS);

        let mut iron_store =
            SparseShardStore::<orchard::tree::MerkleHashOrchard>::new(ORCHARD_SHARD_HEIGHT);
        iron_store
            .checkpoints
            .insert(BlockHeight::from(3_000u32), Checkpoint::tree_empty());
        iron_store.retained.insert(BlockHeight::from(3_000u32));
        let mut iron_tree: IronwoodSparseTree = ShardTree::new(iron_store, MAX_CHECKPOINTS);

        db.transactionally::<_, _, SqliteClientError>(|wdb| {
            flush_orchard(wdb, &mut orch_tree)?;
            flush_ironwood(wdb, &mut iron_tree)
        })
        .expect("flushes");
        drop(db);

        assert_eq!(
            table_heights(dir.path(), "orchard_tree_retained_checkpoints"),
            vec![2_000]
        );
        assert_eq!(
            table_heights(dir.path(), "ironwood_tree_retained_checkpoints"),
            vec![3_000]
        );
    }

    /// A flush with nothing retained among its adds writes no marks — the fix never marks
    /// indiscriminately.
    #[test]
    fn flush_without_retained_adds_writes_no_marks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut db = fresh_db(dir.path());

        let mut store = SparseShardStore::<sapling::Node>::new(SAPLING_SHARD_HEIGHT);
        store
            .checkpoints
            .insert(BlockHeight::from(4_000u32), Checkpoint::tree_empty());
        let mut tree = ShardTree::new(store, MAX_CHECKPOINTS);

        db.transactionally::<_, _, SqliteClientError>(|wdb| flush_sapling(wdb, &mut tree))
            .expect("flushes");
        drop(db);

        assert!(
            table_heights(dir.path(), "sapling_tree_retained_checkpoints").is_empty(),
            "no retained adds, no marks"
        );
    }
}
