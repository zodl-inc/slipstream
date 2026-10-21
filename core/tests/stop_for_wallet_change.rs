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

//! The stop for a wallet change, end to end through upstream's real `scan_cached_blocks`
//! (hermetic: synthetic blocks, no network). The host asks the running session to stop right
//! before it changes the wallet (`Progress::request_stop_for_wallet_change`); the session's
//! `MemBlockSource` then refuses its next block, and upstream hands that back as
//! `ChainError::BlockSource(StoppedForWalletChange)`, the error `scan.rs` maps to
//! `SlipstreamError::StoppedForWalletChange` and the session ends quietly on. The unit tests in
//! `block_source.rs` prove the walk itself; these prove what the host's wallet change depends on:
//! a stopped scan WRITES NOTHING (upstream writes only in its final `put_blocks`, which an error
//! from either of its two walks never reaches), and once a new session re-arms the stop, scanning
//! the same chunk again leaves the wallet exactly as if no stop had happened.
//!
//! "Nothing written" is shown two ways. The read-backs a scan moves (the highest scanned block,
//! the ranges the scheduler would scan next, the `blocks` rows) are equal before and after the
//! stopped scan; the re-arm test's positive control shows each of them moving when a scan does
//! write, so the equality is not vacuous. And `oracle::semantic_diff` finds every table
//! row-identical to a twin wallet set up the same way and never scanned, which covers the tables
//! no read-back names.
//!
//! The scans run through the `SparseFacade`, census_scan.rs's layering and the production
//! inline-sparse path. The write-behind facade, the production default, does not write at all
//! while it scans: it only stashes, and only in that same `put_blocks`, which a stopped scan
//! never reaches.
//!
//! Own integration binary, declared with `required-features = ["zcash_client_sqlite"]` like
//! census_scan. Fixture helpers are replicas of `oracle::testkit` (gated
//! `#[cfg(any(test, feature = "darkside"))]`, invisible here) — same provenance as the copies in
//! census_scan.rs and stress_sparse_join.rs. No tokio runtime: `scan_cached_blocks` is
//! synchronous, and the stop does not depend on how the caller enters it.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use zcash_client_backend::data_api::WalletRead;
use zcash_client_backend::data_api::chain::{
    BlockSource, error::Error as ChainError, scan_cached_blocks,
};
use zcash_client_backend::data_api::scanning::ScanRange;
use zcash_client_backend::proto::compact_formats::{
    ChainMetadata, CompactBlock, CompactSaplingOutput, CompactSaplingSpend, CompactTx,
};
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::BlockHeight;

use zodl_slipstream::Progress;
use zodl_slipstream::block_source::{MemBlockSource, StoppedForWalletChange};
use zodl_slipstream::chunk::Chunk;
use zodl_slipstream::oracle::semantic_diff;
use zodl_slipstream::persist::{SparseFacade, SparseTreeState};
use zodl_slipstream::wallet_session::WalletSession;

/// See stress_sparse_join.rs for provenance (canonical darkside test seed UFVK).
const TEST_UFVK: &str = concat!(
    "uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat",
    "gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6",
    "scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc",
    "z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3"
);

const SYNTH_START: u64 = 1_500_000;
const BLOCKS: u64 = 4;
const OUTS_PER_BLOCK: u32 = 3;

fn h32(tag: u8, n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[0] = tag;
    v[1..9].copy_from_slice(&n.to_le_bytes());
    v
}

fn cmu(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

fn synth_blocks(count: u64, outs_per_block: u32) -> Vec<CompactBlock> {
    let mut blocks = Vec::with_capacity(count as usize);
    let mut tree_size: u32 = 0;
    let mut cmu_counter: u64 = 1;
    for i in 0..count {
        let height = SYNTH_START + i;
        let outputs = (0..outs_per_block)
            .map(|_| {
                let o = CompactSaplingOutput {
                    cmu: cmu(cmu_counter),
                    ephemeral_key: h32(0xEE, cmu_counter),
                    ciphertext: vec![0xC7; 52],
                };
                cmu_counter += 1;
                o
            })
            .collect::<Vec<_>>();
        tree_size += outs_per_block;
        let tx = CompactTx {
            index: 0,
            txid: h32(0x77, height),
            fee: 0,
            spends: vec![CompactSaplingSpend {
                nf: h32(0x4F, height),
            }],
            outputs,
            actions: vec![],
            ..Default::default()
        };
        blocks.push(CompactBlock {
            height,
            hash: h32(0xBB, height),
            prev_hash: if i == 0 {
                vec![0u8; 32]
            } else {
                h32(0xBB, height - 1)
            },
            time: height as u32,
            header: vec![],
            vtx: vec![tx],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: tree_size,
                orchard_commitment_tree_size: 0,
                ironwood_commitment_tree_size: 0,
            }),
        });
    }
    blocks
}

/// The account's birthday: empty frontiers at `SYNTH_START - 1`, which is also the state every
/// scan here starts from.
fn birthday() -> TreeState {
    TreeState {
        network: "main".into(),
        height: SYNTH_START - 1,
        hash: "0".repeat(64),
        time: 1,
        ..Default::default()
    }
}

/// A wallet as a pass finds it before its first range: `dir/data.db` opened (migrations run),
/// the fixture account imported with [`birthday`], and the chain tip at the last synthetic block.
/// Two calls give two wallets `semantic_diff` finds identical (`accounts.uuid`, the one random
/// column, is on the oracle's allowlist).
fn open_wallet(dir: &Path) -> WalletSession {
    let mut session =
        WalletSession::open(zodl_slipstream::Network::MainNetwork, &dir.join("data.db"))
            .expect("open");
    let ufvk = zodl_slipstream::UnifiedFullViewingKey::decode(
        &zodl_slipstream::Network::MainNetwork,
        TEST_UFVK,
    )
    .expect("ufvk decode");
    session
        .import_account(&ufvk, birthday())
        .expect("import_account");
    session
        .update_chain_tip(SYNTH_START + BLOCKS - 1)
        .expect("update_chain_tip");
    session
}

/// What a scan of the synthetic chain changes, read back through the wallet's own API and from
/// its `blocks` table. A received-note count could not tell: the fixture wallet owns nothing in
/// the synthetic chain.
#[derive(Debug, PartialEq, Eq)]
struct ReadBack {
    /// `WalletRead::block_max_scanned`: the highest scanned block, `None` before any.
    max_scanned: Option<u32>,
    /// The ranges the scheduler would scan next (`suggest_scan_ranges`).
    suggested: Vec<ScanRange>,
    /// Rows in the `blocks` table: one per scanned block.
    block_rows: i64,
    /// The wallet's chain tip (`WalletRead::chain_height`, derived from the scan queue).
    chain_height: Option<u64>,
}

fn read_back(session: &mut WalletSession, dir: &Path) -> ReadBack {
    let max_scanned = session
        .db_mut()
        .block_max_scanned()
        .expect("block_max_scanned")
        .map(|m| u32::from(m.block_height()));
    let block_rows = rusqlite::Connection::open(dir.join("data.db"))
        .expect("side connection")
        .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
        .expect("count blocks");
    ReadBack {
        max_scanned,
        suggested: session.suggest_scan_ranges().expect("suggest_scan_ranges"),
        block_rows,
        chain_height: session.chain_height().expect("chain_height"),
    }
}

/// How one `scan_cached_blocks` call ended.
#[derive(Debug, PartialEq, Eq)]
enum ScanEnd {
    /// It ran to the end, and its `put_blocks` stored this many scanned blocks.
    Scanned(u64),
    /// The block source refused a block: `ChainError::BlockSource(StoppedForWalletChange)`.
    StoppedForWalletChange,
    /// Any other error, rendered, so that a failing assertion shows it.
    Failed(String),
}

/// One `scan_cached_blocks` call over the whole chunk from the birthday state, through a
/// `SparseFacade` with a fresh `SparseTreeState` (one per call, as one per range in production).
fn scan(
    session: &mut WalletSession,
    source: &impl BlockSource<Error = StoppedForWalletChange>,
) -> ScanEnd {
    let mut sparse = SparseTreeState::default();
    let from_state = birthday().to_chain_state().expect("chain state");
    let network = session.network;
    let mut facade = SparseFacade {
        inner: session.db_mut(),
        sparse: &mut sparse,
    };
    let from_height = BlockHeight::from(u32::try_from(SYNTH_START).expect("height fits u32"));
    match scan_cached_blocks(
        &network,
        source,
        &mut facade,
        from_height,
        &from_state,
        BLOCKS as usize,
    ) {
        Ok(summary) => {
            let range = summary.scanned_range();
            ScanEnd::Scanned(u64::from(u32::from(range.end) - u32::from(range.start)))
        }
        Err(ChainError::BlockSource(StoppedForWalletChange)) => ScanEnd::StoppedForWalletChange,
        Err(e) => ScanEnd::Failed(e.to_string()),
    }
}

/// A `BlockSource` over a [`MemBlockSource`] that records how many blocks each of upstream's
/// walks was handed and, if told to, asks for the stop for a wallet change as a given walk
/// starts. It only counts and delegates: the refusal is the inner source's own.
struct WalkRecorder<'a> {
    inner: MemBlockSource<'a>,
    progress: &'a Progress,
    /// The walk (1-based) at whose start to request the stop; `None` never requests it.
    request_stop_at_walk: Option<usize>,
    /// Blocks handed out by each walk, in walk order.
    served: RefCell<Vec<usize>>,
}

impl<'a> WalkRecorder<'a> {
    fn new(chunk: &'a Chunk, progress: &'a Progress, request_stop_at_walk: Option<usize>) -> Self {
        Self {
            inner: MemBlockSource::new(chunk).with_stop(Some(progress)),
            progress,
            request_stop_at_walk,
            served: RefCell::default(),
        }
    }

    fn served(&self) -> Vec<usize> {
        self.served.borrow().clone()
    }
}

impl BlockSource for WalkRecorder<'_> {
    type Error = StoppedForWalletChange;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let walk = self.served.borrow().len() + 1;
        if self.request_stop_at_walk == Some(walk) {
            self.progress.request_stop_for_wallet_change();
        }
        let mut served = 0;
        let result = self.inner.with_blocks(from_height, limit, |block| {
            served += 1;
            with_block(block)
        });
        self.served.borrow_mut().push(served);
        result
    }
}

/// Every table of the two wallets is row-identical (`oracle::semantic_diff`). The sessions must be
/// closed first, so that nothing reads a live writer's WAL.
fn assert_wallets_identical(a: &Path, b: &Path, context: &str) {
    let report = semantic_diff(&a.join("data.db"), &b.join("data.db")).expect("semantic_diff");
    assert!(report.is_clean(), "{context}:\n{}", report.render());
}

fn wallet_dirs(root: &Path) -> (PathBuf, PathBuf) {
    (root.join("stopped"), root.join("twin"))
}

/// A stop requested before the scan: upstream hands back the block source's stop, and the wallet
/// is exactly as it was.
#[test]
fn a_stop_requested_before_the_scan_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let (stopped, twin) = wallet_dirs(root.path());
    let chunk = Chunk::from_blocks(0, synth_blocks(BLOCKS, OUTS_PER_BLOCK));
    drop(open_wallet(&twin)); // set up the same way, never scanned

    let mut session = open_wallet(&stopped);
    let before = read_back(&mut session, &stopped);

    let progress = Progress::default();
    progress.request_stop_for_wallet_change();
    let source = MemBlockSource::new(&chunk).with_stop(Some(&progress));
    assert_eq!(scan(&mut session, &source), ScanEnd::StoppedForWalletChange);

    assert_eq!(
        read_back(&mut session, &stopped),
        before,
        "a stopped scan must leave every read-back as it was"
    );
    drop(session);
    assert_wallets_identical(&stopped, &twin, "a stopped scan wrote to the wallet");
}

/// A stop requested once upstream's first walk is over (the walk that queues every block's trial
/// decryption) ends the second walk before its first block: the same error, and again nothing is
/// written, although every block's trial decryption was already queued.
#[test]
fn a_stop_requested_in_the_second_walk_writes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let (stopped, twin) = wallet_dirs(root.path());
    let chunk = Chunk::from_blocks(0, synth_blocks(BLOCKS, OUTS_PER_BLOCK));
    drop(open_wallet(&twin)); // set up the same way, never scanned

    let mut session = open_wallet(&stopped);
    let before = read_back(&mut session, &stopped);

    let progress = Progress::default();
    let source = WalkRecorder::new(&chunk, &progress, Some(2));
    assert_eq!(scan(&mut session, &source), ScanEnd::StoppedForWalletChange);
    assert_eq!(
        source.served(),
        vec![BLOCKS as usize, 0],
        "walk 1 hands every block to the decryptors; walk 2 refuses its first block"
    );

    assert_eq!(
        read_back(&mut session, &stopped),
        before,
        "a scan stopped in its second walk must leave every read-back as it was"
    );
    drop(session);
    assert_wallets_identical(&stopped, &twin, "a stopped second walk wrote to the wallet");
}

/// The stop costs a rescan and nothing else. A request stands for the rest of its session (a new
/// pass, `begin_pass`, does not lift it), `begin_session` re-arms it (`run_session` calls that
/// right after it takes the pass lock), and the re-armed scan of the same chunk leaves the wallet
/// row-identical to a twin that scanned it once, uninterrupted.
#[test]
fn a_re_armed_session_scans_the_chunk_as_if_never_stopped() {
    let root = tempfile::tempdir().expect("tempdir");
    let (stopped, twin) = wallet_dirs(root.path());
    let chunk = Chunk::from_blocks(0, synth_blocks(BLOCKS, OUTS_PER_BLOCK));

    // The twin: one uninterrupted scan, with no stop anywhere.
    let mut twin_session = open_wallet(&twin);
    let unscanned = read_back(&mut twin_session, &twin);
    assert_eq!(
        scan(&mut twin_session, &MemBlockSource::new(&chunk)),
        ScanEnd::Scanned(BLOCKS)
    );
    let scanned = read_back(&mut twin_session, &twin);
    drop(twin_session);
    // Positive control for the other tests: a scan that writes moves the read-backs they compare.
    assert_eq!(unscanned.max_scanned, None);
    assert_eq!(
        scanned.max_scanned,
        Some(u32::try_from(SYNTH_START + BLOCKS - 1).expect("height fits u32"))
    );
    assert_eq!(
        (unscanned.block_rows, scanned.block_rows),
        (0, BLOCKS as i64)
    );
    assert_ne!(
        unscanned.suggested, scanned.suggested,
        "a scan must change what the scheduler would scan next"
    );

    // The other wallet: stopped in its second walk, still stopped in a new pass of the same
    // session, then scanned to the end once a new session has re-armed the stop.
    let mut session = open_wallet(&stopped);
    let progress = Progress::default();
    let interrupted = WalkRecorder::new(&chunk, &progress, Some(2));
    assert_eq!(
        scan(&mut session, &interrupted),
        ScanEnd::StoppedForWalletChange
    );

    progress.begin_pass();
    let retried = WalkRecorder::new(&chunk, &progress, None);
    assert_eq!(
        scan(&mut session, &retried),
        ScanEnd::StoppedForWalletChange
    );
    assert_eq!(
        retried.served(),
        vec![0],
        "the request stands until the session ends: a new pass scans no block"
    );

    progress.begin_session();
    let rearmed = WalkRecorder::new(&chunk, &progress, None);
    assert_eq!(scan(&mut session, &rearmed), ScanEnd::Scanned(BLOCKS));
    assert_eq!(
        rearmed.served(),
        vec![BLOCKS as usize; 2],
        "the re-armed scan walks every block, twice"
    );
    assert_eq!(read_back(&mut session, &stopped), scanned);
    drop(session);

    assert_wallets_identical(
        &stopped,
        &twin,
        "a stopped-then-rescanned wallet differs from one scanned once",
    );
}
