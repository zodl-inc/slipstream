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

//! Golden-oracle harness (T6.2): semantic diff of two wallet databases.
//! D3 enforcement — the sparse persistence path must produce a data.db that is
//! row-identical to upstream's, modulo an explicit (currently empty) allowlist.
//! Used by the CLI `oracle` subcommand and the darkside oracle tests.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::Connection;
use rusqlite::types::ValueRef;

use crate::error::SlipstreamError;

/// (table, column) pairs excluded from comparison. Keep EMPTY until the
/// determinism test proves a column is non-deterministic; every addition needs
/// a Decision-Log entry citing the upstream write site.
///
/// # ALLOWLIST entries
///
/// - `("accounts", "uuid")`: random `Uuid::new_v4()` generated at account-import time.
///   Write site: `zcash_client_sqlite-0.21.0/src/wallet.rs:464` (`let account_uuid =
///   AccountUuid(Uuid::new_v4())`). Non-deterministic by design — it is a stable
///   per-account opaque identity, not part of the scan output. Oracle correctness is
///   unaffected because all scan tables (blocks, sapling_tree_*, orchard_tree_*,
///   nullifier_map, tx_locator_map, scan_queue, etc.) remain clean.
pub const ALLOWLIST: &[(&str, &str)] = &[("accounts", "uuid")];

/// Per-table comparison result.
#[derive(Debug, Clone)]
pub struct TableDiff {
    pub table: String,
    pub rows_a: u64,
    pub rows_b: u64,
    /// Canonicalized rows present in A but not B (first 5 kept), and vice versa.
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
}

impl TableDiff {
    pub fn is_clean(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty() && self.rows_a == self.rows_b
    }
}

#[derive(Debug, Default)]
pub struct DiffReport {
    pub tables: Vec<TableDiff>,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.tables.iter().all(TableDiff::is_clean)
    }

    /// Human-readable verdict block for CLI printing.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for t in &self.tables {
            if t.is_clean() {
                let _ = writeln!(out, "  OK   {:40} {} rows", t.table, t.rows_a);
            } else {
                let _ = writeln!(
                    out,
                    "  DIFF {:40} A={} B={} (+A {} / +B {})",
                    t.table,
                    t.rows_a,
                    t.rows_b,
                    t.only_in_a.len(),
                    t.only_in_b.len()
                );
                for r in t.only_in_a.iter().take(5) {
                    let _ = writeln!(out, "       only-in-A: {r}");
                }
                for r in t.only_in_b.iter().take(5) {
                    let _ = writeln!(out, "       only-in-B: {r}");
                }
            }
        }
        out
    }
}

fn wallet_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Wallet(format!("oracle {context}: {e}"))
}

fn canonical_value(v: ValueRef<'_>) -> String {
    match v {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => format!("{r:?}"),
        ValueRef::Text(t) => format!("'{}'", String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => {
            let mut s = String::with_capacity(2 + b.len() * 2);
            s.push_str("x'");
            for byte in b {
                let _ = write!(s, "{byte:02x}");
            }
            s.push('\'');
            s
        }
    }
}

fn list_tables(conn: &Connection) -> Result<Vec<String>, SlipstreamError> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| wallet_err("list tables", e))?;
    let names = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| wallet_err("list tables", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| wallet_err("list tables", e))?;
    Ok(names)
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, SlipstreamError> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .map_err(|e| wallet_err("table_info", e))?;
    let cols = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| wallet_err("table_info", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| wallet_err("table_info", e))?;
    Ok(cols
        .into_iter()
        .filter(|c| !ALLOWLIST.contains(&(table, c.as_str())))
        .collect())
}

/// Multiset of canonicalized rows for one table.
/// v0.6 P4b: tables whose row RESIDUE depends on put_blocks call cadence, not
/// wallet semantics. `prune_tracked_spends` anchors on the fully-scanned
/// frontier at each call, so even two UPSTREAM syncs with different chunk sizes
/// disagree on which below-window rows linger. The contract compared here is
/// therefore WINDOWED: both sides are normalized to rows at or above
/// `max(block_height across A∪B) − SPEND_MAP_RETENTION_BLOCKS` — everything
/// any read (`detect_*_spend`, `ext_slipstream_v_tx_reconciled`) can ever consult —
/// and STRICT equality is required inside that window. The skip-below-window
/// tracking lives INSIDE upstream `put_blocks_rows` since #2604, keyed on the
/// same public retention constant used here.
const TRANSIENT_WINDOW_TABLES: &[&str] = &[
    "nullifier_map",
    "tx_locator_map",
    "transparent_spend_locator_map",
];

fn transient_window_floor(
    a: &Connection,
    b: &Connection,
    table: &str,
) -> Result<Option<u32>, SlipstreamError> {
    let max_of = |conn: &Connection| -> Result<Option<u32>, SlipstreamError> {
        conn.query_row(
            &format!("SELECT MAX(block_height) FROM \"{table}\""),
            [],
            |row| row.get::<_, Option<u32>>(0),
        )
        .map_err(|e| wallet_err("max height", e))
    };
    Ok(max_of(a)?.max(max_of(b)?).map(|h| {
        h.saturating_sub(zcash_client_backend::data_api::ll::wallet::SPEND_MAP_RETENTION_BLOCKS)
    }))
}

fn row_multiset(
    conn: &Connection,
    table: &str,
    cols: &[String],
    min_height: Option<u32>,
) -> Result<HashMap<String, i64>, SlipstreamError> {
    let col_list = cols
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let filter = match min_height {
        Some(h) => format!(" WHERE block_height >= {h}"),
        None => String::new(),
    };
    let mut stmt = conn
        .prepare(&format!("SELECT {col_list} FROM \"{table}\"{filter}"))
        .map_err(|e| wallet_err("select", e))?;
    let mut rows = stmt.query([]).map_err(|e| wallet_err("query", e))?;
    let mut set: HashMap<String, i64> = HashMap::new();
    while let Some(row) = rows.next().map_err(|e| wallet_err("next", e))? {
        let mut canon = String::new();
        for (i, col) in cols.iter().enumerate() {
            let v = row.get_ref(i).map_err(|e| wallet_err("get_ref", e))?;
            let _ = write!(canon, "{col}={}|", canonical_value(v));
        }
        *set.entry(canon).or_insert(0) += 1;
    }
    Ok(set)
}

/// Semantically diff every table of two wallet databases.
/// Tables are taken from the UNION of both schemas (a missing table shows as a
/// full-table diff). Columns come from DB A's schema (identical migrations are
/// a precondition — both DBs are produced by this crate's WalletSession).
pub fn semantic_diff(db_a: &Path, db_b: &Path) -> Result<DiffReport, SlipstreamError> {
    let a = Connection::open(db_a).map_err(|e| wallet_err("open A", e))?;
    let b = Connection::open(db_b).map_err(|e| wallet_err("open B", e))?;
    let mut tables = list_tables(&a)?;
    for t in list_tables(&b)? {
        if !tables.contains(&t) {
            tables.push(t);
        }
    }
    tables.sort();

    let mut report = DiffReport::default();
    for table in tables {
        let cols = table_columns(&a, &table).or_else(|_| table_columns(&b, &table))?;
        // Windowed comparison for cadence-transient tables (see
        // TRANSIENT_WINDOW_TABLES); full-table strict equality everywhere else.
        let min_height = if TRANSIENT_WINDOW_TABLES.contains(&table.as_str()) {
            transient_window_floor(&a, &b, &table).unwrap_or(None)
        } else {
            None
        };
        let ms_a = row_multiset(&a, &table, &cols, min_height).unwrap_or_default();
        let ms_b = row_multiset(&b, &table, &cols, min_height).unwrap_or_default();
        let rows_a: i64 = ms_a.values().sum();
        let rows_b: i64 = ms_b.values().sum();
        let mut only_in_a = vec![];
        let mut only_in_b = vec![];
        for (row, ca) in &ms_a {
            let cb = ms_b.get(row).copied().unwrap_or(0);
            for _ in cb..*ca {
                only_in_a.push(row.clone());
            }
        }
        for (row, cb) in &ms_b {
            let ca = ms_a.get(row).copied().unwrap_or(0);
            for _ in ca..*cb {
                only_in_b.push(row.clone());
            }
        }
        only_in_a.sort();
        only_in_b.sort();
        report.tables.push(TableDiff {
            table,
            rows_a: rows_a as u64,
            rows_b: rows_b as u64,
            only_in_a,
            only_in_b,
        });
    }
    Ok(report)
}

/// Test kit: deterministic synthetic chain + a full upstream-path scan into a
/// fresh wallet. Reused by the hermetic determinism test (T6.2), the hermetic
/// sparse oracle test (T6.4) and the darkside oracle test (T6.4).
#[cfg(any(test, feature = "darkside"))]
pub mod testkit {
    use std::path::Path;

    use zcash_client_backend::data_api::chain::scan_cached_blocks;
    use zcash_client_backend::proto::compact_formats::{
        ChainMetadata, CompactBlock, CompactOrchardAction, CompactSaplingOutput,
        CompactSaplingSpend, CompactTx,
    };
    use zcash_client_backend::proto::service::TreeState;
    use zcash_protocol::consensus::BlockHeight;

    use crate::block_source::MemBlockSource;
    use crate::chunk::Chunk;
    use crate::error::SlipstreamError;
    use crate::wallet_session::{TEST_UFVK, WalletSession};

    /// First synthetic height: above Sapling activation (419_200), below NU5
    /// (1_687_104) so empty Orchard bundles and zero Orchard tree sizes are valid.
    pub const SYNTH_START: u64 = 1_500_000;

    fn h32(tag: u8, n: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[0] = tag;
        v[1..9].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// Little-endian small integers are canonical Jubjub base-field elements →
    /// valid `cmu` bytes for CompactOutputDescription parsing.
    fn cmu(n: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// Deterministic synthetic chain: `count` linked blocks from SYNTH_START.
    /// Every block has one tx with `outs_per_block` Sapling outputs (random-looking
    /// but fixed ciphertexts that decrypt to nothing) and one foreign Sapling spend
    /// (exercises tx_locator_map/nullifier_map). chain_metadata carries cumulative
    /// Sapling tree sizes starting from 0 (fresh synthetic chain); Orchard stays 0.
    pub fn synth_blocks(count: u64, outs_per_block: u32) -> Vec<CompactBlock> {
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
            // Deviation from plan: CompactTx uses `txid` not `hash` in
            // zcash_client_backend-0.23.0/src/proto/compact_formats.rs:70.
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

    /// First synthetic ORCHARD height: above NU5 activation (1_687_104) so orchard
    /// actions and orchard chain-metadata are valid — the sapling `SYNTH_START`
    /// sits deliberately BELOW NU5 and cannot host orchard chains (v0.4 T10b).
    pub const SYNTH_ORCHARD_START: u64 = 1_700_000;

    /// Dual-pool synthetic chain from [`SYNTH_ORCHARD_START`]: every block has
    /// `orch_per_block` orchard actions; every `sap_every`-th block ALSO has
    /// one sapling output. The interspersed sapling stream gives the two pools
    /// DIFFERENT checkpoint-id sets — the shape that makes the cross-pool
    /// `ensure_checkpoints` fill non-empty (the sandblasting-era regression
    /// vector). cmu streams are the deterministic counters `synth_chain_state`
    /// replays: sapling `cmu(1..)`, orchard `cmu(2_000_000 + k)`.
    pub fn synth_blocks_dual(count: u64, orch_per_block: u32, sap_every: u64) -> Vec<CompactBlock> {
        let mut blocks = Vec::with_capacity(count as usize);
        let mut sap_tree_size: u32 = 0;
        let mut orch_tree_size: u32 = 0;
        let mut sap_counter: u64 = 1;
        let mut orch_counter: u64 = 0;
        for i in 0..count {
            let height = SYNTH_ORCHARD_START + i;
            let actions = (0..orch_per_block)
                .map(|_| {
                    let a = CompactOrchardAction {
                        nullifier: cmu(1_000_000 + orch_counter),
                        cmx: cmu(2_000_000 + orch_counter),
                        ephemeral_key: h32(0xEE, orch_counter),
                        ciphertext: vec![0xC7; 52],
                    };
                    orch_counter += 1;
                    a
                })
                .collect::<Vec<_>>();
            orch_tree_size += orch_per_block;
            let outputs = if i % sap_every == 0 {
                let o = CompactSaplingOutput {
                    cmu: cmu(sap_counter),
                    ephemeral_key: h32(0xE5, sap_counter),
                    ciphertext: vec![0xC7; 52],
                };
                sap_counter += 1;
                sap_tree_size += 1;
                vec![o]
            } else {
                vec![]
            };
            let tx = CompactTx {
                index: 0,
                txid: h32(0x77, height),
                fee: 0,
                spends: vec![],
                outputs,
                actions,
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
                    sapling_commitment_tree_size: sap_tree_size,
                    orchard_commitment_tree_size: orch_tree_size,
                    ironwood_commitment_tree_size: 0,
                }),
            });
        }
        blocks
    }

    /// One genuine orchard compact action: a REAL note encrypted to `ufvk`'s
    /// external orchard address, so compact trial-decryption finds it and the
    /// wallet can later SPEND it (the T10b witness proof). The nullifier field
    /// doubles as the note's rho, so it travels with the action.
    pub struct OwnedOrchardAction {
        pub nullifier: [u8; 32],
        pub cmx: [u8; 32],
        pub ephemeral_key: [u8; 32],
        pub ciphertext: Vec<u8>,
    }

    /// Fabricate an [`OwnedOrchardAction`] worth `value_zat` for `ufvk`. `salt`
    /// varies rho/rseed deterministically (no RNG — oracle fixtures replay).
    pub fn owned_orchard_action(
        ufvk: &zcash_keys::keys::UnifiedFullViewingKey,
        value_zat: u64,
        salt: u64,
    ) -> OwnedOrchardAction {
        use zcash_note_encryption::Domain as _;
        let fvk = ufvk.orchard().expect("test ufvk must carry an orchard fvk");
        let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
        // rho: any canonical Pallas base element works — small LE ints always are.
        let mut rho_bytes = [0u8; 32];
        rho_bytes[..8].copy_from_slice(&salt.to_le_bytes());
        let rho = orchard::note::Rho::from_bytes(&rho_bytes)
            .expect("small-int rho is a canonical field element");
        // rseed: not every 32-byte string is valid for a given rho — scan for one.
        let rseed = (0u8..=255)
            .find_map(|i| {
                let mut b = [i; 32];
                b[..8].copy_from_slice(&salt.to_le_bytes());
                Option::from(orchard::note::RandomSeed::from_bytes(b, &rho))
            })
            .expect("some rseed candidate must be valid");
        let note = orchard::note::Note::from_parts(
            recipient,
            orchard::value::NoteValue::from_raw(value_zat),
            rho,
            rseed,
            // [IW-2b] orchard 0.15 notes carry a version; darkside fixtures
            // fabricate vanilla (pre-ironwood) orchard notes.
            orchard::note::NoteVersion::V2,
        )
        .expect("note parts are consistent by construction");
        let cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
        let enc = orchard::note_encryption::OrchardNoteEncryption::new(None, note, [0u8; 512]);
        let ephemeral_key = orchard::note_encryption::OrchardDomain::epk_bytes(enc.epk()).0;
        let full = enc.encrypt_note_plaintext();
        let full: &[u8] = full.as_ref();
        let ciphertext = full[..52].to_vec();
        OwnedOrchardAction {
            nullifier: rho_bytes,
            cmx,
            ephemeral_key,
            ciphertext,
        }
    }

    /// Deterministic synthetic ORCHARD chain (v0.4 T10b): `count` linked blocks
    /// from [`SYNTH_ORCHARD_START`], one tx per block with `outs_per_block`
    /// orchard actions. Foreign actions carry valid-but-undecryptable fields
    /// (small-int cmx/nullifier — canonical Pallas base elements — and garbage
    /// epk/ciphertext, which trial decryption skips gracefully). When `owned`
    /// is given, the action at that GLOBAL action index is the real one.
    /// Sapling stays empty; chain metadata carries cumulative ORCHARD sizes.
    pub fn synth_blocks_orchard(
        count: u64,
        outs_per_block: u32,
        owned: Option<(u64, &OwnedOrchardAction)>,
    ) -> Vec<CompactBlock> {
        let mut blocks = Vec::with_capacity(count as usize);
        let mut tree_size: u32 = 0;
        let mut action_counter: u64 = 0;
        for i in 0..count {
            let height = SYNTH_ORCHARD_START + i;
            let actions = (0..outs_per_block)
                .map(|_| {
                    let a = match owned {
                        Some((at, o)) if at == action_counter => CompactOrchardAction {
                            nullifier: o.nullifier.to_vec(),
                            cmx: o.cmx.to_vec(),
                            ephemeral_key: o.ephemeral_key.to_vec(),
                            ciphertext: o.ciphertext.clone(),
                        },
                        _ => CompactOrchardAction {
                            // Offset the counters so foreign fields never collide
                            // with each other or with an owned action's rho.
                            nullifier: cmu(1_000_000 + action_counter),
                            cmx: cmu(2_000_000 + action_counter),
                            ephemeral_key: h32(0xEE, action_counter),
                            ciphertext: vec![0xC7; 52],
                        },
                    };
                    action_counter += 1;
                    a
                })
                .collect::<Vec<_>>();
            tree_size += outs_per_block;
            let tx = CompactTx {
                index: 0,
                txid: h32(0x77, height),
                fee: 0,
                spends: vec![],
                outputs: vec![],
                actions,
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
                    sapling_commitment_tree_size: 0,
                    orchard_commitment_tree_size: tree_size,
                    ironwood_commitment_tree_size: 0,
                }),
            });
        }
        blocks
    }

    /// Level-16 root over ONE FULL orchard shard's 65,536 cmx leaves — the
    /// hermetic stand-in for a lightwalletd-served subtree root (what
    /// `GetSubtreeRoots` would return; darkside cannot serve these, see T10b).
    pub fn orchard_shard_root(cmxs: &[Vec<u8>]) -> [u8; 32] {
        use incrementalmerkletree::frontier::Frontier;
        use orchard::tree::MerkleHashOrchard;
        assert_eq!(cmxs.len(), 1 << 16, "a shard is exactly 65,536 leaves");
        let mut frontier: Frontier<MerkleHashOrchard, 16> = Frontier::empty();
        for c in cmxs {
            let bytes: [u8; 32] = c.as_slice().try_into().expect("cmx is 32 bytes");
            let node = Option::from(MerkleHashOrchard::from_bytes(&bytes))
                .expect("fixture cmx must be a canonical field element");
            assert!(frontier.append(node), "frontier overfilled");
        }
        frontier.root().to_bytes()
    }

    /// Open a fresh wallet at `dir/data.db`, import TEST_UFVK with an empty
    /// treestate birthday at SYNTH_START-1, set the chain tip, and scan `blocks`
    /// through `scan_cached_blocks` in `chunk_size`-block calls — through the
    /// plain WalletDb when `sparse` is false, through the `SparseFacade`
    /// (exactly as scan.rs::scan_chunks does, with ONE `SparseTreeState` for the
    /// whole call = one scan range) when `sparse` is true.
    pub fn scan_synthetic(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        chunk_size: usize,
        sparse: bool,
    ) -> Result<(), SlipstreamError> {
        let lens: Vec<usize> = blocks
            .chunks(chunk_size)
            .map(<[CompactBlock]>::len)
            .collect();
        scan_synthetic_windows(dir, blocks, &lens, sparse)
    }

    /// Like [`scan_synthetic`] but scans in explicit variable-length windows
    /// (T6.8-S): each entry of `window_lens` is one `scan_cached_blocks` call,
    /// mirroring the engine's byte-budget-split sub-chunks. `window_lens` must
    /// sum to `blocks.len()`.
    pub fn scan_synthetic_windows(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        window_lens: &[usize],
        sparse: bool,
    ) -> Result<(), SlipstreamError> {
        if window_lens.iter().sum::<usize>() != blocks.len() {
            return Err(SlipstreamError::Wallet(format!(
                "window_lens sum {} != blocks {}",
                window_lens.iter().sum::<usize>(),
                blocks.len()
            )));
        }
        let mut sparse_state = crate::persist::SparseTreeState::default();
        let db_path = dir.join("data.db");
        let mut session = WalletSession::open(crate::Network::MainNetwork, &db_path)?;
        // Same TreeState shape as wallet_session.rs tests (663_149 precedent):
        // 64-char zero hash, empty tree strings = empty frontier birthday.
        let birthday_ts = TreeState {
            network: "main".into(),
            height: 1_499_999, // SYNTH_START - 1
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        session.ensure_account(TEST_UFVK, birthday_ts.clone())?;
        let tip = blocks.last().map(|b| b.height).unwrap_or(SYNTH_START);
        session.update_chain_tip(tip)?;

        let mut from_state = birthday_ts
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let mut offset = 0usize;
        for len in window_lens {
            let window = &blocks[offset..offset + len];
            offset += len;
            let (Some(first), Some(last)) = (window.first(), window.last()) else {
                continue; // zero-length windows are skipped (degenerate input)
            };
            let from_height = u32::try_from(first.height)
                .map_err(|_| SlipstreamError::Wallet("height exceeds u32".into()))?;
            let chunk = Chunk::from_blocks(0, window.to_vec());
            let source = MemBlockSource::new(&chunk);
            let network = session.network;
            if sparse {
                let mut facade = crate::persist::SparseFacade {
                    inner: session.db_mut(),
                    sparse: &mut sparse_state,
                };
                scan_cached_blocks(
                    &network,
                    &source,
                    &mut facade,
                    BlockHeight::from(from_height),
                    &from_state,
                    window.len(),
                )
                .map_err(|e| {
                    SlipstreamError::Wallet(format!("scan_cached_blocks (sparse): {e}"))
                })?;
            } else {
                scan_cached_blocks(
                    &network,
                    &source,
                    session.db_mut(),
                    BlockHeight::from(from_height),
                    &from_state,
                    window.len(),
                )
                .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?;
            }
            // from_state for the NEXT window: re-synthesized from the chain's
            // known cmu sequence (no server in hermetic tests).
            from_state = synth_chain_state(last)?;
        }
        Ok(())
    }

    /// T6.9: like [`scan_synthetic_windows`] but through the WRITE-BEHIND
    /// pipeline — the same `WriteBehindFacade` + `PersistLane` production uses:
    /// per window, the scan reads come from the pending-aware facade, the
    /// commit is stashed and submitted to the lane (depth-1, strictly serial),
    /// and the call drains the lane before returning. Used by the hermetic
    /// write-behind oracle tests: deferral may change TIMING, never CONTENT.
    /// `graft` — v0.4 Plan A: run the range with the graft accumulator (the
    /// hermetic equivalence fixture A/Bs this flag; verdict is always-build in
    /// Task 7).
    pub async fn scan_synthetic_windows_write_behind(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        window_lens: &[usize],
        graft: bool,
    ) -> Result<(), SlipstreamError> {
        // verify_sample=1 (audit-every) — audited grafts BUILD, so these callers
        // exercise the full build path even with graft on (the Task 7 gate shape).
        scan_synthetic_windows_write_behind_with(dir, blocks, window_lens, graft, 1, |_, _| Ok(()))
            .await
            .map(|_| ())
    }

    /// v0.4 T10b: [`scan_synthetic_windows_write_behind`] plus a `prepare` hook that
    /// runs after the session opens and BEFORE `ensure_account` — fixtures use it to
    /// seed subtree roots (a REAL graft needs a "server" root on file) and/or to
    /// create a SPENDING account first (`ensure_account` no-ops once any account
    /// exists; the engine itself only ever imports view-only). The birthday derives
    /// from the first block (`height - 1`), so chains at any activation era work —
    /// for the sapling `SYNTH_START` chains this is the same 1_499_999 as before.
    /// `graft_verify_sample`: 0 = pure install (root-only shapes actually land),
    /// 1 = audit-every (audited grafts install BUILT content), N = 1-in-N.
    /// Returns the lane's cumulative graft verdicts ((sap_grafted, sap_fallback),
    /// (orch_grafted, orch_fallback)) — the in-band DID-IT-FIRE signal, since
    /// build-then-prune and graft converge to identical final DB bytes.
    pub async fn scan_synthetic_windows_write_behind_with(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        window_lens: &[usize],
        graft: bool,
        graft_verify_sample: u32,
        prepare: impl FnOnce(&mut WalletSession, &TreeState) -> Result<(), SlipstreamError>,
    ) -> Result<((u64, u64), (u64, u64)), SlipstreamError> {
        scan_synthetic_windows_write_behind_with_tip(
            dir,
            blocks,
            window_lens,
            graft,
            graft_verify_sample,
            None,
            prepare,
        )
        .await
    }

    /// As above, but with an explicit chain-tip override — lets a test place the
    /// scanned windows deep below the tip (DEEP_HISTORY_CHECKPOINT_MARGIN
    /// territory), the shape of a historic-range restore over spam-era blocks.
    pub async fn scan_synthetic_windows_write_behind_with_tip(
        dir: &Path,
        blocks: Vec<CompactBlock>,
        window_lens: &[usize],
        graft: bool,
        graft_verify_sample: u32,
        tip_override: Option<u64>,
        prepare: impl FnOnce(&mut WalletSession, &TreeState) -> Result<(), SlipstreamError>,
    ) -> Result<((u64, u64), (u64, u64)), SlipstreamError> {
        if window_lens.iter().sum::<usize>() != blocks.len() {
            return Err(SlipstreamError::Wallet(format!(
                "window_lens sum {} != blocks {}",
                window_lens.iter().sum::<usize>(),
                blocks.len()
            )));
        }
        let db_path = dir.join("data.db");
        let mut session = WalletSession::open(crate::Network::MainNetwork, &db_path)?;
        let birthday_height = blocks.first().map_or(SYNTH_START - 1, |b| b.height - 1);
        let birthday_ts = TreeState {
            network: "main".into(),
            height: birthday_height,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        prepare(&mut session, &birthday_ts)?;
        session.ensure_account(TEST_UFVK, birthday_ts.clone())?;
        let tip =
            tip_override.unwrap_or_else(|| blocks.last().map(|b| b.height).unwrap_or(SYNTH_START));
        session.update_chain_tip(tip)?;

        // Seed the facade under the no-pending barrier; open the lane's own
        // connection — exactly as scan.rs::scan_chunks does.
        let range_start = blocks.first().map_or(SYNTH_START, |b| b.height);
        let mut facade = crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
            .map_err(|e| SlipstreamError::Wallet(format!("write-behind seed: {e}")))?;
        let mut lane = crate::persist::PersistLane::open(
            &db_path,
            crate::network::SlipstreamNetwork::MAIN,
            1,
            graft,
            graft_verify_sample,
            false,
            None, // [B6] darkside fixtures: retention off
        )?;

        let mut from_state = birthday_ts
            .to_chain_state()
            .map_err(|e| SlipstreamError::Wallet(format!("chain state: {e}")))?;
        let mut offset = 0usize;
        let mut result: Result<(), SlipstreamError> = Ok(());
        for len in window_lens {
            let window = &blocks[offset..offset + len];
            offset += len;
            let (Some(first), Some(last)) = (window.first(), window.last()) else {
                continue; // zero-length windows are skipped (degenerate input)
            };
            let from_height = match u32::try_from(first.height) {
                Ok(h) => h,
                Err(_) => {
                    result = Err(SlipstreamError::Wallet("height exceeds u32".into()));
                    break;
                }
            };
            let chunk = Chunk::from_blocks(0, window.to_vec());
            let source = MemBlockSource::new(&chunk);
            let network = session.network;
            if let Err(e) = scan_cached_blocks(
                &network,
                &source,
                &mut facade,
                BlockHeight::from(from_height),
                &from_state,
                window.len(),
            ) {
                result = Err(SlipstreamError::Wallet(format!(
                    "scan_cached_blocks (write-behind): {e}"
                )));
                break;
            }
            // Submit the deferred commit (depth-1: awaits the previous one).
            if let Some(pending) = facade.take_stash()
                && let Err(e) = lane.submit(pending).await
            {
                result = Err(e);
                break;
            }
            from_state = match synth_chain_state(last) {
                Ok(s) => s,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
        }
        // Full barrier before returning — mirror of scan_chunks.
        let drain_result = lane.drain().await;
        match (result, drain_result) {
            (Ok(()), Ok(())) => {
                // v0.4: build the open range-end shard (success path only).
                lane.finish_graft_blocking()?;
                Ok(lane.graft_verdict_totals())
            }
            (Err(e), Ok(())) => Err(e),
            (_, Err(p)) => Err(p),
        }
    }

    /// v0.4 Task 9: RESUME a graft-ON write-behind scan on an EXISTING wallet from
    /// `blocks[resume_at..]` — simulates a mid-range process restart (the new lane
    /// re-seeds its accumulator from the buffer table) and the rewind-rescan path.
    /// `from_state` must be the chain state at `blocks[resume_at - 1]`.
    pub async fn resume_synthetic_windows_write_behind(
        dir: &Path,
        blocks: &[CompactBlock],
        resume_at: usize,
        window_lens: &[usize],
        graft: bool,
    ) -> Result<(), SlipstreamError> {
        let tail = &blocks[resume_at..];
        if window_lens.iter().sum::<usize>() != tail.len() {
            return Err(SlipstreamError::Wallet(format!(
                "window_lens sum {} != tail {}",
                window_lens.iter().sum::<usize>(),
                tail.len()
            )));
        }
        let db_path = dir.join("data.db");
        let mut session = WalletSession::open(crate::Network::MainNetwork, &db_path)?;
        let range_start = tail
            .first()
            .map(|b| b.height)
            .ok_or_else(|| SlipstreamError::Wallet("empty resume tail".into()))?;
        let mut facade =
            crate::persist::WriteBehindFacade::seed(&*session.db_mut(), range_start)
                .map_err(|e| SlipstreamError::Wallet(format!("resume write-behind seed: {e}")))?;
        let mut lane = crate::persist::PersistLane::open(
            &db_path,
            crate::network::SlipstreamNetwork::MAIN,
            1,
            graft,
            1,
            false,
            None,
        )?;
        let mut from_state = synth_chain_state(&blocks[resume_at - 1])?;
        let mut offset = 0usize;
        let mut result: Result<(), SlipstreamError> = Ok(());
        for len in window_lens {
            let window = &tail[offset..offset + len];
            offset += len;
            let (Some(first), Some(last)) = (window.first(), window.last()) else {
                continue;
            };
            let from_height = match u32::try_from(first.height) {
                Ok(h) => h,
                Err(_) => {
                    result = Err(SlipstreamError::Wallet("height exceeds u32".into()));
                    break;
                }
            };
            let chunk = Chunk::from_blocks(0, window.to_vec());
            let source = MemBlockSource::new(&chunk);
            let network = session.network;
            if let Err(e) = scan_cached_blocks(
                &network,
                &source,
                &mut facade,
                BlockHeight::from(from_height),
                &from_state,
                window.len(),
            ) {
                result = Err(SlipstreamError::Wallet(format!(
                    "scan_cached_blocks (resume): {e}"
                )));
                break;
            }
            if let Some(pending) = facade.take_stash()
                && let Err(e) = lane.submit(pending).await
            {
                result = Err(e);
                break;
            }
            from_state = match synth_chain_state(last) {
                Ok(s) => s,
                Err(e) => {
                    result = Err(e);
                    break;
                }
            };
        }
        let drain_result = lane.drain().await;
        match (result, drain_result) {
            (Ok(()), Ok(())) => {
                lane.finish_graft_blocking()?;
                Ok(())
            }
            (Err(e), Ok(())) => Err(e),
            (_, Err(p)) => Err(p),
        }
    }

    /// ChainState at `last` for the NEXT window: frontier rebuilt by replaying
    /// every cmu of the synthetic chain from the start through `last` (the
    /// global cmu counter makes this exact; cheap at test sizes).
    fn synth_chain_state(
        last: &CompactBlock,
    ) -> Result<zcash_client_backend::data_api::chain::ChainState, SlipstreamError> {
        // Replay all outputs from SYNTH_START..=last.height to build the frontier.
        use incrementalmerkletree::frontier::Frontier;
        use zcash_primitives::merkle_tree::HashSer;
        let total: u64 = last
            .chain_metadata
            .as_ref()
            .map(|m| m.sapling_commitment_tree_size as u64)
            .unwrap_or(0);
        let mut frontier: Frontier<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }> =
            Frontier::empty();
        for n in 1..=total {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&n.to_le_bytes());
            // Deviation from plan's sapling::Node::from_bytes (CtOption):
            // grpc.rs uses sapling::Node::read(&bytes[..]) via HashSer — same pattern here.
            let node = sapling::Node::read(&bytes[..])
                .map_err(|e| SlipstreamError::Wallet(format!("invalid synth cmu {n}: {e}")))?;
            let _ = frontier.append(node);
        }
        // Orchard synth chains (synth_blocks_orchard): the foreign cmx pattern
        // is the same deterministic counter stream (cmu(2_000_000 + k)), so the
        // orchard frontier replays exactly. Chains with owned actions splice a
        // real cmx into the stream and would need it here too — multi-window
        // drivers currently only use foreign-only orchard chains.
        let orch_total: u64 = last
            .chain_metadata
            .as_ref()
            .map(|m| m.orchard_commitment_tree_size as u64)
            .unwrap_or(0);
        let mut orch_frontier: Frontier<orchard::tree::MerkleHashOrchard, 32> = Frontier::empty();
        for k in 0..orch_total {
            let bytes: [u8; 32] = cmu(2_000_000 + k)
                .as_slice()
                .try_into()
                .map_err(|_| SlipstreamError::Wallet("synth cmx width".into()))?;
            let node = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&bytes))
                .ok_or_else(|| SlipstreamError::Wallet(format!("invalid synth cmx {k}")))?;
            let _ = orch_frontier.append(node);
        }
        let mut hash = [0u8; 32];
        hash[0] = 0xBB;
        hash[1..9].copy_from_slice(&last.height.to_le_bytes());
        Ok(zcash_client_backend::data_api::chain::ChainState::new(
            BlockHeight::from(last.height as u32),
            zcash_primitives::block::BlockHash(hash),
            frontier,
            orch_frontier,
            // [IW-2b] ironwood-era ChainState carries a third frontier; darkside
            // fixture chains have no ironwood outputs.
            Frontier::empty(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_db(path: &std::path::Path, rows: &[(i64, &str)]) {
        let conn = Connection::open(path).expect("open");
        conn.execute_batch("CREATE TABLE t (a INTEGER, b TEXT); CREATE TABLE u (x BLOB);")
            .expect("schema");
        for (a, b) in rows {
            conn.execute(
                "INSERT INTO t (a, b) VALUES (?1, ?2)",
                rusqlite::params![a, b],
            )
            .expect("insert");
        }
    }

    #[test]
    fn identical_dbs_diff_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (2, "y")]);
        mk_db(&pb, &[(2, "y"), (1, "x")]); // insertion order must not matter
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(
            report.is_clean(),
            "expected clean diff:\n{}",
            report.render()
        );
    }

    #[test]
    fn row_delta_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (2, "y")]);
        mk_db(&pb, &[(1, "x"), (2, "z")]);
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(!report.is_clean());
        let t = report
            .tables
            .iter()
            .find(|t| t.table == "t")
            .expect("table t");
        assert_eq!(t.only_in_a.len(), 1);
        assert_eq!(t.only_in_b.len(), 1);
        assert!(t.only_in_a[0].contains("'y'"));
    }

    #[test]
    fn duplicate_row_multiplicity_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x"), (1, "x")]);
        mk_db(&pb, &[(1, "x")]);
        let report = semantic_diff(&pa, &pb).expect("diff");
        let t = report
            .tables
            .iter()
            .find(|t| t.table == "t")
            .expect("table t");
        assert!(!t.is_clean());
        assert_eq!(t.rows_a, 2);
        assert_eq!(t.rows_b, 1);
    }

    #[test]
    fn missing_table_is_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pa = dir.path().join("a.db");
        let pb = dir.path().join("b.db");
        mk_db(&pa, &[(1, "x")]);
        let conn = Connection::open(&pb).expect("open");
        conn.execute_batch("CREATE TABLE t (a INTEGER, b TEXT);")
            .expect("schema");
        // table `u` missing in B entirely
        let report = semantic_diff(&pa, &pb).expect("diff");
        assert!(report.tables.iter().any(|t| t.table == "u"));
    }

    /// T6.2 determinism baseline: the SAME synthetic blocks scanned through the
    /// upstream path into two fresh wallets must produce semantically identical
    /// databases. Any diff here = non-deterministic column → allowlist candidate
    /// (protocol in the phase plan).
    #[test]
    fn upstream_path_is_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(30, 3);
        super::testkit::scan_synthetic(&da, blocks.clone(), 10, false).expect("scan A");
        super::testkit::scan_synthetic(&db, blocks, 10, false).expect("scan B");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "upstream self-diff not clean:\n{}",
            report.render()
        );
    }

    /// T6.3b hermetic identity proof: the SAME synthetic chain scanned through
    /// the upstream path (A) and the sparse facade with the checkpoint
    /// downgrade (B) must produce semantically identical databases. 3 chunks of
    /// 1000 blocks each: ~1000 per-block sapling checkpoints per put_blocks
    /// call against the 100-checkpoint window, so the doomed-checkpoint cutoff
    /// fires in every chunk (~900 downgrades each) and the cross-chunk carry
    /// (previous chunk's surviving checkpoints + missing-checkpoint table
    /// entries) is exercised twice.
    #[test]
    fn sparse_path_matches_upstream_on_synthetic_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(3000, 3);
        super::testkit::scan_synthetic(&da, blocks.clone(), 1000, false).expect("upstream scan");
        super::testkit::scan_synthetic(&db, blocks, 1000, true).expect("sparse scan");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "sparse-vs-upstream diff not clean:\n{}",
            report.render()
        );
    }

    /// T6.8-S hermetic identity proof for VARIABLE (byte-budget-split) chunking:
    /// a dense ("sandblasting"-shaped) synthetic chain — every block several
    /// times the split threshold in wire size — is split into many small
    /// variable windows by the REAL `ChunkSplitter` (the same decisions the
    /// fetch workers make in the spam era), then scanned through BOTH
    /// persistence paths at those identical boundaries: A = upstream WalletDb,
    /// B = SparseFacade (production default). A CLEAN diff proves the sparse
    /// path stays oracle-clean under dense, tiny, variable chunking.
    ///
    /// Methodology note (discovered building this test): chunk boundaries ARE
    /// observable in the wallet DB on the UPSTREAM path itself, by design —
    /// (1) `put_blocks` prunes `nullifier_map` on every call at
    /// fully-scanned-height − PRUNING_DEPTH (zcash_client_backend-0.23.0
    /// data_api/ll/wallet.rs:460-463 → zcash_client_sqlite-0.21.0 lib.rs:2054),
    /// so finer chunking prunes a rolling cache earlier; (2) shard-blob bytes
    /// encode the insert/prune batch history. Cross-chunking byte-comparison is
    /// therefore upstream-false; the oracle compares the two PATHS at EQUAL
    /// boundaries (same as T6.2+ methodology and the CLI oracle, where both
    /// runs share one config).
    #[test]
    fn split_chunking_matches_upstream_on_dense_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        // 80 blocks × 20 sapling outputs ≈ 2.5 KB wire per block: dense-era
        // shape relative to a 6 KiB split threshold (~2-block sub-chunks).
        // Sized for the always-green loop: split COUNT (not absolute output
        // volume) is what exercises the variable-boundary machinery.
        let blocks = super::testkit::synth_blocks(80, 20);

        // Derive the window lengths from the production splitter.
        let mut lens: Vec<usize> = Vec::new();
        let mut splitter = crate::fetch::ChunkSplitter::new(6 * 1024);
        for b in blocks.clone() {
            if let Some((sub, _bytes)) = splitter.push(b) {
                lens.push(sub.len());
            }
        }
        if let Some((sub, _bytes)) = splitter.finish() {
            lens.push(sub.len());
        }
        assert!(
            lens.len() >= 30,
            "dense chain must split into many sub-chunks, got {}",
            lens.len()
        );
        assert_eq!(
            lens.iter().sum::<usize>(),
            blocks.len(),
            "no block lost by the splitter"
        );

        super::testkit::scan_synthetic_windows(&da, blocks.clone(), &lens, false)
            .expect("upstream scan at split boundaries");
        super::testkit::scan_synthetic_windows(&db, blocks, &lens, true)
            .expect("sparse scan at split boundaries");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "split-chunking sparse-vs-upstream diff not clean:\n{}",
            report.render()
        );
    }

    /// T6.9 hermetic write-behind oracle: the SAME synthetic chain scanned
    /// through the upstream path (A) and the WRITE-BEHIND pipeline (B —
    /// pending-aware facade + persist lane, identical window boundaries) must
    /// produce semantically identical databases. Deferral changes timing,
    /// never content. Multi-window (3×1000) so the virtualized reads
    /// (`block_metadata` tail continuity, running nullifier views) are
    /// exercised at two pending boundaries while the previous commit is
    /// potentially still in flight; the checkpoint-downgrade cutoff also fires
    /// in every window (same shape as the sparse oracle above).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_behind_matches_upstream_on_synthetic_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(3000, 3);
        let lens: Vec<usize> = blocks.chunks(1000).map(<[_]>::len).collect();
        super::testkit::scan_synthetic_windows(&da, blocks.clone(), &lens, false)
            .expect("upstream scan");
        super::testkit::scan_synthetic_windows_write_behind(&db, blocks, &lens, false)
            .await
            .expect("write-behind scan");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "write-behind-vs-upstream diff not clean:\n{}",
            report.render()
        );
    }

    /// v0.4 Plan A Task 7 gate: graft-ON (verdict still ALWAYS-BUILD) vs
    /// graft-OFF over the same write-behind pipeline must be semantically
    /// identical. Multi-window on a foreign wallet ⇒ everything buffers as
    /// carried rows until `finish_graft` builds the open shard — exercising
    /// the accumulator, the buffer table round-trip, the carried-row residue
    /// rule, and the range-end finish path in one sweep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graft_verdict_build_matches_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let doff = dir.path().join("off");
        let don = dir.path().join("on");
        std::fs::create_dir_all(&doff).unwrap();
        std::fs::create_dir_all(&don).unwrap();
        let blocks = super::testkit::synth_blocks(3000, 3);
        let lens: Vec<usize> = blocks.chunks(1000).map(<[_]>::len).collect();
        super::testkit::scan_synthetic_windows_write_behind(&doff, blocks.clone(), &lens, false)
            .await
            .expect("graft-off scan");
        super::testkit::scan_synthetic_windows_write_behind(&don, blocks, &lens, true)
            .await
            .expect("graft-on scan");
        let report = semantic_diff(&doff.join("data.db"), &don.join("data.db")).expect("diff");
        // The designed gate (plan Task 7b): everything semantically identical —
        // checkpoints, caps (rebuilt from SHARD ROOTS, so cap equality proves
        // root equality), notes, nullifiers, blocks — with ONE documented
        // exception: the shard BLOBS may differ in retention-flag placement
        // (a deferred build is one from_iter; the incremental path is several).
        // Anchors and witnesses never read those flags; the semantic oracle
        // (Task 10) is the correctness gate for the real verdict.
        for t in &report.tables {
            if t.table.ends_with("_tree_shards") {
                assert_eq!(
                    t.rows_a, t.rows_b,
                    "shard COUNT must match even where blobs differ: {}",
                    t.table
                );
                continue;
            }
            assert!(
                t.is_clean(),
                "graft-on(verdict=build) vs graft-off diff not clean in {}:\n{}",
                t.table,
                report.render()
            );
        }
        // The buffer table must be fully drained on the ON side...
        let conn = rusqlite::Connection::open(don.join("data.db")).expect("open on");
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ext_slipstream_graft_buffer",
                [],
                |r| r.get(0),
            )
            .expect("buffer count");
        assert_eq!(left, 0, "buffer rows must be cleaned after build/finish");
        // ...and must be EMPTY on the OFF side. (The table itself exists on
        // both sides since issue #4: schema is owned by the ext_slipstream_*
        // migration, unconditionally; only its CONTENTS are graft-flag-gated.)
        let conn = rusqlite::Connection::open(doff.join("data.db")).expect("open off");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ext_slipstream_graft_buffer",
                [],
                |r| r.get(0),
            )
            .expect("off-side buffer count");
        assert_eq!(n, 0, "graft-off must not write buffer rows");
    }

    /// v0.4 Task 9(a): a process restart MID-RANGE (and mid-shard) with graft on —
    /// the second lane re-seeds its accumulator from the buffer table and the final
    /// wallet must equal an uninterrupted graft-ON run (modulo the documented
    /// shard-blob retention-flag class).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graft_restart_mid_shard_resumes_from_buffer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uninterrupted = dir.path().join("uninterrupted");
        let restarted = dir.path().join("restarted");
        std::fs::create_dir_all(&uninterrupted).unwrap();
        std::fs::create_dir_all(&restarted).unwrap();
        let blocks = super::testkit::synth_blocks(3000, 3);
        let lens: Vec<usize> = blocks.chunks(1000).map(<[_]>::len).collect();
        super::testkit::scan_synthetic_windows_write_behind(
            &uninterrupted,
            blocks.clone(),
            &lens,
            true,
        )
        .await
        .expect("uninterrupted graft scan");
        // Restarted: first window with one lane, then a FRESH lane for the rest
        // (drops the first lane's in-memory accumulator — exactly a process kill).
        super::testkit::scan_synthetic_windows_write_behind(
            &restarted,
            blocks[..1000].to_vec(),
            &[1000],
            true,
        )
        .await
        .expect("pre-restart scan");
        super::testkit::resume_synthetic_windows_write_behind(
            &restarted,
            &blocks,
            1000,
            &[1000, 1000],
            true,
        )
        .await
        .expect("post-restart resume");
        let report = semantic_diff(&uninterrupted.join("data.db"), &restarted.join("data.db"))
            .expect("diff");
        for t in &report.tables {
            if t.table.ends_with("_tree_shards") {
                assert_eq!(t.rows_a, t.rows_b, "shard count: {}", t.table);
                continue;
            }
            assert!(
                t.is_clean(),
                "restart-resume diff not clean in {}:\n{}",
                t.table,
                report.render()
            );
        }
        let conn = rusqlite::Connection::open(restarted.join("data.db")).expect("open");
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ext_slipstream_graft_buffer",
                [],
                |r| r.get(0),
            )
            .expect("buffer count");
        assert_eq!(left, 0, "resume must drain the buffer");
    }

    /// v0.4 Task 9(b): does graft change REWIND behavior? Both wallets live the
    /// SAME lifecycle (full scan → truncate 50 blocks, inside upstream's retained
    /// checkpoint window → rescan the tail) — one graft-OFF, one graft-ON. The
    /// position-keyed INSERT OR REPLACE contract makes stale buffered rows
    /// converge, so the pair must match modulo the documented shard-blob class.
    /// (A rewind legitimately differs from a never-rewound wallet — upstream
    /// truncate wipes height-keyed history maps — which is why the control is a
    /// rewound graft-OFF wallet, not a straight run.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graft_rewind_rescan_converges() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blocks = super::testkit::synth_blocks(3000, 3);
        let lens: Vec<usize> = blocks.chunks(1000).map(<[_]>::len).collect();
        let mut dbs = vec![];
        for (name, graft) in [("off", false), ("on", true)] {
            let w = dir.path().join(name);
            std::fs::create_dir_all(&w).unwrap();
            super::testkit::scan_synthetic_windows_write_behind(&w, blocks.clone(), &lens, graft)
                .await
                .expect("initial scan");
            {
                use zcash_client_backend::data_api::WalletWrite as _;
                let mut session = crate::wallet_session::WalletSession::open(
                    crate::Network::MainNetwork,
                    &w.join("data.db"),
                )
                .expect("reopen");
                let target =
                    zcash_protocol::consensus::BlockHeight::from(blocks[2949].height as u32);
                session
                    .db_mut()
                    .truncate_to_height(target)
                    .expect("truncate");
            }
            super::testkit::resume_synthetic_windows_write_behind(&w, &blocks, 2950, &[50], graft)
                .await
                .expect("rescan tail after rewind");
            dbs.push(w.join("data.db"));
        }
        let report = semantic_diff(&dbs[0], &dbs[1]).expect("diff");
        for t in &report.tables {
            if t.table.ends_with("_tree_shards") {
                assert_eq!(t.rows_a, t.rows_b, "shard count: {}", t.table);
                continue;
            }
            assert!(
                t.is_clean(),
                "rewound OFF-vs-ON diff not clean in {}:\n{}",
                t.table,
                report.render()
            );
        }
        let conn = rusqlite::Connection::open(&dbs[1]).expect("open on");
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ext_slipstream_graft_buffer",
                [],
                |r| r.get(0),
            )
            .expect("buffer count");
        assert_eq!(left, 0, "rewind + rescan must leave the buffer drained");
    }

    /// T6.9 write-behind oracle on the dense split-chunking chain (T6.8-S
    /// boundaries): many tiny variable windows → many pending boundaries →
    /// the depth-1 pipeline churns constantly. Final DB must still be
    /// byte-identical to the upstream path at the same boundaries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_behind_matches_upstream_on_dense_split_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let da = dir.path().join("wa");
        let db = dir.path().join("wb");
        std::fs::create_dir_all(&da).unwrap();
        std::fs::create_dir_all(&db).unwrap();
        let blocks = super::testkit::synth_blocks(80, 20);

        let mut lens: Vec<usize> = Vec::new();
        let mut splitter = crate::fetch::ChunkSplitter::new(6 * 1024);
        for b in blocks.clone() {
            if let Some((sub, _bytes)) = splitter.push(b) {
                lens.push(sub.len());
            }
        }
        if let Some((sub, _bytes)) = splitter.finish() {
            lens.push(sub.len());
        }
        assert_eq!(
            lens.iter().sum::<usize>(),
            blocks.len(),
            "no block lost by the splitter"
        );

        super::testkit::scan_synthetic_windows(&da, blocks.clone(), &lens, false)
            .expect("upstream scan at split boundaries");
        super::testkit::scan_synthetic_windows_write_behind(&db, blocks, &lens, false)
            .await
            .expect("write-behind scan at split boundaries");
        let report = semantic_diff(&da.join("data.db"), &db.join("data.db")).expect("diff");
        assert!(
            report.is_clean(),
            "write-behind split-chunking diff not clean:\n{}",
            report.render()
        );
    }

    // ── v0.4 T10b: the REAL-graft semantic oracle (hermetic) ────────────────────
    //
    // The plan's Task 10 called for a darkside fixture, but darkside cannot carry
    // this proof: (a) darksidewalletd never serves GetSubtreeRoots, and the graft
    // verdict keys off exactly those ingested roots; (b) closing a shard needs
    // 65,536 REAL outputs, and darkside only ingests full-format blocks/txs
    // (~500 MB of structurally-valid orchard bundles). The hermetic vehicle is
    // also the cryptographically stronger one: darkside performs no proof
    // verification at all, while the follow-up spend test runs the orchard
    // circuit itself against the grafted tree. Shared fixture for both:
    //
    //   660 blocks × 100 orchard actions = 66,000 leaves from SYNTH_ORCHARD_START.
    //   Shard 0 (positions 0..65,535) closes INSIDE the range with zero owned
    //   notes → with a seeded "server" root on file it must GRAFT. The one OWNED
    //   note (real encryption) sits at position 65,600 — inside shard 1, the
    //   range-end shard, which always BUILDS (accumulator rule 1) — so both
    //   paths coexist and the owned note's witness cap-path crosses the grafted
    //   shard-0 root.

    /// The shard-0 "server" root + the spending-account prepare hook shared by the
    /// T10b tests. Returns (blocks, ufvk_encoded, seed) — the account is created
    /// FROM SEED (spending, not view-only) inside the hook so the follow-up spend
    /// test can derive the USK for the same account.
    fn t10b_fixture() -> (
        Vec<zcash_client_backend::proto::compact_formats::CompactBlock>,
        String,
        [u8; 32],
    ) {
        let seed = [7u8; 32];
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &seed,
            zip32::AccountId::ZERO,
        )
        .expect("usk from seed");
        let ufvk = usk.to_unified_full_viewing_key();
        let owned = super::testkit::owned_orchard_action(&ufvk, 500_000, 3);
        // 760 blocks × 100 = 76,000 leaves: shard 0 (0..65,535) closes clean and
        // grafts; the LAST 100 blocks (the engine's retained-checkpoint window)
        // sit entirely in shard 1 (positions 66,000+), which builds — mirroring
        // production's rule-2 invariant (the ChainTip range never grafts, so the
        // retained checkpoints always live in built territory).
        let blocks = super::testkit::synth_blocks_orchard(760, 100, Some((65_600, &owned)));
        let ufvk_str = ufvk
            .encode(&zcash_protocol::consensus::MAIN_NETWORK)
            .expect("a derived UFVK has an encoding");
        (blocks, ufvk_str, seed)
    }

    /// Prepare hook: create the SPENDING account from `seed`, then seed the
    /// shard-0 "server" root (only when `with_root`) — mirroring the engine's
    /// pass-start `put_subtree_roots` ingest.
    fn t10b_prepare(
        seed: [u8; 32],
        blocks: &[zcash_client_backend::proto::compact_formats::CompactBlock],
        with_root: bool,
    ) -> impl FnOnce(
        &mut crate::wallet_session::WalletSession,
        &zcash_client_backend::proto::service::TreeState,
    ) -> Result<(), SlipstreamError>
    + use<> {
        // Shard 0's 65,536 cmx leaves → the root a lightwalletd would serve.
        let cmxs: Vec<Vec<u8>> = blocks
            .iter()
            .flat_map(|b| b.vtx.iter())
            .flat_map(|t| t.actions.iter())
            .map(|a| a.cmx.clone())
            .take(1 << 16)
            .collect();
        let root = super::testkit::orchard_shard_root(&cmxs);
        // Height of the block holding leaf 65,535: 65,536 leaves / 100 per block
        // → block index 655 (holds positions 65,500..65,599).
        let end_height = blocks[655].height;
        move |session, birthday_ts| {
            use secrecy::SecretVec;
            use zcash_client_backend::data_api::{AccountBirthday, WalletWrite};
            let birthday = AccountBirthday::from_treestate(birthday_ts.clone(), None)
                .map_err(|_| SlipstreamError::Wallet("t10b birthday".into()))?;
            session
                .db_mut()
                .create_account("t10b", &SecretVec::new(seed.to_vec()), &birthday, None)
                .map_err(|e| SlipstreamError::Wallet(format!("t10b create_account: {e}")))?;
            if with_root {
                use orchard::tree::MerkleHashOrchard;
                use zcash_client_backend::data_api::chain::CommitmentTreeRoot;
                let node = Option::from(MerkleHashOrchard::from_bytes(&root))
                    .ok_or_else(|| SlipstreamError::Wallet("t10b root decode".into()))?;
                let roots = crate::grpc::SubtreeRoots {
                    sapling: vec![],
                    orchard: vec![CommitmentTreeRoot::from_parts(
                        zcash_protocol::consensus::BlockHeight::from(end_height as u32),
                        node,
                    )],
                    ironwood: vec![],
                };
                session.put_subtree_roots(&roots)?;
            }
            Ok(())
        }
    }

    /// T10b step 1: with a seeded server root, the clean shard must REALLY graft —
    /// and the grafted wallet must be semantically identical to the built one
    /// (modulo the documented shard-blob retention-flag class), owned note
    /// included. The lane runs audit-every (verify_sample=1 in the driver), so a
    /// root mismatch would fail loudly; equality of checkpoints + caps proves the
    /// grafted root feeds the same tree the built path computes.
    /// Heavy (2× 66k-action scans): `cargo test -p zodl-slipstream --release
    /// 2026-07-06 sandblasting-era P0 regression: deep-history windows scanned
    /// over a shard whose store row is a ROOT-ONLY leaf (the pass-start
    /// subtree-root ingest installs one for every chain-wide-completed shard)
    /// used to panic in shardtree's `prune_excess_checkpoints`: window 1's
    /// ~100 ensured store checkpoints point into interior the graft
    /// accumulator BUFFERED (never inserted into the tree), and window 2's
    /// prune evicts them in one per-shard `clear_flags` batch straight into
    /// the root-only leaf — "Tree state inconsistent with checkpoints".
    /// With DEEP_HISTORY_CHECKPOINT_MARGIN dooming, deep batches create no
    /// per-block checkpoints, so there is nothing to evict; the scan must
    /// complete. Fast (2,200 actions) — guards the suite by default.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deep_history_over_ingested_root_only_shard_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 220 note-free blocks, 10 orchard actions each, a sapling output every
        // 3rd block — the interspersed sapling stream makes the cross-pool
        // ensure_checkpoints fill non-empty (the flood vector); all positions
        // stay inside each pool's shard 0.
        let blocks = super::testkit::synth_blocks_dual(220, 10, 3);
        let last_height = blocks.last().expect("blocks").height;
        // The chain tip sits far above the scanned windows — the historic-
        // range restore shape (margin is 10_000; use 2× for headroom).
        let tip = last_height + 20_000;
        // Both pools' shard 0 are chain-wide complete: serve roots so the
        // ingest installs root-only leaves. The values are never compared
        // (neither shard completes within the scanned windows) — any
        // canonical elements work; borrow the first synthetic cmx/cmu.
        let orch_root: [u8; 32] = blocks[0].vtx[0].actions[0]
            .cmx
            .as_slice()
            .try_into()
            .expect("cmx is 32 bytes");
        let sap_root: [u8; 32] = blocks[0].vtx[0].outputs[0]
            .cmu
            .as_slice()
            .try_into()
            .expect("cmu is 32 bytes");
        let res = super::testkit::scan_synthetic_windows_write_behind_with_tip(
            dir.path(),
            blocks,
            &[110, 110],
            true,
            0,
            Some(tip),
            move |session, _birthday_ts| {
                use orchard::tree::MerkleHashOrchard;
                use zcash_client_backend::data_api::chain::CommitmentTreeRoot;
                use zcash_primitives::merkle_tree::HashSer;
                let orch_node = Option::from(MerkleHashOrchard::from_bytes(&orch_root))
                    .ok_or_else(|| SlipstreamError::Wallet("orch root decode".into()))?;
                let sap_node = sapling::Node::read(&sap_root[..])
                    .map_err(|e| SlipstreamError::Wallet(format!("sap root decode: {e}")))?;
                let h = zcash_protocol::consensus::BlockHeight::from(last_height as u32);
                let roots = crate::grpc::SubtreeRoots {
                    sapling: vec![CommitmentTreeRoot::from_parts(h, sap_node)],
                    orchard: vec![CommitmentTreeRoot::from_parts(h, orch_node)],
                    ironwood: vec![],
                };
                session.put_subtree_roots(&roots)
            },
        )
        .await;
        assert!(
            res.is_ok(),
            "deep-history scan over root-only shards died: {res:?}"
        );
    }

    /// -- --ignored graft_real_install`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "heavy: 2× 66k-action orchard scans; run explicitly (use --release)"]
    async fn graft_real_install_matches_build() {
        let dir = tempfile::tempdir().expect("tempdir");
        let doff = dir.path().join("off");
        let don = dir.path().join("on");
        std::fs::create_dir_all(&doff).unwrap();
        std::fs::create_dir_all(&don).unwrap();
        let (blocks, _ufvk, seed) = t10b_fixture();
        let lens = vec![blocks.len()];

        // Control: same spending account, same seeded root, graft OFF → builds.
        let off_verdicts = super::testkit::scan_synthetic_windows_write_behind_with(
            &doff,
            blocks.clone(),
            &lens,
            false,
            0,
            t10b_prepare(seed, &blocks, true),
        )
        .await
        .expect("graft-off control scan");
        assert_eq!(
            off_verdicts,
            ((0, 0), (0, 0)),
            "graft-off renders no verdicts"
        );
        // Graft ON, verify_sample=0 (pure install): shard 0 must land as the
        // root-only leaf. Correctness is carried by cap equality below — caps are
        // rebuilt from shard ROOTS, so a wrong installed root cannot hide.
        let on_verdicts = super::testkit::scan_synthetic_windows_write_behind_with(
            &don,
            blocks.clone(),
            &lens,
            true,
            0,
            t10b_prepare(seed, &blocks, true),
        )
        .await
        .expect("graft-on scan");
        // THE did-it-fire signal: exactly one orchard graft (shard 0), ZERO
        // fallbacks (the seeded root was found), nothing on sapling (empty pool).
        assert_eq!(
            on_verdicts,
            ((0, 0), (1, 0)),
            "graft-on must graft exactly shard 0 with no fallbacks"
        );

        // Semantic equality modulo the documented shard-blob class.
        let report = semantic_diff(&doff.join("data.db"), &don.join("data.db")).expect("diff");
        for t in &report.tables {
            if t.table.ends_with("_tree_shards") {
                assert_eq!(t.rows_a, t.rows_b, "shard COUNT must match: {}", t.table);
                continue;
            }
            assert!(
                t.is_clean(),
                "graft-on vs graft-off diff not clean in {}:\n{}",
                t.table,
                report.render()
            );
        }

        // Final shapes: BOTH sides end root-only — the control builds shard 0 and
        // then prunes the unreferenced interior to its root, which is precisely
        // the shape the graft installs directly (build-then-prune ≡ graft; the
        // verdict counters above are what distinguish the paths).
        let blob = |db: &std::path::Path| -> Vec<u8> {
            let conn = rusqlite::Connection::open(db).expect("open");
            conn.query_row(
                "SELECT shard_data FROM orchard_tree_shards WHERE shard_index = 0",
                [],
                |r| r.get(0),
            )
            .expect("shard 0 row")
        };
        let built = blob(&doff.join("data.db"));
        let grafted = blob(&don.join("data.db"));
        assert!(
            grafted.len() < 100,
            "grafted shard 0 must be the root-only leaf, got {} bytes",
            grafted.len()
        );
        assert!(
            built.len() < 100,
            "control's shard 0 must have pruned to the root-only leaf, got {} bytes",
            built.len()
        );

        // The owned note (in the BUILT shard 1) must be found on both sides.
        let owned_value = |db: &std::path::Path| -> i64 {
            let conn = rusqlite::Connection::open(db).expect("open");
            conn.query_row(
                "SELECT COALESCE(SUM(value),0) FROM orchard_received_notes",
                [],
                |r| r.get(0),
            )
            .expect("owned value")
        };
        assert_eq!(
            owned_value(&doff.join("data.db")),
            500_000,
            "control finds the owned note"
        );
        assert_eq!(
            owned_value(&don.join("data.db")),
            500_000,
            "grafted finds the owned note"
        );

        // And the ON side's buffer is drained (post-commit cleanup ran).
        let conn = rusqlite::Connection::open(don.join("data.db")).expect("open on");
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ext_slipstream_graft_buffer",
                [],
                |r| r.get(0),
            )
            .expect("buffer count");
        assert_eq!(left, 0, "buffer rows must be cleaned after graft/finish");
    }

    /// T10b step 2 — THE SPEND-FROM-GRAFTED-WITNESS PROOF. Restore a wallet with
    /// graft ON (shard 0 installs the seeded server root, never built locally),
    /// then SPEND the owned note that lives in built shard 1. Proving requires the
    /// witness's cap-path — which crosses the grafted shard-0 root — to satisfy
    /// the orchard Halo2 circuit against the wallet's own anchor. This is strictly
    /// stronger than the plan's darkside shape: darkside verifies no proofs, while
    /// here the circuit itself adjudicates the grafted tree. Sapling provers are
    /// structurally required by the API but an orchard-only transaction never
    /// invokes them (the stub panics if it ever were).
    /// Heavy (76k-action scan + orchard proving key + proof): run explicitly with
    /// `cargo test -p zodl-slipstream --release --lib -- --ignored graft_spend_proof`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "heavy: 76k-action scan + orchard proving; run explicitly (use --release)"]
    async fn graft_spend_proof() {
        use std::num::NonZeroU32;
        use zcash_client_backend::data_api::WalletRead;
        use zcash_client_backend::data_api::wallet::{
            ConfirmationsPolicy, SpendingKeys, create_proposed_transactions,
            input_selection::GreedyInputSelector, propose_transfer,
        };
        use zcash_client_backend::fees::{
            DustOutputPolicy, SplitPolicy, StandardFeeRule, zip317::MultiOutputChangeStrategy,
        };
        use zcash_client_backend::wallet::OvkPolicy;
        use zcash_client_backend::zip321::{Payment, TransactionRequest};
        use zcash_protocol::ShieldedPool;
        use zcash_protocol::value::Zatoshis;

        let dir = tempfile::tempdir().expect("tempdir");
        let don = dir.path().join("on");
        std::fs::create_dir_all(&don).unwrap();
        let (blocks, _ufvk_str, seed) = t10b_fixture();
        let lens = vec![blocks.len()];
        let on_verdicts = super::testkit::scan_synthetic_windows_write_behind_with(
            &don,
            blocks.clone(),
            &lens,
            true,
            0,
            t10b_prepare(seed, &blocks, true),
        )
        .await
        .expect("graft-on scan");
        assert_eq!(
            on_verdicts,
            ((0, 0), (1, 0)),
            "shard 0 must graft before the spend"
        );

        // Derive the SAME spending key the account was created from, and pay to
        // the account's own default unified address.
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &seed,
            zip32::AccountId::ZERO,
        )
        .expect("usk from seed");
        let ufvk = usk.to_unified_full_viewing_key();
        let (ua, _) = ufvk
            .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
            .expect("default address");
        let addr = zcash_address::ZcashAddress::try_from_encoded(
            &ua.encode(&zcash_protocol::consensus::MAIN_NETWORK),
        )
        .expect("own address round-trips");
        let request = TransactionRequest::new(vec![
            Payment::new(
                addr,
                Some(Zatoshis::const_from_u64(100_000)),
                None,
                None,
                None,
                vec![],
            )
            .expect("payment"),
        ])
        .expect("transaction request");

        let mut session = crate::wallet_session::WalletSession::open(
            crate::network::SlipstreamNetwork::MAIN,
            &don.join("data.db"),
        )
        .expect("open grafted wallet");
        let db = session.db_mut();
        let account_id = db.get_account_ids().expect("account ids")[0];

        // Production's exact selector + change shapes (rust/src/lib.rs zip317_helper).
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                std::num::NonZeroUsize::new(4).expect("nonzero"),
                Zatoshis::const_from_u64(10_000_000),
            ),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
            db,
            &zcash_protocol::consensus::MAIN_NETWORK,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            &zcash_client_backend::data_api::wallet::input_selection::SpendPolicy::default(),
            None,
            None,
        )
        .expect("propose_transfer must select the owned note from the grafted wallet");

        // Sapling provers: structurally required, never invoked for orchard-only.
        struct NoSapling;
        impl sapling::prover::SpendProver for NoSapling {
            type Proof = ();
            fn prepare_circuit(
                _: sapling::ProofGenerationKey,
                _: sapling::Diversifier,
                _: sapling::Rseed,
                _: sapling::value::NoteValue,
                _: jubjub::Fr,
                _: sapling::value::ValueCommitTrapdoor,
                _: bls12_381::Scalar,
                _: sapling::MerklePath,
            ) -> Option<sapling::circuit::Spend> {
                unreachable!("orchard-only tx must not prepare sapling spends")
            }
            fn create_proof<R: rand::Rng>(
                &self,
                _: sapling::circuit::Spend,
                _: &mut R,
            ) -> Self::Proof {
                unreachable!("orchard-only tx must not prove sapling spends")
            }
            fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
                unreachable!("orchard-only tx must not encode sapling spend proofs")
            }
        }
        impl sapling::prover::OutputProver for NoSapling {
            type Proof = ();
            fn prepare_circuit(
                _: &sapling::keys::EphemeralSecretKey,
                _: sapling::PaymentAddress,
                _: jubjub::Fr,
                _: sapling::value::NoteValue,
                _: sapling::value::ValueCommitTrapdoor,
            ) -> sapling::circuit::Output {
                unreachable!("orchard-only tx must not prepare sapling outputs")
            }
            fn create_proof<R: rand::Rng>(
                &self,
                _: sapling::circuit::Output,
                _: &mut R,
            ) -> Self::Proof {
                unreachable!("orchard-only tx must not prove sapling outputs")
            }
            fn encode_proof(_: Self::Proof) -> sapling::bundle::GrothProofBytes {
                unreachable!("orchard-only tx must not encode sapling output proofs")
            }
        }

        // THE THEOREM: creating the transaction runs the orchard prover, whose
        // circuit must accept a merkle path (witness) whose cap-path crosses the
        // GRAFTED shard-0 root to reach the wallet's anchor. A corrupted graft
        // cannot pass this — the proof simply fails to construct.
        let txids = create_proposed_transactions::<
            _,
            _,
            std::convert::Infallible,
            _,
            std::convert::Infallible,
            _,
        >(
            db,
            &zcash_protocol::consensus::MAIN_NETWORK,
            &zcash_client_sqlite::util::SystemClock,
            &mut rand::rand_core::UnwrapErr(rand::rngs::SysRng),
            &NoSapling,
            &NoSapling,
            &SpendingKeys::from_unified_spending_key(usk),
            OvkPolicy::Sender,
            &proposal,
            None,
        )
        .expect("orchard circuit must accept the spend witness over the grafted tree");
        assert_eq!(txids.len(), 1, "exactly one spend transaction created");
    }

    // ── The graft buffer across interruptions and wallet changes ─────────────────
    //
    // These tests drive the production write-behind lane exactly as `scan_chunks` does
    // (pending-aware facade + `PersistLane`, depth 1, `finish_graft_blocking` on the
    // success arm), one scan range at a time and in production order (a ChainTip
    // stand-in is never grafted; Historic ranges are). The synthetic sapling chains sit
    // on a PRE-HISTORY frontier a few leaves below the shard-0/1 boundary, so a range
    // crosses into shard 1 within a few dozen blocks instead of 65,536 leaves (no server
    // roots are ingested, so every clean close is a fallback build, as for a shard
    // lightwalletd has no root for).
    mod graft_buffer_recovery {
        use std::num::NonZeroU32;
        use std::path::Path;

        use incrementalmerkletree::Position;
        use incrementalmerkletree::frontier::Frontier;
        use shardtree::error::ShardTreeError;
        use zcash_client_backend::data_api::chain::{ChainState, scan_cached_blocks};
        use zcash_client_backend::data_api::{
            AccountBirthday, AccountPurpose, WalletCommitmentTrees as _, WalletWrite as _,
        };
        use zcash_client_backend::proto::compact_formats::{
            ChainMetadata, CompactBlock, CompactSaplingOutput, CompactTx,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_primitives::merkle_tree::HashSer;
        use zcash_protocol::consensus::BlockHeight;

        use crate::block_source::MemBlockSource;
        use crate::chunk::Chunk;
        use crate::error::SlipstreamError;
        use crate::oracle::semantic_diff;
        use crate::persist::{PersistLane, WriteBehindFacade};
        use crate::wallet_session::{TEST_UFVK, WalletSession};
        use crate::{AnchorRetention, AnchorRetentionInterval};

        const START: u64 = super::super::testkit::SYNTH_START;
        const SHARD: u64 = 1 << 16;

        fn h32(tag: u8, n: u64) -> [u8; 32] {
            let mut v = [0u8; 32];
            v[0] = tag;
            v[1..9].copy_from_slice(&n.to_le_bytes());
            v
        }

        /// Little-endian small integers are canonical Jubjub base-field elements.
        fn le(n: u64) -> [u8; 32] {
            let mut v = [0u8; 32];
            v[..8].copy_from_slice(&n.to_le_bytes());
            v
        }

        fn node(n: u64) -> sapling::Node {
            sapling::Node::read(&le(n)[..]).expect("small LE ints are canonical nodes")
        }

        /// The pre-history: a sapling tree of `size` leaves, as a frontier of arbitrary
        /// (valid) nodes.
        fn base_frontier(size: u64) -> Frontier<sapling::Node, 32> {
            let pos = size - 1;
            let ommers = (0..u64::from(pos.count_ones()))
                .map(|i| node(900_000 + i))
                .collect();
            Frontier::from_parts(Position::from(pos), node(800_000), ommers)
                .expect("frontier parts are consistent")
        }

        /// `count` linked blocks from START, ONE foreign sapling output each, on top of the
        /// `base_size`-leaf pre-history: block `i` holds position `base_size + i`.
        fn chain(base_size: u64, count: u64) -> Vec<CompactBlock> {
            chain_at(0, base_size, count)
        }

        /// `count` linked blocks from START + `first`, ONE foreign sapling output each, on
        /// top of a `tree_size`-leaf tree: the block at START + `first` + `j` holds position
        /// `tree_size + j`.
        fn chain_at(first: u64, tree_size: u64, count: u64) -> Vec<CompactBlock> {
            (0..count)
                .map(|j| {
                    let i = first + j;
                    let height = START + i;
                    CompactBlock {
                        height,
                        hash: h32(0xBB, height).to_vec(),
                        prev_hash: if i == 0 {
                            vec![0u8; 32]
                        } else {
                            h32(0xBB, height - 1).to_vec()
                        },
                        time: height as u32,
                        header: vec![],
                        vtx: vec![CompactTx {
                            index: 0,
                            txid: h32(0x77, height).to_vec(),
                            fee: 0,
                            spends: vec![],
                            outputs: vec![CompactSaplingOutput {
                                cmu: le(1_000_000 + i).to_vec(),
                                ephemeral_key: h32(0xEE, i).to_vec(),
                                ciphertext: vec![0xC7; 52],
                            }],
                            actions: vec![],
                            ..Default::default()
                        }],
                        chain_metadata: Some(ChainMetadata {
                            sapling_commitment_tree_size: u32::try_from(tree_size + j + 1)
                                .expect("fits"),
                            orchard_commitment_tree_size: 0,
                            ironwood_commitment_tree_size: 0,
                        }),
                    }
                })
                .collect()
        }

        /// The chain state after `blocks[..idx]` (the birthday state at START - 1 for 0).
        fn state_after(
            base: &Frontier<sapling::Node, 32>,
            blocks: &[CompactBlock],
            idx: usize,
        ) -> ChainState {
            let mut frontier = base.clone();
            for o in blocks[..idx]
                .iter()
                .flat_map(|b| b.vtx.iter())
                .flat_map(|t| t.outputs.iter())
            {
                frontier.append(sapling::Node::read(&o.cmu[..]).expect("canonical cmu"));
            }
            let (height, hash) = match idx {
                0 => (START - 1, [0u8; 32]),
                _ => (blocks[idx - 1].height, h32(0xBB, blocks[idx - 1].height)),
            };
            ChainState::new(
                BlockHeight::from(u32::try_from(height).expect("fits")),
                BlockHash(hash),
                frontier,
                Frontier::empty(),
                Frontier::empty(),
            )
        }

        fn session(dir: &Path) -> WalletSession {
            WalletSession::open(crate::Network::MainNetwork, &dir.join("data.db")).expect("open")
        }

        /// A wallet as a restore finds it: TEST_UFVK imported with the birthday state, chain
        /// tip at `tip` (no subtree roots: every pending range is Historic).
        fn open_wallet(
            dir: &Path,
            base: &Frontier<sapling::Node, 32>,
            blocks: &[CompactBlock],
            tip: u64,
        ) {
            std::fs::create_dir_all(dir).expect("wallet dir");
            let mut s = session(dir);
            let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&s.network, TEST_UFVK)
                .expect("ufvk");
            let birthday = AccountBirthday::from_parts(state_after(base, blocks, 0), None);
            s.db_mut()
                .import_account_ufvk("gap", &ufvk, &birthday, AccountPurpose::ViewOnly, None)
                .expect("import the restored account");
            s.update_chain_tip(tip).expect("chain tip");
        }

        /// The host's wallet change: upstream's account import (`add_account` →
        /// `rewind_to_chain_state` + the forced Historic re-queue), birthday at `blocks[idx]`.
        fn import_account_at(
            dir: &Path,
            base: &Frontier<sapling::Node, 32>,
            blocks: &[CompactBlock],
            idx: usize,
        ) {
            let mut s = session(dir);
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &zcash_protocol::consensus::MAIN_NETWORK,
                &[9u8; 32],
                zip32::AccountId::ZERO,
            )
            .expect("usk");
            let birthday = AccountBirthday::from_parts(state_after(base, blocks, idx), None);
            s.db_mut()
                .import_account_ufvk(
                    "imported",
                    &usk.to_unified_full_viewing_key(),
                    &birthday,
                    AccountPurpose::ViewOnly,
                    None,
                )
                .expect("import the second account");
        }

        /// How a scanned range ends in `scan_chunks`.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum End {
            /// The success arm: final drain, then `finish_graft_blocking`.
            Finish,
            /// The host's abort (`settle_passes` → `AbortHandle::abort`) lands in the final
            /// `wb.lane.drain().await` (scan.rs:526) or in `rx.recv()` after the last
            /// submit: the in-flight commit is an uncancellable `spawn_blocking` and still
            /// completes (the stop's `drain_wallet_writers` waits it out), the future is
            /// dropped, the finish never runs. Simulated as drain + drop: the same commits
            /// land, the same accumulator state is lost. With `lens` covering only the units
            /// that committed, it is also the end state of a MID-range abort, error exit or
            /// wallet-change stop (the error arm drains and skips the finish by design).
            Abort,
        }

        /// One scan range `blocks[start..start + Σlens]` through the production
        /// write-behind lane, in `lens`-block units (one `scan_cached_blocks` call each).
        #[allow(clippy::too_many_arguments)]
        async fn scan_range(
            dir: &Path,
            base: &Frontier<sapling::Node, 32>,
            blocks: &[CompactBlock],
            start: usize,
            lens: &[usize],
            graft: bool,
            anchors: Option<AnchorRetention>,
            end: End,
        ) -> Result<(), SlipstreamError> {
            let mut units = vec![];
            let mut offset = start;
            for len in lens {
                units.push((
                    state_after(base, blocks, offset),
                    &blocks[offset..offset + len],
                ));
                offset += len;
            }
            scan_units(dir, &units, graft, anchors, end).await
        }

        /// One scan range through the production write-behind lane, one
        /// `scan_cached_blocks` call per unit: its `from_state` and its blocks, which must
        /// continue that state.
        async fn scan_units(
            dir: &Path,
            units: &[(ChainState, &[CompactBlock])],
            graft: bool,
            anchors: Option<AnchorRetention>,
            end: End,
        ) -> Result<(), SlipstreamError> {
            let db_path = dir.join("data.db");
            let mut s = session(dir);
            let first_height = units
                .first()
                .and_then(|(_, window)| window.first())
                .map(|block| block.height)
                .ok_or_else(|| SlipstreamError::Wallet("a range of no blocks".into()))?;
            let mut facade = WriteBehindFacade::seed(&*s.db_mut(), first_height)
                .map_err(|e| SlipstreamError::Wallet(format!("facade seed: {e}")))?;
            let mut lane = PersistLane::open(
                &db_path,
                crate::network::SlipstreamNetwork::MAIN,
                1,
                graft,
                0,
                false,
                anchors,
            )?;
            let network = s.network;
            for (from_state, window) in units {
                let chunk = Chunk::from_blocks(0, window.to_vec());
                let source = MemBlockSource::new(&chunk);
                let from_height = BlockHeight::from(u32::try_from(window[0].height).expect("fits"));
                scan_cached_blocks(
                    &network,
                    &source,
                    &mut facade,
                    from_height,
                    from_state,
                    window.len(),
                )
                .map_err(|e| SlipstreamError::Wallet(format!("scan_cached_blocks: {e}")))?;
                if let Some(pending) = facade.take_stash() {
                    lane.submit(pending).await?;
                }
            }
            lane.drain().await?;
            if end == End::Finish {
                lane.finish_graft_blocking()?;
            }
            Ok(())
        }

        /// The graft buffer: (pool, shard_index, position) of every row.
        fn buffer_rows(dir: &Path) -> Vec<(i64, i64, i64)> {
            let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
            let mut stmt = conn
                .prepare(
                    "SELECT pool, shard_index, position FROM ext_slipstream_graft_buffer
                     ORDER BY pool, position",
                )
                .expect("prepare");
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .expect("query")
                .collect::<Result<_, _>>()
                .expect("rows")
        }

        fn suggested(dir: &Path) -> Vec<String> {
            session(dir)
                .suggest_scan_ranges()
                .expect("suggest")
                .iter()
                .map(|r| format!("{r}"))
                .collect()
        }

        /// The sapling checkpoint ids present among `heights`.
        fn sapling_checkpoints_among(dir: &Path, heights: &[u64]) -> Vec<u64> {
            let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
            heights
                .iter()
                .copied()
                .filter(|h| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM sapling_tree_checkpoints WHERE checkpoint_id = ?1",
                        [*h as i64],
                        |r| r.get::<_, i64>(0),
                    )
                    .expect("count")
                        > 0
                })
                .collect()
        }

        /// The wallet's sapling root at the checkpoint for `height` (upstream's own reader).
        fn sapling_root_at(dir: &Path, height: u64) -> Result<Option<sapling::Node>, String> {
            let mut s = session(dir);
            s.db_mut()
                .with_sapling_tree_mut::<_, _, ShardTreeError<
                    zcash_client_sqlite::wallet::commitment_tree::Error,
                >>(|tree| {
                    tree.root_at_checkpoint_id(&BlockHeight::from(
                        u32::try_from(height).expect("fits"),
                    ))
                })
                .map_err(|e| format!("{e:?}"))
        }

        /// (position of the sapling checkpoint for `height`, the tree's max leaf position).
        fn sapling_positions(dir: &Path, height: u64) -> (Option<i64>, Option<u64>) {
            let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
            let cp = conn
                .query_row(
                    "SELECT position FROM sapling_tree_checkpoints WHERE checkpoint_id = ?1",
                    [height as i64],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten();
            let mut s = session(dir);
            let max = s
                .db_mut()
                .with_sapling_tree_mut::<_, _, ShardTreeError<
                    zcash_client_sqlite::wallet::commitment_tree::Error,
                >>(|tree| tree.max_leaf_position(None))
                .ok()
                .flatten()
                .map(u64::from);
            (cp, max)
        }

        /// After an interrupted Historic range, an account import whose birthday falls
        /// inside the interrupted range's open-shard span. R crosses into shard 1 in its
        /// first unit and is interrupted before its second unit commits, so shard 1 holds
        /// buffered rows and no tree content (the unit's frontier sits in shard 0). The
        /// import (`rewind_to_chain_state`) leaves the buffer alone and re-queues the forced
        /// Historic rescan from the birthday, which seeds inside shard 1: it resumes only the
        /// buffered rows below its start, so the rescanned wallet's sapling tree is the
        /// chain's, every leaf at its own position.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn import_inside_an_interrupted_shard_keeps_every_leaf_in_place() {
            // The shard-0/1 boundary falls at block 30 (position 65,536).
            let base_size = SHARD - 30;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 80);
            let tip = blocks.last().expect("blocks").height;
            // The imported account's birthday: block 40 (position 65,546), inside the span
            // [30, 50) the interrupted unit buffered in shard 1.
            let birthday_idx = 40;
            let true_root = state_after(&base, &blocks, blocks.len())
                .final_sapling_tree()
                .root();
            let last_position = base_size + blocks.len() as u64 - 1;

            let root = tempfile::tempdir().expect("tempdir");
            for (name, interrupted) in [("twin", false), ("interrupted", true)] {
                let dir = root.path().join(name);
                open_wallet(&dir, &base, &blocks, tip);
                // R, Historic: blocks [0, 80) in units [50, 30]. Interrupted: only the first
                // unit commits (a host abort at submit(unit 2), an error exit, or the host's
                // wallet-change stop during unit 2's scan).
                let lens: &[usize] = if interrupted { &[50] } else { &[50, 30] };
                let r_end = if interrupted { End::Abort } else { End::Finish };
                scan_range(&dir, &base, &blocks, 0, lens, true, None, r_end)
                    .await
                    .expect("historic range R");
                assert_eq!(
                    buffer_rows(&dir).len(),
                    if interrupted { 20 } else { 0 },
                    "[{name}] shard 1's rows [30, 50) stay buffered only after the interruption"
                );
                import_account_at(&dir, &base, &blocks, birthday_idx);
                assert_eq!(
                    suggested(&dir),
                    ["Historic(1500040..1500080)"],
                    "[{name}] the import re-queues the forced rescan from its birthday"
                );
                // The next pass's first Historic range: the forced rescan [40, 80).
                scan_range(
                    &dir,
                    &base,
                    &blocks,
                    birthday_idx,
                    &[40],
                    true,
                    None,
                    End::Finish,
                )
                .await
                .expect("the rescan after the import");
                assert_eq!(
                    sapling_root_at(&dir, tip),
                    Ok(Some(true_root)),
                    "[{name}] the rescanned wallet's sapling root at the tip is the chain's"
                );
                assert_eq!(
                    sapling_positions(&dir, tip),
                    (Some(last_position as i64), Some(last_position)),
                    "[{name}] the tip checkpoint and the last leaf sit at the chain's last position"
                );
                assert!(
                    buffer_rows(&dir).is_empty(),
                    "[{name}] the rescan drains the graft buffer"
                );
            }
        }

        /// The restart-mid-shard resume when more than one committed unit touched the open
        /// shard: the second unit's commit inserts its `from_state` frontier inside that
        /// shard, so the store holds content for it at the resume seed. The resume keeps the
        /// valid, contiguous buffered prefix (and builds it with its first span), so the
        /// resumed wallet holds the same anchors as the uninterrupted twin.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn mid_shard_resume_keeps_the_buffered_prefix() {
            // The shard-0/1 boundary falls at block 20 (position 65,536).
            let base_size = SHARD - 20;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 150);
            let tip = blocks.last().expect("blocks").height + 20_000;
            let anchors = AnchorRetention::new(
                BlockHeight::from(u32::try_from(START).expect("fits")),
                AnchorRetentionInterval::custom(NonZeroU32::new(50).expect("nonzero")),
            );
            // Unit 2 [40, 80) holds block 50's anchor; unit 3 [80, 150) holds block 100's.
            let r_anchors = [START + 50, START + 100];
            let root = tempfile::tempdir().expect("tempdir");
            for (name, aborted) in [("twin", false), ("resumed", true)] {
                let dir = root.path().join(name);
                open_wallet(&dir, &base, &blocks, tip);
                if aborted {
                    // Abort after unit 2 committed; the next pass resumes the remainder.
                    scan_range(
                        &dir,
                        &base,
                        &blocks,
                        0,
                        &[40, 40],
                        true,
                        Some(anchors.clone()),
                        End::Abort,
                    )
                    .await
                    .expect("R up to the abort");
                    assert_eq!(
                        buffer_rows(&dir).len(),
                        60,
                        "shard 1's rows [20, 80) are buffered at the abort"
                    );
                    scan_range(
                        &dir,
                        &base,
                        &blocks,
                        80,
                        &[70],
                        true,
                        Some(anchors.clone()),
                        End::Finish,
                    )
                    .await
                    .expect("R's remainder");
                } else {
                    scan_range(
                        &dir,
                        &base,
                        &blocks,
                        0,
                        &[40, 40, 70],
                        true,
                        Some(anchors.clone()),
                        End::Finish,
                    )
                    .await
                    .expect("R");
                }
                assert_eq!(
                    sapling_checkpoints_among(&dir, &r_anchors),
                    r_anchors,
                    "[{name}] the wallet holds R's anchors"
                );
                assert!(
                    buffer_rows(&dir).is_empty(),
                    "[{name}] the graft buffer is drained"
                );
            }
        }

        /// R's durable anchors on the 50-block grid: blocks 50 and 100, both in its
        /// range-end shard.
        const R_ANCHORS: [u64; 2] = [START + 50, START + 100];

        /// The ChainTip stand-in [150, 300), never grafted, then the Historic range
        /// R = [20, 150) in two units, on a 50-block anchor grid from START. R crosses into
        /// shard 1 at block 40, so the range-end finish builds its shard-1 rows. Scans one
        /// wallet with graft off and one with graft on, the chain tip `tip_lead` blocks
        /// above the last block, and returns them in that order.
        async fn tip_range_then_r(
            root: &Path,
            tip_lead: u64,
        ) -> (std::path::PathBuf, std::path::PathBuf) {
            let base_size = SHARD - 40;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 300);
            let tip = blocks.last().expect("blocks").height + tip_lead;
            let anchors = AnchorRetention::new(
                BlockHeight::from(u32::try_from(START).expect("fits")),
                AnchorRetentionInterval::custom(NonZeroU32::new(50).expect("nonzero")),
            );
            let mut dirs = vec![];
            for (name, graft) in [("graft-off", false), ("graft-on", true)] {
                let dir = root.join(name);
                open_wallet(&dir, &base, &blocks, tip);
                scan_range(
                    &dir,
                    &base,
                    &blocks,
                    150,
                    &[150],
                    false,
                    Some(anchors.clone()),
                    End::Finish,
                )
                .await
                .expect("tip range");
                scan_range(
                    &dir,
                    &base,
                    &blocks,
                    20,
                    &[65, 65],
                    graft,
                    Some(anchors.clone()),
                    End::Finish,
                )
                .await
                .expect("historic range R");
                assert_eq!(
                    sapling_checkpoints_among(&dir, &R_ANCHORS),
                    R_ANCHORS,
                    "[{name}] the wallet keeps R's anchors"
                );
                dirs.push(dir);
            }
            let on = dirs.pop().expect("graft-on wallet");
            let off = dirs.pop().expect("graft-off wallet");
            (off, on)
        }

        /// Graft on leaves the same wallet as graft off, checkpoint rows and retained marks
        /// included, in every pool. The one documented exception is the shard blobs, which
        /// may differ in retention-flag placement (a deferred build is one `from_iter`, the
        /// incremental path several); their count still matches.
        fn assert_matches_graft_off(off: &Path, on: &Path) {
            let report =
                semantic_diff(&off.join("data.db"), &on.join("data.db")).expect("semantic diff");
            for t in &report.tables {
                if t.table.ends_with("_tree_shards") {
                    assert_eq!(
                        t.rows_a, t.rows_b,
                        "graft on leaves as many {} as graft off",
                        t.table
                    );
                    continue;
                }
                assert!(
                    t.is_clean(),
                    "graft on leaves the same {} as graft off:\n{}",
                    t.table,
                    report.render()
                );
            }
        }

        /// `finish_graft_blocking` builds the range-end shard's rows after the fact, so it
        /// registers their anchors as retained before inserting them, as every build in
        /// `sparse_put_blocks` does ([B6]): with the store at its 100-checkpoint budget (the
        /// ChainTip range's window, scanned first), shardtree's prune inside `insert_tree`
        /// would otherwise evict the anchors it just added, and the retained marks would
        /// never be written.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn finish_keeps_anchors_when_the_checkpoint_budget_is_full() {
            let root = tempfile::tempdir().expect("tempdir");
            // Not deep: the ChainTip stand-in fills the 100-checkpoint window.
            let (off, on) = tip_range_then_r(root.path(), 0).await;
            assert_matches_graft_off(&off, &on);
        }

        /// Buffered rows are built in a later call than the one that scanned them, so they
        /// carry the retentions that call gives its own commitments. Here every range lies
        /// deep below the tip (see `DEEP_HISTORY_CHECKPOINT_MARGIN`), so R's builds (its
        /// shard-0 close and the range-end finish) keep no per-block checkpoint but the
        /// durable anchors, with graft on as with graft off.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn deferred_builds_keep_no_deep_history_checkpoints_but_the_anchors() {
            let root = tempfile::tempdir().expect("tempdir");
            let (off, on) = tip_range_then_r(root.path(), 20_000).await;
            assert_matches_graft_off(&off, &on);
        }

        fn summarize(rows: &[(i64, i64, i64)]) -> String {
            match (rows.first(), rows.last()) {
                (Some(f), Some(l)) => format!(
                    "{} rows, pool {} shard {}, positions {}..={}",
                    rows.len(),
                    f.0,
                    f.1,
                    f.2,
                    l.2
                ),
                _ => "empty".into(),
            }
        }

        /// The start of the next pass with graft on, as `run_to_completion` begins it: the
        /// sweep of the graft buffer's stranded runs.
        fn start_next_pass(
            dir: &Path,
            anchors: Option<&AnchorRetention>,
        ) -> crate::persist::GraftSweep {
            let mut s = session(dir);
            crate::persist::sweep_stranded_graft_rows(
                s.db_mut(),
                &dir.join("data.db"),
                true,
                anchors,
            )
            .expect("the pass-start sweep")
        }

        /// The chain's sapling root after `blocks[..=idx]`, the root at block `START + idx`.
        fn chain_root_at(
            base: &Frontier<sapling::Node, 32>,
            blocks: &[CompactBlock],
            idx: usize,
        ) -> sapling::Node {
            state_after(base, blocks, idx + 1)
                .final_sapling_tree()
                .root()
        }

        /// The tail-shard scenario: the ChainTip stand-in [110, 200), never grafted, then the
        /// Historic range R = [20, 110) in two units, ended as `r_end` says, on a 50-block
        /// anchor grid from START and deep below the tip. R crosses into shard 1 at block 40,
        /// so its range-end finish builds its shard-1 rows [40, 110) (positions
        /// 65,536..=65,605) and their anchors at blocks 50 and 100.
        async fn tip_range_then_r_ending(dir: &Path, r_end: End) -> TailShard {
            let base_size = SHARD - 40;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 200);
            let tip = blocks.last().expect("blocks").height + 20_000;
            let anchors = AnchorRetention::new(
                BlockHeight::from(u32::try_from(START).expect("fits")),
                AnchorRetentionInterval::custom(NonZeroU32::new(50).expect("nonzero")),
            );
            open_wallet(dir, &base, &blocks, tip);
            scan_range(
                dir,
                &base,
                &blocks,
                110,
                &[90],
                false,
                Some(anchors.clone()),
                End::Finish,
            )
            .await
            .expect("tip range");
            scan_range(
                dir,
                &base,
                &blocks,
                20,
                &[45, 45],
                true,
                Some(anchors.clone()),
                r_end,
            )
            .await
            .expect("historic range R");
            assert_eq!(
                suggested(dir),
                ["Historic(1500200..1520200)", "Historic(1500000..1500020)"],
                "R is scanned, whether its finish ran or not"
            );
            TailShard {
                base,
                blocks,
                anchors,
            }
        }

        struct TailShard {
            base: Frontier<sapling::Node, 32>,
            blocks: Vec<CompactBlock>,
            anchors: AnchorRetention,
        }

        /// R's durable anchors, blocks 50 and 100, in its tail shard.
        const TAIL_ANCHORS: [u64; 2] = [START + 50, START + 100];

        /// An abort that lands in a Historic range's final drain (or in `rx.recv()` after its
        /// last submit) skips the range-end finish: every unit commits and R is marked
        /// Scanned, but its tail-shard rows stay buffered, and no later range resumes them
        /// (the next Historic range down starts below R; the ranges above were scanned first,
        /// and the newest pending one seeds in shard 1 above the rows). The next pass's start
        /// sweep builds them as the finish would have, so the aborted wallet ends exactly like
        /// the twin whose R finished.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_builds_the_tail_shard_an_abort_left_buffered() {
            let root = tempfile::tempdir().expect("tempdir");
            let mut dirs = vec![];
            for (name, r_end, buffered) in [("twin", End::Finish, 0), ("aborted", End::Abort, 70)] {
                let dir = root.path().join(name);
                let t = tip_range_then_r_ending(&dir, r_end).await;
                assert_eq!(
                    buffer_rows(&dir).len(),
                    buffered,
                    "[{name}] R's shard-1 rows stay buffered only after the abort"
                );
                // The next pass: its start sweep, then the next Historic range down, [0, 20).
                let sweep = start_next_pass(&dir, Some(&t.anchors));
                assert_eq!(
                    sweep,
                    crate::persist::GraftSweep {
                        built_rows: buffered as u64,
                        ..Default::default()
                    },
                    "[{name}] the sweep builds the stranded rows and queues no rescan"
                );
                scan_range(
                    &dir,
                    &t.base,
                    &t.blocks,
                    0,
                    &[20],
                    true,
                    Some(t.anchors.clone()),
                    End::Finish,
                )
                .await
                .expect("historic range below R");
                let rows = buffer_rows(&dir);
                assert!(
                    rows.is_empty(),
                    "[{name}] the graft buffer is drained: {}",
                    summarize(&rows)
                );
                assert_eq!(
                    sapling_checkpoints_among(&dir, &TAIL_ANCHORS),
                    TAIL_ANCHORS,
                    "[{name}] the wallet holds R's anchors"
                );
                for (anchor, idx) in TAIL_ANCHORS.iter().zip([50, 100]) {
                    assert_eq!(
                        sapling_root_at(&dir, *anchor),
                        Ok(Some(chain_root_at(&t.base, &t.blocks, idx))),
                        "[{name}] the root at R's anchor {anchor} is the chain's"
                    );
                }
                dirs.push(dir);
            }
            let report = semantic_diff(&dirs[0].join("data.db"), &dirs[1].join("data.db"))
                .expect("semantic diff");
            assert!(
                report.is_clean(),
                "the aborted wallet ends as the twin did, checkpoints and retained marks included:\n{}",
                report.render()
            );
        }

        /// Rows an engine buffered before the graft stream got the per-call deep-history doom
        /// carry every block's checkpoint. Built as they are, the deferred build's budget
        /// cutoff keeps them all (the store holds fewer than 100 checkpoints): checkpoints
        /// graft off never creates. The sweep dooms each by its own block's depth below the
        /// tip, so the wallet ends as the twin whose R finished.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_dooms_deep_checkpoints_in_rows_buffered_undoomed() {
            let root = tempfile::tempdir().expect("tempdir");
            let twin = root.path().join("twin");
            let t = tip_range_then_r_ending(&twin, End::Finish).await;
            let legacy = root.path().join("legacy");
            tip_range_then_r_ending(&legacy, End::Abort).await;
            // Each block holds one commitment (block i at position SHARD - 40 + i), so an
            // undoomed stream gave every row its block's checkpoint.
            let conn = rusqlite::Connection::open(legacy.join("data.db")).expect("side conn");
            let undoomed = conn
                .execute(
                    "UPDATE ext_slipstream_graft_buffer
                     SET retention_kind = 2, checkpoint_height = ?1 + position - ?2, marking = 0",
                    rusqlite::params![START as i64, (SHARD - 40) as i64],
                )
                .expect("give every buffered row its block's checkpoint");
            assert_eq!(undoomed, 70, "all of R's shard-1 rows are buffered");
            for dir in [&twin, &legacy] {
                start_next_pass(dir, Some(&t.anchors));
                scan_range(
                    dir,
                    &t.base,
                    &t.blocks,
                    0,
                    &[20],
                    true,
                    Some(t.anchors.clone()),
                    End::Finish,
                )
                .await
                .expect("historic range below R");
            }
            let report = semantic_diff(&twin.join("data.db"), &legacy.join("data.db"))
                .expect("semantic diff");
            assert!(
                report.is_clean(),
                "the wallet keeps no deep checkpoint but R's anchors, as the twin:\n{}",
                report.render()
            );
        }

        /// A stranded run the sweep cannot build as it is: its last row is not the leaf the
        /// tree holds there (the ChainTip range inserted it as its frontier), or a row inside
        /// it disagrees with the leaf R's second unit inserted as its frontier, so the build
        /// is refused. The sweep deletes the run and queues the scanned blocks holding it,
        /// R's [40, 110); the rescan puts the chain's leaves and R's anchors in the tree.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_rescans_a_stranded_run_it_cannot_build() {
            let root = tempfile::tempdir().expect("tempdir");
            // (case, the buffered row replaced): the run's last position, and the position of
            // R's second unit's frontier (its first unit ends at block 64).
            for (case, position) in [
                ("unverifiable end", 65_605i64),
                ("conflicting interior", 65_560),
            ] {
                let dir = root.path().join(case.replace(' ', "-"));
                let t = tip_range_then_r_ending(&dir, End::Abort).await;
                let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
                let changed = conn
                    .execute(
                        "UPDATE ext_slipstream_graft_buffer SET commitment = ?1 WHERE position = ?2",
                        rusqlite::params![le(7).to_vec(), position],
                    )
                    .expect("replace a buffered row");
                assert_eq!(changed, 1, "[{case}] the row is buffered");
                let sweep = start_next_pass(&dir, Some(&t.anchors));
                assert_eq!(
                    sweep,
                    crate::persist::GraftSweep {
                        discarded_rows: 70,
                        rescans: vec![
                            BlockHeight::from(u32::try_from(START + 40).expect("fits"))
                                ..BlockHeight::from(u32::try_from(START + 110).expect("fits"))
                        ],
                        ..Default::default()
                    },
                    "[{case}] the sweep deletes the run and queues R's blocks holding it"
                );
                let rows = buffer_rows(&dir);
                assert!(
                    rows.is_empty(),
                    "[{case}] the run is deleted: {}",
                    summarize(&rows)
                );
                assert_eq!(
                    suggested(&dir),
                    [
                        "Historic(1500200..1520200)",
                        "Historic(1500040..1500110)",
                        "Historic(1500000..1500020)"
                    ],
                    "[{case}] the rescan is queued"
                );
                scan_range(
                    &dir,
                    &t.base,
                    &t.blocks,
                    40,
                    &[70],
                    true,
                    Some(t.anchors.clone()),
                    End::Finish,
                )
                .await
                .expect("the queued rescan");
                assert_eq!(
                    sapling_checkpoints_among(&dir, &TAIL_ANCHORS),
                    TAIL_ANCHORS,
                    "[{case}] the wallet holds R's anchors"
                );
                for (anchor, idx) in TAIL_ANCHORS.iter().zip([50, 100]) {
                    assert_eq!(
                        sapling_root_at(&dir, *anchor),
                        Ok(Some(chain_root_at(&t.base, &t.blocks, idx))),
                        "[{case}] the root at R's anchor {anchor} is the chain's"
                    );
                }
            }
        }

        /// R = [20, 110) is interrupted after its first unit, so its rows [40, 65) in shard 1
        /// end right before its still-queued remainder. A newer pending Historic range also
        /// seeds in shard 1, above them, and is scanned first: its seed would delete them.
        /// Nothing the wallet holds checks where they end (the tree holds no leaf there, and
        /// they do not complete their shard); the remainder starting right after them is only
        /// their position. So the next pass's start sweep deletes them and queues their blocks
        /// [40, 65) for a rescan, which joins the remainder, and the rescanned [40, 110) ends
        /// with the chain's tree, R's anchors included.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_rescans_a_committed_prefix_it_cannot_check() {
            let base_size = SHARD - 40;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 200);
            let tip = blocks.last().expect("blocks").height + 20_000;
            let anchors = AnchorRetention::new(
                BlockHeight::from(u32::try_from(START).expect("fits")),
                AnchorRetentionInterval::custom(NonZeroU32::new(50).expect("nonzero")),
            );
            let root = tempfile::tempdir().expect("tempdir");
            let dir = root.path().join("interrupted");
            open_wallet(&dir, &base, &blocks, tip);
            scan_range(
                &dir,
                &base,
                &blocks,
                110,
                &[90],
                false,
                Some(anchors.clone()),
                End::Finish,
            )
            .await
            .expect("tip range");
            scan_range(
                &dir,
                &base,
                &blocks,
                20,
                &[45],
                true,
                Some(anchors.clone()),
                End::Abort,
            )
            .await
            .expect("R's first unit");
            assert_eq!(
                buffer_rows(&dir).len(),
                25,
                "shard 1's rows [40, 65) are buffered"
            );
            assert_eq!(
                suggested(&dir),
                [
                    "Historic(1500200..1520200)",
                    "Historic(1500065..1500110)",
                    "Historic(1500000..1500020)"
                ],
                "the newer range comes before R's remainder"
            );
            assert_eq!(
                start_next_pass(&dir, Some(&anchors)),
                crate::persist::GraftSweep {
                    discarded_rows: 25,
                    rescans: vec![
                        BlockHeight::from(u32::try_from(START + 40).expect("fits"))
                            ..BlockHeight::from(u32::try_from(START + 65).expect("fits"))
                    ],
                    ..Default::default()
                },
                "the sweep deletes the prefix and queues the blocks holding it"
            );
            let rows = buffer_rows(&dir);
            assert!(
                rows.is_empty(),
                "the prefix is deleted: {}",
                summarize(&rows)
            );
            assert_eq!(
                suggested(&dir),
                [
                    "Historic(1500200..1520200)",
                    "Historic(1500040..1500110)",
                    "Historic(1500000..1500020)"
                ],
                "the rescan joins R's remainder"
            );
            scan_range(
                &dir,
                &base,
                &blocks,
                40,
                &[70],
                true,
                Some(anchors.clone()),
                End::Finish,
            )
            .await
            .expect("the rescan and R's remainder");
            assert_eq!(
                sapling_checkpoints_among(&dir, &TAIL_ANCHORS),
                TAIL_ANCHORS,
                "the wallet holds R's anchors"
            );
            for (anchor, idx) in TAIL_ANCHORS.iter().zip([50, 100]) {
                assert_eq!(
                    sapling_root_at(&dir, *anchor),
                    Ok(Some(chain_root_at(&base, &blocks, idx))),
                    "the root at R's anchor {anchor} is the chain's"
                );
            }
            assert!(buffer_rows(&dir).is_empty(), "the graft buffer is drained");
        }

        /// A stranded run that completes its shard, which only the shard's stored root can
        /// check. R starts inside shard 1, which holds no content when R seeds (the wallet's
        /// birthday is in shard 0, and no range above R was scanned), so R buffers its rows.
        /// Its one unit ends on shard 1's last position, so no shard close builds them, and
        /// the stop skips the range-end finish. The tree holds no leaf where they end (R's own
        /// `from_state` frontier sits right before them). The subtree roots are ingested
        /// before R is scanned, as every pass start ingests them.
        ///
        /// - With the server's root for shard 1 stored, the sweep builds the run: the shard's
        ///   root computed from the run and R's frontier is that root.
        /// - With one row stale (another chain's commitment), the tree refuses the run, and
        ///   the sweep rescans R's blocks.
        /// - With no root stored, nothing checks the run (that it reaches the end of its
        ///   shard is only its position), and the sweep rescans R's blocks.
        ///
        /// Every wallet then holds the chain's sapling tree at R's last block.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_builds_a_run_completing_its_shard_only_on_its_stored_root() {
            use incrementalmerkletree::Level;
            use zcash_client_backend::data_api::chain::CommitmentTreeRoot;

            // The birthday frontier sits in shard 0. R's `from_state` is the tree at block 0
            // (no test scans it), 20 leaves short of shard 1's end; R is blocks [1, 21).
            let birthday = base_frontier(SHARD - 40);
            let r_tree_size = 2 * SHARD - 20;
            let r_frontier = base_frontier(r_tree_size);
            let r_blocks = chain_at(1, r_tree_size, 20);
            let r_state = ChainState::new(
                BlockHeight::from(u32::try_from(START).expect("fits")),
                BlockHash(h32(0xBB, START)),
                r_frontier.clone(),
                Frontier::empty(),
                Frontier::empty(),
            );
            let r_last = r_blocks.last().expect("blocks").height;
            let mut chain_tree = r_frontier.clone();
            for o in r_blocks
                .iter()
                .flat_map(|b| b.vtx.iter())
                .flat_map(|t| t.outputs.iter())
            {
                chain_tree.append(sapling::Node::read(&o.cmu[..]).expect("canonical cmu"));
            }
            let completed = chain_tree.value().expect("the chain's tree is not empty");
            assert_eq!(
                u64::from(completed.position()),
                2 * SHARD - 1,
                "R ends on shard 1's last position"
            );
            // The roots a lightwalletd serves for shards 0 and 1. Shard 0's is the one R's
            // frontier carries (its level-16 ommer).
            let shard_0_root = *r_frontier
                .value()
                .and_then(|f| f.ommers().last())
                .expect("R's frontier lies above shard 0");
            let roots = crate::grpc::SubtreeRoots {
                sapling: vec![
                    CommitmentTreeRoot::from_parts(
                        BlockHeight::from(u32::try_from(START).expect("fits")),
                        shard_0_root,
                    ),
                    CommitmentTreeRoot::from_parts(
                        BlockHeight::from(u32::try_from(r_last).expect("fits")),
                        completed.root(Some(Level::from(16))),
                    ),
                ],
                orchard: vec![],
                ironwood: vec![],
            };
            let rescan = vec![
                BlockHeight::from(u32::try_from(START + 1).expect("fits"))
                    ..BlockHeight::from(u32::try_from(r_last + 1).expect("fits")),
            ];

            let root = tempfile::tempdir().expect("tempdir");
            for (case, slug, stored_root, stale_position) in [
                ("the server's root", "server-root", true, None),
                ("a stale row", "stale-row", true, Some(2 * SHARD - 10)),
                ("no stored root", "no-root", false, None),
            ] {
                let built = stored_root && stale_position.is_none();
                let dir = root.path().join(slug);
                open_wallet(&dir, &birthday, &r_blocks, r_last);
                if stored_root {
                    session(&dir)
                        .put_subtree_roots(&roots)
                        .expect("the pass-start root ingest");
                }
                scan_units(
                    &dir,
                    &[(r_state.clone(), &r_blocks[..])],
                    true,
                    None,
                    End::Abort,
                )
                .await
                .expect("R, stopped before its finish");
                assert_eq!(
                    buffer_rows(&dir).len(),
                    20,
                    "[{case}] R's rows stay buffered in shard 1"
                );
                if let Some(position) = stale_position {
                    let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
                    let changed = conn
                        .execute(
                            "UPDATE ext_slipstream_graft_buffer SET commitment = ?1 WHERE position = ?2",
                            rusqlite::params![le(7).to_vec(), i64::try_from(position).expect("fits")],
                        )
                        .expect("replace a buffered row");
                    assert_eq!(changed, 1, "[{case}] the row is buffered");
                }
                let expected = if built {
                    crate::persist::GraftSweep {
                        built_rows: 20,
                        ..Default::default()
                    }
                } else {
                    crate::persist::GraftSweep {
                        discarded_rows: 20,
                        rescans: rescan.clone(),
                        ..Default::default()
                    }
                };
                assert_eq!(
                    start_next_pass(&dir, None),
                    expected,
                    "[{case}] the sweep builds the run only when the shard's root is the one stored"
                );
                let rows = buffer_rows(&dir);
                assert!(
                    rows.is_empty(),
                    "[{case}] the run leaves the buffer: {}",
                    summarize(&rows)
                );
                if !built {
                    scan_units(
                        &dir,
                        &[(r_state.clone(), &r_blocks[..])],
                        true,
                        None,
                        End::Finish,
                    )
                    .await
                    .expect("the rescan of R");
                }
                assert_eq!(
                    sapling_root_at(&dir, r_last),
                    Ok(Some(chain_tree.root())),
                    "[{case}] the wallet's sapling root at R's last block is the chain's"
                );
                assert!(
                    buffer_rows(&dir).is_empty(),
                    "[{case}] the graft buffer is drained"
                );
            }
        }

        /// A buffered row that will not decode neither stops the sweep nor fails the pass. No
        /// range can resume or build the rows of its shard, so the sweep queues the scanned
        /// blocks holding them for a rescan, by their positions alone, and deletes them; the
        /// other shards are swept as usual. R's tail-shard rows (shard 1) are stranded here, as
        /// an abort in its final drain leaves them, and the buffer also holds a row whose
        /// commitment is three bytes long:
        ///
        /// - in another shard, shard 0, at the position R's block 30 holds: that block is
        ///   queued for a rescan, and R's tail rows are built as usual;
        /// - in shard 1 itself, at a position of the pending range above R: the blocks of R
        ///   holding the tail rows are queued for a rescan. The next Historic range,
        ///   [200, 20200), then seeds in shard 1 and scans, and the rescan of R's blocks puts
        ///   R's anchors in the tree.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn next_pass_sweeps_past_a_row_that_will_not_decode() {
            let height = |i: u64| BlockHeight::from(u32::try_from(START + i).expect("fits"));
            let root = tempfile::tempdir().expect("tempdir");
            for (case, shard, position, sweep) in [
                (
                    "another shard",
                    0i64,
                    i64::try_from(SHARD - 10).expect("fits"),
                    crate::persist::GraftSweep {
                        built_rows: 70,
                        discarded_rows: 1,
                        rescans: vec![height(30)..height(31)],
                    },
                ),
                (
                    "its own shard",
                    1,
                    65_700,
                    crate::persist::GraftSweep {
                        discarded_rows: 71,
                        rescans: vec![height(40)..height(110)],
                        ..Default::default()
                    },
                ),
            ] {
                let dir = root.path().join(case.replace(' ', "-"));
                let t = tip_range_then_r_ending(&dir, End::Abort).await;
                let conn = rusqlite::Connection::open(dir.join("data.db")).expect("side conn");
                conn.execute(
                    "INSERT INTO ext_slipstream_graft_buffer
                     (pool, shard_index, position, commitment, retention_kind)
                     VALUES (2, ?1, ?2, ?3, 0)",
                    rusqlite::params![shard, position, vec![0xC7u8; 3]],
                )
                .expect("buffer a row that will not decode");
                assert_eq!(
                    start_next_pass(&dir, Some(&t.anchors)),
                    sweep,
                    "[{case}] the sweep rescans the blocks of the shard it cannot decode, and goes on"
                );
                let rows = buffer_rows(&dir);
                assert!(
                    rows.is_empty(),
                    "[{case}] the buffer is drained: {}",
                    summarize(&rows)
                );
                let mut blocks = t.blocks.clone();
                if shard == 1 {
                    assert_eq!(
                        suggested(&dir),
                        [
                            "Historic(1500200..1520200)",
                            "Historic(1500040..1500110)",
                            "Historic(1500000..1500020)"
                        ],
                        "[{case}] R's blocks holding its tail rows are queued for a rescan"
                    );
                    // The pass goes on: the next Historic range seeds in shard 1 and scans
                    // (its first blocks stand in for all of it) ...
                    blocks.extend(chain_at(200, SHARD - 40 + 200, 10));
                    scan_range(
                        &dir,
                        &t.base,
                        &blocks,
                        200,
                        &[10],
                        true,
                        Some(t.anchors.clone()),
                        End::Finish,
                    )
                    .await
                    .expect("the next Historic range seeds in shard 1 and scans");
                    // ... and the rescan of R's blocks puts its tail shard in the tree.
                    scan_range(
                        &dir,
                        &t.base,
                        &blocks,
                        40,
                        &[70],
                        true,
                        Some(t.anchors.clone()),
                        End::Finish,
                    )
                    .await
                    .expect("the rescan of R's blocks");
                }
                assert_eq!(
                    sapling_checkpoints_among(&dir, &TAIL_ANCHORS),
                    TAIL_ANCHORS,
                    "[{case}] the wallet holds R's anchors"
                );
                for (anchor, idx) in TAIL_ANCHORS.iter().zip([50, 100]) {
                    assert_eq!(
                        sapling_root_at(&dir, *anchor),
                        Ok(Some(chain_root_at(&t.base, &blocks, idx))),
                        "[{case}] the root at R's anchor {anchor} is the chain's"
                    );
                }
                assert!(
                    buffer_rows(&dir).is_empty(),
                    "[{case}] the graft buffer is drained"
                );
            }
        }

        /// An account import whose birthday lies ABOVE an interrupted range's committed
        /// prefix: the forced Historic rescan [b, tip] coalesces with R's still-Historic
        /// remainder, so the next pass's first range starts right after the buffered rows.
        /// The pass-start sweep leaves them to it (that range is the first to seed in their
        /// shard), and the resumed range ends with the chain's sapling tree.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn import_above_the_committed_prefix_resumes_contiguously() {
            let base_size = SHARD - 30;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 80);
            let tip = blocks.last().expect("blocks").height;
            let true_root = state_after(&base, &blocks, blocks.len())
                .final_sapling_tree()
                .root();
            let root = tempfile::tempdir().expect("tempdir");
            let dir = root.path().join("interrupted");
            open_wallet(&dir, &base, &blocks, tip);
            // R, Historic: blocks [0, 80). Only its first unit [0, 50) commits, so shard 1's
            // rows [30, 50) stay buffered.
            scan_range(&dir, &base, &blocks, 0, &[50], true, None, End::Abort)
                .await
                .expect("historic range R, first unit");
            assert_eq!(
                buffer_rows(&dir).len(),
                20,
                "shard 1's rows [30, 50) are buffered"
            );
            import_account_at(&dir, &base, &blocks, 60);
            assert_eq!(
                suggested(&dir),
                ["Historic(1500050..1500080)"],
                "the import's rescan coalesces with R's remainder"
            );
            assert_eq!(
                start_next_pass(&dir, None),
                crate::persist::GraftSweep::default(),
                "the sweep leaves the rows R's remainder resumes"
            );
            assert_eq!(buffer_rows(&dir).len(), 20, "the rows are still buffered");
            scan_range(&dir, &base, &blocks, 50, &[30], true, None, End::Finish)
                .await
                .expect("R's remainder");
            assert_eq!(
                sapling_root_at(&dir, tip),
                Ok(Some(true_root)),
                "the resumed wallet's sapling root at the tip is the chain's"
            );
            assert!(buffer_rows(&dir).is_empty(), "the graft buffer is drained");
        }

        /// A reorg recovery truncates the wallet (`WalletSession::truncate_to_height`, as the
        /// scheduler's ScanContinuity arm calls it) and queues the blocks above the
        /// truncation again, possibly from another chain. Their graft-buffer rows go with
        /// them; the rows of the blocks the wallet keeps stay for the range that continues
        /// them, and the rescan ends with the chain's sapling tree.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_reorg_truncation_drops_the_buffered_rows_above_it() {
            let base_size = SHARD - 30;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 80);
            let tip = blocks.last().expect("blocks").height;
            let true_root = state_after(&base, &blocks, blocks.len())
                .final_sapling_tree()
                .root();
            let root = tempfile::tempdir().expect("tempdir");
            let dir = root.path().join("reorged");
            open_wallet(&dir, &base, &blocks, tip);
            // R, Historic: blocks [0, 70) in units [50, 20], stopped before its finish, so
            // shard 1's rows [30, 70) stay buffered.
            scan_range(&dir, &base, &blocks, 0, &[50, 20], true, None, End::Abort)
                .await
                .expect("historic range R");
            assert_eq!(
                buffer_rows(&dir).len(),
                40,
                "shard 1's rows [30, 70) are buffered"
            );
            let truncated_to = session(&dir)
                .truncate_to_height(BlockHeight::from(u32::try_from(START + 59).expect("fits")))
                .expect("truncate");
            // The wallet keeps blocks [0, kept).
            let kept = u64::from(u32::from(truncated_to)) + 1 - START;
            assert!(
                (31..70).contains(&kept),
                "the truncation keeps some of shard 1's buffered blocks and drops the others \
                 (it keeps [0, {kept}))"
            );
            let positions: Vec<i64> = buffer_rows(&dir).iter().map(|row| row.2).collect();
            assert_eq!(
                positions,
                (SHARD..base_size + kept)
                    .map(|p| i64::try_from(p).expect("fits"))
                    .collect::<Vec<_>>(),
                "only the rows of the blocks the wallet still holds stay buffered"
            );
            let idx = usize::try_from(kept).expect("fits");
            scan_range(
                &dir,
                &base,
                &blocks,
                idx,
                &[blocks.len() - idx],
                true,
                None,
                End::Finish,
            )
            .await
            .expect("the rescan");
            assert_eq!(
                sapling_root_at(&dir, tip),
                Ok(Some(true_root)),
                "the rescanned wallet's sapling root at the tip is the chain's"
            );
            assert!(buffer_rows(&dir).is_empty(), "the graft buffer is drained");
        }

        /// An account import rewinds the wallet to the chain state below its birthday and
        /// queues every later block again (upstream `add_account` → `rewind_to_chain_state`).
        /// The engine's import (`WalletSession::import_account`) drops the graft-buffer rows
        /// of those blocks at once, and the rescan continues the rows below the birthday.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_import_drops_the_buffered_rows_its_rescan_covers() {
            let base_size = SHARD - 30;
            let base = base_frontier(base_size);
            let blocks = chain(base_size, 80);
            let tip = blocks.last().expect("blocks").height;
            let true_root = state_after(&base, &blocks, blocks.len())
                .final_sapling_tree()
                .root();
            let root = tempfile::tempdir().expect("tempdir");
            let dir = root.path().join("imported");
            open_wallet(&dir, &base, &blocks, tip);
            // R, Historic: only its first unit [0, 50) commits, so shard 1's rows [30, 50)
            // stay buffered.
            scan_range(&dir, &base, &blocks, 0, &[50], true, None, End::Abort)
                .await
                .expect("historic range R, first unit");
            assert_eq!(
                buffer_rows(&dir).len(),
                20,
                "shard 1's rows [30, 50) are buffered"
            );
            // A second account through the engine's import, birthday at block 40
            // (position 65,546).
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &zcash_protocol::consensus::MAIN_NETWORK,
                &[9u8; 32],
                zip32::AccountId::ZERO,
            )
            .expect("usk");
            let birthday = AccountBirthday::from_parts(state_after(&base, &blocks, 40), None);
            session(&dir)
                .import_account_with_birthday(&usk.to_unified_full_viewing_key(), &birthday)
                .expect("import the second account");
            let positions: Vec<i64> = buffer_rows(&dir).iter().map(|row| row.2).collect();
            assert_eq!(
                positions,
                (65_536..65_546).collect::<Vec<i64>>(),
                "only the rows below the birthday stay buffered"
            );
            assert_eq!(
                suggested(&dir),
                ["Historic(1500040..1500080)"],
                "the import queues the blocks from its birthday again"
            );
            scan_range(&dir, &base, &blocks, 40, &[40], true, None, End::Finish)
                .await
                .expect("the rescan");
            assert_eq!(
                sapling_root_at(&dir, tip),
                Ok(Some(true_root)),
                "the rescanned wallet's sapling root at the tip is the chain's"
            );
            assert!(buffer_rows(&dir).is_empty(), "the graft buffer is drained");
        }
    }
}
