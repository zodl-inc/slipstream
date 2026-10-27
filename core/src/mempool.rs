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

//! At-tip mempool monitoring (T8.2). One session = one `GetMempoolStream` from
//! connect to server-close; the engine's follow loop runs sessions strictly
//! BETWEEN sync passes (never concurrent with a scan — single-writer by
//! construction, Deviation D2). Decryption + storage go through upstream's own
//! `decrypt_and_store_transaction` (the old SDK's exact write path,
//! `rust/src/lib.rs:2070`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{WalletRead, wallet::decrypt_and_store_transaction};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};

use crate::{
    config::EngineConfig, error::SlipstreamError, events::Progress, grpc,
    wallet_session::WalletSession,
};

/// A mempool session ends for one of these benign reasons (errors are `Err`).
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// Server closed the stream — a new block was mined (probe + pass NOW).
    BlockBoundary,
    /// No message within the session's idle bound ([`mempool_session_idle`]) — reconnect
    /// after a tip probe (dead-connection vs quiet-mempool are indistinguishable; Deviation D6).
    IdleReconnect,
}

/// Idle bound per session before NU7 (75 s target block spacing). Deliberately NOT the
/// hardening1 `grpc::STREAM_IDLE_TIMEOUT` (30 s) — an empty mempool is legitimate silence,
/// not a stalled connection (Deviation D6).
pub const MEMPOOL_SESSION_IDLE: Duration = Duration::from_secs(60);

/// Idle bound per session from NU7, whose target block spacing is a third of the 75 s
/// before it, so a dead stream would otherwise hide more than two blocks. Still above
/// `grpc::STREAM_IDLE_TIMEOUT` — an empty mempool is legitimately silent (D6) — and below
/// the Tor client's default 60 s response-header timeout.
pub const MEMPOOL_SESSION_IDLE_NU7: Duration = Duration::from_secs(40);

/// The idle bound for a session that waits on the block after `tip`:
/// [`MEMPOOL_SESSION_IDLE_NU7`] once NU7 is active at `tip + 1`, [`MEMPOOL_SESSION_IDLE`]
/// before.
pub fn mempool_session_idle<P: Parameters>(params: &P, tip: u64) -> Duration {
    let next = u32::try_from(tip.saturating_add(1)).unwrap_or(u32::MAX);
    if params.is_nu_active(NetworkUpgrade::Nu7, BlockHeight::from_u32(next)) {
        MEMPOOL_SESSION_IDLE_NU7
    } else {
        MEMPOOL_SESSION_IDLE
    }
}

/// Dedupe-set cap: lightwalletd replays the whole mempool on reconnect
/// (`mempool.go` `g_txList`), so `seen` persists across sessions; clear it when
/// it exceeds this bound (mempool churn makes unbounded growth possible).
pub const SEEN_TXIDS_CAP: usize = 4096;

// Compile-time invariant: the dedupe set must comfortably exceed a realistic
// live mempool so reconnect-replays don't churn it (a runtime `assert!` on a
// constant folds to `assert!(true)` and is optimized out — clippy flags it).
const _: () = assert!(
    SEEN_TXIDS_CAP >= 1024,
    "SEEN_TXIDS_CAP must comfortably exceed a live mempool to avoid churn"
);

/// Outcome counters for one session (logged; the enhanced bump goes to
/// [`Progress`], not here).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub received: u64,
    pub stored_hits: u64,
}

/// Runs one mempool session against `config.endpoint`.
///
/// For each streamed tx: dedupe by txid → parse (`Transaction::read` with a
/// placeholder `BranchId::Sapling`, which is harmless: v5 and v6 transactions carry
/// their consensus branch id in the header, and `read` uses that instead; for v4 and
/// earlier it is only recorded on the parsed value, where nothing but the v4
/// signature hash reads it — and nothing signs a transaction parsed here, so the
/// placeholder branch id never reaches a v4 signature hash) →
/// `decrypt_and_store_transaction(…, mined_height=None)` (upstream's relevance
/// gate stores ONLY wallet-involving txs — `ll/wallet.rs:655-662`) → hit check
/// via `WalletRead::get_transaction(txid)` → `progress.add_enhanced(1)` per NEW
/// stored hit (Swift's `foundTransactions` path fires off this counter, fact C).
///
/// We pass `mined_height = None` even though `raw.height` carries the server tip
/// (Deviation D1): the row converges to its true mined height when the block is
/// scanned by the next follow pass.
///
/// Parse failures on a single tx are logged and SKIPPED (a malformed mempool
/// entry must not kill monitoring); transport errors return `Err` (the caller
/// applies the non-fatal policy).
///
/// `idle` bounds BOTH the stream open and each `next()`; production passes
/// [`mempool_session_idle`] — [`MEMPOOL_SESSION_IDLE`] before NU7,
/// [`MEMPOOL_SESSION_IDLE_NU7`] from it (tests use a short value). A timeout yields a
/// benign [`SessionEnd::IdleReconnect`], never an error.
pub async fn run_session(
    config: &EngineConfig,
    progress: Option<Arc<Progress>>,
    seen: &mut HashSet<[u8; 32]>,
    idle: Duration,
    tor: Option<&crate::connector::TorConn>,
) -> Result<(SessionEnd, SessionStats), SlipstreamError> {
    let mut stats = SessionStats::default();
    if seen.len() > SEEN_TXIDS_CAP {
        seen.clear(); // bounded memory; worst case = one re-emit per live tx
    }
    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = crate::connector::connect_via(
        &config.endpoint,
        tor,
        crate::connector::ConnPurpose::MetadataUnique,
    )
    .await?;
    // Bound the OPEN by `idle`, NOT the gRPC unary timeout: lightwalletd sends
    // GetMempoolStream response headers lazily (see grpc::open_mempool_stream),
    // so a quiet mempool legitimately blocks the open past 30 s. An over-idle
    // open is a benign reconnect (Deviation D6), not a failure.
    let mut stream = match tokio::time::timeout(idle, grpc::open_mempool_stream(&mut client)).await
    {
        Err(_elapsed) => return Ok((SessionEnd::IdleReconnect, stats)),
        Ok(res) => res?,
    };
    loop {
        let next = tokio::time::timeout(idle, stream.next()).await;
        let raw = match next {
            Err(_elapsed) => return Ok((SessionEnd::IdleReconnect, stats)),
            Ok(None) => return Ok((SessionEnd::BlockBoundary, stats)),
            Ok(Some(Err(status))) => {
                return Err(SlipstreamError::Transport(format!(
                    "mempool stream: {status}"
                )));
            }
            Ok(Some(Ok(raw))) => raw,
        };
        stats.received += 1;
        // NOTE: raw.height is the SERVER TIP, not 0 (lightwalletd mempool.go;
        // fact E). We deliberately pass mined_height=None — Deviation D1.
        // Placeholder branch id — harmless, see this function's doc.
        let tx = match Transaction::read(&raw.data[..], BranchId::Sapling) {
            Ok(tx) => tx,
            Err(e) => {
                warn!(%e, "mempool tx parse failed — skipping entry");
                continue;
            }
        };
        // TxId: AsRef<[u8; 32]> (zcash_protocol txid.rs) — annotate so the deref
        // picks the array impl.
        let txid: [u8; 32] = *tx.txid().as_ref();
        if !seen.insert(txid) {
            continue; // replayed on reconnect — already processed
        }
        decrypt_and_store_transaction(&config.network, session.db_mut(), &tx, None)
            .map_err(|e| SlipstreamError::Wallet(format!("mempool decrypt_and_store: {e}")))?;
        let stored = session
            .db_mut()
            .get_transaction(tx.txid())
            .map_err(|e| SlipstreamError::Wallet(format!("mempool hit check: {e}")))?
            .is_some();
        if stored {
            stats.stored_hits += 1;
            info!(txid = %tx.txid(), "mempool transaction stored (0-conf wallet hit)");
            if let Some(ref p) = progress {
                p.add_enhanced(1);
                p.bump_tx_set_version(); // [E-4] a 0-conf wallet tx was stored
            }
        } else {
            debug!(txid = %tx.txid(), "mempool transaction not wallet-relevant");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::SlipstreamNetwork;

    /// Documents Deviation D6: an empty mempool is legitimate silence, so the
    /// session idle bound is INTENTIONALLY looser than the hardening1 stream
    /// idle timeout (which treats silence as a stall).
    #[test]
    fn session_idle_is_longer_than_hardening() {
        for idle in [MEMPOOL_SESSION_IDLE, MEMPOOL_SESSION_IDLE_NU7] {
            assert!(
                idle > grpc::STREAM_IDLE_TIMEOUT,
                "an empty mempool is legitimately silent — must not reuse the 30 s stall timeout (D6)"
            );
        }
    }

    /// 60 s before NU7, 40 s from NU7, judged at the block after the tip.
    #[test]
    fn session_idle_follows_nu7_activation() {
        use zcash_protocol::consensus::{Network, NetworkUpgrade, Parameters};
        let mainnet_nu7 = u64::from(u32::from(
            Network::MainNetwork
                .activation_height(NetworkUpgrade::Nu7)
                .expect("mainnet NU7 height"),
        ));
        assert_eq!(
            mainnet_nu7, 3_543_405,
            "mainnet NU7 activation (zcash_protocol 0.11.0)"
        );
        assert_eq!(
            mempool_session_idle(&Network::MainNetwork, mainnet_nu7 - 2),
            Duration::from_secs(60)
        );
        assert_eq!(
            mempool_session_idle(&Network::MainNetwork, mainnet_nu7 - 1),
            Duration::from_secs(40)
        );
        let nu7 = u64::from(u32::from(
            Network::TestNetwork
                .activation_height(NetworkUpgrade::Nu7)
                .expect("testnet NU7 height"),
        ));
        assert_eq!(
            nu7, 4_465_026,
            "testnet NU7 activation (zcash_protocol 0.11.0)"
        );
        assert_eq!(
            mempool_session_idle(&Network::TestNetwork, 4_000_000),
            Duration::from_secs(60)
        );
        assert_eq!(
            mempool_session_idle(&Network::TestNetwork, nu7 - 2),
            Duration::from_secs(60),
            "the next block is still before NU7"
        );
        assert_eq!(
            mempool_session_idle(&Network::TestNetwork, nu7 - 1),
            Duration::from_secs(40),
            "the next block activates NU7"
        );
        assert_eq!(
            mempool_session_idle(&Network::TestNetwork, nu7 + 10_000),
            Duration::from_secs(40)
        );
    }

    /// The follow loop passes the engine's own network type, so pin the switch through it as
    /// well as through the stock one above.
    #[test]
    fn session_idle_switches_at_nu7_on_the_engine_network() {
        let nu7 = u64::from(u32::from(
            SlipstreamNetwork::TEST
                .activation_height(NetworkUpgrade::Nu7)
                .expect("testnet NU7 height"),
        ));
        assert_eq!(
            mempool_session_idle(&SlipstreamNetwork::TEST, nu7 - 2),
            Duration::from_secs(60),
            "the next block is still before NU7"
        );
        assert_eq!(
            mempool_session_idle(&SlipstreamNetwork::TEST, nu7 - 1),
            Duration::from_secs(40),
            "the next block activates NU7"
        );
    }

    /// The idle bound follows a custom chain's NU7 height too.
    #[test]
    fn session_idle_follows_a_custom_nu7_height() {
        use crate::network::CustomActivations;
        use zcash_protocol::consensus::NetworkType;
        let net = SlipstreamNetwork::Custom {
            constants: NetworkType::Test,
            heights: CustomActivations {
                nu7: Some(6_000),
                ..CustomActivations::all_from_genesis()
            },
        };
        assert_eq!(mempool_session_idle(&net, 5_998), MEMPOOL_SESSION_IDLE);
        assert_eq!(mempool_session_idle(&net, 5_999), MEMPOOL_SESSION_IDLE_NU7);
        let without_nu7 = SlipstreamNetwork::Custom {
            constants: NetworkType::Test,
            heights: CustomActivations::all_from_genesis(),
        };
        assert_eq!(
            mempool_session_idle(&without_nu7, 1_000_000),
            MEMPOOL_SESSION_IDLE
        );
    }

    /// A tip too large for a `u32` height clamps to the last height instead of wrapping to a
    /// low one, and `u64::MAX` does not overflow `tip + 1`.
    #[test]
    fn session_idle_clamps_a_tip_beyond_u32_heights() {
        for tip in [u64::from(u32::MAX) + 1, u64::MAX] {
            assert_eq!(
                mempool_session_idle(&SlipstreamNetwork::TEST, tip),
                Duration::from_secs(40),
                "tip {tip}"
            );
        }
    }

    /// The dedupe contract `run_session` relies on: `HashSet::insert` returns
    /// `true` only the first time a txid is seen, so a reconnect replay (same
    /// txid) is skipped via `if !seen.insert(txid) { continue; }`.
    #[test]
    fn dedupe_set_admits_each_txid_once() {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(seen.insert(a), "first sighting of a is new");
        assert!(!seen.insert(a), "replayed a is a duplicate — skipped");
        assert!(seen.insert(b), "first sighting of b is new");
        assert_eq!(seen.len(), 2, "only distinct txids are retained");
    }
}
