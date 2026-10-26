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

//! Enhancement: turn detected transactions into complete wallet records by
//! fetching full tx data from lightwalletd.
//!
//! ## Concurrency model
//! Fetches run concurrently via `futures_util::stream::FuturesUnordered` with an
//! explicit cap ([`ENHANCE_FETCH_CONCURRENCY`]) on the concurrent GetTransaction
//! calls, so the gateway's per-host heavy-call limit is respected. DB applies are
//! serial (driven by `&mut WalletSession`). Unordered application is correct
//! because each txid write is independent — there are no cross-txid ordering
//! constraints in the `WalletWrite` API.
//!
//! ## Variant semantics
//! Mirrors `Sources/ZcashLightClientKit/Block/Enhance/BlockEnhancer.swift:94-171`
//! and the `TransactionDataRequest` contract in `zcash_client_backend`:
//! - `GetStatus(txid)` — fetch + `set_transaction_status` (Mined/NotInMainChain/TxidNotRecognized)
//! - `Enhancement(txid)` — fetch + `decrypt_and_store_transaction`; on not-found → TxidNotRecognized
//! - `TransactionsInvolvingAddress` — see `apply_address_request`; several skip-guards per Swift oracle

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::StreamExt;
use tracing::{debug, info, warn};
use zcash_client_backend::data_api::{
    OutputStatusFilter, TransactionDataRequest, TransactionStatus, TransactionStatusFilter,
    TransactionsInvolvingAddress, WalletRead, WalletWrite, wallet::decrypt_and_store_transaction,
};
use zcash_client_backend::proto::service::{BlockId, BlockRange, TransparentAddressBlockFilter};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    config::Endpoint,
    connector::{ConnPurpose, LazyConnection, TorConn, connect_via},
    error::SlipstreamError,
    events::Progress,
    grpc::{self, LwdClient},
    wallet_session::WalletSession,
};

/// The answer to one txid fetch: the txid, whether it was an enhancement, the result.
type FetchResult = (
    zcash_primitives::transaction::TxId,
    bool,
    Result<Option<zcash_client_backend::proto::service::RawTransaction>, SlipstreamError>,
);
type FetchFuture = std::pin::Pin<Box<dyn std::future::Future<Output = FetchResult> + Send>>;

/// One `GetTransaction`: over a clone of `client` (Tor off), or over a fresh isolated Tor
/// client, at most [`ISOLATED_FETCH_CONCURRENCY`] at a time.
fn fetch_transaction(
    client: Option<LwdClient>,
    isolate: Option<&(TorConn, Endpoint, Arc<tokio::sync::Semaphore>)>,
    txid: zcash_primitives::transaction::TxId,
    want_enhance: bool,
) -> FetchFuture {
    match isolate {
        None => {
            let mut c = client.expect("a non-isolated fetch has an open client");
            Box::pin(async move {
                let raw = grpc::get_transaction(&mut c, *txid.as_ref()).await;
                (txid, want_enhance, raw)
            })
        }
        Some((tor, endpoint, permits)) => {
            let (tor, endpoint, permits) = (tor.clone(), endpoint.clone(), Arc::clone(permits));
            Box::pin(async move {
                let raw = async {
                    let _permit = permits.acquire_owned().await.map_err(|e| {
                        SlipstreamError::Transport(format!("isolated fetch permits: {e}"))
                    })?;
                    let mut c = tor.connect_isolated(&endpoint).await?;
                    grpc::get_transaction(&mut c, *txid.as_ref()).await
                }
                .await;
                (txid, want_enhance, raw)
            })
        }
    }
}

/// Maximum per-txid retry attempts after the first failure (4 total attempts).
const MAX_TXID_RETRIES: u32 = 3;

/// Per-txid retry backoff schedule: attempt index → sleep Duration.
/// Jittered exponential: 250 ms, 500 ms, 1 s, 2 s (±20% jitter).
fn txid_retry_backoff(attempt: u32) -> std::time::Duration {
    let base_ms = match attempt {
        1 => 250,
        2 => 500,
        3 => 1000,
        _ => 2000,
    };
    let jitter = 0.8 + (rand::random::<f64>() * 0.4);
    std::time::Duration::from_millis((base_ms as f64 * jitter) as u64)
}

/// One GetTransaction fetch with per-txid retry on transient transport errors.
/// A transient error (gRPC UNAVAILABLE / RESOURCE_EXHAUSTED / DEADLINE_EXCEEDED,
/// as classified by [`SlipstreamError::is_transient`]) retries up to
/// [`MAX_TXID_RETRIES`] times with jittered exponential backoff. Non-transient
/// errors (wallet DB, decode, policy denial, rate limit with the whole-round
/// backoff already applied) propagate immediately.
async fn fetch_with_retry(
    client: Option<LwdClient>,
    isolate: Option<&(TorConn, Endpoint, Arc<tokio::sync::Semaphore>)>,
    txid: zcash_primitives::transaction::TxId,
    want_enhance: bool,
) -> FetchResult {
    let mut attempt = 0;
    loop {
        let (_, _, result) = fetch_transaction(client.clone(), isolate, txid, want_enhance).await;
        match result {
            Ok(raw) => return (txid, want_enhance, Ok(raw)),
            Err(e) if e.is_transient() && attempt < MAX_TXID_RETRIES => {
                attempt += 1;
                let backoff = txid_retry_backoff(attempt);
                debug!(
                    %txid,
                    %e,
                    attempt,
                    backoff_ms = backoff.as_millis(),
                    "txid fetch failed (transient) — retrying"
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => {
                return (txid, want_enhance, Err(e));
            }
        }
    }
}

/// Counters from one `run_enhancement` call.
#[derive(Debug, Default, Clone)]
pub struct EnhanceStats {
    /// Total number of `TransactionDataRequest` items processed (across all rounds).
    pub requests: u64,
    /// Transactions stored via `decrypt_and_store_transaction`.
    pub txs_stored: u64,
    /// Status records set via `set_transaction_status`.
    pub statuses_set: u64,
    /// Count of **unique** `TransactionsInvolvingAddress` requests skipped due to unsupported
    /// filters (open-ended range, `requestAt`, unspent-only).  Within a single
    /// `run_enhancement` call, duplicate skip keys (address + range) are counted only once;
    /// subsequent rounds that re-issue the same already-skipped request are silently dropped
    /// and do not increment this counter.
    pub skipped: u64,
    /// v0.5 pacer (plan §3): where enhancement wall goes — Σ awaiting the
    /// concurrent txid fetches (network-bound share)…
    pub fetch_wait: std::time::Duration,
    /// …Σ inside the serial DB applies (decrypt_and_store / set_status)…
    pub store: std::time::Duration,
    /// …Σ inside the serial address-window phase (its fetch+apply together).
    pub address: std::time::Duration,
}

/// Drain all `TransactionDataRequest` items from the wallet.
///
/// Loops up to 3 rounds because applying one batch of responses can cause
/// the wallet to enqueue follow-up requests (e.g. an `Enhancement` may reveal
/// a new transparent input whose spending tx needs a `GetStatus`).
///
/// Address-window requests are processed serially after the txid-fetch batch in
/// each round (they are streaming, not single-shot, and cannot easily be pipelined
/// without holding `session` across awaits — serial is correct here).
///
/// `progress` — if `Some`, bumps `enhanced_txs` each time a transaction is stored
/// via `decrypt_and_store_transaction` (Relaxed; poll-based).
///
/// `skipped_keys` — caller-owned dedupe set for `TransactionsInvolvingAddress` skip
/// keys (T6.1). Dedupe scope is now **one sync pass**: each unique skip is `warn!`-logged
/// once per pass and counted once in `stats.skipped`; duplicates across all
/// interleaved/per-range/final runs are `debug!` only and do not increment the counter.
pub async fn run_enhancement(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: crate::network::SlipstreamNetwork,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
) -> Result<EnhanceStats, SlipstreamError> {
    let open = client.clone();
    let mut client = LazyConnection::new(move || std::future::ready(Ok(open.clone())));
    run_enhancement_lazily(session, &mut client, network, progress, skipped_keys).await
}

/// Concurrent isolated Tor connections opened for wallet-identifying fetches.
/// Matches [`ENHANCE_FETCH_CONCURRENCY`]: each fetch still gets its own circuit, and a device
/// resync over Tor spent ~2.5 min on 111 txids at 4.
const ISOLATED_FETCH_CONCURRENCY: usize = ENHANCE_FETCH_CONCURRENCY;

/// Concurrent GetTransaction fetches (enhancement or status checks). Bounds the
/// concurrent heavy calls to respect the gateway's per-host cap (field evidence:
/// 4-32, tested at 8). Each fetch that hits the cap gets `grpc-status 14` and is
/// retried per-txid with backoff, so this bound prevents the all-at-once storm.
pub const ENHANCE_FETCH_CONCURRENCY: usize = 8;

/// [`run_enhancement`], with every wallet-identifying call (each `GetTransaction`, each
/// `GetTaddressTxids`) on its own isolated Tor circuit when `isolate` names the Tor client and
/// the endpoint, so that the relay cannot link them to each other or to the sync traffic.
/// `client` is used when `isolate` is `None` (Tor off).
pub async fn run_enhancement_isolated(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: crate::network::SlipstreamNetwork,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
    isolate: Option<(&TorConn, &Endpoint)>,
) -> Result<EnhanceStats, SlipstreamError> {
    let open = client.clone();
    let mut client = LazyConnection::new(move || std::future::ready(Ok(open.clone())));
    run_enhancement_lazily_isolated(
        session,
        &mut client,
        network,
        progress,
        skipped_keys,
        isolate,
    )
    .await
}

/// A connect in progress, boxed so that [`enhancement_connection`] can name its type.
type ConnectFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<LwdClient, SlipstreamError>> + Send + 'a>,
>;

/// The connection the scan's interleaved enhancement and the scheduler's per-range
/// enhancement each run over, opened on first use (see [`run_enhancement_lazily`]). What it
/// carries — transactions by txid, address histories — identifies the wallet, so with Tor
/// on it is an isolated circuit ([`ConnPurpose::MetadataUnique`]).
pub(crate) fn enhancement_connection<'a>(
    endpoint: &'a Endpoint,
    tor: Option<&'a TorConn>,
) -> LazyConnection<LwdClient, impl FnMut() -> ConnectFuture<'a> + Send> {
    LazyConnection::new(move || -> ConnectFuture<'a> {
        Box::pin(connect_via(endpoint, tor, ConnPurpose::MetadataUnique))
    })
}

/// [`run_enhancement`] over a connection opened at the first request that needs the
/// server: a transaction fetch, or an address check that gets past the skip guards of
/// [`apply_address_request`]. A run with nothing to fetch — no requests, or only checks it
/// skips, such as the ephemeral-address checks every account with a transparent receiver
/// is due — opens no connection (with Tor on, no isolated circuit). A failed connect fails
/// the run.
pub(crate) async fn run_enhancement_lazily<F, Fut>(
    session: &mut WalletSession,
    client: &mut LazyConnection<LwdClient, F>,
    network: crate::network::SlipstreamNetwork,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
) -> Result<EnhanceStats, SlipstreamError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<LwdClient, SlipstreamError>>,
{
    run_enhancement_lazily_isolated(session, client, network, progress, skipped_keys, None).await
}

/// Lazy enhancement retaining a fresh Tor circuit for each identifying request.
pub(crate) async fn run_enhancement_lazily_isolated<F, Fut>(
    session: &mut WalletSession,
    client: &mut LazyConnection<LwdClient, F>,
    network: crate::network::SlipstreamNetwork,
    progress: Option<Arc<Progress>>,
    skipped_keys: &mut HashSet<String>,
    isolate: Option<(&TorConn, &Endpoint)>,
) -> Result<EnhanceStats, SlipstreamError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<LwdClient, SlipstreamError>>,
{
    let isolate = isolate.map(|(tor, endpoint)| {
        (
            tor.clone(),
            endpoint.clone(),
            Arc::new(tokio::sync::Semaphore::new(ISOLATED_FETCH_CONCURRENCY)),
        )
    });
    let mut stats = EnhanceStats::default();

    for round in 0..3_u32 {
        let requests = session
            .db_mut()
            .transaction_data_requests()
            .map_err(|e| SlipstreamError::Wallet(format!("transaction_data_requests: {e}")))?;

        if requests.is_empty() {
            break;
        }
        debug!(round, count = requests.len(), "enhancement round");
        stats.requests += requests.len() as u64;

        // ── Phase 1: concurrent txid fetches ──────────────────────────────────
        //
        // Build a set of futures, each cloning a lightweight `LwdClient` handle
        // (backed by a shared `Channel` — no new TCP connections per clone).
        // Bounded by ENHANCE_FETCH_CONCURRENCY to respect the gateway's per-host
        // cap on concurrent heavy calls (GetTransaction counts as heavy). Each
        // fetch that fails with a transient transport error (gRPC UNAVAILABLE,
        // RESOURCE_EXHAUSTED, DEADLINE_EXCEEDED) is retried for that txid only,
        // with jittered exponential backoff (250 ms, 500 ms, 1 s, 2 s). A txid
        // that still fails after its retries is left un-enhanced (remains queued
        // in the wallet DB so the next pass retries it) and does not fail the
        // pass — the engine reaches DONE, and follow-mode passes and the final
        // post-loop enhancement will retry it. DB applies are serial below —
        // `session` is never held across an await point.
        let mut address_reqs: Vec<TransactionsInvolvingAddress> = Vec::new();
        let mut txid_reqs: Vec<(zcash_primitives::transaction::TxId, bool)> = Vec::new();

        // Whether this round did anything that can change the wallet's next requests.
        let mut served_any = false;
        for req in requests {
            match req {
                TransactionDataRequest::GetStatus(txid) => {
                    txid_reqs.push((txid, false));
                }
                TransactionDataRequest::Enhancement(txid) => {
                    txid_reqs.push((txid, true));
                }
                TransactionDataRequest::TransactionsInvolvingAddress(tia) => {
                    address_reqs.push(tia);
                }
            }
        }

        served_any |= !txid_reqs.is_empty();

        // Fetch with retry: each txid is retried up to MAX_TXID_RETRIES times on
        // transient errors. buffer_unordered bounds the concurrency.
        let mut failed_txids = Vec::new();
        let open = if !txid_reqs.is_empty() && isolate.is_none() {
            Some(client.get().await?.clone())
        } else {
            None
        };
        let isolate_for_fetches = isolate.clone();
        let txid_fetches =
            futures_util::stream::iter(txid_reqs.into_iter().map(move |(txid, want_enhance)| {
                let c = open.clone();
                let iso = isolate_for_fetches.clone();
                async move { fetch_with_retry(c, iso.as_ref(), txid, want_enhance).await }
            }))
            .buffer_unordered(ENHANCE_FETCH_CONCURRENCY);
        futures_util::pin_mut!(txid_fetches);

        // Collect results as they arrive and apply to DB immediately (serial apply).
        while let Some((txid, want_enhance, fetched)) = txid_fetches.next().await {
            let fetch_started = std::time::Instant::now();
            if fetched.is_ok() {
                // Liveness: each GetTransaction answer is forward progress — over Tor
                // these take seconds each and most never store a transaction.
                if let Some(p) = &progress {
                    p.touch();
                }
            }
            stats.fetch_wait += fetch_started.elapsed();
            let store_started = std::time::Instant::now();
            match apply_txid_fetch(
                session,
                txid,
                want_enhance,
                fetched,
                &network,
                &mut stats,
                progress.as_deref(),
            ) {
                Ok(()) => {}
                Err(e) if e.is_transient() => {
                    // Transient error after all retries: leave un-enhanced, log it.
                    // The wallet DB keeps the request queued, so the next pass retries.
                    failed_txids.push((txid, want_enhance, e));
                }
                Err(e) => {
                    // Non-transient error (wallet DB corruption, scan logic bug, etc.) — propagate.
                    return Err(e);
                }
            }
            stats.store += store_started.elapsed();
        }

        if !failed_txids.is_empty() {
            warn!(
                count = failed_txids.len(),
                "enhancement round: some txids failed after retries (left un-enhanced, will retry next pass)"
            );
            for (txid, want_enhance, err) in &failed_txids {
                let kind = if *want_enhance {
                    "Enhancement"
                } else {
                    "GetStatus"
                };
                warn!(%txid, %kind, %err, "txid fetch failed");
            }
        }

        // ── Phase 2: serial address-window requests ────────────────────────────
        let address_started = std::time::Instant::now();
        for tia in address_reqs {
            // Skip guards first: a skipped request needs no connection, and over Tor each
            // isolated connection costs a fresh circuit (seconds) for nothing.
            let Some(block_range_end) =
                address_request_range_end(session, &network, &tia, &mut stats, skipped_keys)?
            else {
                continue;
            };
            served_any = true;
            let mut isolated;
            let address_client = match &isolate {
                Some((tor, endpoint, _)) => {
                    isolated = tor.connect_isolated(endpoint).await?;
                    &mut isolated
                }
                None => client.get().await?,
            };
            apply_address_request(
                session,
                address_client,
                &network,
                tia,
                block_range_end,
                &mut stats,
                progress.as_deref(),
            )
            .await?;
        }
        stats.address += address_started.elapsed();

        // A round that fetched no txid and served no address request changed nothing in the
        // wallet DB, so the next round would get the same (all skipped) requests again.
        if !served_any {
            break;
        }
    }

    info!(
        requests = stats.requests,
        stored = stats.txs_stored,
        statuses = stats.statuses_set,
        skipped = stats.skipped,
        "enhancement done"
    );
    Ok(stats)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Apply the result of a `GetTransaction` fetch for one `GetStatus` or `Enhancement` request.
/// Returns `Err` when the fetch failed or when the DB write failed: the caller distinguishes
/// transient errors (leave un-enhanced, retry next pass) from non-transient (propagate).
fn apply_txid_fetch(
    session: &mut WalletSession,
    txid: zcash_primitives::transaction::TxId,
    want_enhance: bool,
    fetched: Result<Option<zcash_client_backend::proto::service::RawTransaction>, SlipstreamError>,
    network: &crate::network::SlipstreamNetwork,
    stats: &mut EnhanceStats,
    progress: Option<&Progress>,
) -> Result<(), SlipstreamError> {
    match fetched {
        Err(err) => {
            // Transport-class error (connection refused, timeout, rate limit after backoff,
            // etc.) — return it so the caller can decide whether to leave un-enhanced (transient)
            // or propagate (non-transient).
            return Err(err);
        }
        Ok(None) => {
            // Server did not recognise the txid — record per the data-request contract.
            // (lightwalletd returns NotFound / Unknown-not-found for unrecognised txids.)
            warn!(%txid, "txid not recognised by server; marking TxidNotRecognized");
            session
                .db_mut()
                .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
                .map_err(|e| {
                    SlipstreamError::Wallet(format!(
                        "set_transaction_status TxidNotRecognized: {e}"
                    ))
                })?;
            stats.statuses_set += 1;
        }
        Ok(Some(raw)) => {
            // Mined-height semantics (rust/src/lib.rs:2059-2068):
            // height > 0  → Some(BlockHeight)
            // height == 0 → None (mempool or unknown)
            let mined_height: Option<BlockHeight> =
                if raw.height > 0 && raw.height <= u64::from(u32::MAX) {
                    Some(BlockHeight::from_u32(raw.height as u32))
                } else {
                    None
                };

            if want_enhance {
                // `BranchId::Sapling` is a placeholder, and harmless: v5 and v6
                // transactions carry their consensus branch id in the header and
                // `Transaction::read` uses that instead. For v4 and earlier it is only
                // recorded on the parsed value: v4 serialization does not write it, and
                // only the v4 signature hash reads it. Nothing signs a transaction parsed
                // here, so the placeholder branch id never reaches a v4 signature hash.
                // The txid and trial decryption do not depend on it.
                let tx =
                    Transaction::read(&raw.data[..], zcash_protocol::consensus::BranchId::Sapling)
                        .map_err(|e| SlipstreamError::Wallet(format!("tx parse: {e}")))?;
                decrypt_and_store_transaction(network, session.db_mut(), &tx, mined_height)
                    .map_err(|e| SlipstreamError::Wallet(format!("decrypt_and_store: {e}")))?;
                stats.txs_stored += 1;
                if let Some(p) = progress {
                    p.add_enhanced(1);
                    p.bump_tx_set_version(); // [E-4] a wallet tx was stored/updated
                }
            } else {
                // GetStatus: record the chain view without full tx decryption.
                let status = match mined_height {
                    Some(h) => TransactionStatus::Mined(h),
                    None => TransactionStatus::NotInMainChain,
                };
                session
                    .db_mut()
                    .set_transaction_status(txid, status)
                    .map_err(|e| SlipstreamError::Wallet(format!("set_transaction_status: {e}")))?;
                stats.statuses_set += 1;
                if let Some(p) = progress {
                    // [E-4] a status write is a tx-set UPDATE (pending → mined/expired) —
                    // hosts re-fetch so the state transition surfaces without a scan event.
                    p.bump_tx_set_version();
                }
            }
        }
    }
    Ok(())
}

/// Effective end-EXCLUSIVE bound for a `TransactionsInvolvingAddress` range (T8.5).
/// `None` means "unbounded above" (data_api.rs:1131-1135); the completest answer a
/// lightwalletd can give RIGHT NOW is through the chain tip, so an open range clamps to
/// `chain_height + 1` (end-exclusive ⇒ includes the tip block). The post-success
/// `notify_address_checked(end - 1)` then records exactly the height we checked through,
/// and the wallet re-issues a fresh request covering later heights next pass — no gap.
fn effective_range_end(
    block_range_end: Option<BlockHeight>,
    chain_height: BlockHeight,
) -> BlockHeight {
    block_range_end.unwrap_or(chain_height + 1)
}

/// Skip guards 1-3 of [`apply_address_request`] for one `TransactionsInvolvingAddress` request:
/// `Ok(None)` when the request is skipped (recorded in `skipped_keys` / `stats`), otherwise the
/// effective end-exclusive range end to serve it with.
///
/// `skipped_keys` — the per-run dedupe set shared across all rounds.  When a skip guard
/// fires, the skip key (`address:range_start-range_end` or `address:open-no-tip`) is inserted.
/// If the key is already present (same request re-issued in a later round), the duplicate
/// is silently counted without re-emitting a `warn!` or incrementing `stats.skipped`.
fn address_request_range_end(
    session: &mut WalletSession,
    network: &crate::network::SlipstreamNetwork,
    tia: &TransactionsInvolvingAddress,
    stats: &mut EnhanceStats,
    skipped_keys: &mut HashSet<String>,
) -> Result<Option<BlockHeight>, SlipstreamError> {
    // Guard 1 (T8.5): clamp an open-ended range to the wallet's current chain tip instead
    // of skipping it. An open range (None) means "unbounded above" (data_api.rs:1131-1135);
    // the completest answer lightwalletd can give now is through the tip — so we clamp via
    // effective_range_end and service the request as a closed range. Only skip if there is
    // genuinely no scanned tip yet (cannot happen after preflight; handled defensively so
    // an unbounded request never reaches upstream). Privacy: the clamped request sends the
    // SAME address string to GetTaddressTxids as any closed-range request already does — no
    // new transparent-address leakage surface (book ch.15).
    let block_range_end = match tia.block_range_end() {
        Some(h) => h,
        None => match session.db_mut().chain_height().map_err(|e| {
            SlipstreamError::Wallet(format!("chain_height for open-range clamp: {e}"))
        })? {
            Some(tip) => effective_range_end(None, tip),
            None => {
                let key = format!("{}:open-no-tip", tia.address().encode(network));
                if skipped_keys.insert(key) {
                    warn!(
                        address = %tia.address().encode(network),
                        "TransactionsInvolvingAddress open range with no scanned chain tip — skipping"
                    );
                    stats.skipped += 1;
                } else {
                    debug!(
                        address = %tia.address().encode(network),
                        "TransactionsInvolvingAddress open-no-tip skip (duplicate, already counted)"
                    );
                }
                return Ok(None);
            }
        },
    };

    // Guard 2: requestAt set (privacy-decorrelated scheduling not implemented).
    if tia.request_at().is_some() {
        let key = format!(
            "{}:{}-{}:request_at",
            tia.address().encode(network),
            u64::from(tia.block_range_start()),
            u64::from(block_range_end)
        );
        if skipped_keys.insert(key) {
            warn!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress has requestAt set — skipping (unsupported)"
            );
            stats.skipped += 1;
        } else {
            debug!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress requestAt skip (duplicate, already counted)"
            );
        }
        return Ok(None);
    }

    // Guard 3: unspent-only output filter (not implemented).
    if tia.output_status_filter() == &OutputStatusFilter::Unspent {
        let key = format!(
            "{}:{}-{}:unspent",
            tia.address().encode(network),
            u64::from(tia.block_range_start()),
            u64::from(block_range_end)
        );
        if skipped_keys.insert(key) {
            stats.skipped += 1;
        } else {
            debug!(
                address = %tia.address().encode(network),
                "TransactionsInvolvingAddress unspent-filter skip (duplicate, already counted)"
            );
        }
        return Ok(None);
    }

    Ok(Some(block_range_end))
}

/// Handle one `TransactionsInvolvingAddress` request.
///
/// Mirrors `BlockEnhancer.swift:124-171` skip-guards and streaming logic:
/// 1. Open-ended `block_range_end` (None) → clamp to `chain_height + 1` (T8.5); only
///    skipped if there is no scanned chain tip yet (cannot happen after preflight).
/// 2. `request_at` set → skip + warn (timed/decorrelated fetches not supported yet).
/// 3. `output_status_filter == Unspent` → skip silently (not supported yet).
/// 4. Otherwise: stream `GetTaddressTxids` over `[block_range_start, block_range_end - 1]`
///    and apply `decrypt_and_store_transaction` for each returned tx, honoring
///    `tx_status_filter` (Mined-only / Mempool-only skip per Swift lines 160-163).
/// 5. On success: call `notify_address_checked` with `block_range_end - 1` so the wallet
///    advances its check watermark.
///
/// The skip guards (1-3) run in [`address_request_range_end`], before the caller opens a
/// connection; this function serves a request that passed them (4-5).
async fn apply_address_request(
    session: &mut WalletSession,
    client: &mut LwdClient,
    network: &crate::network::SlipstreamNetwork,
    tia: TransactionsInvolvingAddress,
    block_range_end: BlockHeight,
    stats: &mut EnhanceStats,
    progress: Option<&Progress>,
) -> Result<(), SlipstreamError> {
    // Build the gRPC filter: range is [start, end - 1] inclusive
    // (lightwalletd's GetTaddressTxids takes a closed range; block_range_end is exclusive
    // per the TransactionsInvolvingAddress contract, matching Swift's `blockRangeEnd - 1`).
    let start_height = u64::from(tia.block_range_start());
    let end_height = u64::from(block_range_end).saturating_sub(1);

    let filter = TransparentAddressBlockFilter {
        address: tia.address().encode(network),
        range: Some(BlockRange {
            start: Some(BlockId {
                height: start_height,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end_height,
                hash: vec![],
            }),
            pool_types: vec![],
        }),
    };

    let raw_txs = grpc::get_taddress_txids(client, filter, progress)
        .await
        .map_err(|e| {
            if e.counts_as_unreachable() {
                SlipstreamError::Wallet(format!("get_taddress_txids: {e}"))
            } else {
                e
            }
        })?;
    if let Some(p) = progress {
        p.touch(); // liveness: the address-history answer is forward progress
    }

    let tx_status_filter = tia.tx_status_filter().clone();
    let block_range_end_for_notify = block_range_end;

    for raw in &raw_txs {
        // Mined-height rule (same as txid fetches above).
        let mined_height: Option<BlockHeight> =
            if raw.height > 0 && raw.height <= u64::from(u32::MAX) {
                Some(BlockHeight::from_u32(raw.height as u32))
            } else {
                None
            };

        // tx_status_filter skip logic (BlockEnhancer.swift:160-163):
        // - Mined filter but tx is in mempool (mined_height == None) → skip
        // - Mempool filter but tx is mined (mined_height == Some) → skip
        match &tx_status_filter {
            TransactionStatusFilter::Mined if mined_height.is_none() => continue,
            TransactionStatusFilter::Mempool if mined_height.is_some() => continue,
            _ => {}
        }

        // Placeholder branch id — harmless, see `apply_txid_fetch`.
        let tx = Transaction::read(&raw.data[..], zcash_protocol::consensus::BranchId::Sapling)
            .map_err(|e| SlipstreamError::Wallet(format!("tx parse (taddr): {e}")))?;
        decrypt_and_store_transaction(network, session.db_mut(), &tx, mined_height)
            .map_err(|e| SlipstreamError::Wallet(format!("decrypt_and_store (taddr): {e}")))?;
        stats.txs_stored += 1;
        if let Some(p) = progress {
            p.add_enhanced(1);
            p.bump_tx_set_version(); // [E-4] a wallet tx was stored/updated
        }
    }

    // Notify the wallet backend that the address check has completed.
    // as_of_height = block_range_end - 1 per the TransactionDataRequest contract.
    let as_of = BlockHeight::from_u32(
        u32::try_from(u64::from(block_range_end_for_notify).saturating_sub(1)).unwrap_or(u32::MAX),
    );
    session
        .db_mut()
        .notify_address_checked(tia, as_of)
        .map_err(|e| SlipstreamError::Wallet(format!("notify_address_checked: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enhance_stats_default_is_zero() {
        let s = EnhanceStats::default();
        assert_eq!(s.requests, 0);
        assert_eq!(s.txs_stored, 0);
        assert_eq!(s.statuses_set, 0);
        assert_eq!(s.skipped, 0);
    }

    /// The dedupe-key logic used inside `apply_address_request` must count the SAME
    /// (address, range) skip key only once across multiple rounds.  This test validates
    /// the `HashSet::insert` contract: the first insert returns `true` (new key →
    /// increment skipped), subsequent inserts return `false` (duplicate → silent).
    #[test]
    fn skip_dedupe_counts_unique_keys_only() {
        let mut skipped_keys: HashSet<String> = HashSet::new();
        let mut skipped_count: u64 = 0;

        // Simulate the same open-range address being re-skipped across 3 rounds.
        let addr = "t1abc123";
        let key = format!("{addr}:open");

        for _ in 0..3 {
            if skipped_keys.insert(key.clone()) {
                skipped_count += 1;
            }
        }
        // Must be counted exactly once regardless of how many rounds re-emit it.
        assert_eq!(
            skipped_count, 1,
            "duplicate open-range skip must count as 1 unique skip"
        );
        assert_eq!(skipped_keys.len(), 1);

        // A different address produces a distinct key → additional unique skip.
        let key2 = "t1xyz456:open".to_string();
        if skipped_keys.insert(key2) {
            skipped_count += 1;
        }
        assert_eq!(
            skipped_count, 2,
            "distinct address must count as a separate skip"
        );

        // Range-keyed skip (requestAt guard): same address+range across 2 rounds.
        let key3 = format!("{addr}:663150-663200:request_at");
        for _ in 0..2 {
            if skipped_keys.insert(key3.clone()) {
                skipped_count += 1;
            }
        }
        assert_eq!(
            skipped_count, 3,
            "requestAt skip must be counted once per unique address+range"
        );
    }

    /// T8.5 — open-ended TransactionsInvolvingAddress ranges clamp to the wallet's current
    /// chain height (end-EXCLUSIVE per data_api.rs:1131-1135: "mined at heights LESS than
    /// this height"); closed ranges pass through untouched.
    #[test]
    fn effective_range_end_clamps_open_ranges_to_tip() {
        use zcash_protocol::consensus::BlockHeight;
        let tip = BlockHeight::from_u32(3_375_000);
        // Closed range passes through untouched.
        assert_eq!(
            effective_range_end(Some(BlockHeight::from_u32(100)), tip),
            BlockHeight::from_u32(100)
        );
        // Open range → tip + 1 (end-exclusive ⇒ includes the tip block).
        assert_eq!(
            effective_range_end(None, tip),
            BlockHeight::from_u32(3_375_001)
        );
    }

    // ── Connecting only when a request needs the server ──────────────────────

    /// A connection for tests without a lightwalletd: it counts its connect attempts in
    /// `connects` and fails every one.
    fn no_server(
        connects: &std::cell::Cell<u32>,
    ) -> LazyConnection<
        LwdClient,
        impl FnMut() -> std::future::Ready<Result<LwdClient, SlipstreamError>> + '_,
    > {
        LazyConnection::new(move || {
            connects.set(connects.get() + 1);
            std::future::ready(Err(SlipstreamError::Transport(
                "no server in this test".into(),
            )))
        })
    }

    /// A mainnet wallet in `dir` with no accounts and no chain tip.
    fn fresh_wallet(dir: &tempfile::TempDir) -> WalletSession {
        WalletSession::open(
            zcash_protocol::consensus::Network::MainNetwork,
            &dir.path().join("data.db"),
        )
        .expect("open")
    }

    /// With no transaction data requests, the run returns at once and never opens its
    /// connection.
    #[tokio::test]
    async fn no_requests_open_no_connection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut session = fresh_wallet(&dir);
        let connects = std::cell::Cell::new(0u32);
        let stats = run_enhancement_lazily(
            &mut session,
            &mut no_server(&connects),
            crate::network::SlipstreamNetwork::MAIN,
            None,
            &mut HashSet::new(),
        )
        .await
        .expect("nothing to enhance is not an error");
        assert_eq!(stats.requests, 0);
        assert_eq!(connects.get(), 0, "no requests, no connection");
    }

    /// Every account with a transparent receiver is due checks of its ephemeral
    /// addresses, which the run skips without asking the server (see
    /// `apply_address_request`). A wallet whose only requests are those — a quiet wallet
    /// on a follow pass — opens no connection.
    #[tokio::test]
    async fn skipped_address_checks_open_no_connection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut session = fresh_wallet(&dir);
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(
            &session.network,
            crate::wallet_session::TEST_UFVK,
        )
        .expect("decode TEST_UFVK");
        let birthday = zcash_client_backend::proto::service::TreeState {
            network: "main".into(),
            height: 663_149,
            hash: "0".repeat(64),
            time: 1,
            ..Default::default()
        };
        session.import_account(&ufvk, birthday).expect("import");
        session.update_chain_tip(663_200).expect("chain tip");
        let requests = session
            .db_mut()
            .transaction_data_requests()
            .expect("requests");
        assert!(
            !requests.is_empty(),
            "the account's ephemeral addresses are due a check"
        );
        assert!(
            requests.iter().all(|request| matches!(
                request,
                TransactionDataRequest::TransactionsInvolvingAddress(_)
            )),
            "only address checks: {requests:?}"
        );

        let connects = std::cell::Cell::new(0u32);
        let stats = run_enhancement_lazily(
            &mut session,
            &mut no_server(&connects),
            crate::network::SlipstreamNetwork::MAIN,
            None,
            &mut HashSet::new(),
        )
        .await
        .expect("skipping is not an error");
        assert_eq!(
            stats.skipped,
            requests.len() as u64,
            "every request was skipped"
        );
        assert_eq!(connects.get(), 0, "skipped requests open no connection");
    }

    /// A request only the server can answer opens the connection, and a failed connect
    /// fails the run, as the up-front connect it replaces did.
    #[tokio::test]
    async fn a_request_for_the_server_opens_the_connection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut session = fresh_wallet(&dir);
        session.update_chain_tip(663_200).expect("chain tip");
        // Queue an enhancement of one transaction (query type 1), as a scan does for each
        // transaction it finds.
        rusqlite::Connection::open(dir.path().join("data.db"))
            .expect("side connection")
            .execute(
                "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?1, 1)",
                rusqlite::params![&[7u8; 32][..]],
            )
            .expect("queue an enhancement");
        let requests = session
            .db_mut()
            .transaction_data_requests()
            .expect("requests");
        assert!(
            matches!(
                requests.as_slice(),
                [TransactionDataRequest::Enhancement(_)]
            ),
            "one enhancement: {requests:?}"
        );

        let connects = std::cell::Cell::new(0u32);
        let err = run_enhancement_lazily(
            &mut session,
            &mut no_server(&connects),
            crate::network::SlipstreamNetwork::MAIN,
            None,
            &mut HashSet::new(),
        )
        .await
        .expect_err("the connect fails");
        assert!(
            matches!(err, SlipstreamError::Transport(_)),
            "the connect error surfaces: {err}"
        );
        assert_eq!(connects.get(), 1, "the enhancement needed the server");
    }
}
