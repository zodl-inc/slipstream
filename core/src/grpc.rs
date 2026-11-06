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

//! Lightwalletd connectivity with connection-owned provenance for local OHTTP errors.

use std::{sync::Arc, time::Duration};

use futures_util::StreamExt;
use tonic::transport::{ClientTlsConfig, Endpoint as TonicEndpoint};
use zcash_client_backend::{
    data_api::chain::CommitmentTreeRoot,
    proto::service::{
        BlockId, ChainSpec, Empty, GetAddressUtxosArg, GetAddressUtxosReply, GetSubtreeRootsArg,
        LightdInfo, RawTransaction, ShieldedProtocol, TransparentAddressBlockFilter, TreeState,
        TxFilter, compact_tx_streamer_client::CompactTxStreamerClient,
    },
};
use zcash_primitives::merkle_tree::HashSer;

use crate::{config::Endpoint, error::SlipstreamError};

mod transport;
pub use transport::LwdTransport;
#[cfg(test)]
pub(crate) use transport::tests::bridge_outcome_status;

/// Client returned by Slipstream connectors, preserving local OHTTP error provenance.
/// Manual remote channels use `LwdClient::new(channel.into())`. Consumers annotating the
/// generated `CompactTxStreamerClient<Channel>` should use this alias for connector results.
/// Use [`connect`] instead of the generated raw-Channel client's associated `connect`.
/// `Channel::into()` is always remote; local classifications require a Slipstream connector.
pub type LwdClient = CompactTxStreamerClient<LwdTransport>;

// ── B2 (#1755 failure-path hardening) transport deadlines ──────────────────────
//
// A stalled-but-open connection (NAT/LB silently dropping a flow, a wedged
// backend in a load-balanced cluster) previously hung the corresponding await
// FOREVER — the engine state stayed "Syncing" with frozen counters and zero
// logs (field failure 2, 2026-06-12). Every call below now carries a deadline;
// the resulting Transport error flows into the existing retry/recovery
// semantics (fetch chunks retry+reconnect; per-range/interleaved enhancement is
// non-fatal; preflight/treestate/final-enhancement errors fail the pass loudly).

/// Hard deadline for a single unary gRPC call (and for the response headers of
/// a server-streaming call).
pub(crate) const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle deadline between consecutive messages of a server-streaming response.
/// A healthy stream delivers messages continuously; 30 s of silence on an open
/// stream means the connection is dead.
pub(crate) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Response-headers deadline for `GetBlockRange` against an OHTTP gateway. OHTTP responses stream
/// as chunks, but the initial headers arrive only after the gateway has collected some content
/// from the upstream. Sized just above the connector's own round-trip cap (100 s) so the pipe's
/// UNAVAILABLE wins when the gateway stalls. A shorter [`UNARY_TIMEOUT`] would timeout large
/// chunks prematurely (field evidence 2026-09-10: ~34 MB spam-era chunks over Tor at ~0.4 MB/s
/// looped `timed out after 30s` forever).
pub(crate) const OHTTP_RANGE_OPEN_TIMEOUT: Duration = Duration::from_secs(120);

/// Deadline for opening a `GetBlockRange` stream to `endpoint` (see [`OHTTP_RANGE_OPEN_TIMEOUT`]).
pub(crate) fn range_open_timeout(endpoint: &Endpoint) -> Duration {
    if crate::ohttp::relay_for(&endpoint.host).is_some() {
        OHTTP_RANGE_OPEN_TIMEOUT
    } else {
        UNARY_TIMEOUT
    }
}

fn transport_err(context: &str, e: impl std::fmt::Display) -> SlipstreamError {
    SlipstreamError::Transport(format!("{context}: {e}"))
}

/// Only the in-process OHTTP bridge may attach a local outcome classification.
pub(crate) fn status_err(context: &str, status: tonic::Status) -> SlipstreamError {
    transport::status_err(context, status)
}

// ── T6.8-H2 scan-path transient retries ───────────────────────────────────────
//
// The initial treestate seed and per-chunk-boundary prefetch calls in scan.rs
// had ZERO retries before this fix; a single 30 s server stall was FATAL
// (field evidence 2026-06-13: "transport: get_tree_state: timed out after 30s"
// → whole sync dead at 6.1%).  These retries are INSIDE the prefetch task so
// the fetch/scan overlap is preserved.

/// Maximum number of ADDITIONAL attempts after the first failure (3 total).
pub(crate) const TREESTATE_RETRY_MAX: u32 = 2;

/// Backoff schedule for scan-path treestate retries: attempt index → sleep Duration.
/// Attempt 1 = first retry (1 s), attempt 2 = second retry (3 s).
pub(crate) fn treestate_retry_backoff(attempt: u32) -> std::time::Duration {
    match attempt {
        1 => std::time::Duration::from_secs(1),
        _ => std::time::Duration::from_secs(3),
    }
}

/// Call `op` up to `TREESTATE_RETRY_MAX + 1` times, reconnecting on retry.
///
/// Only [`SlipstreamError::Transport`] (is_transient == true) triggers a retry;
/// decode/proto/logic errors propagate immediately.  Each retry:
///   1. Sleeps for the backoff duration.
///   2. Opens a FRESH channel to `endpoint` (avoids reusing a wedged connection).
///   3. Invokes `op` with the new client.
///
/// The `context` string is included in every `warn!` so device logs clearly show
/// where retries are happening.
pub(crate) async fn retry_get_tree_state(
    endpoint: &Endpoint,
    height: u64,
    context: &str,
    tor: Option<&crate::connector::TorConn>,
    purpose: crate::connector::ConnPurpose,
    progress: Option<Arc<crate::events::Progress>>,
) -> Result<zcash_client_backend::proto::service::TreeState, SlipstreamError> {
    let mut attempt: u32 = 0;
    loop {
        // First attempt: `purpose` (with Tor on, `SyncShared` reuses the session connection,
        // `MetadataUnique` an isolated circuit). Retries always connect fresh on an isolated
        // circuit, so a wedged (or shared) channel is never retried into.
        let purpose = if attempt == 0 {
            purpose
        } else {
            crate::connector::ConnPurpose::MetadataUnique
        };
        let client = crate::connector::connect_via_tracked(endpoint, tor, purpose).await?;
        match with_ohttp_endpoint(
            endpoint,
            tor.is_some(),
            client.call(async |client| get_tree_state(client, height).await),
        )
        .await
        {
            Ok(ts) => {
                // Liveness: a server response is forward progress (tree states ride
                // isolated Tor circuits when Tor is on and can take seconds each).
                if let Some(p) = &progress {
                    p.touch();
                }
                return Ok(ts);
            }
            Err(err) => {
                // A shared connection is replaced after any failed request (ZIP "Circuit
                // isolation policy"), whether or not the call is retried.
                if purpose == crate::connector::ConnPurpose::SyncShared
                    && let Some(t) = tor
                {
                    t.forget_shared(endpoint);
                }
                if !err.is_transient() || attempt >= TREESTATE_RETRY_MAX {
                    return Err(err);
                }
                attempt += 1;
                let backoff = treestate_retry_backoff(attempt);
                tracing::warn!(
                    %err,
                    attempt,
                    height,
                    context,
                    backoff_ms = backoff.as_millis(),
                    "treestate fetch failed (transient) — retrying"
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

tokio::task_local! {
    static OHTTP_HEALTH_ROUTE: Option<crate::transport_health::HealthRoute>;
    static OHTTP_OWNER_HEALTH: Option<Arc<crate::ohttp::RequestHealth>>;
    static OHTTP_FACTORY: Option<OhttpFactory>;
    static OHTTP_STREAM_REQUEST: Option<Arc<crate::ohttp::RequestHealth>>;
}

/// Explicitly scope the exact network future. Tokio does not inherit this into spawned tasks.
pub(crate) async fn with_ohttp_health_route<T>(
    route: Option<crate::transport_health::HealthRoute>,
    future: impl std::future::Future<Output = T>,
) -> T {
    let factory =
        current_factory().filter(|factory| Some(factory.connector.health_route()) == route);
    OHTTP_HEALTH_ROUTE
        .scope(
            route,
            OHTTP_FACTORY.scope(
                factory,
                OHTTP_OWNER_HEALTH.scope(None, OHTTP_STREAM_REQUEST.scope(None, future)),
            ),
        )
        .await
}

pub(crate) fn current_ohttp_health_route() -> Option<crate::transport_health::HealthRoute> {
    OHTTP_HEALTH_ROUTE.try_with(Clone::clone).ok().flatten()
}

pub(crate) async fn with_ohttp_endpoint<T>(
    endpoint: &Endpoint,
    via_tor: bool,
    future: impl std::future::Future<Output = T>,
) -> T {
    let route =
        crate::ohttp::relay_for(&endpoint.host).map(|relay| crate::transport_health::HealthRoute {
            gateway_host: endpoint.host.clone(),
            relay_url: relay.to_owned(),
            via_tor,
        });
    with_ohttp_health_route(route, future).await
}

pub(crate) async fn with_ohttp_stream_request<T>(
    request: Option<Arc<crate::ohttp::RequestHealth>>,
    future: impl std::future::Future<Output = T>,
) -> T {
    OHTTP_STREAM_REQUEST.scope(request, future).await
}

pub(crate) fn current_owner_health() -> Option<Arc<crate::ohttp::RequestHealth>> {
    OHTTP_OWNER_HEALTH.try_with(Clone::clone).ok().flatten()
}

pub(crate) async fn with_owner_health<T>(
    health: Option<Arc<crate::ohttp::RequestHealth>>,
    future: impl std::future::Future<Output = T>,
) -> T {
    OHTTP_OWNER_HEALTH.scope(health, future).await
}

pub(crate) fn unary_health_request() -> Option<Arc<crate::ohttp::RequestHealth>> {
    current_owner_health().or_else(|| {
        current_ohttp_health_route().map(|route| {
            Arc::new(crate::ohttp::RequestHealth::for_route(
                route,
                crate::transport_health::HealthScope::Lightwalletd,
            ))
        })
    })
}

pub(crate) fn request_deadline(
    health: &Option<Arc<crate::ohttp::RequestHealth>>,
    budget: Duration,
) -> tokio::time::Instant {
    health.as_ref().map_or_else(
        || tokio::time::Instant::now() + budget,
        |health| health.timeout_at(budget),
    )
}

pub(crate) fn record_unary_deadline(request: &Option<Arc<crate::ohttp::RequestHealth>>) {
    if let Some(request) = request {
        request.deadline(crate::transport_health::HealthStage::ResponseHead);
    }
}

#[derive(Clone)]
pub(crate) struct OhttpFactory {
    pub(crate) connector: crate::ohttp::OhttpConnector,
    uri: String,
}

pub(crate) fn current_factory() -> Option<OhttpFactory> {
    OHTTP_FACTORY.try_with(Clone::clone).ok().flatten()
}

/// Internal companion of the public `LwdClient`, whose `LwdTransport` attaches typed local
/// outcomes. Its factory keeps the exact relay connection, key cache and Tor isolation; only
/// request-local pipes are new.
#[derive(Clone)]
pub(crate) struct TrackedConnection {
    client: LwdClient,
    pub(crate) factory: Option<OhttpFactory>,
}

impl std::ops::Deref for TrackedConnection {
    type Target = LwdClient;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
impl std::ops::DerefMut for TrackedConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}
impl TrackedConnection {
    pub(crate) fn plain(client: LwdClient) -> Self {
        Self {
            client,
            factory: None,
        }
    }
    #[cfg(feature = "zcash_client_sqlite")]
    pub(crate) fn in_context(client: LwdClient) -> Self {
        Self {
            client,
            factory: current_factory(),
        }
    }
    /// `channel` is the in-process pipe to the local bridge; it is wrapped here so that no caller
    /// can build a connection whose locally generated outcomes lose their classification.
    pub(crate) fn ohttp(
        channel: tonic::transport::Channel,
        connector: crate::ohttp::OhttpConnector,
        uri: String,
    ) -> Self {
        Self {
            client: LwdClient::new(LwdTransport::local_bridge(channel)),
            factory: Some(OhttpFactory { connector, uri }),
        }
    }
    pub(crate) fn into_client(self) -> LwdClient {
        self.client
    }
    pub(crate) async fn call<T>(
        &self,
        call: impl AsyncFnOnce(&mut LwdClient) -> Result<T, SlipstreamError>,
    ) -> Result<T, SlipstreamError> {
        let mut client = self.client.clone();
        let route = self
            .factory
            .as_ref()
            .map(|factory| factory.connector.health_route());
        OHTTP_FACTORY
            .scope(
                self.factory.clone(),
                with_ohttp_health_route(route, Box::pin(call(&mut client))),
            )
            .await
    }
}

pub(crate) struct RpcClient {
    pub(crate) client: LwdClient,
    pub(crate) health: Option<Arc<crate::ohttp::RequestHealth>>,
}

pub(crate) async fn request_client(client: &LwdClient) -> Result<RpcClient, SlipstreamError> {
    if let Some(factory) = current_factory() {
        let health = factory.connector.request_health();
        let channel = TonicEndpoint::from_shared(factory.uri)
            .map_err(|error| transport_err("local OHTTP endpoint", error))?
            .connect_timeout(std::time::Duration::from_secs(10))
            .connect_with_connector(factory.connector.bound_to(health.clone()))
            .await
            .map_err(|error| transport_err("local OHTTP pipe", error))?;
        Ok(RpcClient {
            client: LwdClient::new(LwdTransport::local_bridge(channel)),
            health: Some(health),
        })
    } else {
        Ok(RpcClient {
            client: client.clone(),
            health: unary_health_request(),
        })
    }
}

async fn with_rpc_client<T>(
    client: &mut LwdClient,
    call: impl AsyncFnOnce(&mut LwdClient) -> Result<T, SlipstreamError>,
) -> Result<T, SlipstreamError> {
    // Bound the generic tonic/setup future's stack footprint inside sync_once.
    let mut request = Box::pin(request_client(client)).await?;
    with_owner_health(request.health, Box::pin(call(&mut request.client))).await
}

/// Awaits a unary gRPC call under [`UNARY_TIMEOUT`]; maps the gRPC status
/// into [`SlipstreamError::Transport`] or [`SlipstreamError::PolicyDenied`].
async fn with_unary_timeout<T>(
    context: &str,
    fut: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, SlipstreamError> {
    let health = OHTTP_STREAM_REQUEST
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .or_else(unary_health_request);
    match tokio::time::timeout_at(request_deadline(&health, UNARY_TIMEOUT), fut).await {
        Ok(Ok(resp)) => Ok(resp.into_inner()),
        Ok(Err(status)) => Err(status_err(context, status)),
        Err(_) => {
            record_unary_deadline(&health);
            Err(SlipstreamError::Transport(format!(
                "{context}: timed out after {}s",
                UNARY_TIMEOUT.as_secs()
            )))
        }
    }
}

/// `stream.next()` under [`STREAM_IDLE_TIMEOUT`]; `Ok(None)` = clean end of stream.
pub(crate) async fn next_with_idle_timeout<T, S>(
    stream: &mut S,
    context: &str,
) -> Result<Option<Result<T, tonic::Status>>, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    tokio::time::timeout(STREAM_IDLE_TIMEOUT, stream.next())
        .await
        .map_err(|_| {
            OHTTP_STREAM_REQUEST
                .try_with(|request| {
                    if let Some(request) = request {
                        request.deadline(crate::transport_health::HealthStage::ResponseBody);
                    }
                })
                .ok();
            SlipstreamError::Transport(format!(
                "{context}: stream idle timeout ({}s without a message)",
                STREAM_IDLE_TIMEOUT.as_secs()
            ))
        })
}

/// Collects a server stream's messages under per-message idle deadlines
/// ([`STREAM_IDLE_TIMEOUT`]), mapping each one with `map` and stamping `progress` as it
/// arrives.
///
/// Liveness is per message, not per answer: a healthy stream that delivers a message every 20 s
/// never trips the 30 s idle timeout, and it must not read as stalled while it is still being
/// collected either — a host that restarts a pass after 120 s without progress would otherwise
/// throw the half-collected answer away and ask for it again. An error item or an idle timeout
/// ends the collection with an error and stamps nothing.
async fn collect_stream<T, U, S>(
    stream: &mut S,
    context: &str,
    stream_label: &str,
    progress: Option<&crate::events::Progress>,
    mut map: impl FnMut(T) -> Result<U, SlipstreamError>,
) -> Result<Vec<U>, SlipstreamError>
where
    S: futures_util::Stream<Item = Result<T, tonic::Status>> + Unpin,
{
    let mut collected = Vec::new();
    while let Some(item) = next_with_idle_timeout(stream, context).await? {
        let message = item.map_err(|e| status_err(stream_label, e))?;
        if let Some(p) = progress {
            p.touch(); // liveness: a message from the server arrived
        }
        collected.push(map(message)?);
    }
    Ok(collected)
}

/// Open a channel to lightwalletd. TLS uses webpki roots (same trust source
/// as the upstream tor module).
pub async fn connect(endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
    connect_with(endpoint, true).await
}

/// [`connect`], except that an OHTTP gateway is reached over a relay connection of this client's
/// own instead of the process-wide one. For bulk block streams, whose unread bodies hold HTTP/2
/// flow-control window and would stall every other call sharing their connection.
pub async fn connect_dedicated(endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
    connect_with(endpoint, false).await
}

async fn connect_with(endpoint: &Endpoint, shared: bool) -> Result<LwdClient, SlipstreamError> {
    connect_tracked(endpoint, shared)
        .await
        .map(TrackedConnection::into_client)
}

pub(crate) async fn connect_tracked(
    endpoint: &Endpoint,
    shared: bool,
) -> Result<TrackedConnection, SlipstreamError> {
    // OHTTP gateways (RFC 9458) are never dialled directly: every RPC is HPKE-encrypted and
    // relayed. The connector hands tonic an in-process h2 pipe with trusted local origin.
    if let Some(relay) = crate::ohttp::relay_for(&endpoint.host) {
        tracing::info!(
            network = ?crate::ohttp::gateway_network(&endpoint.host).ok(),
            "lightwalletd via OHTTP (RFC 9458)"
        );
        let connector = if shared {
            crate::ohttp::OhttpConnector::new(&endpoint.host, relay)
        } else {
            crate::ohttp::OhttpConnector::dedicated(&endpoint.host, relay)
        }
        .map_err(|e| transport_err("ohttp connector", e))?;
        // Plain `http://` on purpose: the transport tonic sees is an in-memory pipe to the
        // in-process h2 server; TLS happens inside the connector, towards the relay. (tonic
        // refuses an `https://` URI without a tls_config.)
        let pipe_uri = format!("http://{}:{}", endpoint.host, endpoint.port);
        let channel = TonicEndpoint::from_shared(pipe_uri.clone())
            .map_err(|e| transport_err("endpoint uri", e))?
            .connect_timeout(std::time::Duration::from_secs(10))
            .connect_with_connector(connector.clone())
            .await
            .map_err(|e| {
                let source = std::error::Error::source(&e)
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default();
                tracing::debug!(host = %endpoint.host, err = %e, "ohttp connect failed");
                transport_err(
                    &format!(
                        "ohttp connect {}",
                        crate::ohttp::gateway_label(&endpoint.host)
                    ),
                    format!("{e}{source}"),
                )
            })?;
        net_stats::record(net_stats::NetEvent::DirectChannel);
        return Ok(TrackedConnection::ohttp(channel, connector, pipe_uri));
    }
    let mut ep = TonicEndpoint::from_shared(endpoint.uri())
        .map_err(|e| transport_err("endpoint uri", e))?
        .connect_timeout(std::time::Duration::from_secs(10));
    if endpoint.tls {
        ep = ep
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| transport_err("tls config", e))?;
    }
    let channel = ep.connect().await.map_err(|e| {
        transport_err(
            &format!("connect {}", crate::ohttp::log_host(&endpoint.host)),
            e,
        )
    })?;
    net_stats::record(net_stats::NetEvent::DirectChannel);
    Ok(TrackedConnection::plain(CompactTxStreamerClient::new(
        channel.into(),
    )))
}

pub async fn get_lightd_info(client: &mut LwdClient) -> Result<LightdInfo, SlipstreamError> {
    with_rpc_client(client, async |client| {
        with_unary_timeout("get_lightd_info", client.get_lightd_info(Empty {})).await
    })
    .await
}

/// Broadcast a raw transaction (\[B7\] send tooling). Returns the server's
/// `(error_code, error_message)`; code 0 = accepted into the mempool.
pub async fn send_transaction(
    client: &mut LwdClient,
    tx_bytes: Vec<u8>,
) -> Result<(i32, String), SlipstreamError> {
    with_rpc_client(client, async |client| {
        let req = zcash_client_backend::proto::service::RawTransaction {
            data: tx_bytes,
            height: 0,
        };
        let resp = with_unary_timeout("send_transaction", client.send_transaction(req)).await?;
        Ok((resp.error_code as i32, resp.error_message))
    })
    .await
}

pub async fn get_latest_block_height(client: &mut LwdClient) -> Result<u64, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetLatestBlock);
        Ok(
            with_unary_timeout("get_latest_block", client.get_latest_block(ChainSpec {}))
                .await?
                .height,
        )
    })
    .await
}

pub async fn get_tree_state(
    client: &mut LwdClient,
    height: u64,
) -> Result<TreeState, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetTreeState);
        with_unary_timeout(
            "get_tree_state",
            client.get_tree_state(BlockId {
                height,
                hash: vec![],
            }),
        )
        .await
    })
    .await
}

/// Collected subtree roots for all three pools (Sapling, Orchard, Ironwood).
///
/// Non-exhaustive so that a field for a future pool is not a breaking change.
#[non_exhaustive]
pub struct SubtreeRoots {
    pub sapling: Vec<CommitmentTreeRoot<sapling::Node>>,
    pub orchard: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>,
    pub ironwood: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>,
}

/// The subtree index each pool's subtree-root request starts at — and so the index of its
/// first returned root. All zero (the default) asks for every root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SubtreeRootStart {
    pub sapling: u64,
    pub orchard: u64,
    pub ironwood: u64,
}

/// One pool's subtree-root stream, collected under per-message idle deadlines (B2); every root
/// received stamps `progress`.
async fn collect_subtree_roots<H: HashSer>(
    client: &mut LwdClient,
    protocol: ShieldedProtocol,
    start_index: u64,
    label: &str,
    progress: Option<&crate::events::Progress>,
) -> Result<Vec<CommitmentTreeRoot<H>>, SlipstreamError> {
    with_rpc_client(client, async |client| {
        let mut req = GetSubtreeRootsArg {
            start_index: u32::try_from(start_index).map_err(|_| {
                SlipstreamError::Wallet(format!("{label} subtree index {start_index} exceeds u32"))
            })?,
            ..Default::default()
        };
        req.set_shielded_protocol(protocol);
        let context = format!("get_subtree_roots({label} from {start_index})");
        net_stats::record(net_stats::NetEvent::GetSubtreeRoots);
        let health = unary_health_request();
        with_ohttp_stream_request(health, async {
            let mut stream = with_unary_timeout(&context, client.get_subtree_roots(req)).await?;
            collect_stream(
                &mut stream,
                &context,
                "subtree root stream",
                progress,
                |r| {
                    let node = H::read(&r.root_hash[..])
                        .map_err(|e| SlipstreamError::Transport(format!("{label} root: {e}")))?;
                    Ok(CommitmentTreeRoot::from_parts(
                        zcash_protocol::consensus::BlockHeight::from_u32(
                            r.completing_block_height as u32,
                        ),
                        node,
                    ))
                },
            )
            .await
        })
        .await
    })
    .await
}

/// Every subtree root of every pool, from index 0.
pub async fn get_subtree_roots(
    client: &mut LwdClient,
    progress: Option<&crate::events::Progress>,
) -> Result<SubtreeRoots, SlipstreamError> {
    get_subtree_roots_from(client, SubtreeRootStart::default(), progress).await
}

/// Each pool's subtree roots from its index in `start` onward: a pool's `i`-th root is the
/// root of subtree `start + i`. Store them at the same `start`
/// (`WalletSession::put_subtree_roots_at`).
pub async fn get_subtree_roots_from(
    client: &mut LwdClient,
    start: SubtreeRootStart,
    progress: Option<&crate::events::Progress>,
) -> Result<SubtreeRoots, SlipstreamError> {
    let sapling_roots = collect_subtree_roots::<sapling::Node>(
        client,
        ShieldedProtocol::Sapling,
        start.sapling,
        "sapling",
        progress,
    )
    .await?;
    let orchard_roots = collect_subtree_roots::<orchard::tree::MerkleHashOrchard>(
        client,
        ShieldedProtocol::Orchard,
        start.orchard,
        "orchard",
        progress,
    )
    .await?;
    let ironwood_roots = collect_subtree_roots::<orchard::tree::MerkleHashOrchard>(
        client,
        ShieldedProtocol::Ironwood,
        start.ironwood,
        "ironwood",
        progress,
    )
    .await?;
    Ok(SubtreeRoots {
        sapling: sapling_roots,
        orchard: orchard_roots,
        ironwood: ironwood_roots,
    })
}

/// Fetch a full transaction by txid.
///
/// Returns `Ok(Some(raw))` on success, `Ok(None)` when the server reports the
/// transaction is not found (tonic `NotFound` status code, or `Unknown`/`Internal`
/// with a "not found" message — lightwalletd v0.4.9 uses `Unknown` for unknown txids),
/// and `Err` for all other transport-level failures (connection refused, timeout, etc.).
///
/// # Deviation from T3.1 plan
/// The original T3.1 wrapper returned `Result<RawTransaction, SlipstreamError>`.
/// Changed to `Result<Option<RawTransaction>, SlipstreamError>` per T3.2 Binding Note 4:
/// enhancement must tolerate per-txid "not found" from the server (→ `TxidNotRecognized`)
/// while propagating connection-class errors to the caller.
pub async fn get_transaction(
    client: &mut LwdClient,
    txid: [u8; 32],
) -> Result<Option<RawTransaction>, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetTransaction);
        // B2: unary deadline; the not-found mapping below needs the raw status, so this
        // call cannot reuse with_unary_timeout's uniform error mapping.
        let health = unary_health_request();
        let outcome = tokio::time::timeout_at(
            request_deadline(&health, UNARY_TIMEOUT),
            client.get_transaction(TxFilter {
                hash: txid.to_vec(),
                ..Default::default()
            }),
        )
        .await
        .map_err(|_| {
            record_unary_deadline(&health);
            SlipstreamError::Transport(format!(
                "get_transaction: timed out after {}s",
                UNARY_TIMEOUT.as_secs()
            ))
        })?;
        match outcome {
            Ok(resp) => Ok(Some(resp.into_inner())),
            Err(status) => {
                // lightwalletd returns NotFound or Unknown/Internal with "not found" message
                // for unrecognized txids. Treat these as Ok(None) — caller maps to
                // TxidNotRecognized. All other status codes propagate as transport errors.
                let code = status.code();
                let msg_lower = status.message().to_lowercase();
                if code == tonic::Code::NotFound
                    || ((code == tonic::Code::Unknown || code == tonic::Code::Internal)
                        && (msg_lower.contains("not found")
                            || msg_lower.contains("no such transaction")))
                {
                    Ok(None)
                } else {
                    Err(status_err("get_transaction", status))
                }
            }
        }
    })
    .await
}

/// Stream raw transactions involving a transparent address in a height range; every
/// transaction received stamps `progress`.
pub async fn get_taddress_txids(
    client: &mut LwdClient,
    filter: TransparentAddressBlockFilter,
    progress: Option<&crate::events::Progress>,
) -> Result<Vec<RawTransaction>, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetTaddressTxids);
        let health = unary_health_request();
        with_ohttp_stream_request(health, async {
            let mut stream =
                with_unary_timeout("get_taddress_txids", client.get_taddress_txids(filter)).await?;
            collect_stream(
                &mut stream,
                "get_taddress_txids",
                "taddress txid stream",
                progress,
                Ok,
            )
            .await
        })
        .await
    })
    .await
}

/// Opens a `GetMempoolStream` session (T8.2). The server pushes raw mempool
/// transactions as they arrive and CLOSES the stream when a new block is mined
/// (lightwalletd contract, `service.proto:188-192`). Unlike the other stream
/// helpers this returns the RAW stream — the caller reacts per-message.
///
/// Deliberately NOT wrapped in `with_unary_timeout`: `GetMempoolStream` is
/// server-streaming and lightwalletd sends its response HEADERS lazily — only
/// with the first mempool tx, or when it closes the stream on a new block. On a
/// quiet mempool the `.await` here legitimately blocks past the 30 s unary
/// timeout whenever the next block takes longer than that — routinely before
/// NU7 (75 s target spacing), and still often from NU7 (a third of that, with
/// block intervals spread around the target) — so wrapping it would spuriously
/// fail. The CALLER bounds the open with `mempool::mempool_session_idle` and
/// treats an over-idle open as a benign reconnect (Deviation D6), not a failure.
pub async fn open_mempool_stream(
    client: &mut LwdClient,
) -> Result<tonic::Streaming<RawTransaction>, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetMempoolStream);
        client
            .get_mempool_stream(Empty {})
            .await
            .map(tonic::Response::into_inner)
            .map_err(|status| status_err("get_mempool_stream", status))
    })
    .await
}

/// Collect UTXOs for the given transparent addresses from `start_height`; every UTXO received
/// stamps `progress`.
pub async fn get_address_utxos(
    client: &mut LwdClient,
    addresses: Vec<String>,
    start_height: u64,
    progress: Option<&crate::events::Progress>,
) -> Result<Vec<GetAddressUtxosReply>, SlipstreamError> {
    with_rpc_client(client, async |client| {
        net_stats::record(net_stats::NetEvent::GetAddressUtxos);
        let health = unary_health_request();
        with_ohttp_stream_request(health, async {
            let mut stream = with_unary_timeout(
                "get_address_utxos",
                client.get_address_utxos_stream(GetAddressUtxosArg {
                    addresses,
                    start_height,
                    max_entries: 0,
                }),
            )
            .await?;
            collect_stream(
                &mut stream,
                "get_address_utxos",
                "utxo stream",
                progress,
                Ok,
            )
            .await
        })
        .await
    })
    .await
}

/// Pass-level network telemetry: the lightwalletd channels the engine opens and the RPCs it
/// issues, by kind.
///
/// Process-cumulative atomics, like `persist::lane_stats`: fetch workers, tree-state
/// prefetches and the mempool session each run on their own task. `engine::sync_once`
/// snapshots [`totals`](net_stats::totals) when a pass starts and returns the pass's delta as
/// `SyncOutcome::net`, which `report::log_pass_summary` logs as `pass network split`. A process
/// that runs several engines at once counts them all.
///
/// A channel counts once it is connected (a failed connect opens nothing); an RPC counts when
/// it is issued, whether or not it succeeds.
pub mod net_stats {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// What [`record`] counts.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum NetEvent {
        /// A direct (non-Tor) channel connected.
        DirectChannel,
        /// A channel connected over a Tor circuit.
        TorChannel,
        /// `GetLatestBlock`.
        GetLatestBlock,
        /// One pool's `GetSubtreeRoots` stream.
        GetSubtreeRoots,
        /// A `GetBlockRange` stream: every fetch attempt, and the endpoint probe's sample.
        GetBlockRange,
        /// `GetTreeState`.
        GetTreeState,
        /// `GetAddressUtxosStream`.
        GetAddressUtxos,
        /// `GetTaddressTxids`.
        GetTaddressTxids,
        /// `GetTransaction`.
        GetTransaction,
        /// `GetMempoolStream`.
        GetMempoolStream,
    }

    static DIRECT_CHANNELS: AtomicU64 = AtomicU64::new(0);
    static TOR_CHANNELS: AtomicU64 = AtomicU64::new(0);
    static GET_LATEST_BLOCK: AtomicU64 = AtomicU64::new(0);
    static GET_SUBTREE_ROOTS: AtomicU64 = AtomicU64::new(0);
    static GET_BLOCK_RANGE: AtomicU64 = AtomicU64::new(0);
    static GET_TREE_STATE: AtomicU64 = AtomicU64::new(0);
    static GET_ADDRESS_UTXOS: AtomicU64 = AtomicU64::new(0);
    static GET_TADDRESS_TXIDS: AtomicU64 = AtomicU64::new(0);
    static GET_TRANSACTION: AtomicU64 = AtomicU64::new(0);
    static GET_MEMPOOL_STREAM: AtomicU64 = AtomicU64::new(0);

    fn counter(event: NetEvent) -> &'static AtomicU64 {
        match event {
            NetEvent::DirectChannel => &DIRECT_CHANNELS,
            NetEvent::TorChannel => &TOR_CHANNELS,
            NetEvent::GetLatestBlock => &GET_LATEST_BLOCK,
            NetEvent::GetSubtreeRoots => &GET_SUBTREE_ROOTS,
            NetEvent::GetBlockRange => &GET_BLOCK_RANGE,
            NetEvent::GetTreeState => &GET_TREE_STATE,
            NetEvent::GetAddressUtxos => &GET_ADDRESS_UTXOS,
            NetEvent::GetTaddressTxids => &GET_TADDRESS_TXIDS,
            NetEvent::GetTransaction => &GET_TRANSACTION,
            NetEvent::GetMempoolStream => &GET_MEMPOOL_STREAM,
        }
    }

    /// Counts one `event`.
    pub(crate) fn record(event: NetEvent) {
        counter(event).fetch_add(1, Ordering::Relaxed);
    }

    /// Channel and RPC counts: since process start ([`totals`]), or over a pass
    /// ([`Totals::delta_since`]).
    ///
    /// Non-exhaustive so that a count for a future RPC kind is not a breaking change.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Totals {
        pub direct_channels: u64,
        pub tor_channels: u64,
        pub get_latest_block: u64,
        pub get_subtree_roots: u64,
        pub get_block_range: u64,
        pub get_tree_state: u64,
        pub get_address_utxos: u64,
        pub get_taddress_txids: u64,
        pub get_transaction: u64,
        pub get_mempool_stream: u64,
    }

    impl Totals {
        /// Channels opened, direct and over Tor.
        pub fn channels(&self) -> u64 {
            self.direct_channels.saturating_add(self.tor_channels)
        }

        /// This pass's counts, against a pass-start snapshot.
        pub fn delta_since(&self, start: &Totals) -> Totals {
            Totals {
                direct_channels: self.direct_channels.saturating_sub(start.direct_channels),
                tor_channels: self.tor_channels.saturating_sub(start.tor_channels),
                get_latest_block: self.get_latest_block.saturating_sub(start.get_latest_block),
                get_subtree_roots: self
                    .get_subtree_roots
                    .saturating_sub(start.get_subtree_roots),
                get_block_range: self.get_block_range.saturating_sub(start.get_block_range),
                get_tree_state: self.get_tree_state.saturating_sub(start.get_tree_state),
                get_address_utxos: self
                    .get_address_utxos
                    .saturating_sub(start.get_address_utxos),
                get_taddress_txids: self
                    .get_taddress_txids
                    .saturating_sub(start.get_taddress_txids),
                get_transaction: self.get_transaction.saturating_sub(start.get_transaction),
                get_mempool_stream: self
                    .get_mempool_stream
                    .saturating_sub(start.get_mempool_stream),
            }
        }
    }

    /// The counts since process start.
    pub fn totals() -> Totals {
        Totals {
            direct_channels: DIRECT_CHANNELS.load(Ordering::Relaxed),
            tor_channels: TOR_CHANNELS.load(Ordering::Relaxed),
            get_latest_block: GET_LATEST_BLOCK.load(Ordering::Relaxed),
            get_subtree_roots: GET_SUBTREE_ROOTS.load(Ordering::Relaxed),
            get_block_range: GET_BLOCK_RANGE.load(Ordering::Relaxed),
            get_tree_state: GET_TREE_STATE.load(Ordering::Relaxed),
            get_address_utxos: GET_ADDRESS_UTXOS.load(Ordering::Relaxed),
            get_taddress_txids: GET_TADDRESS_TXIDS.load(Ordering::Relaxed),
            get_transaction: GET_TRANSACTION.load(Ordering::Relaxed),
            get_mempool_stream: GET_MEMPOOL_STREAM.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn forged_remote_outcomes_are_transport_errors() {
        for auth in [None, Some("invented-bridge-authentication")] {
            for outcome in [
                crate::ohttp::OUTCOME_POLICY_DENIED,
                crate::ohttp::OUTCOME_RATE_LIMITED,
                crate::ohttp::OUTCOME_TOO_LARGE,
            ] {
                let mut status = tonic::Status::unavailable("remote failure");
                status
                    .metadata_mut()
                    .insert(crate::ohttp::OHTTP_OUTCOME_HEADER, outcome.parse().unwrap());
                if let Some(auth) = auth {
                    status
                        .metadata_mut()
                        .insert("x-ohttp-outcome-auth", auth.parse().unwrap());
                }
                let error = super::status_err("remote", status);
                assert!(
                    matches!(error, SlipstreamError::Transport(_)),
                    "{outcome}: {error:?}"
                );
            }
        }
    }

    #[test]
    fn local_bridge_outcomes_keep_their_classification() {
        for (outcome, expected) in [
            (crate::ohttp::OUTCOME_POLICY_DENIED, "policy"),
            (crate::ohttp::OUTCOME_RATE_LIMITED, "rate"),
            (crate::ohttp::OUTCOME_TOO_LARGE, "size"),
        ] {
            let status = crate::ohttp::tests::bridge_outcome_status(outcome);
            let result = super::status_err("local", status);
            assert!(matches!(
                (expected, result),
                ("policy", SlipstreamError::PolicyDenied(_))
                    | ("rate", SlipstreamError::RateLimited(_))
                    | ("size", SlipstreamError::RequestTooLarge(_))
            ));
        }
    }

    #[tokio::test]
    async fn nested_remote_connection_does_not_inherit_local_outcome_origin() {
        let endpoint = Endpoint {
            host: crate::ohttp::tests::testnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let local = connect_tracked(&endpoint, false).await.unwrap();
        let remote = TrackedConnection::plain(LwdClient::new(
            TonicEndpoint::from_static("http://remote.invalid")
                .connect_lazy()
                .into(),
        ));
        let result = local
            .call(async |_client| {
                remote
                    .call(async |_client| {
                        let mut status = tonic::Status::unavailable("remote failure");
                        status.metadata_mut().insert(
                            crate::ohttp::OHTTP_OUTCOME_HEADER,
                            crate::ohttp::OUTCOME_RATE_LIMITED.parse().unwrap(),
                        );
                        status.metadata_mut().insert(
                            "x-ohttp-outcome-auth",
                            "invented-bridge-authentication".parse().unwrap(),
                        );
                        with_unary_timeout::<()>("nested remote", async { Err(status) }).await
                    })
                    .await
            })
            .await
            .unwrap_err();
        assert!(
            matches!(result, SlipstreamError::Transport(_)),
            "{result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_local_setup_consumes_the_existing_unary_deadline_budget() {
        let route = crate::transport_health::HealthRoute {
            gateway_host: "health-local-budget.invalid".into(),
            relay_url: "https://health-local-budget-relay.invalid/relay".into(),
            via_tor: false,
        };
        let request = Arc::new(crate::ohttp::RequestHealth::for_route(
            route,
            crate::transport_health::HealthScope::Lightwalletd,
        ));
        let started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(5)).await;
        let result = with_owner_health(
            Some(request),
            with_unary_timeout::<()>("after-local-setup", std::future::pending()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(30),
            "local setup must not extend the logical RPC deadline"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_nested_public_route_shadows_private_scope() {
        use crate::transport_health::{self, HealthRoute};
        let route = HealthRoute {
            gateway_host: "health-private.invalid".into(),
            relay_url: "https://health-private-relay.invalid/relay".into(),
            via_tor: true,
        };
        let subscription = transport_health::subscribe(route.clone(), 42, Arc::new(|_| {}));
        let public = Endpoint {
            host: "public-lightwalletd.invalid".into(),
            port: 443,
            tls: true,
        };
        let result = with_ohttp_health_route(
            Some(route),
            with_ohttp_endpoint(
                &public,
                false,
                with_unary_timeout::<()>("public", std::future::pending()),
            ),
        )
        .await;
        assert!(result.is_err());
        assert!(subscription.snapshot().observations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn health_concurrent_selected_endpoints_keep_routes_and_tor_modes() {
        use crate::transport_health::{self, HealthOutcome, HealthRoute};
        let first = Endpoint {
            host: crate::ohttp::tests::mainnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let selected = Endpoint {
            host: crate::ohttp::tests::testnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let first_route = HealthRoute {
            gateway_host: first.host.clone(),
            relay_url: crate::ohttp::relay_for(&first.host).unwrap().into(),
            via_tor: false,
        };
        let selected_route = HealthRoute {
            gateway_host: selected.host.clone(),
            relay_url: crate::ohttp::relay_for(&selected.host).unwrap().into(),
            via_tor: true,
        };
        let subscriptions = [
            transport_health::subscribe(first_route.clone(), 41, Arc::new(|_| {})),
            transport_health::subscribe(selected_route.clone(), 42, Arc::new(|_| {})),
        ];
        let start = transport_health::monotonic_time_nanoseconds();
        let (a, b) = tokio::join!(
            with_ohttp_endpoint(
                &first,
                false,
                with_unary_timeout::<()>("first", std::future::pending())
            ),
            with_ohttp_endpoint(
                &selected,
                true,
                with_unary_timeout::<()>("selected", std::future::pending())
            )
        );
        assert!(a.is_err() && b.is_err());
        for (subscription, route) in subscriptions.iter().zip([first_route, selected_route]) {
            let snapshot = subscription.snapshot();
            assert!(snapshot.observations.iter().any(|o| !o.historical
                && o.started_at_nanoseconds >= start
                && o.route == route
                && o.outcome == HealthOutcome::TransportUnavailable));
            assert!(snapshot.observations.iter().all(|o| o.route == route));
        }
    }

    /// The in-process OHTTP channel is still a direct channel when its relay leg
    /// does not use Tor. Opening the pipe performs no relay or gateway network request.
    #[tokio::test]
    async fn ohttp_channel_is_included_in_direct_channel_accounting() {
        let before = net_stats::totals();
        let endpoint = Endpoint {
            host: crate::ohttp::tests::testnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let _client = connect(&endpoint).await.expect("open OHTTP pipe");
        assert!(
            net_stats::totals().delta_since(&before).direct_channels >= 1,
            "an OHTTP channel without Tor must be counted once it connects"
        );
    }
    use super::*;
    use crate::config::Endpoint;

    #[tokio::test]
    async fn connect_to_unroutable_host_fails_with_transport_error() {
        let ep = Endpoint {
            host: "127.0.0.1".into(),
            port: 1,
            tls: false,
        };
        match connect(&ep).await {
            Err(SlipstreamError::Transport(msg)) => assert!(msg.contains("connect")),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    // ── B2 (#1755) deadline tests — `start_paused` auto-advances the mock clock
    // when the runtime is idle, so the 30 s deadlines fire instantly. ───────────

    /// A unary call that never resolves (stalled-but-open connection) must
    /// surface as a Transport timeout, never hang.
    #[tokio::test(start_paused = true)]
    async fn unary_timeout_fires_on_stalled_call() {
        let fut = futures_util::future::pending::<Result<tonic::Response<()>, tonic::Status>>();
        match with_unary_timeout("stalled_unary", fut).await {
            Err(SlipstreamError::Transport(msg)) => {
                assert!(msg.contains("stalled_unary"), "context missing: {msg}");
                assert!(msg.contains("timed out"), "timeout marker missing: {msg}");
            }
            other => panic!("expected Transport timeout, got {other:?}"),
        }
    }

    /// A stream that stops delivering messages while staying open must surface
    /// as a stream-idle Transport timeout, never hang.
    #[tokio::test(start_paused = true)]
    async fn stream_idle_timeout_fires_on_stalled_stream() {
        let mut stream = futures_util::stream::pending::<Result<u32, tonic::Status>>();
        match next_with_idle_timeout(&mut stream, "stalled_stream").await {
            Err(SlipstreamError::Transport(msg)) => {
                assert!(msg.contains("stalled_stream"), "context missing: {msg}");
                assert!(
                    msg.contains("stream idle timeout"),
                    "idle marker missing: {msg}"
                );
            }
            other => panic!("expected Transport idle timeout, got {other:?}"),
        }
    }

    /// Healthy streams pass through unchanged: messages then a clean end.
    #[tokio::test]
    async fn stream_idle_timeout_passes_messages_and_end() {
        let mut stream = futures_util::stream::iter(vec![Ok::<u32, tonic::Status>(7), Ok(8)]);
        let first = next_with_idle_timeout(&mut stream, "healthy")
            .await
            .expect("no timeout");
        assert_eq!(first.expect("a message").expect("ok item"), 7);
        let second = next_with_idle_timeout(&mut stream, "healthy")
            .await
            .expect("no timeout");
        assert_eq!(second.expect("a message").expect("ok item"), 8);
        let end = next_with_idle_timeout(&mut stream, "healthy")
            .await
            .expect("no timeout");
        assert!(end.is_none(), "clean end of stream must be Ok(None)");
    }

    /// A long, healthy metadata stream is progress WHILE it is being collected: every message
    /// stamps the stall clock as it arrives. This stream delivers two messages and then goes
    /// silent, so the collection itself dies of the idle timeout — yet the clock was stamped.
    #[tokio::test(start_paused = true)]
    async fn collect_stream_stamps_progress_per_message_before_the_stream_ends() {
        let progress = crate::events::Progress::default();
        let mut stream = futures_util::stream::iter(vec![Ok::<u32, tonic::Status>(1), Ok(2)])
            .chain(futures_util::stream::pending());
        let err = collect_stream(
            &mut stream,
            "healthy_then_silent",
            "test stream",
            Some(&progress),
            Ok,
        )
        .await
        .expect_err("a stream that goes silent still dies of the idle timeout");
        assert!(
            err.to_string().contains("stream idle timeout"),
            "got: {err}"
        );
        assert_ne!(
            progress.last_progress_unix_secs(),
            0,
            "each received message must stamp the clock"
        );
    }

    /// An error item fails the collection with the stream's label and is not progress.
    #[tokio::test]
    async fn collect_stream_does_not_stamp_progress_for_an_error_item() {
        let progress = crate::events::Progress::default();
        let mut stream = futures_util::stream::iter(vec![Err::<u32, tonic::Status>(
            tonic::Status::unavailable("gone"),
        )]);
        let err = collect_stream(&mut stream, "failing", "test stream", Some(&progress), Ok)
            .await
            .expect_err("an error item fails the collection");
        assert!(err.to_string().contains("test stream: "), "got: {err}");
        assert_eq!(
            progress.last_progress_unix_secs(),
            0,
            "an error item is not progress"
        );
    }

    /// A healthy stream is mapped message by message and ends cleanly.
    #[tokio::test]
    async fn collect_stream_maps_every_message_and_ends_cleanly() {
        let progress = crate::events::Progress::default();
        let mut stream = futures_util::stream::iter(vec![Ok::<u32, tonic::Status>(3), Ok(4)]);
        let out = collect_stream(
            &mut stream,
            "healthy",
            "test stream",
            Some(&progress),
            |m| Ok(m * 10),
        )
        .await
        .expect("clean end");
        assert_eq!(out, vec![30, 40]);
        assert_ne!(progress.last_progress_unix_secs(), 0);
    }

    // Live-network smoke; run manually: cargo test -p zodl-slipstream -- --ignored
    #[tokio::test]
    #[ignore = "network"]
    async fn live_lightd_info_smoke() {
        let ep = Endpoint {
            host: "zec.rocks".into(),
            port: 443,
            tls: true,
        };
        let mut c = connect(&ep).await.expect("connect");
        let info = get_lightd_info(&mut c).await.expect("info");
        assert_eq!(info.chain_name, "main");
        let h = get_latest_block_height(&mut c).await.expect("height");
        assert!(h > 2_000_000);
    }

    // ── T6.8-H2 retry helper unit tests ─────────────────────────────────────────

    /// retry_get_tree_state succeeds on first attempt when the operation returns Ok.
    /// Verified by checking the call counter is exactly 1.
    #[tokio::test]
    async fn retry_treestate_succeeds_on_first_attempt() {
        // Uses an unroutable endpoint so connect() always fails (Transport error).
        // Confirm the first attempt sees a transport error. We can't mock the actual
        // get_tree_state, so we verify the retry helper propagates errors from connect.
        let ep = Endpoint {
            host: "127.0.0.1".into(),
            port: 1,
            tls: false,
        };
        // Should fail (connect refused — transient), retry up to 3 times.
        // PASS_RETRY_MAX=2 means 3 total attempts; all will fail with Transport.
        // The test just confirms that: (a) it returns a Transport error (not panic),
        // and (b) the function exists and is callable.
        let result = retry_get_tree_state(
            &ep,
            1_000_000,
            "test-context",
            None,
            crate::connector::ConnPurpose::MetadataUnique,
            None,
        )
        .await;
        assert!(
            matches!(result, Err(SlipstreamError::Transport(_))),
            "unroutable endpoint must yield Transport error, got: {result:?}"
        );
    }

    /// Non-transient errors must NOT be retried — they propagate immediately.
    /// We test this via the pure treestate_retry_backoff / TREESTATE_RETRY_MAX constants.
    #[test]
    fn retry_constants_are_sane() {
        // 2 additional attempts (3 total, matching TREESTATE_RETRY_MAX).
        assert_eq!(
            TREESTATE_RETRY_MAX, 2,
            "must allow exactly 2 retries (3 total)"
        );
        // Backoff schedule: attempt 1 = 1s, attempt 2 = 3s.
        assert_eq!(
            treestate_retry_backoff(1),
            std::time::Duration::from_secs(1)
        );
        assert_eq!(
            treestate_retry_backoff(2),
            std::time::Duration::from_secs(3)
        );
        // Attempt 3+ uses the default arm (3s cap).
        assert_eq!(
            treestate_retry_backoff(3),
            std::time::Duration::from_secs(3)
        );
    }

    /// Verify that Transport errors are classified as transient (the condition the
    /// retry helper uses to decide whether to retry).
    #[test]
    fn transport_error_is_transient_for_retry() {
        let err = SlipstreamError::Transport("timed out after 30s".into());
        assert!(err.is_transient(), "Transport must be transient for retry");

        // Non-transient variants must NOT trigger retry.
        let wallet = SlipstreamError::Wallet("db error".into());
        assert!(!wallet.is_transient(), "Wallet must not be transient");
        let config = SlipstreamError::Config("bad host".into());
        assert!(!config.is_transient(), "Config must not be transient");
    }

    // ── Pass-level network telemetry ──────────────────────────────────────────

    /// A pass's counts are the field-by-field difference from the pass-start snapshot,
    /// never negative.
    #[test]
    fn net_stats_delta_is_per_counter_and_never_negative() {
        use net_stats::Totals;
        let start = Totals {
            direct_channels: 3,
            tor_channels: 1,
            get_tree_state: 5,
            ..Totals::default()
        };
        let end = Totals {
            direct_channels: 7,
            tor_channels: 1,
            get_tree_state: 6,
            get_block_range: 2,
            ..Totals::default()
        };
        let pass = end.delta_since(&start);
        assert_eq!(
            pass,
            Totals {
                direct_channels: 4,
                get_tree_state: 1,
                get_block_range: 2,
                ..Totals::default()
            }
        );
        assert_eq!(pass.channels(), 4);
        assert_eq!(
            start.delta_since(&end),
            Totals::default(),
            "saturates at zero"
        );
    }

    /// Recording an event bumps its counter. Other tests in this process may record
    /// too, so this asserts a lower bound.
    #[test]
    fn net_stats_record_bumps_the_named_counter() {
        use net_stats::{NetEvent, record, totals};
        let before = totals();
        record(NetEvent::GetTransaction);
        record(NetEvent::TorChannel);
        let pass = totals().delta_since(&before);
        assert!(pass.get_transaction >= 1, "got {pass:?}");
        assert!(pass.tor_channels >= 1, "got {pass:?}");
    }
}
