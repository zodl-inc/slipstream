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

//! Lightwalletd connection factory honoring the old SDK's per-call Tor policy.
//!
//! Mirrors the old SDK's `ServiceMode`: the **bulk** block fetch is direct (the old
//! SDK's `blockStream` uses `.direct` — public range data, too high-volume for Tor; per-user
//! exposure (IP + birthday) is identical with or without Tor). Wallet-**identifying** metadata
//! (treestate, latest-block, lightd info) goes over **isolated Tor circuits** when Tor is on.
//!
//! **OHTTP gateways** (`crate::ohttp::relay_for(host).is_some()`) are the exception to "bulk is
//! direct": with Tor on, EVERY purpose — bulk included — is OHTTP-encapsulated AND its TCP leg to
//! the relay is dialled through Tor. Anything less would either bypass OHTTP (the gateway refuses
//! plain gRPC with 426 anyway) or hand the relay the device IP while the user asked for Tor.
//!
//! Tor is transport-only — the bytes written to the wallet DB are identical either way, so the
//! golden + darkside oracles are unaffected.
//!
//! Runtime model (T-Tor.0, GO): the engine OWNS its arti [`TorConn`], bootstrapped on the
//! engine's own tokio runtime (`TorClient::with_runtime(PreferredRuntime::current())`), so no
//! `block_on` and no cross-runtime polling — see `tests/tor_runtime_spike.rs`.

use std::{
    collections::HashMap,
    future::Future,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arti_client::{
    DataStream, StreamPrefs, TorClient,
    config::{BoolOrAuto, TorClientConfigBuilder},
};
use hyper_util::rt::TokioIo;
use tonic::transport::{ClientTlsConfig, Endpoint as TonicEndpoint, Uri};
use tor_rtcompat::PreferredRuntime;
use tower_service::Service;

use crate::{
    config::Endpoint,
    error::SlipstreamError,
    grpc::{self, LwdClient},
    ohttp::{Dialer, OhttpConnector},
};

/// Why a lightwalletd connection is being opened — selects direct vs Tor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPurpose {
    /// Bulk compact-block download. Direct with Tor off; with Tor ON it rides Tor for EVERY host
    /// (OHTTP gateway or clearnet lightwalletd), each fetch connection on a circuit of its own.
    /// Upstream Zashi kept bulk direct even with Tor on (`blockStream(.direct)`); Zodl changed
    /// that on 2026-09-14 so that a clearnet lightwalletd used as the OHTTP fallback never sees
    /// the device IP while Tor is on.
    BulkFetch,
    /// Wallet-identifying metadata (treestate, latest-block, tip). Isolated Tor (`.uniqueTor`).
    MetadataUnique,
    /// Server validation / lightd info. Default Tor circuit (`.defaultTor`).
    MetadataDefault,
    /// Public sync metadata asked many times per pass (chunk-boundary tree states, tip probes).
    /// With Tor ON: one session-wide connection on the default circuit, reused for up to
    /// `SHARED_CONN_MAX_AGE` (10 min), instead of a fresh isolated circuit per call (ZIP "Circuit
    /// isolation policy": public range data MAY share one circuit per session). Never use it
    /// for a wallet-identifying call.
    SyncShared,
}

/// Which Tor circuit a purpose uses, or `None` for direct. This is the single source of the
/// per-call policy (mirrors the old SDK's `ServiceMode` mapping); [`Connector::connect`] uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TorMode {
    Isolated,
    Default,
    /// The default circuit, through one cached connection per endpoint ([`TorConn::shared`]).
    Shared,
    /// A circuit of the connection's own, for throughput rather than unlinkability: the bulk
    /// fetch workers each get one, so the download is not capped by a single circuit's window.
    OwnCircuit,
}

/// How long [`ConnPurpose::SyncShared`] reuses one connection before opening a new one, so a long
/// session is not a single linkable stream at the Relay (arti retires a used circuit after 10 min
/// as well).
const SHARED_CONN_MAX_AGE: Duration = Duration::from_secs(10 * 60);

fn tor_mode(purpose: ConnPurpose) -> Option<TorMode> {
    match purpose {
        // Public range data: needs no isolation from itself, but one circuit per fetch worker.
        // A Tor circuit carries at most one flow-control window (1000 cells, ~500 KB) per round
        // trip (arti 0.35 has no congestion control), so the workers sharing the default circuit
        // all ran at that one circuit's rate: 0.3 to 1.6 MB/s on EC2 (2026-10-26), with no gain
        // from 8 workers over 4. On circuits of their own, 4 workers fetched 230 MB at 2.9 MB/s.
        // The ZIP's circuit isolation policy lets public range data share a circuit; it does
        // not ask for it, and splitting public data over several circuits links nothing more.
        ConnPurpose::BulkFetch => Some(TorMode::OwnCircuit),
        ConnPurpose::MetadataUnique => Some(TorMode::Isolated),
        ConnPurpose::MetadataDefault => Some(TorMode::Default),
        ConnPurpose::SyncShared => Some(TorMode::Shared),
    }
}

/// The full routing decision for one connect. With a Tor handle present (Tor ON) NOTHING bypasses
/// Tor, whatever the host: OHTTP gateways and clearnet lightwalletd alike carry bulk on the default
/// circuit and metadata on its usual circuit. `is_ohttp_gateway` is kept for call-site clarity and
/// logging; it no longer changes the decision. Without Tor, [`connect_via`] goes direct (and
/// `grpc::connect` speaks OHTTP to gateways over the direct relay leg).
fn route(purpose: ConnPurpose, is_ohttp_gateway: bool) -> Option<TorMode> {
    let _ = is_ohttp_gateway;
    tor_mode(purpose)
}

/// Per-attempt timeout for building a Tor circuit + connecting to lightwalletd. A healthy circuit
/// builds in a few seconds; a STUCK one (dead relay / bad path) is cut here so we can retry on a
/// FRESH isolated circuit instead of blocking on arti's much longer internal circuit-build
/// timeout. Field evidence (2026-06-17, device, Tor ON): a single stuck circuit wedged a per-range
/// enhancement connect for ~58s, turning a ~90s restore into ~161s. 15s leaves a slow-but-healthy
/// circuit room while cutting a stuck one promptly.
const TOR_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Fresh-circuit attempts before giving up a single connect. With `Isolated` mode each attempt
/// draws a NEW isolated circuit, so a transient bad circuit recovers on the next try. The error
/// returned after all broken-circuit attempts is still `Transport` (transient); a relay pause
/// returns `RateLimited` immediately for caller backoff. Every higher resilience layer
/// (scan treestate retry, the per-range enhancement's non-fatal defer, the initial-pass
/// never-Error retry loop) still stacks on top. 3 attempts ⇒ ≤45s worst case vs the old single
/// ~58s-then-fail, and ~0 overhead in the healthy case (attempt 1 connects fast).
const TOR_CONNECT_ATTEMPTS: u32 = 3;

/// Per-attempt timeout for an OHTTP-over-Tor connect. It has to build TWO circuits (gateway key
/// fetch + relay) and complete two TLS handshakes over them before the first RPC can go out, so it
/// gets more room than the single-stream direct-over-Tor case.
const TOR_OHTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

// Timeouts zcash_client_backend's `tor::Timeouts::default()` applies to gRPC-over-Tor channels.
const TOR_GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOR_GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const TOR_GRPC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const TOR_GRPC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);

/// A bootstrapped arti Tor client, owned by the engine and driven on its own runtime.
#[derive(Clone)]
pub struct TorConn {
    client: Arc<TorClient<PreferredRuntime>>,
    client_trace_prefix: Option<String>,
    /// [`TorMode::Shared`] connections, per endpoint (`host:port`), with their opening time.
    shared: Arc<std::sync::Mutex<HashMap<String, (LwdClient, Instant)>>>,
}

impl TorConn {
    /// Bootstrap a Tor client on the CURRENT (engine's) runtime, from `tor_dir` — the same
    /// `arti-data` / `arti-cache` layout (and permission policy) `zcash_client_backend::tor::Client`
    /// uses, so the directory is shared with / warm from the SDK's own Tor client.
    /// Performs the one-time Tor bootstrap; call once at sync start when Tor is enabled.
    pub async fn bootstrap(
        tor_dir: &Path,
        dangerously_trust_everyone: bool,
        client_trace_prefix: Option<String>,
    ) -> Result<Self, SlipstreamError> {
        let boot =
            |e: &dyn std::fmt::Display| SlipstreamError::Transport(format!("tor bootstrap: {e}"));
        let runtime = PreferredRuntime::current().map_err(|e| boot(&e))?;
        if !tokio::fs::try_exists(tor_dir).await.map_err(|e| boot(&e))? {
            return Err(SlipstreamError::Config(format!(
                "tor bootstrap: directory {} does not exist",
                tor_dir.display()
            )));
        }
        let mut config_builder = TorClientConfigBuilder::from_directories(
            tor_dir.join("arti-data"),
            tor_dir.join("arti-cache"),
        );
        if dangerously_trust_everyone {
            config_builder
                .storage()
                .permissions()
                .dangerously_trust_everyone();
        }
        let config = config_builder.build().map_err(|e| boot(&e))?;
        tracing::debug!(dir = %tor_dir.display(), "bootstrapping arti Tor client (engine-owned)");
        let client = TorClient::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await
            .map_err(|e| boot(&e))?;
        tracing::debug!("arti Tor client bootstrapped");
        Ok(Self {
            client,
            client_trace_prefix,
            shared: Arc::default(),
        })
    }

    /// Wrap an already-bootstrapped arti client (e.g. one shared with another component).
    pub fn from_client(
        client: Arc<TorClient<PreferredRuntime>>,
        client_trace_prefix: Option<String>,
    ) -> Self {
        Self {
            client,
            client_trace_prefix,
            shared: Arc::default(),
        }
    }

    /// The underlying arti handle.
    pub fn client(&self) -> &Arc<TorClient<PreferredRuntime>> {
        &self.client
    }

    /// Tor clients can become less bootstrapped over time (lost connectivity, expired directory);
    /// re-bootstrap before opening streams, as `zcash_client_backend` does.
    async fn ensure_bootstrapped(&self) -> Result<(), SlipstreamError> {
        if !self.client.bootstrap_status().ready_for_traffic() {
            tracing::debug!("re-bootstrapping Tor");
            self.client
                .bootstrap()
                .await
                .map_err(|e| SlipstreamError::Transport(format!("tor re-bootstrap: {e}")))?;
        }
        Ok(())
    }

    /// Open an isolated (`.uniqueTor`-style) lightwalletd client to `endpoint` through Tor.
    /// OHTTP gateways are OHTTP-encapsulated with the relay leg dialled through Tor; other hosts
    /// are dialled directly over Tor. Public entry point for hosts outside the engine (the SDK's
    /// FFI Tor client) that must share this routing policy.
    pub async fn connect_isolated(
        &self,
        endpoint: &Endpoint,
    ) -> Result<LwdClient, SlipstreamError> {
        self.connect(TorMode::Isolated, endpoint).await
    }

    async fn connect(
        &self,
        mode: TorMode,
        endpoint: &Endpoint,
    ) -> Result<LwdClient, SlipstreamError> {
        if mode == TorMode::Shared {
            return self.connect_shared(endpoint).await;
        }
        self.ensure_bootstrapped().await?;
        let relay = crate::ohttp::relay_for(&endpoint.host);
        let per_attempt = if relay.is_some() {
            TOR_OHTTP_CONNECT_TIMEOUT
        } else {
            TOR_CONNECT_TIMEOUT
        };

        // Bounded circuit build + retry on a FRESH circuit (see TOR_CONNECT_* docs). A stuck
        // circuit is cut at the per-attempt timeout and the next attempt draws a new isolated
        // circuit, instead of blocking on arti's long internal timeout. The healthy case connects
        // on attempt 1 with no added latency.
        retry_tor_connect(per_attempt, |attempt| {
            // `.uniqueTor` (and a bulk worker's own circuit) = a fresh isolated circuit EACH
            // attempt (so a retry escapes a stuck circuit); `.defaultTor` = the default circuit
            // (a retry still gets a fresh isolated one, since the default one just failed us).
            let client = match (mode, attempt) {
                (TorMode::Default | TorMode::Shared, 1) => self.client.clone(),
                _ => self.client.isolated_client(),
            };
            let client_trace_prefix = self.client_trace_prefix.clone();
            async move {
                match relay {
                    Some(relay) => {
                        Self::connect_ohttp(client, endpoint, relay, client_trace_prefix).await
                    }
                    None => Self::connect_direct_over_tor(client, endpoint).await,
                }
            }
        })
        .await
    }

    /// Drop the cached shared (`SyncShared`) connection to `endpoint` after a call on it failed, so
    /// the next `SyncShared` connect opens a fresh one instead of reusing a broken channel.
    pub fn forget_shared(&self, endpoint: &Endpoint) {
        let key = format!("{}:{}", endpoint.host, endpoint.port);
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    /// [`TorMode::Shared`]: hand out the cached connection to `endpoint` while it is younger than
    /// [`SHARED_CONN_MAX_AGE`], else open one on the default circuit and cache it. A tonic
    /// channel multiplexes concurrent calls and redials a broken transport itself; callers that
    /// retry after a failure use an isolated connection, so a bad shared one is never retried
    /// into.
    async fn connect_shared(&self, endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
        let key = format!("{}:{}", endpoint.host, endpoint.port);
        {
            let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((client, opened)) = shared.get(&key)
                && opened.elapsed() < SHARED_CONN_MAX_AGE
            {
                return Ok(client.clone());
            }
        }
        let client = Box::pin(self.connect(TorMode::Default, endpoint)).await?;
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, (client.clone(), Instant::now()));
        Ok(client)
    }

    /// OHTTP gateway over Tor: tonic talks to the in-process OHTTP pipe exactly as in
    /// [`grpc::connect`]; the connector's TCP legs (relay POSTs, gateway key fetch) go through
    /// `client`. `warm_up` pulls the key config and opens the pooled relay connection NOW, inside
    /// the caller's per-attempt timeout, so a stuck circuit is retried instead of eating the first
    /// RPC's deadline.
    async fn connect_ohttp(
        client: Arc<TorClient<PreferredRuntime>>,
        endpoint: &Endpoint,
        relay: &str,
        client_trace_prefix: Option<String>,
    ) -> Result<LwdClient, SlipstreamError> {
        tracing::info!(
            gateway = %endpoint.host,
            relay,
            "lightwalletd via OHTTP (RFC 9458) over Tor — relay leg dialled through arti"
        );
        let connector = OhttpConnector::with_dialer(
            &endpoint.host,
            relay,
            Dialer::Tor(client),
            client_trace_prefix,
        )
        .map_err(|e| SlipstreamError::Transport(format!("ohttp connector: {e}")))?;
        Self::connect_ohttp_channel(connector, endpoint).await
    }

    async fn connect_ohttp_channel(
        connector: OhttpConnector,
        endpoint: &Endpoint,
    ) -> Result<LwdClient, SlipstreamError> {
        connector.warm_up_typed().await?;
        // Plain `http://`: the transport tonic sees is an in-memory pipe; TLS happens inside the
        // connector, towards the relay (tonic refuses `https://` without a tls_config).
        let pipe_uri = format!("http://{}:{}", endpoint.host, endpoint.port);
        let channel = TonicEndpoint::from_shared(pipe_uri)
            .map_err(|e| SlipstreamError::Transport(format!("endpoint uri: {e}")))?
            .connect_timeout(Duration::from_secs(10))
            .connect_with_connector(connector)
            .await
            .map_err(|e| {
                SlipstreamError::Transport(format!("ohttp connect {}: {e}", endpoint.host))
            })?;
        Ok(LwdClient::new(channel))
    }

    /// Non-OHTTP host: gRPC(+TLS) directly over a Tor stream — a port of
    /// `zcash_client_backend::tor::Client::connect_to_lightwalletd` (same tonic timeouts and
    /// keep-alives, webpki roots, `.onion` allowed when the host is one).
    async fn connect_direct_over_tor(
        client: Arc<TorClient<PreferredRuntime>>,
        endpoint: &Endpoint,
    ) -> Result<LwdClient, SlipstreamError> {
        let uri: Uri = endpoint
            .uri()
            .parse()
            .map_err(|e| SlipstreamError::Config(format!("bad endpoint uri for tor: {e}")))?;
        let mut prefs = StreamPrefs::new();
        if endpoint.host.ends_with(".onion") {
            prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
        }
        let mut ep = TonicEndpoint::from(uri)
            .connect_timeout(TOR_GRPC_CONNECT_TIMEOUT)
            .timeout(TOR_GRPC_REQUEST_TIMEOUT)
            .http2_keep_alive_interval(TOR_GRPC_KEEPALIVE_INTERVAL)
            .keep_alive_timeout(TOR_GRPC_KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(false);
        if endpoint.tls {
            ep = ep
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(|e| SlipstreamError::Transport(format!("tls config: {e}")))?;
        }
        let channel = ep
            .connect_with_connector(TorTcpConnector { client, prefs })
            .await
            .map_err(|e| {
                let source = std::error::Error::source(&e)
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default();
                SlipstreamError::Transport(format!("tor connect {}: {e}{source}", endpoint.host))
            })?;
        Ok(LwdClient::new(channel))
    }
}

/// `tower::Service<Uri>` that opens the gRPC transport as an arti stream (the host is resolved at
/// the Tor exit, never locally).
struct TorTcpConnector {
    client: Arc<TorClient<PreferredRuntime>>,
    prefs: StreamPrefs,
}

impl Service<Uri> for TorTcpConnector {
    type Response = TokioIo<DataStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let client = self.client.clone();
        let prefs = self.prefs.clone();
        Box::pin(async move {
            let host = dst.host().ok_or("endpoint uri without host")?.to_string();
            let port = dst
                .port_u16()
                .unwrap_or(if dst.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            tracing::debug!(host, port, "connecting through Tor");
            let stream = client
                .connect_with_prefs((host.as_str(), port), &prefs)
                .await?;
            Ok(TokioIo::new(stream))
        })
    }
}

/// Plan-chunk cap (blocks per `GetBlockRange`) whenever bulk goes over OHTTP, with or without
/// Tor. An OHTTP response is one buffered message, so a chunk is downloaded whole before any
/// block can be scanned, and the gateway rejects upstream responses over its size cap. A
/// 10k-block spam-era chunk (~height 1.7M+) exceeded the gateway's 256 MiB cap on mainnet and
/// stalled restores; 2k blocks keep every response bounded and let progress advance (at Tor
/// throughput, ~0.4 MB/s observed, it also keeps each round trip inside the OHTTP deadlines).
/// Direct gRPC streams incrementally and keeps the configured size.
pub const OHTTP_MAX_CHUNK_BLOCKS: u32 = 2_000;

/// Effective `chunk_blocks` for a bulk fetch of `endpoint`.
pub fn bulk_chunk_blocks(configured: u32, endpoint: &Endpoint) -> u32 {
    if crate::ohttp::relay_for(&endpoint.host).is_some() {
        configured.min(OHTTP_MAX_CHUNK_BLOCKS)
    } else {
        configured
    }
}

/// Builds lightwalletd clients honoring the per-call Tor policy.
#[derive(Clone)]
pub struct Connector {
    endpoint: Endpoint,
    tor: Option<TorConn>,
}

impl Connector {
    /// Tor-off: every purpose dials directly.
    pub fn direct(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            tor: None,
        }
    }

    /// Tor-on: metadata over Tor, bulk still direct (unless the endpoint is an OHTTP gateway, in
    /// which case bulk is OHTTP-over-Tor as well).
    pub fn with_tor(endpoint: Endpoint, tor: TorConn) -> Self {
        Self {
            endpoint,
            tor: Some(tor),
        }
    }

    /// Open a lightwalletd client for `purpose`.
    pub async fn connect(&self, purpose: ConnPurpose) -> Result<LwdClient, SlipstreamError> {
        connect_via(&self.endpoint, self.tor.as_ref(), purpose).await
    }
}

/// Free-function form of [`Connector::connect`] for call sites that already thread `endpoint`
/// (from `EngineConfig`) and an optional Tor handle separately — avoids restructuring the run
/// path around the bundled [`Connector`]. Per-call policy: with `tor` `Some` every purpose rides
/// Tor (bulk on a circuit per connection, metadata on its own — see `route` helper); with `tor`
/// `None`, `connect_direct_with_retry` → `grpc::connect`, which already speaks OHTTP to gateways
/// over the direct relay leg.
pub async fn connect_via(
    endpoint: &Endpoint,
    tor: Option<&TorConn>,
    purpose: ConnPurpose,
) -> Result<LwdClient, SlipstreamError> {
    let is_ohttp_gateway = crate::ohttp::relay_for(&endpoint.host).is_some();
    match (tor, route(purpose, is_ohttp_gateway)) {
        (Some(t), Some(mode)) => t.connect(mode, endpoint).await,
        // Bulk streams get a relay connection of their own: a block-range body the scan is not
        // reading yet holds HTTP/2 flow-control window, and on a connection shared with the
        // tree-state and tip calls it stalled all of them (device, spam era: "no chunk received
        // in 30s" + GetTreeState timeouts until the pass restarted).
        _ if purpose == ConnPurpose::BulkFetch => {
            connect_direct_dedicated_with_retry(endpoint).await
        }
        _ => connect_direct_with_retry(endpoint).await,
    }
}

/// Bounded transient-failure retries for the DIRECT (non-Tor) connect path. The Tor path refreshes
/// a fresh circuit per attempt ([`TOR_CONNECT_ATTEMPTS`]); the direct path has no circuit to
/// refresh, so it waits out a brief server outage with capped exponential backoff and resumes in
/// place — instead of letting a transient `connect` failure bubble up and restart the WHOLE sync
/// pass (which resets per-pass progress and re-establishes everything; field log syncLogsMac3,
/// 2026-06-29). 6 attempts with the backoff below ⇒ ~31s survival window; a genuinely-down or
/// misconfigured endpoint still surfaces after it, and the healthy case connects on attempt 1 with
/// ~0 overhead. A longer outage falls back to a pass restart, which the SDK's monotonic progress
/// floor keeps from visibly regressing.
const DIRECT_CONNECT_ATTEMPTS: u32 = 6;

/// Capped exponential backoff between direct-connect attempts: 1, 2, 4, 8, 16s (then held at 16s).
fn direct_connect_backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << attempt.saturating_sub(1).min(4))
}

/// Retry a transient connect/op with bounded backoff. Returns the first `Ok`, or the error from the
/// final attempt. A NON-transient error (config / logic) returns immediately — only `is_transient()`
/// failures are retried. Generic over the success type so the retry + backoff logic is unit-testable
/// without a live client.
async fn retry_transient<T, F, Fut>(
    mut op: F,
    attempts: u32,
    backoff: impl Fn(u32) -> std::time::Duration,
) -> Result<T, SlipstreamError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, SlipstreamError>>,
{
    let mut attempt: u32 = 1;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !e.is_transient() || attempt >= attempts {
                    return Err(e);
                }
                tracing::warn!(attempt, err = %e, "direct connect failed (transient) — retrying after backoff");
                tokio::time::sleep(backoff(attempt)).await;
                attempt += 1;
            }
        }
    }
}

/// Direct (non-Tor) lightwalletd connect with bounded transient-failure retry (see
/// `DIRECT_CONNECT_ATTEMPTS`). Drop-in for `grpc::connect` at the sites that must survive a brief
/// server outage without restarting the sync pass: the bulk-fetch workers and the direct branch of
/// [`connect_via`].
pub async fn connect_direct_with_retry(endpoint: &Endpoint) -> Result<LwdClient, SlipstreamError> {
    retry_transient(
        || grpc::connect(endpoint),
        DIRECT_CONNECT_ATTEMPTS,
        direct_connect_backoff,
    )
    .await
}

/// Bound each circuit attempt independently; callers supply the circuit-specific operation.
async fn retry_tor_connect<T, F, Fut>(
    per_attempt: Duration,
    mut connect: F,
) -> Result<T, SlipstreamError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, SlipstreamError>>,
{
    let mut last_err: Option<SlipstreamError> = None;
    for attempt in 1..=TOR_CONNECT_ATTEMPTS {
        match tokio::time::timeout(per_attempt, connect(attempt)).await {
            Ok(Ok(c)) => {
                grpc::net_stats::record(grpc::net_stats::NetEvent::TorChannel);
                return Ok(c);
            }
            Ok(Err(e @ SlipstreamError::RateLimited(_))) => {
                // A new circuit still reaches the same paused relay. Let the caller's
                // existing backoff run without counting this as an unreachable endpoint.
                return Err(e);
            }
            Ok(Err(e)) => {
                tracing::warn!(attempt, err = %e, "tor connect failed — retrying on a fresh circuit");
                last_err = Some(match e {
                    SlipstreamError::Transport(detail) => {
                        SlipstreamError::Transport(format!("tor connect: {detail}"))
                    }
                    other => other,
                });
            }
            Err(_elapsed) => {
                tracing::warn!(
                    attempt,
                    timeout_secs = per_attempt.as_secs(),
                    "tor circuit build timed out — retrying on a fresh circuit"
                );
                last_err = Some(SlipstreamError::Transport(format!(
                    "tor connect: circuit build exceeded {}s",
                    per_attempt.as_secs()
                )));
            }
        }
    }
    // Preserve the final error's class for caller retry and endpoint-reachability decisions.
    Err(last_err.unwrap_or_else(|| {
        SlipstreamError::Transport("tor connect: failed to obtain a circuit".to_string())
    }))
}

/// A lightwalletd connection opened on first use and reused after that.
///
/// For connections a range often never needs: opened up front, each one costs a TLS
/// handshake and, with Tor on, an isolated circuit, whether or not anything is ever sent
/// over it. `connect` runs on the first [`get`](Self::get), and again only if that attempt
/// failed.
pub struct LazyConnection<C, F> {
    connect: F,
    client: Option<C>,
}

impl<C, F, Fut> LazyConnection<C, F>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<C, SlipstreamError>>,
{
    /// A connection `connect` opens when it is first needed.
    pub fn new(connect: F) -> Self {
        Self {
            connect,
            client: None,
        }
    }

    /// The client, connecting first if this is the first use or the last connect failed.
    pub async fn get(&mut self) -> Result<&mut C, SlipstreamError> {
        let client = match self.client.take() {
            Some(client) => client,
            None => (self.connect)().await?,
        };
        Ok(self.client.insert(client))
    }
}

/// [`connect_direct_with_retry`] for bulk block download: an OHTTP gateway is reached over a relay
/// connection used by this client alone (`grpc::connect_dedicated`), never the process-wide one.
pub async fn connect_direct_dedicated_with_retry(
    endpoint: &Endpoint,
) -> Result<LwdClient, SlipstreamError> {
    retry_transient(
        || grpc::connect_dedicated(endpoint),
        DIRECT_CONNECT_ATTEMPTS,
        direct_connect_backoff,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ohttp_endpoint() -> Endpoint {
        Endpoint {
            host: "ohttp-gateway-testnet.example".into(),
            port: 443,
            tls: true,
        }
    }

    #[tokio::test]
    async fn cached_relay_pause_stays_typed_through_tor_warm_up_and_retry() {
        let connector = crate::ohttp::tests::connector_with_cached_relay_pause().await;
        let endpoint = ohttp_endpoint();
        let attempts = std::cell::Cell::new(0);
        let result = retry_tor_connect(TOR_OHTTP_CONNECT_TIMEOUT, |_| {
            attempts.set(attempts.get() + 1);
            TorConn::connect_ohttp_channel(connector.clone(), &endpoint)
        })
        .await;
        let Err(error) = result else {
            panic!("the relay's cached pause must hold warm-up");
        };
        assert!(
            matches!(error, SlipstreamError::RateLimited(_)),
            "{error:?}"
        );
        assert!(error.is_transient());
        assert!(!error.counts_as_unreachable());
        assert_eq!(
            attempts.get(),
            1,
            "a fresh circuit cannot escape a relay pause"
        );
    }

    #[tokio::test]
    async fn fresh_key_fetch_rate_limit_stays_typed_through_tor_warm_up_and_retry() {
        let (connector, gets) =
            crate::ohttp::tests::connector_with_fresh_key_fetch_rate_limit().await;
        let endpoint = ohttp_endpoint();
        let attempts = std::cell::Cell::new(0);
        let result = retry_tor_connect(TOR_OHTTP_CONNECT_TIMEOUT, |_| {
            attempts.set(attempts.get() + 1);
            TorConn::connect_ohttp_channel(connector.clone(), &endpoint)
        })
        .await;
        let Err(error) = result else {
            panic!("the relay refused the key fetch");
        };
        assert!(
            matches!(error, SlipstreamError::RateLimited(_)),
            "{error:?}"
        );
        assert!(error.is_transient());
        assert!(!error.counts_as_unreachable());
        assert_eq!(attempts.get(), 1, "return to caller backoff immediately");
        assert_eq!(gets.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tor_connect_rate_limit_does_not_spend_fresh_circuit_retries() {
        let attempts = std::cell::Cell::new(0);
        let error = retry_tor_connect::<(), _, _>(TOR_CONNECT_TIMEOUT, |_| {
            attempts.set(attempts.get() + 1);
            async { Err(SlipstreamError::RateLimited("relay pause".into())) }
        })
        .await
        .expect_err("held by relay");
        assert!(
            matches!(error, SlipstreamError::RateLimited(_)),
            "{error:?}"
        );
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn tor_connect_recovers_on_a_fresh_circuit_before_the_budget_is_spent() {
        let attempts = std::cell::Cell::new(0);
        let client = retry_tor_connect(TOR_CONNECT_TIMEOUT, |attempt| {
            attempts.set(attempts.get() + 1);
            async move {
                if attempt == 1 {
                    Err(SlipstreamError::Transport("broken circuit".into()))
                } else {
                    Ok("connected")
                }
            }
        })
        .await
        .expect("the next circuit succeeds");
        assert_eq!(client, "connected");
        assert_eq!(attempts.get(), 2);
    }

    #[tokio::test]
    async fn tor_connect_transport_failures_use_all_circuit_attempts() {
        let attempts = std::cell::Cell::new(0);
        let error = retry_tor_connect::<(), _, _>(TOR_CONNECT_TIMEOUT, |attempt| {
            attempts.set(attempts.get() + 1);
            async move {
                Err(SlipstreamError::Transport(format!(
                    "broken circuit {attempt}"
                )))
            }
        })
        .await
        .expect_err("no usable circuit");
        assert!(
            matches!(&error, SlipstreamError::Transport(detail) if detail.contains("broken circuit 3")),
            "{error:?}"
        );
        assert_eq!(attempts.get(), TOR_CONNECT_ATTEMPTS);
    }

    #[tokio::test]
    async fn tor_connect_preserves_non_rate_error_classification() {
        let error = retry_tor_connect::<(), _, _>(TOR_CONNECT_TIMEOUT, |_| async {
            Err(SlipstreamError::Config("invalid endpoint".into()))
        })
        .await
        .expect_err("invalid configuration");
        assert!(matches!(error, SlipstreamError::Config(_)), "{error:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn tor_connect_timeouts_remain_transport_and_retry_fresh_circuits() {
        let attempts = std::cell::Cell::new(0);
        let start = tokio::time::Instant::now();
        let error = retry_tor_connect::<(), _, _>(TOR_CONNECT_TIMEOUT, |_| {
            attempts.set(attempts.get() + 1);
            std::future::pending()
        })
        .await
        .expect_err("all circuit attempts timed out");
        assert!(matches!(error, SlipstreamError::Transport(_)), "{error:?}");
        assert!(error.is_transient());
        assert!(error.counts_as_unreachable());
        assert_eq!(attempts.get(), TOR_CONNECT_ATTEMPTS);
        assert_eq!(start.elapsed(), TOR_CONNECT_TIMEOUT * TOR_CONNECT_ATTEMPTS);
    }

    #[test]
    fn plain_hosts_route_every_purpose_through_tor_too() {
        // Tor ON + clearnet lightwalletd (the OHTTP fallback / a manual pick): bulk must NOT
        // bypass Tor — the device IP would otherwise reach the server during the block download.
        assert_eq!(tor_mode(ConnPurpose::BulkFetch), Some(TorMode::OwnCircuit));
        assert_eq!(
            route(ConnPurpose::BulkFetch, false),
            Some(TorMode::OwnCircuit)
        );
        assert_eq!(
            route(ConnPurpose::MetadataUnique, false),
            Some(TorMode::Isolated)
        );
        assert_eq!(
            route(ConnPurpose::MetadataDefault, false),
            Some(TorMode::Default)
        );
    }

    #[test]
    fn ohttp_gateway_routes_every_purpose_through_tor() {
        // With Tor on and an OHTTP gateway endpoint, nothing may bypass Tor: bulk rides a
        // circuit per fetch connection, metadata keeps its usual isolation.
        assert_eq!(
            route(ConnPurpose::BulkFetch, true),
            Some(TorMode::OwnCircuit)
        );
        assert_eq!(
            route(ConnPurpose::MetadataUnique, true),
            Some(TorMode::Isolated)
        );
        assert_eq!(
            route(ConnPurpose::MetadataDefault, true),
            Some(TorMode::Default)
        );
        assert!(crate::ohttp::relay_for("ohttp-gateway-testnet.example").is_some());
        // Public sync metadata shares the session connection on the default circuit.
        assert_eq!(route(ConnPurpose::SyncShared, true), Some(TorMode::Shared));
        assert_eq!(route(ConnPurpose::SyncShared, false), Some(TorMode::Shared));
    }

    #[test]
    fn bulk_chunk_cap_applies_to_ohttp_only() {
        let gw = Endpoint {
            host: "ohttp-gateway-testnet.example".into(),
            port: 443,
            tls: true,
        };
        let plain = Endpoint {
            host: "zec.rocks".into(),
            port: 443,
            tls: true,
        };
        assert_eq!(bulk_chunk_blocks(10_000, &gw), OHTTP_MAX_CHUNK_BLOCKS);
        assert_eq!(bulk_chunk_blocks(500, &gw), 500);
        assert_eq!(bulk_chunk_blocks(10_000, &plain), 10_000);
        const {
            assert!(
                OHTTP_MAX_CHUNK_BLOCKS >= 100,
                "must satisfy EngineConfig's chunk_blocks >= 100"
            )
        };
        const { assert!(OHTTP_MAX_CHUNK_BLOCKS < crate::config::EngineConfig::DEFAULT_CHUNK_BLOCKS) };
    }

    #[test]
    fn ohttp_over_tor_timeout_leaves_room_for_two_circuits() {
        assert!(TOR_OHTTP_CONNECT_TIMEOUT >= TOR_CONNECT_TIMEOUT);
        // Every fresh-circuit dial attempt fits in the OHTTP connect budget, with room to spare.
        assert!(
            crate::ohttp::TOR_DIAL_TIMEOUT * crate::ohttp::TOR_DIAL_ATTEMPTS
                < TOR_OHTTP_CONNECT_TIMEOUT
        );
        assert!(TOR_OHTTP_CONNECT_TIMEOUT.as_secs() <= 60);
    }

    #[test]
    fn metadata_maps_to_isolated_and_default_circuits() {
        assert_eq!(
            tor_mode(ConnPurpose::MetadataUnique),
            Some(TorMode::Isolated)
        ); // .uniqueTor
        assert_eq!(
            tor_mode(ConnPurpose::MetadataDefault),
            Some(TorMode::Default)
        ); // .defaultTor
    }

    /// Locks the bounded-retry design intent: at least one fresh-circuit retry, and a per-attempt
    /// timeout that gives a healthy circuit room (>=5s) while cutting a stuck one promptly (<=30s).
    #[test]
    fn tor_connect_retry_constants_are_sane() {
        const {
            assert!(
                TOR_CONNECT_ATTEMPTS >= 2,
                "need at least one retry on a fresh circuit"
            )
        };
        let secs = TOR_CONNECT_TIMEOUT.as_secs();
        assert!(
            (5..=30).contains(&secs),
            "per-attempt timeout must be 5..=30s (room for a healthy circuit, cut a stuck one), got {secs}s"
        );
    }

    #[tokio::test]
    async fn retry_transient_recovers_from_a_brief_outage() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<u32, SlipstreamError> = retry_transient(
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move {
                    if n < 3 {
                        Err(SlipstreamError::Transport("server down".into()))
                    } else {
                        Ok(n)
                    }
                }
            },
            DIRECT_CONNECT_ATTEMPTS,
            |_| std::time::Duration::ZERO,
        )
        .await;
        assert_eq!(out.expect("recovers in place — no pass restart"), 3);
        assert_eq!(
            calls.get(),
            3,
            "stops retrying the moment the connect succeeds"
        );
    }

    #[tokio::test]
    async fn retry_transient_gives_up_after_budget() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<u32, SlipstreamError> = retry_transient(
            || {
                calls.set(calls.get() + 1);
                async { Err(SlipstreamError::Transport("still down".into())) }
            },
            4,
            |_| std::time::Duration::ZERO,
        )
        .await;
        assert!(
            out.is_err(),
            "a genuinely-down endpoint still surfaces (pass then falls back to a restart)"
        );
        assert_eq!(calls.get(), 4, "exactly `attempts` tries");
    }

    #[tokio::test]
    async fn retry_transient_does_not_retry_nontransient() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let out: Result<u32, SlipstreamError> = retry_transient(
            || {
                calls.set(calls.get() + 1);
                async { Err(SlipstreamError::Config("bad uri".into())) }
            },
            DIRECT_CONNECT_ATTEMPTS,
            |_| std::time::Duration::ZERO,
        )
        .await;
        assert!(out.is_err());
        assert_eq!(
            calls.get(),
            1,
            "a non-transient (config) error surfaces immediately, never retried"
        );
    }

    #[test]
    fn direct_connect_backoff_is_capped_exponential() {
        assert_eq!(direct_connect_backoff(1).as_secs(), 1);
        assert_eq!(direct_connect_backoff(2).as_secs(), 2);
        assert_eq!(direct_connect_backoff(5).as_secs(), 16);
        assert_eq!(
            direct_connect_backoff(99).as_secs(),
            16,
            "held at the 16s cap, never overflows"
        );
        const {
            assert!(
                DIRECT_CONNECT_ATTEMPTS >= 2,
                "need at least one retry to absorb a blip"
            )
        };
    }

    // ── LazyConnection ───────────────────────────────────────────────────────

    /// A connection that is never asked for is never opened.
    #[test]
    fn lazy_connection_unused_never_connects() {
        let calls = std::cell::Cell::new(0u32);
        {
            let _unused = LazyConnection::new(|| {
                calls.set(calls.get() + 1);
                async { Ok::<u32, SlipstreamError>(7) }
            });
        }
        assert_eq!(calls.get(), 0, "an unused lazy connection opens nothing");
    }

    /// The first use connects; later uses reuse that client.
    #[tokio::test]
    async fn lazy_connection_connects_on_first_use_and_reuses_the_client() {
        let calls = std::cell::Cell::new(0u32);
        let mut lazy = LazyConnection::new(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move { Ok::<u32, SlipstreamError>(n) }
        });
        assert_eq!(*lazy.get().await.expect("the first use connects"), 1);
        assert_eq!(*lazy.get().await.expect("later uses reuse it"), 1);
        assert_eq!(calls.get(), 1, "connected exactly once");
    }

    /// A failed connect leaves nothing behind; the next use connects again.
    #[tokio::test]
    async fn lazy_connection_retries_after_a_failed_connect() {
        let calls = std::cell::Cell::new(0u32);
        let mut lazy = LazyConnection::new(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n == 1 {
                    Err(SlipstreamError::Transport("server down".into()))
                } else {
                    Ok::<u32, SlipstreamError>(n)
                }
            }
        });
        assert!(lazy.get().await.is_err(), "the failed connect surfaces");
        assert_eq!(*lazy.get().await.expect("the next use connects again"), 2);
        assert_eq!(calls.get(), 2);
    }
}
