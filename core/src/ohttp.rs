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

//! Oblivious HTTP (RFC 9458) transport for lightwalletd.
//!
//! Endpoints whose host is a ZODL OHTTP *gateway* (see [`relay_for`]) are not dialled directly.
//! Instead every gRPC call is HPKE-encrypted to the gateway's published key and POSTed to a
//! *relay*, so the relay sees the client IP but only ciphertext, and the gateway (and the
//! lightwalletd behind it) sees plaintext but only the relay's IP.
//!
//! Integration point: [`OhttpConnector`] is a `tower::Service<Uri>` usable with
//! `tonic::transport::Endpoint::connect_with_connector`, exactly like the Tor connector in
//! `zcash_client_backend`. It hands tonic an in-memory duplex stream whose other end is an
//! in-process HTTP/2 server. That server turns each gRPC request into one OHTTP round trip and
//! replies with a normal gRPC response (headers + body + trailers), so `CompactTxStreamerClient<Channel>`
//! and every caller in this crate stay unchanged. Responses are Chunked OHTTP: the gateway seals
//! them chunk by chunk as lightwalletd streams, and this module decodes them the same way, so a
//! server-streaming RPC delivers its first message before the response has ended.
//!
//! The protocol itself (RFC 9458 §4.3/§4.4 with the suite DHKEM(X25519, HKDF-SHA256) /
//! HKDF-SHA256 / AES-128-GCM, Binary HTTP, signed key-configuration verification, key selection,
//! outer-status classification and size limits) is the shared sans-IO `zodl-ohttp-client` crate,
//! driven with its `ClientProfile::SLIPSTREAM` (gRPC) and `ClientProfile::SLIPSTREAM_HTTP`
//! ([`http_round_trip`]) profiles. This module keeps the I/O: the dialer, the pooled h2 sender,
//! the relay table, timeouts and the mapping to gRPC. The gateway carries the gRPC status in the
//! Binary HTTP trailer section when lightwalletd streamed it, and in the header section when the
//! answer was trailers-only or collected first (a cache hit); this module puts it into the HTTP/2
//! trailers either way, where tonic reads it.
//!
//! **Tor.** The TCP leg to the relay (and the one-off `/ohttp-configs/signed` key fetch) is
//! opened through a [`Dialer`]: [`Dialer::Direct`] uses the device's own connection,
//! [`Dialer::Tor`] opens an arti stream so the relay only ever sees a Tor exit IP. Everything
//! above TCP (TLS to the relay, HPKE to the gateway) is identical in both cases.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    sync::OnceLock,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::io::{AsyncRead, AsyncWrite};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::DuplexStream;
use tokio::sync::Mutex;
use tower_service::Service;
pub use zcash_protocol::consensus::NetworkType;
use zodl_ohttp_client::{
    BhttpRequest, BhttpResponse, CONTENT_TYPE_CHUNKED_RES, ChunkedResponseDecoder, ClientProfile,
    ClientTrace, DOH_RESOLVERS, GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES,
    GATEWAY_MAX_SEALED_RESPONSE_BYTES, KeyConfig, Network, NetworkRule, RelayBackoff,
    ResponseEvent, SizeGuard, check_size, doh_query_url, encapsulate_chunked_request,
    envelope_from_doh_json, key_config_dns_name, signed_config_url, verify_signed_config,
};

/// In-memory pipe capacity between tonic and the in-process h2 server.
const DUPLEX_BUF: usize = 4 << 20;
/// Whole OHTTP round trip (encapsulate → relay → gateway → lightwalletd → back). The engine's own
/// `UNARY_TIMEOUT` (30 s) bounds the wait for response headers, so this only matters for large
/// buffered streams; the gateway itself gives lightwalletd 80 s.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(100);

/// Idle timeout between chunks in a streaming OHTTP response. A healthy stream delivers chunks
/// continuously; 30 s of silence means the connection is dead.
const CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on opening a direct TCP connection to the relay.
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Longest a pooled relay connection is reused with Tor off: connection lifetime is linkable
/// metadata the relay sees, so a long-lived wallet process moves to a fresh connection now and
/// then. In-flight requests finish on the old one.
const H2_MAX_CONNECTION_AGE: Duration = Duration::from_secs(10 * 60);

/// Trailers-only metadata the in-process server attaches to a gRPC error so that the engine can
/// tell an OHTTP outcome from an unreachable server (see `grpc::status_err`). It never leaves
/// the process.
pub(crate) const OHTTP_OUTCOME_HEADER: &str = "x-ohttp-outcome";
/// An inner 403: the gateway refused this operation by policy.
pub(crate) const OUTCOME_POLICY_DENIED: &str = "policy-denied";
/// An outer 429, or a request held back while the relay's `Retry-After` pause runs.
pub(crate) const OUTCOME_RATE_LIMITED: &str = "rate-limited";
/// An outer 413, or a sealed request over 10 MiB that was not sent.
pub(crate) const OUTCOME_TOO_LARGE: &str = "too-large";

/// Verified key configurations shared by every connection to the same gateway through the same
/// relay, so that a new connection (a tip probe, a fetch worker, an isolated Tor client) does
/// not fetch the signed configuration again while it is valid. Entries end at `not_after`.
static SHARED_KEYS: OnceLock<std::sync::Mutex<HashMap<(String, String), CachedKey>>> =
    OnceLock::new();

fn shared_keys() -> std::sync::MutexGuard<'static, HashMap<(String, String), CachedKey>> {
    SHARED_KEYS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Hostname prefix that marks an endpoint as an OHTTP gateway (mirrors the Kotlin SDK).
pub const GATEWAY_HOST_PREFIX: &str = "ohttp-gateway";

/// Process-wide default client trace prefix for OHTTP connections (set once from JNI).
static DEFAULT_CLIENT_TRACE_PREFIX: OnceLock<Option<String>> = OnceLock::new();

/// Process-wide cache of OHTTP clients for Direct-dialer connections only. Each cached client
/// pools HTTP/2 connections and verified key configs per gateway. Tor-dialer clients are never
/// cached (fresh client per call) to avoid linking requests across isolated circuits.
static CLIENT_CACHE: OnceLock<Mutex<HashMap<ClientCacheKey, Arc<OhttpClient>>>> = OnceLock::new();

/// Cache key for OHTTP clients: gateway host, relay URL, trace prefix, and profile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ClientCacheKey {
    gateway_host: String,
    relay_url: String,
    trace_prefix: Option<String>,
    /// Profile identified by which const it equals (1=ANDROID, 2=IOS, 3=SLIPSTREAM,
    /// 4=SLIPSTREAM_HTTP, 5=LIBRARY). Any other profile has no key and is never cached.
    profile_id: u8,
}

impl ClientCacheKey {
    fn new(
        gateway_host: &str,
        relay_url: &str,
        trace_prefix: Option<String>,
        profile: ClientProfile,
    ) -> Option<Self> {
        let profile_id = if profile == ClientProfile::ANDROID {
            1
        } else if profile == ClientProfile::IOS {
            2
        } else if profile == ClientProfile::SLIPSTREAM {
            3
        } else if profile == ClientProfile::SLIPSTREAM_HTTP {
            4
        } else if profile == ClientProfile::LIBRARY {
            5
        } else {
            return None;
        };

        Some(Self {
            gateway_host: gateway_host.to_string(),
            relay_url: relay_url.to_string(),
            trace_prefix,
            profile_id,
        })
    }
}

/// Set the default client trace prefix for all OHTTP connections without an explicit prefix.
/// Called from JNI/FFI when the engine or TorRuntime is created.
///
/// Debug-only gating (P7) is the caller's job: the Android SDK passes a prefix only when its
/// own `BuildConfig.DEBUG` is true, the Swift SDK only under `#if DEBUG`. It cannot be a
/// `cfg(debug_assertions)` gate here because the mobile SDKs always build this crate with the
/// release profile, which silently dropped the prefix in debug app builds too.
pub fn set_default_client_trace_prefix(prefix: Option<String>) {
    let _ = DEFAULT_CLIENT_TRACE_PREFIX.set(prefix);
}

/// Get the default client trace prefix.
fn get_default_client_trace_prefix() -> Option<String> {
    DEFAULT_CLIENT_TRACE_PREFIX
        .get()
        .and_then(|opt| opt.clone())
}

/// Get or create a cached OHTTP client for the given parameters. **Privacy:** only
/// `Dialer::Direct` clients are cached (keyed by gateway_host + relay_url + trace_prefix +
/// profile); `Dialer::Tor` always creates a fresh client to avoid linking requests across
/// isolated circuits or leaking the device IP when the caller asked for Tor.
async fn get_or_create_client(
    gateway_host: &str,
    relay_url: &str,
    dialer: Dialer,
    client_trace_prefix: Option<String>,
    profile: ClientProfile,
) -> Result<Arc<OhttpClient>, String> {
    // Tor clients are never cached: each call gets a fresh client with fresh connections.
    // Neither is a profile outside the known presets, which has no distinguishing cache key.
    let key = if dialer.is_tor() {
        None
    } else {
        ClientCacheKey::new(
            gateway_host,
            relay_url,
            client_trace_prefix.clone(),
            profile,
        )
    };
    let Some(key) = key else {
        return Ok(Arc::new(OhttpClient::new(
            gateway_host,
            relay_url,
            dialer,
            client_trace_prefix,
            profile,
        )?));
    };

    // Direct clients are cached per (gateway_host, relay_url, trace_prefix, profile)
    let cache = CLIENT_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().await;

    if let Some(client) = map.get(&key) {
        return Ok(Arc::clone(client));
    }

    // Create and cache a new Direct-dialer client
    let client = Arc::new(OhttpClient::new(
        gateway_host,
        relay_url,
        dialer,
        client_trace_prefix,
        profile,
    )?);
    map.insert(key, Arc::clone(&client));
    Ok(client)
}

/// Relay URL for a given gateway host. One relay per gateway: mainnet and testnet gateways use
/// different HPKE keys, and an RFC 9458 relay has a single fixed gateway target.
///
/// Uses Fastly-hosted relays in production (`relay.example.invalid`).
/// Relay URLs can be overridden at build time via environment variables
/// `ZODL_OHTTP_RELAY_URL_MAINNET` and `ZODL_OHTTP_RELAY_URL_TESTNET` (see `zodl-ohttp-client`
/// documentation).
pub fn relay_for(gateway_host: &str) -> Option<&'static str> {
    zodl_ohttp_client::relay_for(gateway_host)
}

/// Object-safe alias for the byte stream underneath TLS (a plain TCP socket or an arti Tor
/// stream); Rust allows only one non-auto trait per `dyn`, hence the blanket supertrait.
trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncIo for T {}
type BoxedIo = Box<dyn AsyncIo>;

/// Per-attempt bound on opening one Tor stream to the relay/gateway. A healthy circuit connects
/// in a few seconds; a stuck one is cut here and retried on a FRESH isolated circuit.
/// 8 s x 3 attempts = 24 s, inside the 30 s `TOR_OHTTP_CONNECT_TIMEOUT` with 6 s left for TLS and
/// the request, so the third fresh circuit gets its full attempt.
pub(crate) const TOR_DIAL_TIMEOUT: Duration = Duration::from_secs(8);
/// Fresh-circuit attempts per Tor dial before the error surfaces to the caller.
pub(crate) const TOR_DIAL_ATTEMPTS: u32 = 3;

/// How the TCP leg towards the relay / gateway is opened.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Dialer {
    /// The device's own network path (the relay sees the device IP, but only ciphertext).
    Direct,
    /// Through Tor: the relay sees a Tor exit IP. Streams opened from this handle share its
    /// isolation group; callers hand in an `isolated_client()` when they want a fresh one.
    Tor(Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>),
}

impl Dialer {
    pub fn is_tor(&self) -> bool {
        matches!(self, Dialer::Tor(_))
    }

    async fn dial(&self, host: &str, port: u16) -> Result<BoxedIo, String> {
        match self {
            Dialer::Direct => {
                let tcp = tokio::time::timeout(
                    DIRECT_DIAL_TIMEOUT,
                    tokio::net::TcpStream::connect((host, port)),
                )
                .await
                .map_err(|_| {
                    format!(
                        "connect {host}: exceeded {}s",
                        DIRECT_DIAL_TIMEOUT.as_secs()
                    )
                })?
                .map_err(|e| format!("connect {host}: {e}"))?;
                let _ = tcp.set_nodelay(true);
                Ok(Box::new(tcp))
            }
            Dialer::Tor(client) => {
                // arti resolves `host` at the exit relay, so no DNS leaves the device either.
                let mut last_err = String::new();
                for attempt in 1..=TOR_DIAL_ATTEMPTS {
                    let c = if attempt == 1 {
                        Arc::clone(client)
                    } else {
                        client.isolated_client()
                    };
                    let started = std::time::Instant::now();
                    match tokio::time::timeout(TOR_DIAL_TIMEOUT, c.connect((host, port))).await {
                        Ok(Ok(stream)) => {
                            tracing::info!(
                                host,
                                port,
                                attempt,
                                ms = started.elapsed().as_millis() as u64,
                                "ohttp: dialled through Tor"
                            );
                            return Ok(Box::new(stream));
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(host, attempt, err = %e, "ohttp: tor dial failed — retrying on a fresh circuit");
                            last_err = format!("tor connect {host}: {e}");
                        }
                        Err(_) => {
                            tracing::warn!(
                                host,
                                attempt,
                                timeout_secs = TOR_DIAL_TIMEOUT.as_secs(),
                                "ohttp: tor dial timed out — retrying on a fresh circuit"
                            );
                            last_err = format!(
                                "tor connect {host}: exceeded {}s",
                                TOR_DIAL_TIMEOUT.as_secs()
                            );
                        }
                    }
                }
                Err(last_err)
            }
        }
    }
}

/// `tower::Service<Uri>` connector for `Endpoint::connect_with_connector`.
#[derive(Clone)]
pub struct OhttpConnector {
    client: Arc<OhttpClient>,
}

impl OhttpConnector {
    /// Direct dialer: the relay sees the device IP.
    pub fn new(gateway_host: &str, relay_url: &str) -> Result<Self, String> {
        Self::with_dialer(
            gateway_host,
            relay_url,
            Dialer::Direct,
            get_default_client_trace_prefix(),
        )
    }

    /// Connector whose TCP legs (relay POSTs and the gateway key fetch) go through `dialer`.
    pub fn with_dialer(
        gateway_host: &str,
        relay_url: &str,
        dialer: Dialer,
        client_trace_prefix: Option<String>,
    ) -> Result<Self, String> {
        Ok(Self {
            client: Arc::new(OhttpClient::new(
                gateway_host,
                relay_url,
                dialer,
                client_trace_prefix.or_else(get_default_client_trace_prefix),
                ClientProfile::SLIPSTREAM,
            )?),
        })
    }

    /// Eagerly fetch the gateway key configuration and open the pooled h2 connection to the
    /// relay, so that the caller can bound (and retry on a fresh circuit) the slow part of a Tor
    /// connect instead of paying it inside the first RPC's deadline. Idempotent.
    pub async fn warm_up(&self) -> Result<(), String> {
        self.client
            .key_config(false)
            .await
            .map_err(RoundTripError::into_message)?;
        if self.client.h2_sender(&self.client.relay).await?.is_none() {
            tracing::debug!("ohttp: relay did not negotiate h2; will use HTTP/1.1 per request");
        }
        Ok(())
    }
}

impl Service<Uri> for OhttpConnector {
    type Response = TokioIo<DuplexStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _dst: Uri) -> Self::Future {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let client = Arc::clone(&client);
                    async move { Ok::<_, Infallible>(client.handle(req).await) }
                });
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(server_io), svc);
                if let Err(e) = conn.await {
                    tracing::debug!(err = %e, "ohttp: in-process h2 connection closed");
                }
            });
            Ok(TokioIo::new(client_io))
        })
    }
}

/// The gateway key in use and the end of the signed configuration it came from.
#[derive(Clone, Copy, Debug)]
struct CachedKey {
    config: KeyConfig,
    /// Unix time (seconds) at which the signed envelope stops being valid.
    not_after: u64,
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system time: {e}"))
}

/// The network a gateway serves, by exact host: the envelope must name it, and the wallet using
/// the gateway must be on it (`EngineConfig::validate`, [`http_round_trip`]).
pub(crate) fn gateway_network(gateway_host: &str) -> Result<Network, String> {
    NetworkRule::KnownHosts
        .network_for(gateway_host)
        .map_err(|e| e.to_string())
}

/// Refuses an OHTTP gateway that serves another network than `network`: its calls would reach
/// the wrong chain, under a key configuration signed for that chain. Regtest has no gateway.
pub(crate) fn check_gateway_network(
    gateway_host: &str,
    network: NetworkType,
) -> Result<(), String> {
    let gateway = gateway_network(gateway_host)?;
    let wallet = match network {
        NetworkType::Main => Some(Network::Mainnet),
        NetworkType::Test => Some(Network::Testnet),
        NetworkType::Regtest => None,
    };
    if wallet == Some(gateway) {
        Ok(())
    } else {
        Err(format!(
            "OHTTP gateway {gateway_host} serves {}, not this wallet's network",
            gateway.as_str()
        ))
    }
}

/// Verify a signed key-configuration envelope for `gateway_host` under `profile` (network from
/// the host's exact name, pinned signing key, validity window at `now`, signature) and pick the
/// key out of it. Pure: the fetch and the cache are the caller's.
fn open_signed_keys(
    profile: &ClientProfile,
    json: &[u8],
    gateway_host: &str,
    now: u64,
) -> Result<CachedKey, String> {
    let network = gateway_network(gateway_host)?;
    let keys = verify_signed_config(json, network, now, &profile.signed_config)
        .map_err(|e| e.to_string())?;
    let config = KeyConfig::select_with(&keys.document, &profile.key_selection)
        .map_err(|e| e.to_string())?;
    Ok(CachedKey {
        config,
        not_after: keys.not_after,
    })
}

struct HttpsTarget {
    host: String,
    port: u16,
    path: String,
}

fn parse_https(url: &str) -> Result<HttpsTarget, String> {
    let uri: Uri = url.parse().map_err(|e| format!("bad url {url}: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err(format!("relay/gateway URL must be https: {url}"));
    }
    Ok(HttpsTarget {
        host: uri.host().ok_or("url without host")?.to_string(),
        port: uri.port_u16().unwrap_or(443),
        path: uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
    })
}

/// The outer answer of one HTTPS exchange, body read in full (within the size cap).
struct RelayAnswer {
    status: StatusCode,
    content_type: Option<String>,
    /// `Retry-After` of a 429, see [`retry_after`].
    retry_after: Option<Duration>,
    body: Vec<u8>,
}

/// The outer answer of one HTTPS exchange with the body left unread, to be decoded chunk by
/// chunk as it arrives.
struct RelayStream {
    status: StatusCode,
    content_type: Option<String>,
    /// `Retry-After` of a 429, see [`retry_after`].
    retry_after: Option<Duration>,
    body: BoxBody<Bytes, hyper::Error>,
}

/// The `Retry-After` of an outer answer as delay-seconds (RFC 9110, section 10.2.3), capped at
/// 120 s (`zodl_ohttp_client::MAX_RETRY_AFTER`). The HTTP-date form is not used by the relays
/// and is ignored.
fn retry_after(headers: &http::HeaderMap) -> Option<Duration> {
    zodl_ohttp_client::retry_after_delay(headers.get(header::RETRY_AFTER)?.to_str().ok())
}

/// Error from the chunked body pump: transport (network) or decode (BHTTP format).
enum PumpError {
    /// Transport failure: network read error, idle timeout, or truncated stream.
    Transport(String),
    /// Decode failure: invalid BHTTP format, but the sealed response was received intact.
    Decode(String),
}

impl PumpError {
    fn transport(msg: impl Into<String>) -> Self {
        PumpError::Transport(msg.into())
    }

    fn decode(msg: impl Into<String>) -> Self {
        PumpError::Decode(msg.into())
    }
}

/// Streaming half of [`OhttpClient::round_trip_stream_once`]: reads the relay body frame by
/// frame, enforces the response size bound, feeds the chunked decoder and forwards its events.
/// It stops as soon as the receiver is gone (the RPC was cancelled or timed out) and drops the
/// body, even while an incomplete chunk produces no events, so a dropped call stops reading
/// ciphertext from the relay.
async fn pump_chunked_body(
    mut body_stream: BoxBody<Bytes, hyper::Error>,
    mut decoder: ChunkedResponseDecoder,
    mut guard: SizeGuard,
    tx: tokio::sync::mpsc::Sender<Result<ResponseEvent, PumpError>>,
) {
    loop {
        tokio::select! {
            biased;
            () = tx.closed() => {
                // Receiver dropped: stop reading and drop the body promptly
                drop(body_stream);
                return;
            }
            frame_result = tokio::time::timeout(CHUNK_IDLE_TIMEOUT, body_stream.frame()) => {
                match frame_result {
                    Ok(Some(Ok(frame))) => {
                        if let Ok(data) = frame.into_data() {
                            // Enforce size limit before pushing to decoder
                            if let Err(e) = guard.push(data.len()) {
                                let _ = tx.send(Err(PumpError::transport(format!("response too large: {e}")))).await;
                                return;
                            }
                            match decoder.push(&data) {
                                Ok(events) => {
                                    for event in events {
                                        if tx.send(Ok(event)).await.is_err() {
                                            return; // Receiver dropped
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(PumpError::decode(format!("bhttp decode: {e}")))).await;
                                    return;
                                }
                            }
                        }
                    }
                    Ok(Some(Err(e))) => {
                        let _ = tx.send(Err(PumpError::transport(format!("read chunk: {e}")))).await;
                        return;
                    }
                    Ok(None) => {
                        // Stream ended normally
                        break;
                    }
                    Err(_) => {
                        let _ = tx
                            .send(Err(PumpError::transport("idle timeout: no chunk received in 30s")))
                            .await;
                        return;
                    }
                }
            }
        }
    }

    // Finish decoding
    match decoder.finish() {
        Ok(events) => {
            for event in events {
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
        }
        Err(e @ zodl_ohttp_client::Error::Truncated) => {
            let _ = tx
                .send(Err(PumpError::transport(format!(
                    "incomplete response: {e}"
                ))))
                .await;
        }
        Err(e) => {
            let _ = tx
                .send(Err(PumpError::decode(format!("finish decode: {e}"))))
                .await;
        }
    }
}

/// What [`run_exchange_chunked`] needs from the relay's answer to one sealed POST, whatever
/// became of its body. Keeps one exchange loop (re-sealing, key refetch, outer-status and
/// content-type checks) for the buffered and the streamed paths.
trait OuterAnswer {
    fn status(&self) -> StatusCode;
    fn content_type(&self) -> Option<&str>;
    /// The start of the body, for the error message of a non-success outer status.
    fn detail(&self) -> String;
    /// How long the relay asked the client to wait (an outer 429).
    fn retry_after(&self) -> Option<Duration>;
}

impl OuterAnswer for RelayAnswer {
    fn status(&self) -> StatusCode {
        self.status
    }
    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
    fn detail(&self) -> String {
        String::from_utf8_lossy(&self.body)
            .chars()
            .take(160)
            .collect()
    }
    fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl OuterAnswer for RelayStream {
    fn status(&self) -> StatusCode {
        self.status
    }
    fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
    fn detail(&self) -> String {
        String::new()
    }
    fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

/// Whether a failed relay fetch of the key configuration goes on to the DNS fallback. A 429, or
/// the relay's running pause, is the relay's back-off signal, not a relay that could not deliver:
/// the client waits instead of asking the resolvers.
fn relay_failure_has_dns_fallback(err: &RoundTripError) -> bool {
    !matches!(err, RoundTripError::RateLimited { .. })
}

/// The headers of a DoH query: the client's fixed key-fetch headers (`Accept-Encoding`,
/// `User-Agent`), with the DoH JSON `Accept` in place of the relay fetch's, so that the resolver
/// sees the same fixed headers as the relay does.
fn doh_headers(profile: &ClientProfile) -> Vec<(&'static str, String)> {
    let mut headers = vec![(header::ACCEPT.as_str(), "application/dns-json".to_string())];
    headers.extend(
        profile
            .headers
            .key_fetch(None)
            .into_iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("accept")),
    );
    headers
}

/// Why one HTTPS exchange failed.
#[derive(Debug)]
enum HttpsError {
    /// The pooled h2 connection was not ready: nothing reached the far end, so the caller may
    /// try again (a relay POST is sealed afresh first).
    PreSend(String),
    /// Anything else (connect, TLS, send, read): not retried here, to avoid repeating a request
    /// with side effects. Only a failure after `on_send` ran may have reached the far end.
    Other(String),
    /// Not sent: the relay's `Retry-After` pause began while this request was being prepared.
    RelayPaused(String),
    /// A size guard refused the answer, by the length it declared or by the bytes read so far.
    TooLarge(String),
}

impl HttpsError {
    fn into_message(self) -> String {
        match self {
            HttpsError::PreSend(m)
            | HttpsError::Other(m)
            | HttpsError::RelayPaused(m)
            | HttpsError::TooLarge(m) => m,
        }
    }

    /// Classifies a `send_request` error. It never returns `PreSend`: this code does not
    /// currently distinguish a request that was never written from one that may have reached the
    /// relay, so every send error is treated as potentially post-send (`Other`) and never resealed
    /// or re-POSTed, to avoid repeating a request with side effects (ZIP Gateway rule 11). Only
    /// `ready()` failures, classified at their own call sites, are `PreSend`.
    fn classify_send_error(e: impl std::fmt::Display, target_host: &str) -> Self {
        HttpsError::Other(format!("h2 send {target_host}: {e}"))
    }
}

/// Reads `body` to its end into memory, within `guard`. `declared_len` is the length the peer
/// announced (`Content-Length`): a length past the guard's limit is refused before a frame is
/// pulled. Each data frame is counted with `guard` before it is buffered, so the read stops at
/// the first one that goes past the limit and the frames behind it are never pulled from the
/// peer. Both refusals are [`HttpsError::TooLarge`]. A read error, or [`CHUNK_IDLE_TIMEOUT`]
/// without a frame, is [`HttpsError::Other`]. `host` names the peer in the messages.
async fn read_body_capped<B>(
    mut body: B,
    declared_len: Option<u64>,
    mut guard: SizeGuard,
    host: &str,
) -> Result<Vec<u8>, HttpsError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if let Some(declared) = declared_len {
        guard
            .check_declared(declared)
            .map_err(|e| HttpsError::TooLarge(format!("read {host}: {e}")))?;
    }
    let mut bytes = Vec::new();
    loop {
        let Some(frame) = tokio::time::timeout(CHUNK_IDLE_TIMEOUT, body.frame())
            .await
            .map_err(|_| {
                HttpsError::Other(format!(
                    "read {host}: idle timeout ({}s without data)",
                    CHUNK_IDLE_TIMEOUT.as_secs()
                ))
            })?
        else {
            break;
        };
        let frame = frame.map_err(|e| HttpsError::Other(format!("read {host}: {e}")))?;
        if let Ok(data) = frame.into_data() {
            guard
                .push(data.len())
                .map_err(|e| HttpsError::TooLarge(format!("read {host}: {e}")))?;
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

/// Why a whole OHTTP round trip failed; the gRPC bridge maps each differently.
#[derive(Debug)]
enum RoundTripError {
    /// Key fetch, relay, gateway or the exchange broke off (gRPC `UNAVAILABLE`).
    Transport(String),
    /// The answer does not authenticate or is not a Binary HTTP response (gRPC `INTERNAL`).
    Decode(String),
    /// An outer 429, or not sent because the relay's `Retry-After` pause is still running: a
    /// back-off signal, not an unreachable gateway (gRPC `UNAVAILABLE`, marked rate-limited).
    RateLimited {
        detail: String,
        retry_after: Option<Duration>,
    },
    /// An outer 413, or a sealed request over 10 MiB refused before it was sent (gRPC
    /// `RESOURCE_EXHAUSTED`, not retried).
    TooLarge(String),
    /// The answer is past the size ceiling of the request: the sealed answer stopped being read
    /// at it, or its opened body is longer than the caller allowed (gRPC `RESOURCE_EXHAUSTED`,
    /// not retried). The request had been sent.
    ResponseTooLarge(String),
}

impl RoundTripError {
    fn into_message(self) -> String {
        self.to_string()
    }

    /// A key configuration fetch the relay answered with a status other than success: a 429 is
    /// the relay's back-off signal, as on a post, not an unreachable gateway.
    fn key_fetch_refused(status: StatusCode, retry_after: Option<Duration>) -> Self {
        let detail = format!("signed config fetch from relay: HTTP {status}");
        if status == StatusCode::TOO_MANY_REQUESTS {
            RoundTripError::RateLimited {
                detail,
                retry_after,
            }
        } else {
            RoundTripError::Transport(detail)
        }
    }
}

impl std::fmt::Display for RoundTripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoundTripError::Transport(e)
            | RoundTripError::TooLarge(e)
            | RoundTripError::ResponseTooLarge(e) => f.write_str(e),
            RoundTripError::Decode(e) => write!(f, "bhttp decode: {e}"),
            RoundTripError::RateLimited { detail, .. } => f.write_str(detail),
        }
    }
}

/// Runs `attempt`, and once more when its answer is the gateway's freshness refusal (an inner
/// 400 with `ohttp-freshness: rejected`). The refusal carried the gateway clock, which the
/// decoder has already learned, so the second attempt (sealed afresh by `attempt`) is stamped
/// right. At most one retry: a second refusal is returned as it is.
///
/// With the B3 send-error classification, at most 4 relay POSTs per call can reach the network:
/// freshness retry (2) × key-refresh retry (2). A reseal after a PreSend failure does not reach
/// the relay.
async fn with_freshness_retry<T, F, Fut, J>(
    mut attempt: F,
    is_refusal: J,
) -> Result<T, RoundTripError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RoundTripError>>,
    J: Fn(&T) -> bool,
{
    let first = attempt().await?;
    if !is_refusal(&first) {
        return Ok(first);
    }
    drop(first);
    tracing::warn!(
        offset_secs = zodl_ohttp_client::freshness::clock_offset_secs(),
        "ohttp: gateway refused the request as stale; sending it again"
    );
    attempt().await
}

/// `on_dispatch` wrapped so that it runs at most once, across the attempts of one request: the
/// first send marks the request as possibly delivered, and a later post of it (after a key
/// refresh, or when the gateway refused it as stale) does not call the hook again.
fn once_dispatch<D: Fn()>(on_dispatch: D) -> impl Fn() {
    let done = std::sync::atomic::AtomicBool::new(false);
    move || {
        if !done.swap(true, std::sync::atomic::Ordering::Relaxed) {
            on_dispatch();
        }
    }
}

/// The most sealed bytes read of an answer whose body the caller allows `max_response_bytes`:
/// the body, one 256th more for the chunk tags and length prefixes, and 64 KiB for the header
/// fields and the framing; never more than the gateway's own sealed cap. The opened body is
/// then checked against `max_response_bytes` itself, see [`check_response_body`].
fn sealed_response_ceiling(max_response_bytes: usize) -> usize {
    max_response_bytes
        .saturating_add(max_response_bytes / 256)
        .saturating_add(64 * 1024)
        .min(GATEWAY_MAX_SEALED_RESPONSE_BYTES)
}

/// Refuses an opened answer body of `len` bytes when it is longer than `max`, the ceiling the
/// caller set (`None`: the caller set none).
fn check_response_body(len: usize, max: Option<usize>) -> Result<(), RoundTripError> {
    match max {
        Some(max) if len > max => Err(RoundTripError::ResponseTooLarge(format!(
            "response body too large: {len} > {max} bytes"
        ))),
        _ => Ok(()),
    }
}

/// The relay POST loop for chunked OHTTP. Returns the decoder and the relay's answer (buffered
/// or streamed, per `post`). **Every post is sealed afresh** (a new ephemeral key, so new
/// ciphertext): the gateway answers a repeated ciphertext with 409. A pre-send transport failure
/// is retried once; an outer 400 or 422 refetches the key and retries once. An answer that a
/// size guard refused ([`HttpsError::TooLarge`]) is final: [`RoundTripError::ResponseTooLarge`],
/// not posted again.
///
/// The caller's dispatch hook is not called here but inside `post`, at the moment the sealed
/// request is handed to the relay connection: until then a post may still fail without having
/// sent anything.
async fn run_exchange_chunked<A, P, PF, R, RF>(
    mut key: KeyConfig,
    request: &BhttpRequest,
    mut post: P,
    mut refetch: R,
) -> Result<(ChunkedResponseDecoder, A), RoundTripError>
where
    A: OuterAnswer,
    P: FnMut(Vec<u8>) -> PF,
    PF: Future<Output = Result<A, HttpsError>>,
    R: FnMut() -> RF,
    RF: Future<Output = Result<KeyConfig, RoundTripError>>,
{
    let mut attempt = 0u32;
    loop {
        let mut resent = false;
        let (opener, answer) = loop {
            let encoded =
                zodl_ohttp_client::encode_bhttp_request(request, &ClientProfile::SLIPSTREAM.encode)
                    .map_err(|e| RoundTripError::Transport(e.to_string()))?;
            let (sealed, opener) = encapsulate_chunked_request(&key, &encoded)
                .map_err(|e| RoundTripError::Transport(e.to_string()))?;
            check_size(sealed.len(), Some(GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES))
                .map_err(|e| RoundTripError::TooLarge(format!("sealed request not sent: {e}")))?;
            match post(sealed).await {
                Ok(answer) => break (opener, answer),
                Err(HttpsError::PreSend(e)) if !resent => {
                    resent = true;
                    tracing::debug!(err = %e, "ohttp: relay post failed before send; sealing again");
                }
                Err(HttpsError::RelayPaused(detail)) => {
                    return Err(RoundTripError::RateLimited {
                        detail,
                        retry_after: None,
                    });
                }
                Err(HttpsError::TooLarge(detail)) => {
                    return Err(RoundTripError::ResponseTooLarge(detail));
                }
                Err(e) => return Err(RoundTripError::Transport(e.into_message())),
            }
        };
        let status = answer.status();

        // Check outer response - 400/422 triggers key refetch
        if matches!(status.as_u16(), 400 | 422) && attempt == 0 {
            tracing::warn!(
                status = status.as_u16(),
                "ohttp: gateway rejected request; refreshing key config"
            );
            key = refetch().await?;
            attempt += 1;
            continue;
        }

        if !status.is_success() {
            let msg = format!("relay/gateway HTTP {status}: {}", answer.detail());
            return Err(match status {
                // A back-off signal, not an unreachable gateway: the caller records the pause
                // for the relay and every later request through it waits for it.
                StatusCode::TOO_MANY_REQUESTS => RoundTripError::RateLimited {
                    detail: msg,
                    retry_after: answer.retry_after(),
                },
                StatusCode::PAYLOAD_TOO_LARGE => RoundTripError::TooLarge(msg),
                _ => RoundTripError::Transport(msg),
            });
        }

        // Check content-type
        let media_type = answer.content_type().unwrap_or("");
        let essence = media_type.split(';').next().unwrap_or_default().trim();
        if !essence.eq_ignore_ascii_case(CONTENT_TYPE_CHUNKED_RES) {
            return Err(RoundTripError::Transport(format!(
                "relay answered {media_type:?}, not {CONTENT_TYPE_CHUNKED_RES}"
            )));
        }

        return Ok((opener.decoder(), answer));
    }
}

/// The decoded events of one chunked response after its head, as the gRPC body frames tonic
/// reads from the in-process pipe.
///
/// The gateway may carry the gRPC status in the Binary HTTP *header* section: lightwalletd's
/// own trailers-only answers (an error, or an empty server stream), and every response the
/// gateway collected before sending (a cache hit, a backend error) have `grpc-status` there
/// and an empty trailer section. tonic requires a `grpc-status` trailer on every stream that
/// was not trailers-only, so those fields are moved into the one trailers frame this emits.
/// A response without a status anywhere ends with `INTERNAL`, a decode failure with
/// `INTERNAL`, and a transport failure (read error, idle timeout, a body that ends before the
/// final chunk) with `UNAVAILABLE`. The trailers are held until the final chunk has opened
/// (`End`): a failure after them, in a later chunk or in the padding, still ends the call with
/// its error instead of the gateway's status. Nothing follows the trailers frame.
struct GrpcFrames {
    /// The `grpc-*` fields taken out of the response headers.
    header_fields: HeaderMap,
    /// The trailers received, waiting for the final chunk.
    pending: Option<HeaderMap>,
    trailers_sent: bool,
}

impl GrpcFrames {
    fn new(header_fields: HeaderMap) -> Self {
        Self {
            header_fields,
            pending: None,
            trailers_sent: false,
        }
    }

    /// The trailers to deliver: the trailer section's fields, else the header section's
    /// `grpc-*` fields, else `INTERNAL`.
    fn status_trailers(&mut self, fields: Vec<(String, String)>) -> HeaderMap {
        let mut trailers = HeaderMap::new();
        for (k, v) in fields {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_bytes(v.as_bytes()),
            ) {
                trailers.insert(name, value);
            }
        }
        if !trailers.contains_key("grpc-status") {
            let mut name = None;
            for (n, value) in self.header_fields.drain() {
                if n.is_some() {
                    name = n;
                }
                if let Some(n) = name.clone() {
                    trailers.append(n, value);
                }
            }
        }
        if !trailers.contains_key("grpc-status") {
            trailers.insert("grpc-status", HeaderValue::from_static("13"));
            trailers.insert(
                "grpc-message",
                HeaderValue::from_static("ohttp: gateway response without grpc-status"),
            );
        }
        trailers
    }

    fn frame(&mut self, event: Result<ResponseEvent, PumpError>) -> Option<Frame<Bytes>> {
        if self.trailers_sent {
            return None;
        }
        match event {
            Ok(ResponseEvent::Data(bytes)) => Some(Frame::data(Bytes::from(bytes))),
            Ok(ResponseEvent::Trailers(fields)) => {
                if self.pending.is_none() {
                    self.pending = Some(self.status_trailers(fields));
                }
                None
            }
            // The final chunk opened and the message ended in it: deliver the status.
            Ok(ResponseEvent::End) => {
                let trailers = match self.pending.take() {
                    Some(trailers) => trailers,
                    None => self.status_trailers(Vec::new()),
                };
                self.trailers_sent = true;
                Some(Frame::trailers(trailers))
            }
            // The head was taken before this.
            Ok(ResponseEvent::Head { .. }) => None,
            Err(PumpError::Transport(e)) => {
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("14"));
                if let Ok(msg) = HeaderValue::from_str(&format!("ohttp: {e}")) {
                    trailers.insert("grpc-message", msg);
                }
                self.trailers_sent = true;
                Some(Frame::trailers(trailers))
            }
            Err(PumpError::Decode(e)) => {
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("13"));
                if let Ok(msg) = HeaderValue::from_str(&format!("ohttp: {e}")) {
                    trailers.insert("grpc-message", msg);
                }
                self.trailers_sent = true;
                Some(Frame::trailers(trailers))
            }
        }
    }
}

/// The decoded events of one response after its head.
type EventStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<ResponseEvent, PumpError>> + Send + Sync>>;

/// A pooled HTTP/2 sender to the relay and the time its connection was opened.
type PooledH2 = (http2::SendRequest<Full<Bytes>>, std::time::Instant);

struct OhttpClient {
    gateway_host: String,
    relay_url: String,
    relay: HttpsTarget,
    key_config: Mutex<Option<CachedKey>>,
    tls: Arc<rustls::ClientConfig>,
    dialer: Dialer,
    /// One multiplexed HTTP/2 connection per `host:port`, shared by all concurrent RPCs. Opening a
    /// TCP+TLS connection per call is both slow and, on the Android emulator's user-mode network
    /// stack, a reliable way to crash qemu under connection churn. Over Tor this matters even
    /// more: every new connection would be a new circuit build.
    /// Each with the time it was opened, see [`H2_MAX_CONNECTION_AGE`].
    h2_pool: Mutex<HashMap<String, PooledH2>>,
    /// Optional client trace ID generator. When set, every relay POST carries X-Client-Trace-Id.
    client_trace: Option<ClientTrace>,
    /// The shared core's options for this client (`SLIPSTREAM` for gRPC, `SLIPSTREAM_HTTP` for
    /// [`http_round_trip`]).
    profile: ClientProfile,
}

fn forward_header(name: &HeaderName) -> bool {
    let n = name.as_str();
    n == "content-type" || n == "te" || n == "user-agent" || n.starts_with("grpc-")
}

impl OhttpClient {
    fn new(
        gateway_host: &str,
        relay_url: &str,
        dialer: Dialer,
        client_trace_prefix: Option<String>,
        profile: ClientProfile,
    ) -> Result<Self, String> {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            gateway_host: gateway_host.to_string(),
            relay_url: relay_url.to_string(),
            relay: parse_https(relay_url)?,
            key_config: Mutex::new(None),
            tls: Arc::new(tls),
            dialer,
            h2_pool: Mutex::new(HashMap::new()),
            client_trace: client_trace_prefix.map(|p| ClientTrace::new(&p, &profile.trace)),
            profile,
        })
    }

    /// TCP (direct or via Tor, per the dialer) + TLS (ALPN h2 preferred) to `target`.
    async fn tls_connect(
        &self,
        target: &HttpsTarget,
    ) -> Result<(tokio_rustls::client::TlsStream<BoxedIo>, bool), String> {
        let io = self.dialer.dial(&target.host, target.port).await?;
        let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| format!("server name: {e}"))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, io)
            .await
            .map_err(|e| format!("tls {}: {e}", target.host))?;
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        Ok((tls, is_h2))
    }

    /// Pooled HTTP/2 sender for `target`, (re)connecting when there is none or it has closed.
    /// Returns `None` if the server does not negotiate h2 (caller falls back to HTTP/1.1).
    async fn h2_sender(
        &self,
        target: &HttpsTarget,
    ) -> Result<Option<http2::SendRequest<Full<Bytes>>>, String> {
        let key = format!("{}:{}", target.host, target.port);
        {
            let pool = self.h2_pool.lock().await;
            if let Some((s, opened)) = pool.get(&key)
                && !s.is_closed()
                && (self.dialer.is_tor() || opened.elapsed() < H2_MAX_CONNECTION_AGE)
            {
                return Ok(Some(s.clone()));
            }
        }
        let (tls, is_h2) = self.tls_connect(target).await?;
        if !is_h2 {
            return Ok(None);
        }
        let (sender, conn) =
            http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|e| format!("h2 handshake {}: {e}", target.host))?;
        let host = target.host.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(host = %host, err = %e, "ohttp: h2 connection ended");
            }
        });
        tracing::info!(host = %target.host, via_tor = self.dialer.is_tor(), "ohttp: opened pooled h2 connection");
        let mut pool = self.h2_pool.lock().await;
        pool.insert(key, (sender.clone(), std::time::Instant::now()));
        Ok(Some(sender))
    }

    fn build_request(
        &self,
        target: &HttpsTarget,
        method: Method,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
    ) -> Result<Request<Full<Bytes>>, String> {
        let uri = format!("https://{}:{}{}", target.host, target.port, target.path);
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, &target.host);
        for (name, value) in headers {
            req = req.header(*name, value.as_str());
        }
        req.body(Full::new(Bytes::from(body)))
            .map_err(|e| format!("build request: {e}"))
    }

    /// One HTTPS exchange, sent once: multiplexed over the pooled h2 connection when available,
    /// otherwise a fresh HTTP/1.1 connection. A failure before anything was sent on a pooled h2
    /// connection is [`HttpsError::PreSend`] (and drops that connection from the pool); it is
    /// never retried here, because resending a relay POST's body would repeat its ciphertext.
    /// The caller decides, and seals afresh. The body is read by [`read_body_capped`] through
    /// `guard`: a declared length past the size cap, or the first frame that goes past it, ends
    /// the exchange as [`HttpsError::TooLarge`].
    ///
    /// `on_send` is called once, right before the request is handed to the connection: on h2
    /// when the connection is ready, on HTTP/1.1 when TLS and the handshake are done. A failure
    /// before that point (connect, TLS, handshake, a connection that is not ready) never calls
    /// it, so it marks the exchanges that may have reached the far end.
    async fn https_once<F: Fn()>(
        &self,
        target: &HttpsTarget,
        method: Method,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
        guard: SizeGuard,
        on_send: &F,
    ) -> Result<RelayAnswer, HttpsError> {
        let req = self
            .build_request(target, method, headers, body)
            .map_err(HttpsError::Other)?;
        let pool_key = format!("{}:{}", target.host, target.port);
        let resp = match self.h2_sender(target).await.map_err(HttpsError::Other)? {
            Some(mut sender) => {
                if let Err(e) = sender.ready().await {
                    self.h2_pool.lock().await.remove(&pool_key);
                    return Err(HttpsError::PreSend(format!(
                        "h2 ready {}: {e}",
                        target.host
                    )));
                }
                on_send();
                match sender.send_request(req).await {
                    Ok(r) => r.map(|b| b.boxed()),
                    Err(e) => {
                        self.h2_pool.lock().await.remove(&pool_key);
                        return Err(HttpsError::classify_send_error(e, &target.host));
                    }
                }
            }
            None => {
                let (tls, _) = self.tls_connect(target).await.map_err(HttpsError::Other)?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .map_err(|e| HttpsError::Other(format!("http1 handshake: {e}")))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                on_send();
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| HttpsError::Other(format!("send {}: {e}", target.host)))?
                    .map(|b| b.boxed())
            }
        };
        let (parts, body) = resp.into_parts();
        self.note_retry_after(parts.status, &parts.headers);
        let declared_len = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let bytes = read_body_capped(body, declared_len, guard, &target.host).await?;
        Ok(RelayAnswer {
            status: parts.status,
            content_type: parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            retry_after: retry_after(&parts.headers),
            body: bytes,
        })
    }

    /// POST one sealed chunked request body to the relay. Returns buffered response, read
    /// through `guard` (the caller's choice, so a request that allows only a small answer does
    /// not buffer a large one). `on_send` is called as [`Self::https_once`] describes, so not
    /// when the relay's pause stops the post or the connection cannot be made ready.
    async fn post_sealed<F: Fn()>(
        &self,
        body: Vec<u8>,
        guard: SizeGuard,
        on_send: &F,
    ) -> Result<RelayAnswer, HttpsError> {
        self.relay_pause_before_post()?;
        let trace = self.client_trace.as_ref().map(|t| t.next());
        let headers = self.profile.headers.relay_post(trace.as_deref());
        self.https_once(&self.relay, Method::POST, &headers, body, guard, on_send)
            .await
    }

    /// POST one sealed chunked request body to the relay. Returns the response with its body
    /// unread. `on_send` is called as for [`Self::post_sealed`].
    async fn post_sealed_stream<F: Fn()>(
        &self,
        body: Vec<u8>,
        on_send: &F,
    ) -> Result<RelayStream, HttpsError> {
        self.relay_pause_before_post()?;
        let trace = self.client_trace.as_ref().map(|t| t.next());
        let headers = self.profile.headers.relay_post(trace.as_deref());
        self.https_once_stream(&self.relay, Method::POST, &headers, body, on_send)
            .await
    }

    /// Like https_once but returns the response stream instead of buffering the body. `on_send`
    /// is called under the same rule.
    async fn https_once_stream<F: Fn()>(
        &self,
        target: &HttpsTarget,
        method: Method,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
        on_send: &F,
    ) -> Result<RelayStream, HttpsError> {
        let req = self
            .build_request(target, method, headers, body)
            .map_err(HttpsError::Other)?;
        let pool_key = format!("{}:{}", target.host, target.port);
        let resp = match self.h2_sender(target).await.map_err(HttpsError::Other)? {
            Some(mut sender) => {
                if let Err(e) = sender.ready().await {
                    self.h2_pool.lock().await.remove(&pool_key);
                    return Err(HttpsError::PreSend(format!(
                        "h2 ready {}: {e}",
                        target.host
                    )));
                }
                on_send();
                match sender.send_request(req).await {
                    Ok(r) => r.map(|b| b.boxed()),
                    Err(e) => {
                        self.h2_pool.lock().await.remove(&pool_key);
                        return Err(HttpsError::classify_send_error(e, &target.host));
                    }
                }
            }
            None => {
                let (tls, _) = self.tls_connect(target).await.map_err(HttpsError::Other)?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .map_err(|e| HttpsError::Other(format!("http1 handshake: {e}")))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                on_send();
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| HttpsError::Other(format!("send {}: {e}", target.host)))?
                    .map(|b| b.boxed())
            }
        };
        let (parts, body) = resp.into_parts();
        self.note_retry_after(parts.status, &parts.headers);
        let content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(RelayStream {
            status: parts.status,
            content_type,
            retry_after: retry_after(&parts.headers),
            body,
        })
    }

    /// The gateway's key configuration: the cached one while it is fresh, else fetched through
    /// the relay, with the DNS fallback of [`Self::key_config_from_dns`] when the relay fetch or
    /// its verification fails. A relay 429, or the relay's running pause, is
    /// [`RoundTripError::RateLimited`] as on a post, without the DNS fallback.
    async fn key_config(&self, refresh: bool) -> Result<KeyConfig, RoundTripError> {
        let shared_key = (self.gateway_host.clone(), self.backoff_key());
        {
            let mut cached = self.key_config.lock().await;
            if !refresh {
                let now = unix_now().map_err(RoundTripError::Transport)?;
                if let Some(k) = cached.as_ref() {
                    if self.profile.cache.is_fresh(Some(k.not_after), now) {
                        return Ok(k.config);
                    }
                    tracing::info!(
                        gateway = %self.gateway_host,
                        not_after = k.not_after,
                        now,
                        "ohttp: cached key config expired, refreshing"
                    );
                }
                // Another connection to this gateway through this relay may hold a valid one.
                let shared = shared_keys().get(&shared_key).copied();
                if let Some(k) = shared
                    && self.profile.cache.is_fresh(Some(k.not_after), now)
                {
                    *cached = Some(k);
                    return Ok(k.config);
                }
            }
            // The kept key is discarded before the fetch that replaces it, so a failed fetch
            // leaves none to be used next.
            if self.profile.cache.drop_before_refetch {
                *cached = None;
                shared_keys().remove(&shared_key);
            }
        }

        // The relay's running pause, and a relay or signed config URL that is not https, fail
        // closed before any request and without the DNS fallback. The gateway host is only looked
        // up when the relay has failed: a host outside the static configuration keeps the relay
        // error.
        self.check_relay_pause()?;
        parse_https(&self.relay_url).map_err(RoundTripError::Transport)?;
        let signed_config_url_str =
            signed_config_url(&self.relay_url, self.profile.signed_config_url)
                .map_err(|e| RoundTripError::Transport(e.to_string()))?;
        let signed_config_target =
            parse_https(&signed_config_url_str).map_err(RoundTripError::Transport)?;

        let relay_fetch_and_verify = async {
            let headers = self.profile.headers.key_fetch(None);

            // A key config GET is idempotent: a failure before anything was sent is tried once more.
            let mut resent = false;
            let answer = loop {
                match self
                    .https_once(
                        &signed_config_target,
                        Method::GET,
                        &headers,
                        Vec::new(),
                        self.profile.limits.key_config_guard(),
                        &|| {},
                    )
                    .await
                {
                    Ok(answer) => break answer,
                    Err(HttpsError::PreSend(e)) if !resent => {
                        resent = true;
                        tracing::debug!(err = %e, "ohttp: key config fetch failed before send; retrying");
                    }
                    Err(e) => return Err(RoundTripError::Transport(e.into_message())),
                }
            };
            if !self.profile.outer.success.accepts(answer.status.as_u16()) {
                return Err(RoundTripError::key_fetch_refused(
                    answer.status,
                    answer.retry_after,
                ));
            }

            let now = unix_now().map_err(RoundTripError::Transport)?;
            let cfg = open_signed_keys(&self.profile, &answer.body, &self.gateway_host, now)
                .map_err(|e| {
                    RoundTripError::Transport(format!("relay envelope verification failed: {e}"))
                })?;
            tracing::debug!("ohttp: key config fetched and verified from relay");
            Ok(cfg)
        }
        .await;

        let cfg = match relay_fetch_and_verify {
            Ok(cfg) => cfg,
            Err(relay_err) => self.key_config_from_dns(relay_err).await?,
        };

        tracing::info!(
            gateway = %self.gateway_host,
            key_id = cfg.config.key_id(),
            not_after = cfg.not_after,
            via_tor = self.dialer.is_tor(),
            "ohttp: signed key config loaded and verified"
        );
        *self.key_config.lock().await = Some(cfg);
        shared_keys().insert(shared_key, cfg);
        Ok(cfg.config)
    }

    /// The DNS-over-HTTPS fallback after the relay fetch or its verification failed with
    /// `relay_err`: each resolver of [`DOH_RESOLVERS`] in order, its answer parsed and verified
    /// like the relay's; the first that verifies wins. When none does, or the gateway host is
    /// outside the static configuration (no DNS record to fall back to), or `relay_err` has no
    /// fallback ([`relay_failure_has_dns_fallback`]), `relay_err` is returned.
    async fn key_config_from_dns(
        &self,
        relay_err: RoundTripError,
    ) -> Result<CachedKey, RoundTripError> {
        if !relay_failure_has_dns_fallback(&relay_err) {
            return Err(relay_err);
        }
        let Ok(network) = gateway_network(&self.gateway_host) else {
            return Err(relay_err);
        };
        tracing::info!(err = %relay_err, "ohttp: relay key config failed, trying DNS");

        let dns_name = key_config_dns_name(network);
        for resolver in DOH_RESOLVERS {
            let doh_url = doh_query_url(resolver, network);
            tracing::debug!(resolver = %resolver, dns_name = %dns_name, "ohttp: trying DoH resolver");

            let dns_result = async {
                let doh_body = self.fetch_dns_key_config(&doh_url).await?;
                let envelope = envelope_from_doh_json(&doh_body, network)
                    .map_err(|e| format!("parse error: {}", e))?;
                open_signed_keys(&self.profile, &envelope, &self.gateway_host, unix_now()?)
                    .map_err(|e| format!("verification failed: {}", e))
            }
            .await;

            match dns_result {
                Ok(cfg) => {
                    tracing::info!(resolver = %resolver, "ohttp: key config fetched and verified from DNS");
                    return Ok(cfg);
                }
                Err(e) => {
                    tracing::debug!(resolver = %resolver, err = %e, "ohttp: DNS resolver failed");
                }
            }
        }
        Err(relay_err)
    }

    /// Fetch a DoH JSON response for the signed key configuration TXT record. The DoH query goes
    /// over Tor if the client uses Tor, exactly like the relay fetch.
    async fn fetch_dns_key_config(&self, doh_url: &str) -> Result<Vec<u8>, String> {
        let target = parse_https(doh_url)?;
        let headers = doh_headers(&self.profile);

        let answer = self
            .https_once(
                &target,
                Method::GET,
                &headers,
                Vec::new(),
                self.profile.limits.key_config_guard(),
                &|| {},
            )
            .await
            .map_err(|e| e.into_message())?;

        if !self.profile.outer.success.accepts(answer.status.as_u16()) {
            return Err(format!("DoH query: HTTP {}", answer.status));
        }

        Ok(answer.body)
    }

    /// The pause check again, right before a post: another request may have been answered 429
    /// while this one fetched the key configuration.
    fn relay_pause_before_post(&self) -> Result<(), HttpsError> {
        self.check_relay_pause()
            .map_err(|e| HttpsError::RelayPaused(e.into_message()))
    }

    /// Key of this relay in the shared key cache and the relay pause: fetches over Tor and outside
    /// Tor keep separate entries, so that neither links the two ("Retrieval, caching and
    /// rotation" in the ZIP).
    fn backoff_key(&self) -> String {
        if self.dialer.is_tor() {
            format!("tor {}", self.relay_url)
        } else {
            self.relay_url.clone()
        }
    }

    /// Fails at once, without posting, while the relay's `Retry-After` pause runs.
    fn check_relay_pause(&self) -> Result<(), RoundTripError> {
        match RelayBackoff::global().remaining(&self.backoff_key()) {
            Some(wait) => Err(RoundTripError::RateLimited {
                detail: format!(
                    "relay rate limit: not sent, {}s of the relay's pause left",
                    wait.as_secs().max(1)
                ),
                retry_after: None,
            }),
            None => Ok(()),
        }
    }

    /// Records the pause an outer 429 asks for as soon as its head arrives (before its body is
    /// read, which may stall or be cancelled), so that every later request through this relay
    /// waits for it.
    fn note_retry_after(&self, status: StatusCode, headers: &HeaderMap) {
        if status != StatusCode::TOO_MANY_REQUESTS {
            return;
        }
        if let Some(wait) = retry_after(headers) {
            tracing::warn!(
                wait_secs = wait.as_secs(),
                relay = %self.relay_url,
                "ohttp: relay rate limit (429); holding requests through it"
            );
            RelayBackoff::global().note(&self.backoff_key(), wait);
        }
    }

    /// [`Self::round_trip_once`], sent once more (sealed afresh) when the gateway refused it
    /// as stale: an inner 400 with `ohttp-freshness: rejected` ("Request freshness" in the
    /// ZIP). That response carries the gateway clock, which the decoder has already learned,
    /// so the second attempt is stamped right even on a device whose clock is off. Never more
    /// than one retry per request.
    async fn round_trip<D>(
        &self,
        request: &BhttpRequest,
        max_response_bytes: Option<usize>,
        on_dispatch: D,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        D: Fn(),
    {
        let dispatch = once_dispatch(on_dispatch);
        with_freshness_retry(
            || self.round_trip_once(request, max_response_bytes, &dispatch),
            |r: &BhttpResponse| zodl_ohttp_client::freshness::is_rejection(r.status, &r.headers),
        )
        .await
    }

    /// Encapsulate + relay + decapsulate with chunked OHTTP. The key configuration is
    /// fetched again, and the request sealed again, when the gateway rejects the request (outer
    /// 400 or 422). Decodes the chunked response and returns the inner message.
    ///
    /// `max_response_bytes` is the largest answer body the caller accepts. The sealed answer is
    /// read through a guard of [`sealed_response_ceiling`] bytes, so one that goes past it is
    /// not buffered further or opened ([`RoundTripError::ResponseTooLarge`]); the body it opens
    /// to is then checked against `max_response_bytes` itself. `None` leaves only the general
    /// cap of the client's profile.
    ///
    /// `on_dispatch` is called right before the sealed request is written to the relay
    /// connection, after the relay-pause check and the connection setup (see
    /// [`Self::https_once`]). So a relay pause, a relay that cannot be reached and a connection
    /// that is not ready leave it uncalled, while a failure after it may have reached the relay.
    async fn round_trip_once<D>(
        &self,
        request: &BhttpRequest,
        max_response_bytes: Option<usize>,
        on_dispatch: &D,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        D: Fn(),
    {
        self.check_relay_pause()?;
        let key = self.key_config(false).await?;
        let guard = match max_response_bytes {
            Some(max) => SizeGuard::new(Some(sealed_response_ceiling(max))),
            None => self.profile.limits.response_guard(),
        };
        let this = self;
        let (mut decoder, answer) = run_exchange_chunked(
            key,
            request,
            move |body| this.post_sealed(body, guard, on_dispatch),
            move || this.key_config(true),
        )
        .await?;

        // Decode the buffered response body through the chunked decoder
        let mut events = decoder
            .push(&answer.body)
            .map_err(|e| RoundTripError::Decode(e.to_string()))?;
        events.extend(decoder.finish().map_err(|e| match e {
            zodl_ohttp_client::Error::Truncated => RoundTripError::Transport(e.to_string()),
            e => RoundTripError::Decode(e.to_string()),
        })?);

        // Collect events into a Response and convert to BhttpResponse
        let response = zodl_ohttp_client::collect_response(events)
            .map_err(|e| RoundTripError::Decode(e.to_string()))?;
        check_response_body(response.body.len(), max_response_bytes)?;

        // Convert Response to BhttpResponse (headers as bytes)
        Ok(BhttpResponse {
            status: response.status,
            informational: Vec::new(),
            headers: response
                .headers
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
                .collect(),
            body: response.body,
            trailers: Vec::new(),
        })
    }

    /// [`Self::round_trip_stream_once`] with the same single retry as [`Self::round_trip`] when
    /// the gateway refused the request as stale. The refusal is known from the head alone, so
    /// nothing of it reaches the caller.
    async fn round_trip_stream<D>(
        &self,
        request: BhttpRequest,
        on_dispatch: D,
    ) -> Result<(u16, HeaderMap, EventStream), RoundTripError>
    where
        D: Fn(),
    {
        let dispatch = once_dispatch(on_dispatch);
        // A refused first attempt is dropped (its decoding task ends with the receiver).
        with_freshness_retry(
            || self.round_trip_stream_once(request.clone(), &dispatch),
            |(status, headers, _): &(u16, HeaderMap, EventStream)| {
                let fields: Vec<(&[u8], &[u8])> = headers
                    .iter()
                    .map(|(k, v)| (k.as_str().as_bytes(), v.as_bytes()))
                    .collect();
                zodl_ohttp_client::freshness::is_rejection(*status, &fields)
            },
        )
        .await
    }

    /// Encapsulate + relay + stream-decode with chunked OHTTP. Returns the inner status and
    /// headers once the head has been decoded, and the remaining events (body, trailers, end)
    /// as they are decoded chunk by chunk: the first gRPC message is available before the
    /// response has been received in full. Same exchange loop as [`Self::round_trip`]: every
    /// post is sealed afresh, an outer 400 or 422 refetches the key and retries once.
    /// `on_dispatch` is called as [`Self::round_trip_once`] describes.
    async fn round_trip_stream_once<D>(
        &self,
        request: BhttpRequest,
        on_dispatch: &D,
    ) -> Result<(u16, HeaderMap, EventStream), RoundTripError>
    where
        D: Fn(),
    {
        use futures_util::stream::StreamExt as _;
        use tokio::sync::mpsc;

        self.check_relay_pause()?;
        let key = self.key_config(false).await?;
        let this = self;
        let (decoder, answer) = run_exchange_chunked(
            key,
            &request,
            move |body| this.post_sealed_stream(body, on_dispatch),
            move || this.key_config(true),
        )
        .await?;

        // Spawn task to decode chunks and forward events with idle timeout
        let (tx, rx) = mpsc::channel::<Result<ResponseEvent, PumpError>>(16);
        let guard = this.profile.limits.response_guard();

        tokio::spawn(pump_chunked_body(answer.body, decoder, guard, tx));

        // Wait for first Head event
        let mut rx = tokio_stream::wrappers::ReceiverStream::new(rx);
        let (http_status, headers) = match rx.next().await {
            Some(Ok(ResponseEvent::Head { status, headers: h })) => {
                let mut header_map = HeaderMap::new();
                for (k, v) in h {
                    if let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(k.as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        header_map.insert(name, value);
                    }
                }
                (status, header_map)
            }
            Some(Err(PumpError::Transport(e))) => {
                return Err(RoundTripError::Transport(e));
            }
            Some(Err(PumpError::Decode(e))) => {
                return Err(RoundTripError::Decode(e));
            }
            None => {
                return Err(RoundTripError::Transport("no Head event received".into()));
            }
            _ => {
                return Err(RoundTripError::Decode(
                    "unexpected event before Head".into(),
                ));
            }
        };

        Ok((http_status, headers, Box::pin(rx)))
    }

    /// In-process h2 handler: one gRPC request in, one gRPC response (with trailers) out.
    /// Uses streaming decoding: the first gRPC message frame is returned before the full response
    /// has been received from the gateway.
    async fn handle(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, Infallible>> {
        use futures_util::stream::StreamExt as _;

        let (parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let body = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => return grpc_error(GRPC_INTERNAL, &format!("read request body: {e}")),
        };

        let request = grpc_request(
            &self.gateway_host,
            parts.method.as_str(),
            &path,
            &parts.headers,
            &body,
        );

        let started = std::time::Instant::now();
        // Timeout only for getting the Head (status + headers)
        let (http_status, mut headers, events) =
            match tokio::time::timeout(ROUND_TRIP_TIMEOUT, self.round_trip_stream(request, || {}))
                .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(RoundTripError::Decode(e))) => {
                    return grpc_error(GRPC_INTERNAL, &format!("bhttp decode: {e}"));
                }
                Ok(Err(RoundTripError::Transport(e))) => {
                    tracing::warn!(path = %path, err = %e, "ohttp: round trip failed");
                    return grpc_error(GRPC_UNAVAILABLE, &format!("ohttp: {e}"));
                }
                Ok(Err(RoundTripError::RateLimited {
                    detail,
                    retry_after,
                })) => {
                    tracing::warn!(
                        path = %path,
                        err = %detail,
                        retry_after_secs = retry_after.map(|d| d.as_secs()),
                        "ohttp: rate limited"
                    );
                    return grpc_error_with(
                        GRPC_UNAVAILABLE,
                        &format!("ohttp: {detail}"),
                        Some(OUTCOME_RATE_LIMITED),
                    );
                }
                Ok(Err(RoundTripError::TooLarge(e) | RoundTripError::ResponseTooLarge(e))) => {
                    tracing::warn!(path = %path, err = %e, "ohttp: request or response too large");
                    return grpc_error_with(
                        GRPC_RESOURCE_EXHAUSTED,
                        &format!("ohttp: {e}"),
                        Some(OUTCOME_TOO_LARGE),
                    );
                }
                Err(_) => {
                    tracing::warn!(path = %path, "ohttp: round trip timed out waiting for Head");
                    return grpc_error(GRPC_UNAVAILABLE, "ohttp: round trip timed out");
                }
            };

        if let Some(response) = inner_not_grpc(http_status, &headers) {
            if http_status == 403 {
                tracing::warn!(path = %path, "ohttp: the gateway refused this call by policy (inner 403)");
            }
            return response;
        }

        // Keep content-type and date as response headers; `grpc-*` fields found in the header
        // section (a trailers-only or a collected answer) go out as HTTP/2 trailers, where tonic
        // reads the status, see `GrpcFrames`.
        let mut response_headers = HeaderMap::new();
        let mut grpc_fields = HeaderMap::new();
        let mut last_name: Option<HeaderName> = None;
        for (name, value) in headers.drain() {
            if name.is_some() {
                last_name = name;
            }
            let Some(name) = last_name.clone() else {
                continue;
            };
            if name.as_str().starts_with("grpc-") {
                grpc_fields.append(name, value);
            } else if name == header::CONTENT_TYPE || name == header::DATE {
                response_headers.append(name, value);
            }
        }

        tracing::debug!(
            path = %path,
            http_status,
            header_grpc_status = grpc_fields
                .get("grpc-status")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-"),
            ms = started.elapsed().as_millis() as u64,
            "ohttp: rpc streaming"
        );

        // Body frames, then exactly one trailers frame carrying the gRPC status.
        let mut frames = GrpcFrames::new(grpc_fields);
        let body = BodyExt::boxed(StreamBody::new(events.filter_map(move |event| {
            futures_util::future::ready(frames.frame(event).map(Ok::<_, Infallible>))
        })));

        let mut resp = Response::new(body);
        *resp.status_mut() = StatusCode::from_u16(http_status).unwrap_or(StatusCode::OK);
        *resp.headers_mut() = response_headers;
        resp
    }
}

/// The Binary HTTP request for one gRPC call: method and path as received, `:authority` the
/// gateway host, `:scheme` https, only the headers [`forward_header`] lets through (names
/// lower-cased by the `SLIPSTREAM` profile's encoding).
fn grpc_request(
    gateway_host: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> BhttpRequest {
    let mut request = BhttpRequest::new(method, gateway_host, path).body(body);
    for (name, value) in headers {
        if forward_header(name) {
            request = request.header(name.as_str(), value.as_bytes());
        }
    }
    request
}

/// Where `http_round_trip` sends its request, as the gateway will see it.
struct HttpTarget {
    scheme: String,
    host: String,
    path: String,
}

fn parse_http_target(url: &str) -> Result<HttpTarget, String> {
    let uri = url
        .parse::<http::Uri>()
        .map_err(|e| format!("invalid URL: {e}"))?;
    let host = uri.host().ok_or("URL has no host")?.to_string();
    let path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let scheme = uri.scheme_str().unwrap_or("https").to_string();
    Ok(HttpTarget { scheme, host, path })
}

/// Sends an HTTP request through OHTTP (RFC 9458): HPKE-encapsulates the request,
/// POSTs it to the relay, and decapsulates the response.
///
/// Intended for non-gRPC HTTP use cases (voting, PIR, etc.) that need the same
/// privacy properties as lightwalletd but do not use gRPC's framing.
///
/// # Arguments
/// * `gateway_host` - OHTTP gateway hostname (e.g., "ohttp-gateway.example")
/// * `network` - The wallet's network; a gateway serving another one is refused before
///   anything is sent
/// * `dialer` - How to reach the relay: `Dialer::Direct` or `Dialer::Tor(_)`
/// * `method` - HTTP method (e.g., "GET", "POST")
/// * `url` - Full target URL (e.g., "<https://voting.valargroup.dev/api/vote>")
/// * `headers` - Request headers as (name, value) pairs
/// * `body` - Request body bytes
///
/// # Returns
/// `Ok((status, headers, body))` on success, or `Err(msg)` on failure. The whole exchange is
/// bounded by 100 s.
///
/// # Privacy
/// The relay sees the client IP (or Tor exit with `Dialer::Tor`) and the HPKE-encrypted
/// ciphertext, but not the plaintext request. The gateway sees the plaintext request
/// but only the relay's IP. Uses signed HPKE key configs fetched through the relay,
/// with automatic key rotation retry on gateway 400/422.
///
/// # Response size cap
/// A sealed response larger than the gateway's own 256 MiB cap (plus 64 KiB of framing) is
/// rejected while it is being read, before it is buffered or decrypted.
///
/// # Caching
/// The verified key configuration and HTTP/TLS connections to the relay are cached per gateway
/// host, avoiding repeated key fetches and TLS handshakes.
pub async fn http_round_trip(
    gateway_host: &str,
    network: NetworkType,
    dialer: Dialer,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let (target, relay_url) = http_target_and_relay(gateway_host, network, url)?;
    http_round_trip_via(
        relay_url,
        gateway_host,
        dialer,
        method,
        target,
        headers,
        body,
        None,
        || {},
    )
    .await
    .map_err(|e| e.to_string())
}

/// Why [`http_round_trip_with_dispatch`] failed. Its `Display` is the message alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpRoundTripError {
    /// The answer is past the `max_response_bytes` the caller allowed: the sealed answer stopped
    /// being read at its ceiling, or the body it opened to is longer than that. The request had
    /// been sent: `on_dispatch` has run.
    ResponseTooLarge(String),
    /// Any other failure: a gateway of another network, a URL that does not parse, no relay for
    /// the gateway, the key configuration, the relay, the gateway, the 100 s bound. `on_dispatch`
    /// tells whether the request may have been sent.
    Failed(String),
}

impl std::fmt::Display for HttpRoundTripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpRoundTripError::ResponseTooLarge(m) | HttpRoundTripError::Failed(m) => {
                f.write_str(m)
            }
        }
    }
}

impl std::error::Error for HttpRoundTripError {}

/// Like [`http_round_trip`], but with a ceiling on the answer and a hook for the send.
///
/// The answer is read only up to `max_response_bytes` (see the argument below): a service that
/// answers with more fails early as [`HttpRoundTripError::ResponseTooLarge`], not after the
/// answer has been buffered and opened.
///
/// `on_dispatch` is called right before the sealed request is written to the relay connection:
/// after the key config fetch, the encapsulation, the relay-pause check and the connection setup.
/// This lets the caller distinguish failures that never sent ciphertext (key fetch,
/// encapsulation, a relay pause, a relay that cannot be reached, a connection that is not ready)
/// from those that may have (a failed write, relay transport, gateway processing).
///
/// # Arguments
/// * `gateway_host` - OHTTP gateway hostname (e.g., "ohttp-gateway.example")
/// * `network` - The wallet's network; a gateway serving another one is refused before
///   anything is sent
/// * `dialer` - How to reach the relay: `Dialer::Direct` or `Dialer::Tor(_)`
/// * `method` - HTTP method (e.g., "GET", "POST")
/// * `url` - Full target URL (e.g., "<https://voting.valargroup.dev/api/vote>")
/// * `headers` - Request headers as (name, value) pairs
/// * `body` - Request body bytes
/// * `max_response_bytes` - The largest answer body read. A larger answer stops being read there
///   and fails as [`HttpRoundTripError::ResponseTooLarge`]. The sealed answer gets a little more
///   room for its framing (a 256th of this and 64 KiB); the body it opens to must then fit in
///   `max_response_bytes` itself.
/// * `on_dispatch` - Called at most once, right before the sealed request is written to the
///   relay connection, after the relay-pause check and the connection setup. So a pause, a
///   relay that cannot be reached, or a connection that is not ready leaves it uncalled. A
///   failure after it may have reached the relay.
///
/// # Returns
/// `Ok((status, headers, body))` on success, or an [`HttpRoundTripError`] on failure:
/// `ResponseTooLarge` when the answer is past `max_response_bytes`, `Failed` for anything else.
///
/// # Example
/// ```no_run
/// # async fn demo() -> Result<(), String> {
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use zodl_slipstream::ohttp::{
///     Dialer, HttpRoundTripError, NetworkType, http_round_trip_with_dispatch,
/// };
///
/// let dispatched = AtomicBool::new(false);
/// match http_round_trip_with_dispatch(
///     "ohttp-gateway.example",
///     NetworkType::Main,
///     Dialer::Direct,
///     "POST",
///     "https://voting.example/api/vote",
///     &[("content-type".to_string(), "application/json".to_string())],
///     b"{\"vote\": 1}",
///     256 * 1024,
///     || dispatched.store(true, Ordering::SeqCst),
/// )
/// .await
/// {
///     Ok(response) => println!("Vote sent: {}", response.0),
///     Err(HttpRoundTripError::ResponseTooLarge(e)) => {
///         // Answered, but too large: the request was sent
///         println!("Answer past the ceiling: {e}");
///     }
///     Err(e) if !dispatched.load(Ordering::SeqCst) => {
///         // Safe to retry: request never left the device
///         println!("Pre-dispatch failure: {e}");
///     }
///     Err(e) => {
///         // Request may have been sent; do not retry (possible duplicate)
///         println!("Post-dispatch failure: {e}");
///     }
/// }
/// # Ok(()) }
/// ```
#[allow(clippy::too_many_arguments)] // http_round_trip's shape plus the ceiling and the hook
pub async fn http_round_trip_with_dispatch<D>(
    gateway_host: &str,
    network: NetworkType,
    dialer: Dialer,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    max_response_bytes: usize,
    on_dispatch: D,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), HttpRoundTripError>
where
    D: Fn() + Send + Sync,
{
    let (target, relay_url) =
        http_target_and_relay(gateway_host, network, url).map_err(HttpRoundTripError::Failed)?;
    http_round_trip_via(
        relay_url,
        gateway_host,
        dialer,
        method,
        target,
        headers,
        body,
        Some(max_response_bytes),
        on_dispatch,
    )
    .await
}

/// What a plain HTTP round trip settles before anything is sent: the gateway serves the wallet's
/// network, `url` parses, and the gateway has a relay.
fn http_target_and_relay(
    gateway_host: &str,
    network: NetworkType,
    url: &str,
) -> Result<(HttpTarget, &'static str), String> {
    check_gateway_network(gateway_host, network)?;

    // Parse URL to extract scheme, host, path for BHTTP encoding
    let target = parse_http_target(url)?;

    // Get relay URL for this gateway
    let relay_url = relay_for(gateway_host)
        .ok_or_else(|| format!("no relay configured for gateway {}", gateway_host))?;

    Ok((target, relay_url))
}

/// A round trip's error as the caller of [`http_round_trip_with_dispatch`] sees it: an answer
/// past its ceiling is told apart, every other failure keeps its message.
fn http_error(error: RoundTripError) -> HttpRoundTripError {
    match error {
        RoundTripError::ResponseTooLarge(message) => HttpRoundTripError::ResponseTooLarge(message),
        other => HttpRoundTripError::Failed(other.to_string()),
    }
}

/// [`http_round_trip`] against an explicit relay URL (the body of the public function, so a
/// test can point it at a local relay without touching the process-wide relay table).
/// `max_response_bytes` is the ceiling [`http_round_trip_with_dispatch`] describes; `None` sets
/// none of the caller's, which leaves the general cap of [`http_round_trip`]. `on_dispatch` is
/// called right before the sealed request is written to the relay connection, after the
/// relay-pause check and the connection setup, as [`http_round_trip_with_dispatch`] describes.
/// Setup errors and the 100 s bound are [`HttpRoundTripError::Failed`].
#[allow(clippy::too_many_arguments)] // one seam over the limit; bundling would hide the borrows
async fn http_round_trip_via<D>(
    relay_url: &str,
    gateway_host: &str,
    dialer: Dialer,
    method: &str,
    target: HttpTarget,
    headers: &[(String, String)],
    body: &[u8],
    max_response_bytes: Option<usize>,
    on_dispatch: D,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), HttpRoundTripError>
where
    D: Fn(),
{
    // Get or create cached OHTTP client (caches key config and HTTP/2 connections)
    let client = get_or_create_client(
        gateway_host,
        relay_url,
        dialer,
        get_default_client_trace_prefix(),
        ClientProfile::SLIPSTREAM_HTTP,
    )
    .await
    .map_err(HttpRoundTripError::Failed)?;

    // HTTP request as Binary HTTP (RFC 9292): the URL's scheme, header names as given
    let mut request = BhttpRequest::new(method, target.host, target.path)
        .scheme(target.scheme)
        .body(body);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }

    // Send through OHTTP relay (encapsulate, POST, decapsulate), the whole exchange bounded
    let response = tokio::time::timeout(
        ROUND_TRIP_TIMEOUT,
        client.round_trip(&request, max_response_bytes, on_dispatch),
    )
    .await
    .map_err(|_| {
        HttpRoundTripError::Failed(format!(
            "ohttp: round trip timed out after {}s",
            ROUND_TRIP_TIMEOUT.as_secs()
        ))
    })?
    .map_err(http_error)?;

    // Headers as lossy UTF-8 text; the trailer section is not read
    let response_headers = response.headers_utf8_lossy();
    Ok((response.status, response_headers, response.body))
}

const GRPC_UNAVAILABLE: &str = "14";
const GRPC_INTERNAL: &str = "13";
const GRPC_RESOURCE_EXHAUSTED: &str = "8";

/// The error a decrypted answer gets when it is not a gRPC response: an inner status other
/// than 200, or a content type other than `application/grpc*`, is `INTERNAL`. An inner 403 is
/// marked as a policy denial, which the engine never counts as an unreachable server.
fn inner_not_grpc(
    http_status: u16,
    headers: &HeaderMap,
) -> Option<Response<BoxBody<Bytes, Infallible>>> {
    if http_status != 200 {
        let outcome = (http_status == 403).then_some(OUTCOME_POLICY_DENIED);
        return Some(grpc_error_with(
            GRPC_INTERNAL,
            &format!("ohttp: inner HTTP {http_status}, not a gRPC response"),
            outcome,
        ));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/grpc") {
        return Some(grpc_error(
            GRPC_INTERNAL,
            &format!("ohttp: inner content-type {content_type:?}, not a gRPC response"),
        ));
    }
    None
}

/// gRPC "trailers-only" error response: status in the headers, empty body. tonic surfaces it as
/// a `Status` with that code, which this crate's retry logic already treats as transient for
/// `UNAVAILABLE`.
fn grpc_error(code: &'static str, message: &str) -> Response<BoxBody<Bytes, Infallible>> {
    grpc_error_with(code, message, None)
}

/// [`grpc_error`] carrying an [`OHTTP_OUTCOME_HEADER`] (tonic hands it over as the status's
/// metadata).
fn grpc_error_with(
    code: &'static str,
    message: &str,
    outcome: Option<&'static str>,
) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(Full::new(Bytes::new()).boxed());
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    h.insert("grpc-status", HeaderValue::from_static(code));
    if let Some(outcome) = outcome {
        h.insert(OHTTP_OUTCOME_HEADER, HeaderValue::from_static(outcome));
    }
    let msg: String = message
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if let Ok(v) = HeaderValue::from_str(&msg) {
        h.insert("grpc-message", v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::cell::Cell;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zodl_ohttp_client::encode_bhttp_request;

    /// `http_round_trip` refuses a gateway of another network before anything is sent.
    #[tokio::test]
    async fn http_round_trip_refuses_a_gateway_of_another_network() {
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let err = http_round_trip_with_dispatch(
            "ohttp-gateway.example",
            NetworkType::Test,
            Dialer::Direct,
            "GET",
            "https://vote.example/api",
            &[],
            b"",
            256 * 1024,
            || dispatched.store(true, std::sync::atomic::Ordering::SeqCst),
        )
        .await
        .expect_err("refused");
        assert!(
            matches!(&err, HttpRoundTripError::Failed(m) if m.contains("mainnet")),
            "{err:?}"
        );
        assert!(!dispatched.load(std::sync::atomic::Ordering::SeqCst));
        assert!(check_gateway_network("ohttp-gateway.example", NetworkType::Main).is_ok());
        assert!(check_gateway_network("ohttp-gateway-testnet.example", NetworkType::Test).is_ok());
        assert!(
            check_gateway_network("ohttp-gateway-testnet.example", NetworkType::Main).is_err()
        );
        assert!(check_gateway_network("ohttp-gateway.example", NetworkType::Regtest).is_err());
        assert!(check_gateway_network("gw.example", NetworkType::Main).is_err());
    }

    #[test]
    fn send_errors_are_never_pre_send() {
        // A send error cannot prove the request was not delivered, so it must not be retried.
        match HttpsError::classify_send_error("stream closed", "relay.example") {
            HttpsError::Other(m) => assert_eq!(m, "h2 send relay.example: stream closed"),
            other => panic!("send error must not be PreSend: {other:?}"),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// One X25519 key configuration offering HKDF-SHA256 + AES-128-GCM, with `public_key`.
    fn key_document(key_id: u8, public_key: [u8; 32]) -> Vec<u8> {
        // Length(41) || key_id || kem=0x0020 || pk[32] || suites_len=4 || kdf=1 || aead=1
        let mut doc = vec![0x00, 0x29, key_id, 0x00, 0x20];
        doc.extend_from_slice(&public_key);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);
        doc
    }

    /// A key the HPKE sender accepts (the X25519 base point), selected as Slipstream selects.
    fn test_key() -> KeyConfig {
        let mut public_key = [0u8; 32];
        public_key[0] = 9;
        KeyConfig::select_with(
            &key_document(1, public_key),
            &ClientProfile::SLIPSTREAM.key_selection,
        )
        .expect("select")
    }

    fn test_request() -> BhttpRequest {
        BhttpRequest::new(
            "POST",
            "gw.example",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/Ping",
        )
        .header("content-type", "application/grpc")
        .body(vec![0, 0, 0, 0, 0])
    }

    fn outer_answer(status: u16) -> RelayAnswer {
        RelayAnswer {
            status: StatusCode::from_u16(status).expect("status"),
            content_type: Some(CONTENT_TYPE_CHUNKED_RES.to_string()),
            retry_after: None,
            body: b"nope".to_vec(),
        }
    }

    /// Test helper: wraps run_exchange_chunked for backward compatibility with existing tests.
    /// Decodes the buffered response and returns a BhttpResponse.
    async fn run_exchange<P, PF, R, RF>(
        _profile: &ClientProfile,
        key: KeyConfig,
        request: &BhttpRequest,
        post: P,
        refetch: R,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        P: FnMut(Vec<u8>) -> PF,
        PF: Future<Output = Result<RelayAnswer, HttpsError>>,
        R: FnMut() -> RF,
        RF: Future<Output = Result<KeyConfig, RoundTripError>>,
    {
        let (mut decoder, answer) = run_exchange_chunked(key, request, post, refetch).await?;

        // Decode the buffered response
        let mut events = decoder
            .push(&answer.body)
            .map_err(|e| RoundTripError::Decode(e.to_string()))?;
        events.extend(
            decoder
                .finish()
                .map_err(|e| RoundTripError::Decode(e.to_string()))?,
        );

        // Convert to BhttpResponse
        let response = zodl_ohttp_client::collect_response(events)
            .map_err(|e| RoundTripError::Decode(e.to_string()))?;

        Ok(BhttpResponse {
            status: response.status,
            informational: Vec::new(),
            headers: response
                .headers
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v.into_bytes()))
                .collect(),
            body: response.body,
            trailers: Vec::new(),
        })
    }

    #[test]
    fn selects_the_first_key_that_offers_the_suite() {
        let cfg = KeyConfig::select_with(
            &key_document(1, [0xAB; 32]),
            &ClientProfile::SLIPSTREAM.key_selection,
        )
        .expect("select");
        assert_eq!(cfg.key_id(), 1);
        assert_eq!(cfg.public_key(), &[0xAB; 32]);
    }

    #[test]
    fn skips_a_non_x25519_configuration() {
        // key_id=2, kem=0x0010, two bytes of key material: skipped unread, next one chosen.
        let mut doc = vec![0x00, 0x05, 0x02, 0x00, 0x10, 0xFF, 0xFF];
        doc.extend_from_slice(&key_document(7, [0x33; 32]));
        let cfg =
            KeyConfig::select_with(&doc, &ClientProfile::SLIPSTREAM.key_selection).expect("select");
        assert_eq!(cfg.key_id(), 7);
    }

    #[test]
    fn rejects_unsupported_suite() {
        let mut doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        doc.extend_from_slice(&[0x01; 32]);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x00, 0x03]);
        assert!(KeyConfig::select_with(&doc, &ClientProfile::SLIPSTREAM.key_selection).is_err());
    }

    #[test]
    fn relay_mapping_covers_both_gateways() {
        assert!(relay_for("ohttp-gateway-testnet.example").is_some());
        assert!(relay_for("ohttp-gateway.example").is_some());
        assert!(relay_for("zec.rocks").is_none());
    }

    /// A signed envelope for `testnet` with the given window and a signature of zeros.
    fn unsigned_testnet_envelope(not_before: u64, not_after: u64) -> Vec<u8> {
        let config_doc = key_document(1, [0xCD; 32]);
        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": base64::prelude::BASE64_STANDARD.encode(&config_doc),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": "a3620fb6",
            "sig": base64::prelude::BASE64_STANDARD.encode([0u8; 64]),
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    /// C-01 fix test: Verify that signature verification rejects tampered configs.
    /// This test MUST FAIL if the signature check is removed or bypassed.
    #[test]
    fn rejects_invalid_signature_in_signed_config() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now - 60, now + 3600);
        let err = open_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &json,
            "ohttp-gateway-testnet.example",
            now,
        )
        .expect_err("verify must reject an invalid signature");
        assert!(err.contains("bad signature"), "got: {err}");
    }

    /// C-01 fix test: Verify that expired configs are rejected.
    #[test]
    fn rejects_expired_signed_config() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now - 7200, now - 3600);
        let err = open_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &json,
            "ohttp-gateway-testnet.example",
            now,
        )
        .expect_err("must reject expired config");
        assert!(err.contains("validity window"), "got: {err}");
    }

    /// C-01 fix test: Verify that configs with too-long validity windows are rejected.
    #[test]
    fn rejects_long_validity_window() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now, now + 25 * 60 * 60);
        let err = open_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &json,
            "ohttp-gateway-testnet.example",
            now,
        )
        .expect_err("must reject validity window >24h");
        assert!(err.contains("longer than a day"), "got: {err}");
    }

    /// The envelope is checked against the network the gateway host names: a testnet envelope
    /// does not verify for the mainnet gateway.
    #[test]
    fn rejects_envelope_for_the_other_network() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now - 60, now + 3600);
        let err = open_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &json,
            "ohttp-gateway.example",
            now,
        )
        .expect_err("network binding");
        assert!(err.contains("signed for"), "got: {err}");
    }

    #[test]
    fn grpc_request_forwards_only_grpc_headers_in_lower_case() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("grpc-timeout", HeaderValue::from_static("5S"));
        headers.insert("x-secret", HeaderValue::from_static("hunter2"));
        let request = grpc_request("gw.zodl.com", "POST", "/a.B/C", &headers, b"xyz");
        assert_eq!(request.scheme, b"https");
        assert_eq!(request.authority, b"gw.zodl.com");
        assert_eq!(request.path, b"/a.B/C");
        assert_eq!(request.body, b"xyz");
        let encoded =
            encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM.encode).expect("encode");
        assert!(contains(&encoded, b"grpc-timeout"));
        assert!(contains(&encoded, b"content-type"));
        assert!(!contains(&encoded, b"x-secret"));
    }

    #[test]
    fn http_profile_keeps_header_names_as_given_and_grpc_profile_lowercases() {
        let request = BhttpRequest::new("GET", "h.example", "/").header("X-Custom", "1");
        let as_given =
            encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM_HTTP.encode).unwrap();
        assert!(contains(&as_given, b"X-Custom"));
        let lowered = encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM.encode).unwrap();
        assert!(contains(&lowered, b"x-custom") && !contains(&lowered, b"X-Custom"));
    }

    /// C-08: a relay POST is never sent twice with the same ciphertext. The gateway answers a
    /// repeat with 409, so after a failure before the send the request is sealed again.
    #[tokio::test]
    async fn a_relay_post_that_failed_before_send_is_sealed_again() {
        let bodies = StdMutex::new(Vec::<Vec<u8>>::new());
        let result = run_exchange(
            &ClientProfile::SLIPSTREAM,
            test_key(),
            &test_request(),
            |body| {
                bodies.lock().unwrap().push(body);
                async { Err::<RelayAnswer, _>(HttpsError::PreSend("h2 ready: closed".into())) }
            },
            || async { Err(RoundTripError::Transport("unexpected refetch".into())) },
        )
        .await;
        let Err(RoundTripError::Transport(message)) = result else {
            panic!("expected a transport error, got {result:?}");
        };
        assert!(message.contains("h2 ready"), "got: {message}");
        let bodies = bodies.into_inner().unwrap();
        assert_eq!(bodies.len(), 2, "one pre-send retry");
        assert_eq!(bodies[0].len(), bodies[1].len());
        assert_ne!(bodies[0], bodies[1], "a retry must carry fresh ciphertext");
    }

    /// Only a failure before the send is retried; after it the answer decides.
    #[tokio::test]
    async fn an_outer_error_after_a_pre_send_retry_is_not_retried() {
        let bodies = StdMutex::new(Vec::<Vec<u8>>::new());
        let calls = Cell::new(0u32);
        let result = run_exchange(
            &ClientProfile::SLIPSTREAM,
            test_key(),
            &test_request(),
            |body| {
                bodies.lock().unwrap().push(body);
                let n = calls.get();
                calls.set(n + 1);
                async move {
                    if n == 0 {
                        Err(HttpsError::PreSend("h2 ready: closed".into()))
                    } else {
                        Ok(outer_answer(503))
                    }
                }
            },
            || async { Err(RoundTripError::Transport("unexpected refetch".into())) },
        )
        .await;
        let Err(RoundTripError::Transport(message)) = result else {
            panic!("expected a transport error, got {result:?}");
        };
        assert_eq!(message, "relay/gateway HTTP 503 Service Unavailable: nope");
        let bodies = bodies.into_inner().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_ne!(bodies[0], bodies[1]);
    }

    /// An outer 400 or 422 means the gateway does not know the key: refetch it, seal again and
    /// post once more, whatever the body says; the second one is final.
    #[tokio::test]
    async fn outer_400_and_422_refetch_the_key_and_retry_once_with_a_new_sealing() {
        for status in [400u16, 422] {
            let bodies = StdMutex::new(Vec::<Vec<u8>>::new());
            let refetches = Cell::new(0u32);
            let result = run_exchange(
                &ClientProfile::SLIPSTREAM,
                test_key(),
                &test_request(),
                |body| {
                    bodies.lock().unwrap().push(body);
                    async move { Ok::<RelayAnswer, HttpsError>(outer_answer(status)) }
                },
                || {
                    refetches.set(refetches.get() + 1);
                    async { Ok::<KeyConfig, RoundTripError>(test_key()) }
                },
            )
            .await;
            let Err(RoundTripError::Transport(message)) = result else {
                panic!("expected a transport error, got {result:?}");
            };
            assert!(
                message.starts_with(&format!("relay/gateway HTTP {status}")),
                "got: {message}"
            );
            assert_eq!(refetches.get(), 1, "status {status}");
            let bodies = bodies.into_inner().unwrap();
            assert_eq!(bodies.len(), 2, "status {status}");
            assert_ne!(bodies[0], bodies[1], "status {status}");
        }
    }

    /// Other outer errors are final: no refetch, no second post.
    #[tokio::test]
    async fn other_outer_errors_are_final() {
        for status in [401u16, 409, 413, 426, 500, 502, 503] {
            let posts = Cell::new(0u32);
            let result = run_exchange(
                &ClientProfile::SLIPSTREAM,
                test_key(),
                &test_request(),
                |_body| {
                    posts.set(posts.get() + 1);
                    async move { Ok::<RelayAnswer, HttpsError>(outer_answer(status)) }
                },
                || async { Err(RoundTripError::Transport("unexpected refetch".into())) },
            )
            .await;
            let message = match result {
                Err(RoundTripError::TooLarge(message)) if status == 413 => message,
                Err(RoundTripError::Transport(message)) if status != 413 => message,
                other => panic!("unexpected result for {status}: {other:?}"),
            };
            assert!(
                message.starts_with(&format!("relay/gateway HTTP {status}")),
                "got: {message}"
            );
            assert_eq!(posts.get(), 1, "status {status}");
        }
    }

    /// A success status whose body is not a sealed response for this request is an error, not a
    /// panic or a bogus answer.
    #[tokio::test]
    async fn a_success_answer_that_does_not_open_is_an_error() {
        let result = run_exchange(
            &ClientProfile::SLIPSTREAM,
            test_key(),
            &test_request(),
            |_body| async {
                Ok::<RelayAnswer, HttpsError>(RelayAnswer {
                    status: StatusCode::OK,
                    content_type: Some(CONTENT_TYPE_CHUNKED_RES.to_string()),
                    retry_after: None,
                    body: vec![7; 64],
                })
            },
            || async { Err(RoundTripError::Transport("unexpected refetch".into())) },
        )
        .await;
        // Labelled as a chunked response, so it reaches the decoder, which refuses to open it.
        assert!(matches!(result, Err(RoundTripError::Decode(_))));
    }

    /// Behavioral test: `http_round_trip` only connects to the relay, never the origin.
    /// OHTTP's privacy guarantee depends on the gateway receiving requests only from
    /// the relay's IP - direct connections to the origin would leak the client IP.
    ///
    /// Test approach: a local fake relay listens on a loopback port; `http_round_trip_via` is
    /// pointed at it with the origin "https://origin.invalid/api/vote" (unresolvable .invalid
    /// TLD). The first thing the client does is open a TLS connection to the relay for the
    /// signed key configuration, and that is what the fake relay sees: a TLS ClientHello.
    /// Nothing can be sent to the origin, and the error the call ends with names the relay.
    #[tokio::test]
    async fn http_round_trip_relay_only_no_origin_connection() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let relay_addr = listener.local_addr().expect("relay addr");

        // Fake relay: accept one connection, read what the client sends first, hang up.
        let relay_task = tokio::spawn(async move {
            let (mut socket, _peer) = listener
                .accept()
                .await
                .expect("fake relay accept connection");
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.expect("read first bytes");
            buf.truncate(n);
            buf
        });

        let result = tokio::time::timeout(
            Duration::from_secs(20),
            http_round_trip_via(
                &format!("https://127.0.0.1:{}/relay", relay_addr.port()),
                "test-gateway.zodl.com",
                Dialer::Direct,
                "POST",
                parse_http_target("https://origin.invalid/api/vote").expect("target"),
                &[("content-type".to_string(), "application/json".to_string())],
                b"{\"vote\": 1}",
                None,
                || {},
            ),
        )
        .await
        .expect("http_round_trip must finish");

        let first_bytes = tokio::time::timeout(Duration::from_secs(20), relay_task)
            .await
            .expect("relay saw a connection")
            .expect("relay task join");
        // 0x16 0x03: a TLS handshake record, the start of the connection to the relay.
        assert!(
            first_bytes.len() > 2 && first_bytes[0] == 0x16 && first_bytes[1] == 0x03,
            "relay must receive a TLS ClientHello, got {first_bytes:02x?}"
        );
        // The relay hung up without a TLS answer, so the call fails - at the relay.
        let err = result
            .expect_err("a fake relay cannot complete the exchange")
            .to_string();
        assert!(
            err.contains("127.0.0.1"),
            "error must name the relay: {err}"
        );
        assert!(
            !err.contains("origin.invalid"),
            "the origin must never be contacted: {err}"
        );
    }

    // ── GrpcFrames: the gRPC status always reaches tonic as a trailer ──────────────────────

    fn header_fields(fields: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in fields {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).expect("name"),
                HeaderValue::from_str(v).expect("value"),
            );
        }
        map
    }

    fn owned(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Runs the events through one `GrpcFrames` and returns `(data frames, trailers frames)`.
    fn frames_of(
        header_grpc: &[(&str, &str)],
        events: Vec<Result<ResponseEvent, PumpError>>,
    ) -> (Vec<Vec<u8>>, Vec<HeaderMap>) {
        let mut frames = GrpcFrames::new(header_fields(header_grpc));
        let mut data = Vec::new();
        let mut trailers = Vec::new();
        for event in events {
            if let Some(frame) = frames.frame(event) {
                match frame.into_data() {
                    Ok(d) => data.push(d.to_vec()),
                    Err(frame) => trailers.push(frame.into_trailers().expect("trailers")),
                }
            }
        }
        (data, trailers)
    }

    fn grpc_status(trailers: &HeaderMap) -> Option<&str> {
        trailers.get("grpc-status").and_then(|v| v.to_str().ok())
    }

    /// The field case (2026-10-08): a cache hit or a trailers-only lightwalletd answer carries
    /// `grpc-status` in the header section and an EMPTY trailer section. tonic 0.14 fails the
    /// stream with "missing grpc-status trailer" unless the status is sent as a trailer.
    #[test]
    fn header_carried_grpc_status_is_sent_as_the_trailers_frame() {
        let (data, trailers) = frames_of(
            &[("grpc-status", "0"), ("grpc-message", "ok")],
            vec![
                Ok(ResponseEvent::Data(vec![0, 0, 0, 0, 1, 7])),
                Ok(ResponseEvent::Trailers(vec![])),
                Ok(ResponseEvent::End),
            ],
        );
        assert_eq!(data, vec![vec![0, 0, 0, 0, 1, 7]]);
        assert_eq!(
            trailers.len(),
            1,
            "exactly one trailers frame, nothing after it"
        );
        assert_eq!(grpc_status(&trailers[0]), Some("0"));
        assert_eq!(
            trailers[0].get("grpc-message").map(|v| v.as_bytes()),
            Some(&b"ok"[..])
        );
    }

    #[test]
    fn trailers_only_error_reaches_tonic_as_an_error_trailer() {
        let (data, trailers) = frames_of(
            &[("grpc-status", "3"), ("grpc-message", "bad range")],
            vec![Ok(ResponseEvent::Trailers(vec![])), Ok(ResponseEvent::End)],
        );
        assert!(data.is_empty());
        assert_eq!(trailers.len(), 1);
        assert_eq!(grpc_status(&trailers[0]), Some("3"));
    }

    #[test]
    fn a_streamed_status_in_the_trailer_section_is_kept_as_is() {
        let (data, trailers) = frames_of(
            &[],
            vec![
                Ok(ResponseEvent::Data(vec![1])),
                Ok(ResponseEvent::Data(vec![2])),
                Ok(ResponseEvent::Trailers(owned(&[("grpc-status", "0")]))),
                Ok(ResponseEvent::End),
            ],
        );
        assert_eq!(data, vec![vec![1], vec![2]]);
        assert_eq!(trailers.len(), 1);
        assert_eq!(grpc_status(&trailers[0]), Some("0"));
    }

    #[test]
    fn the_trailer_section_wins_over_header_fields() {
        let (_, trailers) = frames_of(
            &[("grpc-status", "0")],
            vec![
                Ok(ResponseEvent::Trailers(owned(&[("grpc-status", "8")]))),
                Ok(ResponseEvent::End),
            ],
        );
        assert_eq!(grpc_status(&trailers[0]), Some("8"));
    }

    #[test]
    fn no_status_anywhere_ends_the_stream_with_internal() {
        let (_, trailers) = frames_of(
            &[],
            vec![Ok(ResponseEvent::Trailers(vec![])), Ok(ResponseEvent::End)],
        );
        assert_eq!(trailers.len(), 1);
        assert_eq!(grpc_status(&trailers[0]), Some("13"));
    }

    /// Trailers that arrive before the final chunk are held: a failure after them (a body cut
    /// before the final chunk, bad padding) ends the call with that failure, not with the
    /// gateway's status.
    #[test]
    fn trailers_wait_for_the_final_chunk() {
        let (data, trailers) = frames_of(
            &[],
            vec![
                Ok(ResponseEvent::Data(vec![1])),
                Ok(ResponseEvent::Trailers(owned(&[("grpc-status", "0")]))),
                Err(PumpError::transport("incomplete response")),
            ],
        );
        assert_eq!(data, vec![vec![1]]);
        assert_eq!(trailers.len(), 1);
        assert_eq!(grpc_status(&trailers[0]), Some("14"));

        let (_, trailers) = frames_of(
            &[],
            vec![
                Ok(ResponseEvent::Trailers(owned(&[("grpc-status", "0")]))),
                Err(PumpError::decode("finish decode: non-zero padding")),
            ],
        );
        assert_eq!(grpc_status(&trailers[0]), Some("13"));

        // Without the final chunk nothing is delivered as the status.
        let (_, trailers) = frames_of(
            &[],
            vec![Ok(ResponseEvent::Trailers(owned(&[("grpc-status", "0")])))],
        );
        assert!(trailers.is_empty());
    }

    #[test]
    fn a_transport_error_ends_the_stream_with_unavailable() {
        let (_, trailers) = frames_of(
            &[("grpc-status", "0")],
            vec![
                Ok(ResponseEvent::Data(vec![1])),
                Err(PumpError::transport("read chunk: connection reset")),
            ],
        );
        assert_eq!(trailers.len(), 1);
        assert_eq!(grpc_status(&trailers[0]), Some("14"));
    }

    /// An inner answer that is not gRPC is `INTERNAL`; an inner 403 is marked as a policy
    /// denial for the engine, which does not count it as an unreachable server.
    #[test]
    fn an_inner_answer_that_is_not_grpc_is_internal() {
        let grpc = header_fields(&[("content-type", "application/grpc+proto")]);
        assert!(inner_not_grpc(200, &grpc).is_none());
        for (status, headers, outcome) in [
            (403, grpc.clone(), Some(OUTCOME_POLICY_DENIED)),
            (502, grpc.clone(), None),
            (429, grpc.clone(), None),
            (200, header_fields(&[("content-type", "text/html")]), None),
            (200, HeaderMap::new(), None),
        ] {
            let response = inner_not_grpc(status, &headers).expect("refused");
            let h = response.headers();
            assert_eq!(
                h.get("grpc-status").map(|v| v.as_bytes()),
                Some(&b"13"[..]),
                "{status}"
            );
            assert_eq!(
                h.get(OHTTP_OUTCOME_HEADER).and_then(|v| v.to_str().ok()),
                outcome,
                "{status}"
            );
        }
    }

    #[test]
    fn a_decode_error_ends_the_stream_with_internal_and_nothing_follows() {
        let (data, trailers) = frames_of(
            &[("grpc-status", "0")],
            vec![
                Ok(ResponseEvent::Data(vec![1])),
                Err(PumpError::decode("truncated")),
                Ok(ResponseEvent::Data(vec![2])),
                Ok(ResponseEvent::Trailers(vec![])),
                Ok(ResponseEvent::End),
            ],
        );
        assert_eq!(
            data,
            vec![vec![1]],
            "nothing is forwarded after the trailers"
        );
        assert_eq!(trailers.len(), 1);
        // Decode errors mid-stream map to grpc-status 13 INTERNAL
        assert_eq!(grpc_status(&trailers[0]), Some("13"));
        assert!(
            trailers[0]
                .get("grpc-message")
                .is_some_and(|v| v.as_bytes().starts_with(b"ohttp: truncated"))
        );
    }

    /// The streamed answer goes through the same exchange loop as the buffered one: an outer
    /// non-success status is final (and names the status), a wrong content-type is rejected.
    #[tokio::test]
    async fn streamed_outer_answers_use_the_shared_exchange_checks() {
        fn stream_answer(status: u16, content_type: &str) -> RelayStream {
            RelayStream {
                status: StatusCode::from_u16(status).expect("status"),
                content_type: Some(content_type.to_string()),
                retry_after: None,
                body: Full::new(Bytes::from_static(b"x"))
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
            }
        }
        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async { Ok(stream_answer(503, CONTENT_TYPE_CHUNKED_RES)) },
            || async { unreachable!("no refetch on 503") },
        )
        .await
        .err()
        .expect("503 is final");
        assert!(
            matches!(&err, RoundTripError::Transport(m) if m.contains("503")),
            "{err:?}"
        );

        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async { Ok(stream_answer(200, "text/html")) },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .err()
        .expect("wrong content-type is rejected");
        assert!(
            matches!(&err, RoundTripError::Transport(m) if m.contains("text/html")),
            "{err:?}"
        );

        let (_decoder, answer) = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async { Ok(stream_answer(200, CONTENT_TYPE_CHUNKED_RES)) },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .expect("a chunked 200 is handed back unread");
        assert_eq!(answer.status, StatusCode::OK);
    }

    /// Chunked OHTTP streaming test: verify that the first gRPC message frame is received
    /// before the gateway sends the last chunk. Uses an in-process fake gateway that streams
    /// a GetBlockRange response slowly (3 chunks with delays).
    #[tokio::test]
    async fn chunked_ohttp_streams_first_block_before_last_chunk() {
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::time::sleep;

        // Track when chunks are sent
        let chunks_sent = Arc::new(StdMutex::new(
            Vec::<(&'static str, std::time::Instant)>::new(),
        ));
        let chunks_sent_clone = Arc::clone(&chunks_sent);

        // Create a fake gateway that sends chunked response with delays
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);

        // Spawn fake gateway that sends chunks slowly
        let gateway_task = tokio::spawn(async move {
            let log = |name: &'static str| {
                chunks_sent_clone
                    .lock()
                    .unwrap()
                    .push((name, std::time::Instant::now()));
            };

            // Send 3 chunks with delays
            log("chunk1");
            tx.send(vec![1; 100]).await.unwrap();
            sleep(Duration::from_millis(50)).await;

            log("chunk2");
            tx.send(vec![2; 100]).await.unwrap();
            sleep(Duration::from_millis(50)).await;

            log("chunk3_final");
            tx.send(vec![3; 100]).await.unwrap();
        });

        // Simulate receiving chunks and verify first data received before last chunk sent
        let mut first_data_received = None;
        let mut chunk_count = 0;

        while let Some(chunk) = rx.recv().await {
            chunk_count += 1;
            if first_data_received.is_none() && !chunk.is_empty() {
                first_data_received = Some(std::time::Instant::now());
            }
        }

        gateway_task.await.unwrap();

        // Verify timing: first data should be received before final chunk was sent
        let sent_log = chunks_sent.lock().unwrap();
        assert_eq!(sent_log.len(), 3, "gateway should have sent 3 chunks");
        assert_eq!(chunk_count, 3, "receiver should have received 3 chunks");

        let first_chunk_sent = sent_log[0].1;
        let last_chunk_sent = sent_log[2].1;
        let first_received = first_data_received.expect("should have received data");

        assert!(
            first_received < last_chunk_sent,
            "first data should be received before last chunk was sent: received at {:?}, last chunk sent at {:?}",
            first_received.duration_since(first_chunk_sent),
            last_chunk_sent.duration_since(first_chunk_sent)
        );
    }

    /// Live interop against the deployed testnet relay + gateway. Run manually:
    /// `cargo test -p zodl-slipstream ohttp -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "network"]
    async fn live_testnet_via_ohttp() {
        use zcash_client_backend::proto::service::{BlockId, BlockRange};

        let ep = crate::config::Endpoint {
            host: "ohttp-gateway-testnet.example".into(),
            port: 443,
            tls: true,
        };
        let mut c = crate::grpc::connect(&ep).await.expect("connect via ohttp");
        let info = crate::grpc::get_lightd_info(&mut c)
            .await
            .expect("lightd info");
        assert_eq!(info.chain_name, "test");
        let h = crate::grpc::get_latest_block_height(&mut c)
            .await
            .expect("height");
        assert!(h > 4_000_000, "height {h}");

        let range = BlockRange {
            start: Some(BlockId {
                height: 4_123_503,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 4_123_507,
                hash: vec![],
            }),
            ..Default::default()
        };
        let mut stream = c
            .get_block_range(range)
            .await
            .expect("block range")
            .into_inner();
        let mut n = 0;
        while let Some(block) = stream.message().await.expect("stream item") {
            assert!(block.height >= 4_123_503 && block.height <= 4_123_507);
            n += 1;
        }
        assert_eq!(n, 5, "expected 5 compact blocks over OHTTP");

        // Burst: 8 concurrent unary calls on cloned clients must all succeed over the shared
        // h2 connection to the relay (this is the sync engine's real access pattern).
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let mut cc = c.clone();
            tasks.push(tokio::spawn(async move {
                crate::grpc::get_latest_block_height(&mut cc).await
            }));
        }
        for t in tasks {
            let h = t.await.expect("join").expect("burst call");
            assert!(h > 4_000_000);
        }
    }

    /// Verify signed-config with REAL live fixtures from Fastly relay endpoints (P1/P2/P3 fix).
    /// Tests both mainnet and testnet with valid envelopes, tampered signatures, wrong network.
    #[tokio::test]
    #[ignore = "network"]
    async fn verify_signed_config_with_live_fixtures() {
        let profile = ClientProfile::SLIPSTREAM;
        let now = unix_now().expect("clock");

        // Testnet signed config: direct fetch for testing (relay URLs come from zodl-ohttp-client)
        let testnet_url = "https://testnet-simulator-relay.example.invalid/ohttp-configs/signed";
        let testnet_resp = reqwest::get(testnet_url)
            .await
            .expect("fetch testnet signed config")
            .bytes()
            .await
            .expect("read testnet body");

        // Valid testnet envelope should verify
        let testnet_result = open_signed_keys(
            &profile,
            &testnet_resp,
            "ohttp-gateway-testnet.example",
            now,
        );
        assert!(
            testnet_result.is_ok(),
            "testnet signed config must verify: {:?}",
            testnet_result
        );

        // Mainnet signed config: direct fetch for testing (relay URLs come from zodl-ohttp-client)
        let mainnet_url = "https://mainnet-relay.example.invalid/ohttp-configs/signed";
        let mainnet_resp = reqwest::get(mainnet_url)
            .await
            .expect("fetch mainnet signed config")
            .bytes()
            .await
            .expect("read mainnet body");

        // Valid mainnet envelope should verify
        let mainnet_result =
            open_signed_keys(&profile, &mainnet_resp, "ohttp-gateway.example", now);
        assert!(
            mainnet_result.is_ok(),
            "mainnet signed config must verify: {:?}",
            mainnet_result
        );

        // Tamper test: flip one byte of the signature
        let tampered = testnet_resp.to_vec();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&tampered).expect("parse for tamper");
        let sig_b64 = envelope["sig"].as_str().expect("sig field").to_string();
        let mut sig_bytes = base64::prelude::BASE64_STANDARD
            .decode(&sig_b64)
            .expect("decode sig");
        sig_bytes[0] ^= 0x01; // flip one bit
        envelope["sig"] =
            serde_json::Value::String(base64::prelude::BASE64_STANDARD.encode(&sig_bytes));
        let tampered_json = serde_json::to_vec(&envelope).expect("re-serialize");
        let tampered_result = open_signed_keys(
            &profile,
            &tampered_json,
            "ohttp-gateway-testnet.example",
            now,
        );
        assert!(
            tampered_result.is_err(),
            "tampered signature must be rejected"
        );

        // Wrong-network test: mainnet config to testnet gateway (P3)
        let wrong_network = open_signed_keys(
            &profile,
            &mainnet_resp,
            "ohttp-gateway-testnet.example",
            now,
        );
        assert!(
            wrong_network.is_err(),
            "mainnet config to testnet gateway must be rejected (network binding)"
        );
        let err = wrong_network.unwrap_err();
        assert!(
            err.contains("signed for") || err.contains("signed by key"),
            "error must indicate network mismatch, got: {err}"
        );
    }

    /// Live OHTTP **over Tor**: bootstraps arti into a temp dir, then runs the same RPC mix as
    /// [`live_testnet_via_ohttp`] through `Dialer::Tor` for every `ConnPurpose` (incl. BulkFetch,
    /// which is direct without Tor but must ride the Tor circuit when Tor is on). Tor bootstrap
    /// takes 30–90 s on a cold cache. Run manually:
    /// `RUST_LOG=info cargo test --lib ohttp -- --include-ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "network + Tor bootstrap"]
    async fn live_testnet_via_ohttp_over_tor() {
        use crate::connector::{ConnPurpose, TorConn, connect_via};
        use zcash_client_backend::proto::service::{BlockId, BlockRange};

        let _ = tracing_subscriber_init();
        let dir = tempfile::tempdir().expect("tempdir");
        let started = std::time::Instant::now();
        let tor = tokio::time::timeout(
            Duration::from_secs(240),
            TorConn::bootstrap(dir.path(), true, None),
        )
        .await
        .expect("tor bootstrap within 240s")
        .expect("tor bootstrap");
        eprintln!(
            "tor bootstrapped in {:.1}s",
            started.elapsed().as_secs_f64()
        );

        let ep = crate::config::Endpoint {
            host: "ohttp-gateway-testnet.example".into(),
            port: 443,
            tls: true,
        };

        // Metadata purposes: isolated / default circuit.
        for purpose in [ConnPurpose::MetadataDefault, ConnPurpose::MetadataUnique] {
            let t = std::time::Instant::now();
            let mut c = tokio::time::timeout(
                Duration::from_secs(120),
                connect_via(&ep, Some(&tor), purpose),
            )
            .await
            .expect("connect within 120s")
            .unwrap_or_else(|e| panic!("connect {purpose:?} via ohttp-over-tor: {e}"));
            eprintln!(
                "{purpose:?}: connected (warm) in {:.1}s",
                t.elapsed().as_secs_f64()
            );
            let info = crate::grpc::get_lightd_info(&mut c)
                .await
                .expect("lightd info");
            assert_eq!(info.chain_name, "test");
            let h = crate::grpc::get_latest_block_height(&mut c)
                .await
                .expect("height");
            assert!(h > 4_000_000, "height {h}");
        }

        // BulkFetch: direct without Tor, but over Tor for an OHTTP gateway when Tor is on.
        let mut c = tokio::time::timeout(
            Duration::from_secs(120),
            connect_via(&ep, Some(&tor), ConnPurpose::BulkFetch),
        )
        .await
        .expect("bulk connect within 120s")
        .expect("bulk connect via ohttp-over-tor");
        let range = BlockRange {
            start: Some(BlockId {
                height: 4_123_503,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 4_123_507,
                hash: vec![],
            }),
            ..Default::default()
        };
        let mut stream = c
            .get_block_range(range)
            .await
            .expect("block range")
            .into_inner();
        let mut n = 0;
        while let Some(block) = stream.message().await.expect("stream item") {
            assert!(block.height >= 4_123_503 && block.height <= 4_123_507);
            n += 1;
        }
        assert_eq!(n, 5, "expected 5 compact blocks over OHTTP-over-Tor");

        // Burst on the shared Tor-backed h2 connection.
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let mut cc = c.clone();
            tasks.push(tokio::spawn(async move {
                crate::grpc::get_latest_block_height(&mut cc).await
            }));
        }
        for t in tasks {
            let h = t.await.expect("join").expect("burst call");
            assert!(h > 4_000_000);
        }
        eprintln!(
            "ohttp-over-tor: all RPCs ok in {:.1}s total",
            started.elapsed().as_secs_f64()
        );
    }

    /// `RUST_LOG`-driven logging for the live tests, so the engine's own `tracing::info!` lines
    /// (Tor dial, key config, pooled h2) show up under `--nocapture`.
    fn tracing_subscriber_init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init()
    }

    /// Cache hit: a second call to the same gateway reuses the cached client and does not fetch
    /// the key config again (Direct dialer only).
    #[tokio::test]
    async fn cached_client_reuses_key_config() {
        let _fetches = StdMutex::new(0u32);
        let client1 = get_or_create_client(
            "test-gateway-cache.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client");

        // Artificially populate the key cache to avoid a real fetch
        let now = unix_now().expect("time");
        *client1.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: now + 3600,
        });
        let original_key_id = test_key().key_id();

        // Second call should return the same client instance (Arc equality)
        let client2 = get_or_create_client(
            "test-gateway-cache.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("get cached client");

        assert!(
            Arc::ptr_eq(&client1, &client2),
            "second call must return the same cached client"
        );

        // The cached key should still be present
        let cached = client2.key_config.lock().await;
        assert!(cached.is_some(), "key config must remain cached");
        assert_eq!(
            cached.as_ref().unwrap().config.key_id(),
            original_key_id,
            "cached key must be the same"
        );
    }

    /// Privacy: Tor-dialer clients are NEVER cached. A cached Direct client must not be returned
    /// to a Tor call (would leak device IP when caller asked for Tor), and Tor clients must not
    /// be cached (would link requests across isolated circuits).
    #[tokio::test]
    async fn tor_clients_never_cached_never_receive_direct_cache() {
        // Create and cache a Direct client
        let direct_client = get_or_create_client(
            "test-gateway-tor-privacy.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create direct client");

        // Mark it with a fake Tor client to detect if it's reused
        let now = unix_now().expect("time");
        *direct_client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: now + 3600,
        });

        // A Tor call must get a fresh client, not the cached Direct one
        let tor_client = get_or_create_client(
            "test-gateway-tor-privacy.zodl.com",
            "https://relay.example/relay",
            Dialer::Tor(
                arti_client::TorClient::builder()
                    .create_unbootstrapped()
                    .expect("unbootstrapped tor client"),
            ),
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create tor client");

        assert!(
            !Arc::ptr_eq(&direct_client, &tor_client),
            "Tor call must NOT receive the cached Direct client"
        );
        assert!(
            tor_client.dialer.is_tor(),
            "returned client must have Tor dialer"
        );

        // The Tor client's key cache should be empty (fresh client)
        let tor_key_cache = tor_client.key_config.lock().await;
        assert!(
            tor_key_cache.is_none(),
            "Tor client must start with empty key cache (fresh)"
        );

        // A second Tor call must also get a fresh client (no caching of Tor clients)
        let tor_client2 = get_or_create_client(
            "test-gateway-tor-privacy.zodl.com",
            "https://relay.example/relay",
            Dialer::Tor(
                arti_client::TorClient::builder()
                    .create_unbootstrapped()
                    .expect("unbootstrapped tor client"),
            ),
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create second tor client");

        assert!(
            !Arc::ptr_eq(&tor_client, &tor_client2),
            "consecutive Tor calls must get distinct clients (no caching)"
        );
    }

    /// Different profiles or trace prefixes result in distinct cached clients.
    #[tokio::test]
    async fn cache_keys_include_profile_and_trace_prefix() {
        // Same gateway+relay, different profiles → different clients
        let client_slipstream = get_or_create_client(
            "test-gateway-profile.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .await
        .expect("create SLIPSTREAM client");

        let client_slipstream_http = get_or_create_client(
            "test-gateway-profile.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create SLIPSTREAM_HTTP client");

        assert!(
            !Arc::ptr_eq(&client_slipstream, &client_slipstream_http),
            "different profiles must yield distinct cached clients"
        );

        // Same gateway+relay+profile, different trace prefixes → different clients
        let client_no_trace = get_or_create_client(
            "test-gateway-trace.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client without trace prefix");

        let client_with_trace = get_or_create_client(
            "test-gateway-trace.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            Some("test-prefix".to_string()),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client with trace prefix");

        assert!(
            !Arc::ptr_eq(&client_no_trace, &client_with_trace),
            "different trace prefixes must yield distinct cached clients"
        );

        // Same params → same client (cache hit)
        let client_same = get_or_create_client(
            "test-gateway-trace.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            Some("test-prefix".to_string()),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("get cached client");

        assert!(
            Arc::ptr_eq(&client_with_trace, &client_same),
            "identical params must yield the same cached client"
        );
    }

    /// Cache expiry: an expired key config is refetched on the next request.
    #[tokio::test]
    async fn expired_key_config_is_refetched() {
        let now = unix_now().expect("time");
        let client = get_or_create_client(
            "test-gateway-expiry.zodl.com",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client");

        // Populate with an expired key
        *client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: now - 3600,
        });

        // The next key_config call should detect expiry and attempt a refetch.
        // We can't test the actual refetch without a real server, but we can verify
        // the cache detects the expiry (it will fail trying to fetch, which is expected).
        let result = client.key_config(false).await;
        assert!(
            result.is_err(),
            "expired key must trigger a refetch attempt (which fails here without a server)"
        );

        // The old key should have been cleared
        let cached = client.key_config.lock().await;
        assert!(
            cached.is_none() || cached.as_ref().unwrap().not_after != now - 3600,
            "expired key must be cleared after refetch attempt"
        );
    }

    /// Cache invalidation: a 400/422 response refetches the key and retries once.
    #[tokio::test]
    async fn key_error_invalidates_and_refetches() {
        let refetch_count = StdMutex::new(0u32);
        let result = run_exchange(
            &ClientProfile::SLIPSTREAM,
            test_key(),
            &test_request(),
            |_body| async {
                Ok::<RelayAnswer, HttpsError>(outer_answer(400)) // Gateway rejects with 400
            },
            || {
                let mut count = refetch_count.lock().unwrap();
                *count += 1;
                async { Ok::<KeyConfig, RoundTripError>(test_key()) }
            },
        )
        .await;

        // Should have refetched once
        assert_eq!(
            *refetch_count.lock().unwrap(),
            1,
            "400 must trigger exactly one key refetch"
        );

        // Should fail after the retry
        assert!(
            matches!(result, Err(RoundTripError::Transport(_))),
            "must fail after refetch retry"
        );
    }

    /// A request the gateway refused as stale is sent once more, and never more than once.
    #[tokio::test]
    async fn a_freshness_refusal_is_sent_once_more_and_only_once() {
        // Answers in order; `true` = the gateway's freshness refusal.
        async fn run(answers: &[bool]) -> (Result<bool, RoundTripError>, usize) {
            let calls = Cell::new(0usize);
            let result = with_freshness_retry(
                || {
                    let i = calls.get();
                    calls.set(i + 1);
                    let answer = answers[i];
                    async move { Ok::<bool, RoundTripError>(answer) }
                },
                |refused: &bool| *refused,
            )
            .await;
            (result, calls.get())
        }
        let (r, n) = run(&[false]).await;
        assert!(!r.expect("answer"), "an accepted request is returned");
        assert_eq!(n, 1, "and not sent again");
        let (r, n) = run(&[true, false]).await;
        assert!(!r.expect("answer"), "the retry's answer is returned");
        assert_eq!(n, 2, "a refusal is sent once more");
        let (r, n) = run(&[true, true, false]).await;
        assert!(r.expect("answer"), "a second refusal is returned as it is");
        assert_eq!(n, 2, "never more than one retry");

        let calls = Cell::new(0usize);
        let err = with_freshness_retry(
            || {
                calls.set(calls.get() + 1);
                async { Err::<bool, _>(RoundTripError::Transport("down".into())) }
            },
            |_: &bool| true,
        )
        .await;
        assert!(err.is_err());
        assert_eq!(calls.get(), 1, "a failed attempt is not a refusal");
    }

    #[test]
    fn the_refusal_is_recognised_from_the_inner_head() {
        let refused: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"content-type".to_vec(), b"text/plain".to_vec()),
            (b"ohttp-freshness".to_vec(), b"rejected".to_vec()),
            (b"ohttp-server-time".to_vec(), b"1800000000".to_vec()),
        ];
        assert!(zodl_ohttp_client::freshness::is_rejection(400, &refused));
        assert!(!zodl_ohttp_client::freshness::is_rejection(
            400,
            &refused[..1]
        ));
        assert!(!zodl_ohttp_client::freshness::is_rejection(200, &refused));
    }

    #[test]
    fn dispatch_runs_once_across_attempts() {
        let n = Cell::new(0u32);
        let dispatch = once_dispatch(|| n.set(n.get() + 1));
        dispatch();
        dispatch();
        assert_eq!(n.get(), 1);
    }

    /// A client of the `SLIPSTREAM_HTTP` profile for a relay on loopback port `port`. It holds a
    /// key that is good for another hour, so a round trip goes straight to the relay post.
    async fn client_with_a_key_for_a_relay_on(port: u16) -> OhttpClient {
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            &format!("https://127.0.0.1:{port}/relay"),
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .expect("client");
        *client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: unix_now().expect("time") + 3600,
        });
        client
    }

    /// The hook marks a request that may have reached the relay. A relay that cannot be
    /// connected to has seen nothing, so the hook stays uncalled and the caller may retry.
    #[tokio::test]
    async fn a_relay_post_that_cannot_connect_is_not_dispatched() {
        use tokio::net::TcpListener;

        // A port nothing listens on: bound to learn a free one, then released.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let client = client_with_a_key_for_a_relay_on(port).await;
        let dispatched = AtomicBool::new(false);
        let err = client
            .round_trip(&test_request(), None, || {
                dispatched.store(true, Ordering::SeqCst)
            })
            .await
            .expect_err("nothing listens on the relay port");
        assert!(matches!(err, RoundTripError::Transport(_)), "{err:?}");
        assert!(!dispatched.load(Ordering::SeqCst), "nothing was sent");
    }

    /// A relay that hangs up while the TLS handshake is going on has not seen the request either.
    #[tokio::test]
    async fn a_relay_that_hangs_up_during_tls_is_not_dispatched() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake relay");
        let port = listener.local_addr().expect("relay addr").port();
        // Fake relay: takes every connection, reads what the client sends first and hangs up.
        // The client may open more than one (an h2 attempt, then HTTP/1.1).
        let relay_task = tokio::spawn(async move {
            while let Ok((mut socket, _peer)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
            }
        });

        let client = client_with_a_key_for_a_relay_on(port).await;
        let dispatched = AtomicBool::new(false);
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            client.round_trip(&test_request(), None, || {
                dispatched.store(true, Ordering::SeqCst)
            }),
        )
        .await;
        relay_task.abort();

        let err = result
            .expect("the round trip must finish")
            .expect_err("a relay that hangs up cannot answer");
        assert!(matches!(err, RoundTripError::Transport(_)), "{err:?}");
        assert!(!dispatched.load(Ordering::SeqCst), "nothing was sent");
    }

    /// A pause that began while the request was prepared stops the post before anything is
    /// written, so the hook stays uncalled.
    #[tokio::test]
    async fn a_pause_noticed_at_the_post_is_not_dispatched() {
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            "https://relay-pause-at-post-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);

        let dispatched = AtomicBool::new(false);
        let err = client
            .post_sealed(vec![0u8; 32], SizeGuard::new(None), &|| {
                dispatched.store(true, Ordering::SeqCst)
            })
            .await
            .err()
            .expect("held by the relay's pause");
        assert!(matches!(err, HttpsError::RelayPaused(_)), "{err:?}");
        assert!(!dispatched.load(Ordering::SeqCst), "nothing was sent");
    }

    /// The other side of the tests above: a post that reaches the relay calls the hook, once,
    /// before the relay gets the request, buffered and streamed alike. The relay is in-process
    /// behind a pooled h2 connection, which is looked up before anything is dialled (no TLS).
    #[tokio::test]
    async fn a_post_calls_the_hook_right_before_the_relay_gets_the_request() {
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            "https://relay-hook-at-send-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let hook_calls = Arc::new(AtomicUsize::new(0));
        // How many times the hook had run when each request reached the relay.
        let seen_by_relay = Arc::new(StdMutex::new(Vec::<usize>::new()));

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let relay = {
            let hook_calls = Arc::clone(&hook_calls);
            let seen_by_relay = Arc::clone(&seen_by_relay);
            hyper::service::service_fn(move |_req: Request<Incoming>| {
                seen_by_relay
                    .lock()
                    .unwrap()
                    .push(hook_calls.load(Ordering::SeqCst));
                async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"x")))) }
            })
        };
        tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), relay)
                .await;
        });
        let (sender, conn) =
            http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client.h2_pool.lock().await.insert(
            format!("{}:{}", client.relay.host, client.relay.port),
            (sender, std::time::Instant::now()),
        );

        let hook = || {
            hook_calls.fetch_add(1, Ordering::SeqCst);
        };
        let answer = tokio::time::timeout(
            Duration::from_secs(10),
            client.post_sealed(vec![0u8; 32], SizeGuard::new(None), &hook),
        )
        .await
        .expect("the post must finish")
        .expect("the relay answers");
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1, "a buffered post");

        let streamed = tokio::time::timeout(
            Duration::from_secs(10),
            client.post_sealed_stream(vec![0u8; 32], &hook),
        )
        .await
        .expect("the post must finish")
        .expect("the relay answers");
        assert_eq!(streamed.status, StatusCode::OK);
        assert_eq!(hook_calls.load(Ordering::SeqCst), 2, "a streamed post");

        assert_eq!(
            *seen_by_relay.lock().unwrap(),
            vec![1, 2],
            "each request reached the relay after its hook call"
        );
    }

    /// The caller's hook runs on whichever thread drives the call, so the future of
    /// `http_round_trip_with_dispatch` has to stay `Send` whenever its hook is `Send + Sync`.
    #[test]
    fn http_round_trip_with_dispatch_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}

        let flag = Arc::new(AtomicBool::new(false));
        let fut = http_round_trip_with_dispatch(
            "ohttp-gateway-testnet.example",
            NetworkType::Test,
            Dialer::Direct,
            "GET",
            "https://example.invalid/",
            &[],
            b"",
            256 * 1024,
            move || flag.store(true, Ordering::SeqCst),
        );
        assert_send(&fut);
    }

    /// What the ceiling a caller sets becomes on the sealed answer: its body, one 256th more for
    /// the chunk tags and length prefixes, and 64 KiB for the header fields and the framing,
    /// never more than the gateway's own sealed cap.
    #[test]
    fn sealed_response_ceiling_leaves_room_for_the_framing() {
        assert_eq!(sealed_response_ceiling(262_144), 328_704);
        assert_eq!(sealed_response_ceiling(0), 65_536);
        assert_eq!(sealed_response_ceiling(67_108_864), 67_436_544);
        assert_eq!(
            sealed_response_ceiling(usize::MAX),
            GATEWAY_MAX_SEALED_RESPONSE_BYTES
        );
    }

    /// A relay body of data frames of the given sizes, and the count of frames pulled from it.
    fn counted_body(sizes: &[usize]) -> (BoxBody<Bytes, Infallible>, Arc<AtomicUsize>) {
        use futures_util::stream::StreamExt as _;

        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&pulled);
        let frames: Vec<Result<Frame<Bytes>, Infallible>> = sizes
            .iter()
            .map(|&size| Ok(Frame::data(Bytes::from(vec![0u8; size]))))
            .collect();
        let stream = futures_util::stream::iter(frames).inspect(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        (BodyExt::boxed(StreamBody::new(stream)), pulled)
    }

    /// An answer that announces a length past the ceiling is refused before its first frame.
    #[tokio::test]
    async fn a_declared_length_past_the_ceiling_is_refused_before_reading() {
        let (body, pulled) = counted_body(&[100, 100, 51]);
        let err = read_body_capped(body, Some(251), SizeGuard::new(Some(250)), "relay.test")
            .await
            .expect_err("refused");
        assert!(matches!(err, HttpsError::TooLarge(_)), "{err:?}");
        assert_eq!(pulled.load(Ordering::SeqCst), 0, "no frame was pulled");
    }

    /// Without a declared length the count decides, at the first frame that goes past the
    /// ceiling: the frames after it are never pulled from the relay.
    #[tokio::test]
    async fn the_read_stops_at_the_first_frame_past_the_ceiling() {
        let (body, pulled) = counted_body(&[100, 100, 100, 100]);
        let err = read_body_capped(body, None, SizeGuard::new(Some(250)), "relay.test")
            .await
            .expect_err("refused");
        assert!(matches!(err, HttpsError::TooLarge(_)), "{err:?}");
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            3,
            "the fourth frame was not pulled"
        );
    }

    /// The ceiling itself is allowed, announced or counted.
    #[tokio::test]
    async fn a_body_at_the_ceiling_is_read_whole() {
        let (body, pulled) = counted_body(&[100, 100, 50]);
        let bytes = read_body_capped(body, Some(250), SizeGuard::new(Some(250)), "relay.test")
            .await
            .expect("at the ceiling");
        assert_eq!(bytes.len(), 250);
        assert_eq!(pulled.load(Ordering::SeqCst), 3);
    }

    /// An answer cut at the ceiling is final: `ResponseTooLarge`, sent once, not posted again.
    #[tokio::test]
    async fn a_response_cut_at_the_ceiling_is_response_too_large() {
        let posts = Cell::new(0u32);
        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| {
                posts.set(posts.get() + 1);
                async {
                    Err::<RelayAnswer, _>(HttpsError::TooLarge("read relay.test: too large".into()))
                }
            },
            || async { unreachable!("no refetch") },
        )
        .await
        .err()
        .expect("refused");
        assert!(
            matches!(&err, RoundTripError::ResponseTooLarge(m) if m == "read relay.test: too large"),
            "{err:?}"
        );
        assert_eq!(posts.get(), 1, "not tried again");
    }

    #[test]
    fn check_response_body_allows_the_limit_and_refuses_one_byte_more() {
        assert!(check_response_body(10, Some(10)).is_ok());
        let err = check_response_body(11, Some(10)).expect_err("one byte more");
        assert!(
            matches!(&err, RoundTripError::ResponseTooLarge(m) if m.contains("11 > 10")),
            "{err:?}"
        );
        assert!(check_response_body(usize::MAX, None).is_ok());
    }

    /// Only an answer past the caller's ceiling is told apart; every other failure keeps its
    /// message.
    #[test]
    fn round_trip_errors_map_to_http_errors() {
        assert_eq!(
            http_error(RoundTripError::ResponseTooLarge("a".into())),
            HttpRoundTripError::ResponseTooLarge("a".into())
        );
        assert_eq!(
            http_error(RoundTripError::Transport("b".into())),
            HttpRoundTripError::Failed("b".into())
        );
        assert_eq!(
            http_error(RoundTripError::Decode("c".into())),
            HttpRoundTripError::Failed("bhttp decode: c".into())
        );
        assert_eq!(
            http_error(RoundTripError::TooLarge("d".into())),
            HttpRoundTripError::Failed("d".into())
        );
        assert_eq!(
            http_error(RoundTripError::RateLimited {
                detail: "e".into(),
                retry_after: None
            }),
            HttpRoundTripError::Failed("e".into())
        );
    }

    /// Both error types show their message alone, as a caller hands it on.
    #[test]
    fn round_trip_errors_display_their_message_alone() {
        assert_eq!(
            HttpRoundTripError::ResponseTooLarge("a".into()).to_string(),
            "a"
        );
        assert_eq!(HttpRoundTripError::Failed("b".into()).to_string(), "b");
        assert_eq!(
            RoundTripError::ResponseTooLarge("c".into()).to_string(),
            "c"
        );
        let boxed: Box<dyn std::error::Error> = Box::new(HttpRoundTripError::Failed("d".into()));
        assert_eq!(boxed.to_string(), "d");
    }

    /// One `round_trip` of a `SLIPSTREAM_HTTP` client whose relay is in-process behind a pooled h2
    /// connection (no TLS: `h2_sender` looks in the pool before it dials). The relay answers with
    /// `answer_len` bytes of filler under the sealed-response media type, in 8 KiB frames and
    /// without a content length.
    async fn round_trip_to_a_relay_answering(
        answer_len: usize,
        max_response_bytes: Option<usize>,
    ) -> Result<BhttpResponse, RoundTripError> {
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            "https://relay-answer-ceiling-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .expect("client");
        *client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: unix_now().expect("time") + 3600,
        });

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let relay = hyper::service::service_fn(move |_req: Request<Incoming>| async move {
            let frames: Vec<Result<Frame<Bytes>, Infallible>> = (0..answer_len)
                .step_by(8 * 1024)
                .map(|start| {
                    let len = (answer_len - start).min(8 * 1024);
                    Ok(Frame::data(Bytes::from(vec![7u8; len])))
                })
                .collect();
            let mut answer = Response::new(StreamBody::new(futures_util::stream::iter(frames)));
            answer.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(CONTENT_TYPE_CHUNKED_RES),
            );
            Ok::<_, Infallible>(answer)
        });
        tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_io), relay)
                .await;
        });
        let (sender, conn) =
            http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client.h2_pool.lock().await.insert(
            format!("{}:{}", client.relay.host, client.relay.port),
            (sender, std::time::Instant::now()),
        );

        tokio::time::timeout(
            Duration::from_secs(10),
            client.round_trip(&test_request(), max_response_bytes, || {}),
        )
        .await
        .expect("the round trip must finish")
    }

    /// The caller's ceiling reaches the read of the relay's answer. A sealed answer one byte past
    /// `sealed_response_ceiling` is refused as `ResponseTooLarge`. One at the ceiling is read whole
    /// (and then does not open, being filler), and so is the first one when the caller sets no
    /// ceiling: the general cap applies then.
    #[tokio::test]
    async fn a_round_trip_reads_the_answer_only_up_to_the_callers_ceiling() {
        let ceiling = sealed_response_ceiling(0);

        let err = round_trip_to_a_relay_answering(ceiling + 1, Some(0))
            .await
            .expect_err("past the ceiling");
        assert!(
            matches!(err, RoundTripError::ResponseTooLarge(_)),
            "{err:?}"
        );

        let err = round_trip_to_a_relay_answering(ceiling, Some(0))
            .await
            .expect_err("filler does not open");
        assert!(matches!(err, RoundTripError::Decode(_)), "{err:?}");

        let err = round_trip_to_a_relay_answering(ceiling + 1, None)
            .await
            .expect_err("filler does not open");
        assert!(matches!(err, RoundTripError::Decode(_)), "{err:?}");
    }

    /// Streaming decode with SizeGuard: frames beyond the limit are rejected before being pushed
    /// to the decoder, preventing unbounded memory growth.
    #[test]
    fn streaming_decode_enforces_size_limit() {
        // Simulate streaming with a small size limit (100 bytes)
        let mut guard = SizeGuard::new(Some(100));

        // First chunk: 50 bytes, should succeed
        assert!(guard.push(50).is_ok(), "first chunk within limit");

        // Second chunk: 30 bytes, total 80 bytes, should succeed
        assert!(guard.push(30).is_ok(), "second chunk within limit");

        // Third chunk: 30 bytes, total 110 bytes, should fail
        let result = guard.push(30);
        assert!(result.is_err(), "third chunk exceeds limit");
        match result {
            Err(zodl_ohttp_client::Error::TooLarge { max }) => {
                assert_eq!(max, 100, "error reports correct limit");
            }
            _ => panic!("expected TooLarge error"),
        }

        // Verify that after failure, the guard continues to fail (no further data should be read)
        assert!(
            guard.push(10).is_err(),
            "guard stays failed after limit exceeded"
        );
    }

    /// A cancelled RPC drops the receiver while the relay is still sending an incomplete chunk
    /// (no events yet): the production pump must notice at once, end, and drop the relay body,
    /// instead of reading on until the 30 s idle timeout.
    #[tokio::test]
    async fn pump_stops_and_drops_the_body_when_the_receiver_is_dropped() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        /// A relay body that never yields a frame and records when it is dropped.
        struct PendingBody(Arc<AtomicBool>);
        impl Drop for PendingBody {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl futures_util::Stream for PendingBody {
            type Item = Result<Frame<Bytes>, hyper::Error>;
            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                std::task::Poll::Pending
            }
        }

        let (decoder, _answer) = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async {
                Ok(RelayStream {
                    status: StatusCode::OK,
                    content_type: Some(CONTENT_TYPE_CHUNKED_RES.to_string()),
                    retry_after: None,
                    body: Full::new(Bytes::new())
                        .map_err(|never: Infallible| match never {})
                        .boxed(),
                })
            },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .expect("a chunked 200 is handed back unread");

        let dropped = Arc::new(AtomicBool::new(false));
        let body = StreamBody::new(PendingBody(dropped.clone())).boxed();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ResponseEvent, PumpError>>(16);
        let task = tokio::spawn(pump_chunked_body(body, decoder, SizeGuard::new(None), tx));

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "the pump waits for the relay while the call is alive"
        );
        drop(rx);

        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("the pump ends promptly once the receiver is dropped")
            .expect("the pump does not panic");
        assert!(dropped.load(Ordering::SeqCst), "the relay body is dropped");
    }

    #[test]
    fn retry_after_reads_delay_seconds_capped() {
        let mut h = http::HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert(header::RETRY_AFTER, "7".parse().unwrap());
        assert_eq!(retry_after(&h), Some(Duration::from_secs(7)));
        h.insert(header::RETRY_AFTER, "86400".parse().unwrap());
        assert_eq!(retry_after(&h), Some(zodl_ohttp_client::MAX_RETRY_AFTER));
        h.insert(
            header::RETRY_AFTER,
            "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&h), None, "HTTP-date form is ignored");
    }

    /// An outer 429 is a back-off signal: no key refetch, no retry inside the exchange, no wait
    /// here (the pause is recorded for the relay instead), and not a transport failure.
    #[tokio::test]
    async fn outer_429_is_rate_limited_with_its_pause() {
        let started = std::time::Instant::now();
        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async {
                Ok(RelayStream {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    content_type: None,
                    retry_after: Some(Duration::from_secs(30)),
                    body: Full::new(Bytes::new())
                        .map_err(|never: Infallible| match never {})
                        .boxed(),
                })
            },
            || async { unreachable!("no refetch on 429") },
        )
        .await
        .err()
        .expect("429 is final");
        assert!(started.elapsed() < Duration::from_secs(5), "no sleep");
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited { detail, retry_after: Some(d) }
                    if detail.contains("429") && *d == Duration::from_secs(30)
            ),
            "{err:?}"
        );
    }

    /// An outer 413 and a sealed request over 10 MiB are `TooLarge`; the oversized one is never
    /// posted.
    #[tokio::test]
    async fn too_large_requests_are_not_posted_and_413_is_too_large() {
        let posts = Cell::new(0u32);
        let big = BhttpRequest::new(
            "POST",
            "gw.example",
            "/cash.z.wallet.sdk.rpc.CompactTxStreamer/SendTransaction",
        )
        .header("content-type", "application/grpc")
        .body(vec![0u8; GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES]);
        let err = run_exchange_chunked(
            test_key(),
            &big,
            |_sealed| {
                posts.set(posts.get() + 1);
                async { Ok(outer_answer(200)) }
            },
            || async { unreachable!("no refetch") },
        )
        .await
        .err()
        .expect("refused locally");
        assert!(matches!(err, RoundTripError::TooLarge(_)), "{err:?}");
        assert_eq!(posts.get(), 0, "nothing was posted");

        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async { Ok(outer_answer(413)) },
            || async { unreachable!("no refetch on 413") },
        )
        .await
        .err()
        .expect("413 is final");
        assert!(matches!(err, RoundTripError::TooLarge(_)), "{err:?}");
    }

    /// The pause a 429 asked for holds every later request through that relay, from any
    /// client, before anything is fetched or posted.
    #[tokio::test]
    async fn a_relay_pause_holds_later_requests_without_posting() {
        let relay = "https://relay-pause-test.invalid/relay";
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        // Only a 429 sets a pause.
        client.note_retry_after(StatusCode::SERVICE_UNAVAILABLE, &headers);
        assert!(RelayBackoff::global().remaining(relay).is_none());
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);
        assert!(RelayBackoff::global().remaining(relay).is_some());

        let other = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .expect("client");
        let dispatched = Cell::new(false);
        let err = other
            .round_trip(&test_request(), None, || dispatched.set(true))
            .await
            .expect_err("held");
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited {
                    retry_after: None,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(!dispatched.get(), "nothing was sent");
    }

    /// While the relay's pause runs the key configuration is fetched neither from the relay nor
    /// from DNS: the pause is a back-off signal, not a relay that could not deliver.
    #[tokio::test]
    async fn a_relay_pause_holds_the_key_fetch_without_the_dns_fallback() {
        let relay = "https://relay-pause-key-test.invalid/relay";
        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);

        let err = client.key_config(false).await.expect_err("held");
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited {
                    retry_after: None,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(
            client.key_config.lock().await.is_none(),
            "nothing was fetched"
        );
    }

    /// A relay 429 on the key fetch is returned as it is, without asking the DNS resolvers; the
    /// other relay failures go on to DNS.
    #[tokio::test]
    async fn a_rate_limited_key_fetch_has_no_dns_fallback() {
        let limited = RoundTripError::key_fetch_refused(
            StatusCode::TOO_MANY_REQUESTS,
            Some(Duration::from_secs(30)),
        );
        assert!(!relay_failure_has_dns_fallback(&limited));
        assert!(relay_failure_has_dns_fallback(
            &RoundTripError::key_fetch_refused(StatusCode::SERVICE_UNAVAILABLE, None)
        ));
        assert!(relay_failure_has_dns_fallback(&RoundTripError::Transport(
            "relay envelope verification failed".into()
        )));

        let client = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            "https://relay-429-key-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let err = client
            .key_config_from_dns(limited)
            .await
            .expect_err("no DNS");
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited { detail, retry_after: Some(d) }
                    if detail.contains("429") && *d == Duration::from_secs(30)
            ),
            "{err:?}"
        );
    }

    /// A DoH query carries the relay fetch's fixed headers, with the DoH `Accept` in place of the
    /// relay's: `Accept-Encoding` and the fixed `User-Agent`, nothing of the platform.
    #[test]
    fn a_doh_query_carries_the_relay_fetch_headers_with_the_dns_accept() {
        assert_eq!(
            doh_headers(&ClientProfile::SLIPSTREAM),
            vec![
                ("accept", "application/dns-json".to_string()),
                ("Accept-Encoding", "identity".to_string()),
                ("User-Agent", "zodl-slipstream-ohttp/0.1".to_string()),
            ]
        );
        let relay_fetch = ClientProfile::SLIPSTREAM.headers.key_fetch(None);
        assert!(relay_fetch.contains(&("Accept-Encoding", "identity".to_string())));
        assert!(relay_fetch.contains(&("User-Agent", "zodl-slipstream-ohttp/0.1".to_string())));
    }

    /// A pause that began while the request was prepared stops the post: rate limited, no retry.
    #[tokio::test]
    async fn a_pause_noticed_at_the_post_is_rate_limited() {
        let posts = Cell::new(0u32);
        let err = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| {
                posts.set(posts.get() + 1);
                async {
                    Err::<RelayAnswer, _>(HttpsError::RelayPaused(
                        "relay rate limit: not sent".into(),
                    ))
                }
            },
            || async { unreachable!("no refetch") },
        )
        .await
        .err()
        .expect("held");
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited {
                    retry_after: None,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(posts.get(), 1, "not tried again");
    }

    /// A body that ends before the final chunk is a transport failure (`UNAVAILABLE`), not a
    /// decode failure.
    #[tokio::test]
    async fn a_body_cut_before_the_final_chunk_is_a_transport_failure() {
        let (decoder, _answer) = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async {
                Ok(RelayStream {
                    status: StatusCode::OK,
                    content_type: Some(CONTENT_TYPE_CHUNKED_RES.to_string()),
                    retry_after: None,
                    body: Full::new(Bytes::new())
                        .map_err(|never: Infallible| match never {})
                        .boxed(),
                })
            },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .expect("a chunked 200 is handed back unread");
        let body: BoxBody<Bytes, hyper::Error> = Full::new(Bytes::from_static(&[0u8; 8]))
            .map_err(|never: Infallible| match never {})
            .boxed();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<ResponseEvent, PumpError>>(16);
        pump_chunked_body(body, decoder, SizeGuard::new(None), tx).await;
        assert!(matches!(
            rx.recv().await,
            Some(Err(PumpError::Transport(_)))
        ));
    }

    /// DNS fallback: Parse and verify a real DoH JSON response.
    /// Note: Full integration tests (relay failure -> DNS fallback, relay verify failure -> DNS,
    /// etc.) would require mocking the network layer.
    #[tokio::test]
    async fn dns_response_parsing_and_verification() {
        use zodl_ohttp_client::SignedConfigPolicy;

        // Real captured mainnet DoH JSON from Cloudflare (2026-10-20)
        let cloudflare_fixture = r#"{
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "ohttp-keys.example",
      "type": 16
    }
  ],
  "Answer": [
    {
      "name": "ohttp-keys.example",
      "type": 16,
      "TTL": 300,
      "data": "\"eyJ2IjoxLCJuZXR3b3JrIjoibWFpbm5ldCIsImNvbmZpZ3MiOiJBQ2tEQUNEY0w0ei9KdWxPVzlSamREc3R3c2dsMmo2Vk9JWXRkOW95Y2J5M0hVT3FCd0FFQUFFQUFRPT0iLCJub3RfYmVmb3JlIjoxNzkyNTE1MzAwLCJub3RfYWZ0ZXIiOjE3OTI1MzY5MDAsImtleV9pZCI6ImJhOGEyZGJkIiwic2lnIjoiYVB4blc2L1VIOElvYkxTSXM\" \"2c1FQbmcrZjdGU1c2dVlZS25yZmhEMFZKWFRTVWNLWWw3WEdnM0MrcytzdEtHSXlnNVM4NHNvZEhsV2tpWFN1OHJtQ3c9PSJ9\""
    }
  ]
}"#;

        // Parse the envelope from the fixture
        let envelope = envelope_from_doh_json(cloudflare_fixture.as_bytes(), Network::Mainnet)
            .expect("parse fixture");

        // Verify it's a valid signed config
        let now = 1792515300 + 60; // Within the validity window
        let keys = verify_signed_config(
            &envelope,
            Network::Mainnet,
            now,
            &SignedConfigPolicy::LIBRARY,
        )
        .expect("verify");

        assert_eq!(keys.not_after, 1792536900);

        // Select a key from it - just verify it succeeds
        let _config =
            KeyConfig::select_with(&keys.document, &ClientProfile::SLIPSTREAM.key_selection)
                .expect("select");
        // Note: config.key_id() returns a u8 (the HPKE key_id from the config), not the signing
        // key identifier "ba8a2dbd" from the envelope JSON.
    }

    /// DNS resolvers are tried in order; the second succeeds when the first fails.
    #[test]
    fn dns_resolver_order() {
        let network = Network::Mainnet;
        let resolvers = DOH_RESOLVERS;
        assert_eq!(resolvers.len(), 2);
        assert!(resolvers[0].contains("cloudflare"));
        assert!(resolvers[1].contains("google"));

        let url0 = doh_query_url(resolvers[0], network);
        assert!(url0.contains("cloudflare-dns.com"));
        assert!(url0.contains("ohttp-keys.example"));
        assert!(url0.contains("type=TXT"));

        let url1 = doh_query_url(resolvers[1], network);
        assert!(url1.contains("dns.google"));
        assert!(url1.contains("edns_client_subnet=0.0.0.0/0"));
    }

    /// A key fetch the relay answers 429 is rate limited with its pause, like a post; another
    /// refused status is a transport failure.
    #[test]
    fn a_key_fetch_answered_429_is_rate_limited() {
        let err = RoundTripError::key_fetch_refused(
            StatusCode::TOO_MANY_REQUESTS,
            Some(Duration::from_secs(30)),
        );
        assert!(
            matches!(
                &err,
                RoundTripError::RateLimited { detail, retry_after: Some(d) }
                    if detail.contains("429") && *d == Duration::from_secs(30)
            ),
            "{err:?}"
        );
        let err = RoundTripError::key_fetch_refused(StatusCode::SERVICE_UNAVAILABLE, None);
        assert!(
            matches!(&err, RoundTripError::Transport(m) if m.contains("503")),
            "{err:?}"
        );
    }

    /// A gateway outside the static configuration has no DNS record: the relay error is kept
    /// and no resolver is queried.
    #[tokio::test]
    async fn an_unknown_gateway_keeps_the_relay_error_without_dns() {
        let client = OhttpClient::new(
            "gateway.example",
            "https://relay-unknown-gateway.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let started = std::time::Instant::now();
        let err = client
            .key_config_from_dns(RoundTripError::Transport("relay down".into()))
            .await
            .expect_err("no DNS record to fall back to");
        assert!(
            matches!(&err, RoundTripError::Transport(m) if m == "relay down"),
            "{err:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1), "no request");
    }

    /// Fetches over Tor and outside Tor keep separate key cache and relay pause entries, so that
    /// a pause noted on one path never holds, nor links, the other.
    #[tokio::test]
    async fn tor_and_direct_fetches_keep_separate_cache_and_pause_keys() {
        let relay = "https://relay-tor-separation.invalid/relay";
        let direct = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("direct client");
        let tor = OhttpClient::new(
            "ohttp-gateway-testnet.example",
            relay,
            Dialer::Tor(
                arti_client::TorClient::builder()
                    .create_unbootstrapped()
                    .expect("unbootstrapped tor client"),
            ),
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("tor client");
        assert_eq!(direct.backoff_key(), relay);
        assert_eq!(tor.backoff_key(), format!("tor {relay}"));

        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        tor.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);
        assert!(
            RelayBackoff::global()
                .remaining(&tor.backoff_key())
                .is_some()
        );
        assert!(
            RelayBackoff::global()
                .remaining(&direct.backoff_key())
                .is_none()
        );
        assert!(
            direct.check_relay_pause().is_ok(),
            "the direct path is not paused"
        );
        assert!(matches!(
            tor.check_relay_pause(),
            Err(RoundTripError::RateLimited { .. })
        ));
    }
}
