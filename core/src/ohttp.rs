// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL Slipstream.

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
//! and every caller in this crate stay unchanged. Server-streaming RPCs are buffered by the
//! gateway and delivered as one body containing all the length-prefixed messages.
//!
//! The protocol itself (RFC 9458 §4.3/§4.4 with the suite DHKEM(X25519, HKDF-SHA256) /
//! HKDF-SHA256 / AES-128-GCM, Binary HTTP, signed key-configuration verification, key selection,
//! outer-status classification and size limits) is the shared sans-IO `zodl-ohttp-client` crate,
//! driven with its `ClientProfile::SLIPSTREAM` (gRPC) and `ClientProfile::SLIPSTREAM_HTTP`
//! ([`http_round_trip`]) profiles. This module keeps the I/O: the dialer, the pooled h2 sender,
//! the relay table, timeouts and the mapping to gRPC. The gateway folds the gRPC trailers into
//! the Binary HTTP header section and this module moves them back into HTTP/2 trailers.
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
use zodl_ohttp_client::{
    BhttpRequest, BhttpResponse, ClientProfile, ClientTrace, Completed, Error as CoreError,
    KeyConfig, SizeGuard, complete_exchange_in_place, encapsulate_request, signed_config_url,
    verify_signed_config,
};

/// In-memory pipe capacity between tonic and the in-process h2 server.
const DUPLEX_BUF: usize = 4 << 20;
/// Whole OHTTP round trip (encapsulate → relay → gateway → lightwalletd → back). The engine's own
/// `UNARY_TIMEOUT` (30 s) bounds the wait for response headers, so this only matters for large
/// buffered streams; the gateway itself gives lightwalletd 80 s.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(100);

/// Hostname prefix that marks an endpoint as an OHTTP gateway (mirrors the Kotlin SDK).
pub const GATEWAY_HOST_PREFIX: &str = "ohttp-gateway";

/// Process-wide default client trace prefix for OHTTP connections (set once from JNI).
static DEFAULT_CLIENT_TRACE_PREFIX: OnceLock<Option<String>> = OnceLock::new();

/// Process-wide relay URL override for testing (debug builds only).
static RELAY_URL_OVERRIDE: OnceLock<Option<String>> = OnceLock::new();

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

/// Override relay URL for testing (e.g., relay-simulator). Only allowed in debug builds.
pub fn set_relay_url_override(url: Option<String>) {
    #[cfg(debug_assertions)]
    {
        let _ = RELAY_URL_OVERRIDE.set(url);
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (url, &RELAY_URL_OVERRIDE);
        tracing::warn!("set_relay_url_override called in release build (ignored)");
    }
}

/// Get the default client trace prefix.
fn get_default_client_trace_prefix() -> Option<String> {
    DEFAULT_CLIENT_TRACE_PREFIX
        .get()
        .and_then(|opt| opt.clone())
}

/// Relay URL for a given gateway host. One relay per gateway: mainnet and testnet gateways use
/// different HPKE keys, and an RFC 9458 relay has a single fixed gateway target.
///
/// Uses Fastly-hosted relays in production (temporary hostnames; final hostnames will be
/// set in COR-1830). Debug builds can override via [`set_relay_url_override`] for local testing.
pub fn relay_for(gateway_host: &str) -> Option<&'static str> {
    // Debug builds: check for override first
    #[cfg(debug_assertions)]
    {
        if let Some(Some(override_url)) = RELAY_URL_OVERRIDE.get() {
            // SAFETY: We leak the string to get a 'static lifetime. This is acceptable because
            // the override is set once at startup in debug builds only.
            return Some(Box::leak(override_url.clone().into_boxed_str()));
        }
    }

    // Production relay URLs
    match gateway_host {
        "ohttp-gateway-testnet.example" => {
            // Fastly dev relay (serves /ohttp-configs + /relay)
            Some("https://testnet-relay.example.invalid/relay")
        }
        "ohttp-gateway.example" => {
            // Fastly prod relay (serves /ohttp-configs + /relay)
            Some("https://mainnet-relay.example.invalid/relay")
        }
        _ => None,
    }
}

/// Object-safe alias for the byte stream underneath TLS (a plain TCP socket or an arti Tor
/// stream); Rust allows only one non-auto trait per `dyn`, hence the blanket supertrait.
trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncIo for T {}
type BoxedIo = Box<dyn AsyncIo>;

/// Per-attempt bound on opening one Tor stream to the relay/gateway. A healthy circuit connects
/// in a few seconds; a stuck one is cut here and retried on a FRESH isolated circuit.
const TOR_DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// Fresh-circuit attempts per Tor dial before the error surfaces to the caller.
const TOR_DIAL_ATTEMPTS: u32 = 3;

/// How the TCP leg towards the relay / gateway is opened.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Dialer {
    /// The device's own network path (the relay sees the device IP, but only ciphertext).
    Direct,
    /// Through Tor: the relay sees a Tor exit IP. Streams opened from this handle share its
    /// isolation group; callers hand in an `isolated_client()` when they want a fresh one.
    Tor(Box<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>),
}

impl Dialer {
    pub fn is_tor(&self) -> bool {
        matches!(self, Dialer::Tor(_))
    }

    async fn dial(&self, host: &str, port: u16) -> Result<BoxedIo, String> {
        match self {
            Dialer::Direct => {
                let tcp = tokio::net::TcpStream::connect((host, port))
                    .await
                    .map_err(|e| format!("connect {host}: {e}"))?;
                let _ = tcp.set_nodelay(true);
                Ok(Box::new(tcp))
            }
            Dialer::Tor(client) => {
                // arti resolves `host` at the exit relay, so no DNS leaves the device either.
                let mut last_err = String::new();
                for attempt in 1..=TOR_DIAL_ATTEMPTS {
                    let c = if attempt == 1 {
                        (**client).clone()
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
        self.client.key_config(false).await?;
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

/// Verify a signed key-configuration envelope for `gateway_host` under `profile` (network from
/// the host, pinned signing key, validity window at `now`, signature) and pick the key out of it.
/// Pure: the fetch and the cache are the caller's.
fn open_signed_keys(
    profile: &ClientProfile,
    json: &[u8],
    gateway_host: &str,
    now: u64,
) -> Result<CachedKey, String> {
    let network = profile
        .network_rule
        .network_for(gateway_host)
        .map_err(|e| e.to_string())?;
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
    body: Vec<u8>,
}

/// Why one HTTPS exchange failed.
#[derive(Debug)]
enum HttpsError {
    /// The pooled h2 connection was not ready or refused the request: nothing reached the far
    /// end, so the caller may try again (a relay POST is sealed afresh first).
    PreSend(String),
    /// Anything else (connect, TLS, read, size cap): not retried.
    Other(String),
}

impl HttpsError {
    fn into_message(self) -> String {
        match self {
            HttpsError::PreSend(m) | HttpsError::Other(m) => m,
        }
    }
}

/// Why a whole OHTTP round trip failed; the gRPC bridge maps the two differently.
#[derive(Debug)]
enum RoundTripError {
    /// Key fetch, relay, gateway or decryption failed (gRPC `UNAVAILABLE`).
    Transport(String),
    /// The decrypted answer is not a Binary HTTP response (gRPC `INTERNAL`).
    Decode(String),
}

/// The relay POST loop, free of I/O: `post` sends one sealed body to the relay and `refetch`
/// fetches the key configuration again. **Every post is sealed afresh** (a new ephemeral key,
/// so new ciphertext): the gateway answers a repeated ciphertext with 409, and the opener of
/// one sealing opens that sealing's answer only. A pre-send transport failure is retried once;
/// an outer 400 or 422 refetches the key and retries once (both classified by the shared core).
async fn run_exchange<P, PF, R, RF>(
    profile: &ClientProfile,
    mut key: KeyConfig,
    request: &BhttpRequest,
    mut post: P,
    mut refetch: R,
) -> Result<BhttpResponse, RoundTripError>
where
    P: FnMut(Vec<u8>) -> PF,
    PF: Future<Output = Result<RelayAnswer, HttpsError>>,
    R: FnMut() -> RF,
    RF: Future<Output = Result<KeyConfig, String>>,
{
    let mut attempt = 0u32;
    loop {
        let mut resent = false;
        let (opener, mut answer) = loop {
            let sealed = encapsulate_request(&key, request, &profile.encode, &profile.limits)
                .map_err(|e| RoundTripError::Transport(e.to_string()))?;
            match post(sealed.body).await {
                Ok(answer) => break (sealed.opener, answer),
                Err(HttpsError::PreSend(e)) if !resent => {
                    resent = true;
                    tracing::debug!(err = %e, "ohttp: relay post failed before send; sealing again");
                }
                Err(e) => return Err(RoundTripError::Transport(e.into_message())),
            }
        };
        let status = answer.status.as_u16();
        match complete_exchange_in_place(
            profile,
            opener,
            status,
            answer.content_type.as_deref(),
            &mut answer.body,
            attempt,
        ) {
            Ok(Completed::Response(response)) => return Ok(response),
            Ok(Completed::RefetchKeyConfig) => {
                if attempt > 0 {
                    return Err(RoundTripError::Transport(
                        "ohttp: gateway rejected request after key refresh".into(),
                    ));
                }
                tracing::warn!(
                    status,
                    "ohttp: gateway rejected request; refreshing key config"
                );
                key = refetch().await.map_err(RoundTripError::Transport)?;
                attempt += 1;
            }
            Ok(Completed::Refused { status, detail }) => {
                let code = StatusCode::from_u16(status)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| status.to_string());
                let shown: String = detail.chars().take(160).collect();
                return Err(RoundTripError::Transport(format!(
                    "relay/gateway HTTP {code}: {shown}"
                )));
            }
            Ok(Completed::WrongMediaType { content_type }) => {
                return Err(RoundTripError::Transport(format!(
                    "relay answered {content_type:?}, not message/ohttp-res"
                )));
            }
            Err(e @ (CoreError::BhttpFormat(_) | CoreError::NotAResponse)) => {
                return Err(RoundTripError::Decode(e.to_string()));
            }
            Err(e) => return Err(RoundTripError::Transport(e.to_string())),
        }
    }
}

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
    h2_pool: Mutex<HashMap<String, http2::SendRequest<Full<Bytes>>>>,
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
            if let Some(s) = pool.get(&key)
                && !s.is_closed()
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
        pool.insert(key, sender.clone());
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
    /// The caller decides, and seals afresh. The body is read through `guard`, which aborts the
    /// read at the first byte past the size cap.
    async fn https_once(
        &self,
        target: &HttpsTarget,
        method: Method,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
        mut guard: SizeGuard,
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
                match sender.send_request(req).await {
                    Ok(r) => r.map(|b| b.boxed()),
                    Err(e) => {
                        self.h2_pool.lock().await.remove(&pool_key);
                        return Err(HttpsError::PreSend(format!("h2 send {}: {e}", target.host)));
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
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| HttpsError::Other(format!("send {}: {e}", target.host)))?
                    .map(|b| b.boxed())
            }
        };
        let (parts, mut body) = resp.into_parts();
        if let Some(declared) = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            guard
                .check_declared(declared)
                .map_err(|e| HttpsError::Other(format!("read {}: {e}", target.host)))?;
        }
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame =
                frame.map_err(|e| HttpsError::Other(format!("read {}: {e}", target.host)))?;
            if let Ok(data) = frame.into_data() {
                guard
                    .push(data.len())
                    .map_err(|e| HttpsError::Other(format!("read {}: {e}", target.host)))?;
                bytes.extend_from_slice(&data);
            }
        }
        Ok(RelayAnswer {
            status: parts.status,
            content_type: parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            body: bytes,
        })
    }

    /// POST one sealed request body to the relay.
    async fn post_sealed(&self, body: Vec<u8>) -> Result<RelayAnswer, HttpsError> {
        let trace = self.client_trace.as_ref().map(|t| t.next());
        let headers = self.profile.headers.relay_post(trace.as_deref());
        self.https_once(
            &self.relay,
            Method::POST,
            &headers,
            body,
            self.profile.limits.response_guard(),
        )
        .await
    }

    async fn key_config(&self, refresh: bool) -> Result<KeyConfig, String> {
        // C-01 fix: Check cache expiry based on not_after timestamp
        {
            let mut cached = self.key_config.lock().await;
            if !refresh && let Some(k) = cached.as_ref() {
                let now = unix_now()?;
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
            // The kept key is discarded before the fetch that replaces it, so a failed fetch
            // leaves none to be used next.
            if self.profile.cache.drop_before_refetch {
                *cached = None;
            }
        }

        // C-01 fix: Fetch signed config through relay host at /ohttp-configs/signed
        // Construct target from relay host (not gateway) to avoid direct gateway access
        let signed_config_target = parse_https(
            &signed_config_url(&self.relay_url, self.profile.signed_config_url)
                .map_err(|e| e.to_string())?,
        )?;
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
                )
                .await
            {
                Ok(answer) => break answer,
                Err(HttpsError::PreSend(e)) if !resent => {
                    resent = true;
                    tracing::debug!(err = %e, "ohttp: key config fetch failed before send; retrying");
                }
                Err(e) => return Err(e.into_message()),
            }
        };
        if !self.profile.outer.success.accepts(answer.status.as_u16()) {
            return Err(format!("signed config fetch: HTTP {}", answer.status));
        }

        // C-01 fix: Verify signature and parse config
        let cfg = open_signed_keys(&self.profile, &answer.body, &self.gateway_host, unix_now()?)?;
        tracing::info!(
            gateway = %self.gateway_host,
            key_id = cfg.config.key_id(),
            not_after = cfg.not_after,
            via_tor = self.dialer.is_tor(),
            "ohttp: signed key config loaded and verified"
        );
        *self.key_config.lock().await = Some(cfg);
        Ok(cfg.config)
    }

    /// Encapsulate + relay + decapsulate (see [`run_exchange`]). The key configuration is
    /// fetched again, and the request sealed again, when the gateway rejects the request (outer
    /// 400 or 422), which is what key rotation looks like from here.
    async fn round_trip(&self, request: &BhttpRequest) -> Result<BhttpResponse, RoundTripError> {
        let key = self
            .key_config(false)
            .await
            .map_err(RoundTripError::Transport)?;
        let this = self;
        run_exchange(
            &self.profile,
            key,
            request,
            move |body| this.post_sealed(body),
            move || this.key_config(true),
        )
        .await
    }

    /// In-process h2 handler: one gRPC request in, one gRPC response (with trailers) out.
    async fn handle(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, Infallible>> {
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
        let response =
            match tokio::time::timeout(ROUND_TRIP_TIMEOUT, self.round_trip(&request)).await {
                Ok(Ok(r)) => r,
                Ok(Err(RoundTripError::Decode(e))) => {
                    return grpc_error(GRPC_INTERNAL, &format!("bhttp decode: {e}"));
                }
                Ok(Err(RoundTripError::Transport(e))) => {
                    tracing::warn!(path = %path, err = %e, "ohttp: round trip failed");
                    return grpc_error(GRPC_UNAVAILABLE, &format!("ohttp: {e}"));
                }
                Err(_) => {
                    tracing::warn!(path = %path, "ohttp: round trip timed out");
                    return grpc_error(GRPC_UNAVAILABLE, "ohttp: round trip timed out");
                }
            };

        let (http_status, headers, trailers) = grpc_parts(&response);
        tracing::debug!(
            path = %path,
            http_status,
            grpc_status = ?trailers.get("grpc-status"),
            bytes = response.body.len(),
            ms = started.elapsed().as_millis() as u64,
            "ohttp: rpc complete"
        );

        let content = Bytes::from(response.body);
        let mut frames: Vec<Result<Frame<Bytes>, Infallible>> = Vec::with_capacity(2);
        if !content.is_empty() {
            frames.push(Ok(Frame::data(content)));
        }
        frames.push(Ok(Frame::trailers(trailers)));
        let body = StreamBody::new(futures_util::stream::iter(frames)).boxed();

        let mut resp = Response::new(body);
        *resp.status_mut() = StatusCode::from_u16(http_status).unwrap_or(StatusCode::OK);
        *resp.headers_mut() = headers;
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

/// The gRPC view of a decoded gateway response: HTTP status, HTTP/2 headers (`content-type` and
/// `date` only) and trailers (the `grpc-*` fields the gateway folded into the header section;
/// the Binary HTTP trailer section is not read). A missing `grpc-status` becomes INTERNAL.
fn grpc_parts(response: &BhttpResponse) -> (u16, HeaderMap, HeaderMap) {
    let mut headers = HeaderMap::new();
    let mut trailers = HeaderMap::new();
    for (field_name, field_value) in &response.headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(field_name),
            HeaderValue::from_bytes(field_value),
        ) else {
            continue;
        };
        if name.as_str().starts_with("grpc-") {
            trailers.insert(name, value);
        } else if name == header::CONTENT_TYPE || name == header::DATE {
            headers.insert(name, value);
        }
    }
    if !trailers.contains_key("grpc-status") {
        trailers.insert("grpc-status", HeaderValue::from_static("13"));
        trailers.insert(
            "grpc-message",
            HeaderValue::from_static("ohttp: gateway response without grpc-status"),
        );
    }
    if !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
    }
    (response.status, headers, trailers)
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
/// * `dialer` - How to reach the relay: `Dialer::Direct` or `Dialer::Tor(_)`
/// * `method` - HTTP method (e.g., "GET", "POST")
/// * `url` - Full target URL (e.g., "<https://voting.valargroup.dev/api/vote>")
/// * `headers` - Request headers as (name, value) pairs
/// * `body` - Request body bytes
///
/// # Returns
/// `Ok((status, headers, body))` on success, or `Err(msg)` on failure.
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
pub async fn http_round_trip(
    gateway_host: &str,
    dialer: Dialer,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    // Parse URL to extract scheme, host, path for BHTTP encoding
    let target = parse_http_target(url)?;

    // Get relay URL for this gateway
    let relay_url = relay_for(gateway_host)
        .ok_or_else(|| format!("no relay configured for gateway {}", gateway_host))?;

    http_round_trip_via(
        relay_url,
        gateway_host,
        dialer,
        method,
        target,
        headers,
        body,
    )
    .await
}

/// [`http_round_trip`] against an explicit relay URL (the body of the public function, so a
/// test can point it at a local relay without touching the process-wide relay table).
async fn http_round_trip_via(
    relay_url: &str,
    gateway_host: &str,
    dialer: Dialer,
    method: &str,
    target: HttpTarget,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    // Create OHTTP client
    let client = OhttpClient::new(
        gateway_host,
        relay_url,
        dialer,
        get_default_client_trace_prefix(),
        ClientProfile::SLIPSTREAM_HTTP,
    )?;

    // HTTP request as Binary HTTP (RFC 9292): the URL's scheme, header names as given
    let mut request = BhttpRequest::new(method, target.host, target.path)
        .scheme(target.scheme)
        .body(body);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }

    // Send through OHTTP relay (encapsulate, POST, decapsulate)
    let response = client.round_trip(&request).await.map_err(|e| match e {
        RoundTripError::Transport(e) => e,
        RoundTripError::Decode(e) => format!("bhttp decode: {e}"),
    })?;

    // Headers as lossy UTF-8 text; the trailer section is not read
    let response_headers = response.headers_utf8_lossy();
    Ok((response.status, response_headers, response.body))
}

const GRPC_UNAVAILABLE: &str = "14";
const GRPC_INTERNAL: &str = "13";

/// gRPC "trailers-only" error response: status in the headers, empty body. tonic surfaces it as
/// a `Status` with that code, which this crate's retry logic already treats as transient for
/// `UNAVAILABLE`.
fn grpc_error(code: &'static str, message: &str) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(Full::new(Bytes::new()).boxed());
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/grpc"),
    );
    h.insert("grpc-status", HeaderValue::from_static(code));
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
    use zodl_ohttp_client::encode_bhttp_request;

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
            content_type: None,
            body: b"nope".to_vec(),
        }
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

    #[test]
    fn grpc_response_fields_are_split_into_headers_and_trailers() {
        let response = BhttpResponse {
            status: 200,
            informational: Vec::new(),
            headers: vec![
                (b"content-type".to_vec(), b"application/grpc".to_vec()),
                (b"grpc-status".to_vec(), b"0".to_vec()),
                (b"x-other".to_vec(), b"y".to_vec()),
            ],
            body: Vec::new(),
            // The Binary HTTP trailer section is not read.
            trailers: vec![(b"grpc-message".to_vec(), b"ignored".to_vec())],
        };
        let (status, headers, trailers) = grpc_parts(&response);
        assert_eq!(status, 200);
        assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        assert!(headers.get("x-other").is_none());
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
        assert!(trailers.get("grpc-message").is_none());
    }

    #[test]
    fn a_response_without_grpc_status_is_internal() {
        let response = BhttpResponse {
            status: 502,
            informational: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let (status, headers, trailers) = grpc_parts(&response);
        assert_eq!(status, 502);
        assert_eq!(headers.get("content-type").unwrap(), "application/grpc");
        assert_eq!(trailers.get("grpc-status").unwrap(), "13");
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
                async { Err::<RelayAnswer, _>(HttpsError::PreSend("h2 send: closed".into())) }
            },
            || async { Err::<KeyConfig, String>("unexpected refetch".into()) },
        )
        .await;
        let Err(RoundTripError::Transport(message)) = result else {
            panic!("expected a transport error, got {result:?}");
        };
        assert!(message.contains("h2 send"), "got: {message}");
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
            || async { Err::<KeyConfig, String>("unexpected refetch".into()) },
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
                    async { Ok::<KeyConfig, String>(test_key()) }
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
                || async { Err::<KeyConfig, String>("unexpected refetch".into()) },
            )
            .await;
            let Err(RoundTripError::Transport(message)) = result else {
                panic!("expected a transport error, got {result:?}");
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
                    content_type: Some("message/ohttp-res".into()),
                    body: vec![7; 64],
                })
            },
            || async { Err::<KeyConfig, String>("unexpected refetch".into()) },
        )
        .await;
        assert!(matches!(result, Err(RoundTripError::Transport(_))));
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
        let err = result.expect_err("a fake relay cannot complete the exchange");
        assert!(
            err.contains("127.0.0.1"),
            "error must name the relay: {err}"
        );
        assert!(
            !err.contains("origin.invalid"),
            "the origin must never be contacted: {err}"
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

        // Testnet signed config via relay-simulator
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

        // Mainnet signed config via relay-simulator
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
}
