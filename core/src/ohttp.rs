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
//! Wire format is RFC 9458 §4.3/§4.4 with the suite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//! AES-128-GCM; the gateway folds the gRPC trailers into the Binary HTTP header section and this
//! module moves them back into HTTP/2 trailers.
//!
//! **Tor.** The TCP leg to the relay (and the one-off `/ohttp-configs` key fetch from the gateway)
//! is opened through a [`Dialer`]: [`Dialer::Direct`] uses the device's own connection,
//! [`Dialer::Tor`] opens an arti stream so the relay only ever sees a Tor exit IP. Everything
//! above TCP (TLS to the relay, HPKE to the gateway) is identical in both cases.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io::Cursor,
    pin::Pin,
    sync::Arc,
    sync::OnceLock,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite};

use aes_gcm::{
    Aes128Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use bytes::Bytes;
use hkdf::Hkdf;
use hpke::{
    Deserializable, Kem, OpModeS, Serializable, aead::AesGcm128, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header,
};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand_core::{OsRng, TryRngCore};
use sha2::Sha256;
use tokio::io::DuplexStream;
use tokio::sync::Mutex;
use tower_service::Service;

type OhttpKem = X25519HkdfSha256;
type OhttpKdf = HkdfSha256;
type OhttpAead = AesGcm128;

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;
const N_K: usize = 16; // AES-128-GCM key
const N_N: usize = 12; // AES-GCM nonce
const N_T: usize = 16; // AES-GCM tag
const N_ENC: usize = 32; // X25519 encapsulated key
const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";

/// In-memory pipe capacity between tonic and the in-process h2 server.
const DUPLEX_BUF: usize = 4 << 20;
/// Whole OHTTP round trip (encapsulate → relay → gateway → lightwalletd → back). The engine's own
/// `UNARY_TIMEOUT` (30 s) bounds the wait for response headers, so this only matters for large
/// buffered streams; the gateway itself gives lightwalletd 80 s.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(100);
const USER_AGENT: &str = "zodl-slipstream-ohttp/0.1";

/// Hostname prefix that marks an endpoint as an OHTTP gateway (mirrors the Kotlin SDK).
pub const GATEWAY_HOST_PREFIX: &str = "ohttp-gateway";

/// Process-wide default client trace prefix for OHTTP connections (set once from JNI).
static DEFAULT_CLIENT_TRACE_PREFIX: OnceLock<Option<String>> = OnceLock::new();

/// Set the default client trace prefix for all OHTTP connections without an explicit prefix.
/// Called from JNI when TorRuntime is created.
pub fn set_default_client_trace_prefix(prefix: Option<String>) {
    let _ = DEFAULT_CLIENT_TRACE_PREFIX.set(prefix);
}

/// Get the default client trace prefix.
fn get_default_client_trace_prefix() -> Option<String> {
    DEFAULT_CLIENT_TRACE_PREFIX
        .get()
        .and_then(|opt| opt.clone())
}

/// Relay URL for a given gateway host. One relay per gateway: mainnet and testnet gateways use
/// different HPKE keys, and an RFC 9458 relay has a single fixed gateway target.
pub fn relay_for(gateway_host: &str) -> Option<&'static str> {
    match gateway_host {
        "ohttp-gateway-testnet.example" => Some("https://testnet-simulator-relay.example.invalid/relay"),
        "ohttp-gateway.example" => Some("https://simulator-relay.example.invalid/relay"),
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

/// One HPKE key configuration from an `application/ohttp-keys` document (RFC 9458 §3.1).
#[derive(Clone, Debug)]
struct KeyConfig {
    key_id: u8,
    public_key: [u8; 32],
}

impl KeyConfig {
    /// `hdr = key_id || kem_id || kdf_id || aead_id`
    fn header(&self) -> [u8; 7] {
        let [k0, k1] = KEM_ID.to_be_bytes();
        let [d0, d1] = KDF_ID.to_be_bytes();
        let [a0, a1] = AEAD_ID.to_be_bytes();
        [self.key_id, k0, k1, d0, d1, a0, a1]
    }

    /// First key config in the document that offers our suite.
    fn parse_supported(doc: &[u8]) -> Result<Self, String> {
        let mut pos = 0usize;
        let rd_u8 = |pos: &mut usize| -> Result<u8, String> {
            let b = *doc.get(*pos).ok_or("truncated key config")?;
            *pos += 1;
            Ok(b)
        };
        let rd_u16 = |pos: &mut usize| -> Result<u16, String> {
            let hi = *doc.get(*pos).ok_or("truncated key config")?;
            let lo = *doc.get(*pos + 1).ok_or("truncated key config")?;
            *pos += 2;
            Ok(u16::from_be_bytes([hi, lo]))
        };
        while pos + 2 <= doc.len() {
            let len = rd_u16(&mut pos)? as usize;
            let end = pos + len;
            if end > doc.len() {
                return Err("truncated key config entry".into());
            }
            let key_id = rd_u8(&mut pos)?;
            let kem_id = rd_u16(&mut pos)?;
            if kem_id != KEM_ID {
                pos = end;
                continue;
            }
            let pk_end = pos + N_ENC;
            if pk_end > end {
                return Err("truncated public key".into());
            }
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&doc[pos..pk_end]);
            pos = pk_end;
            let suites_len = rd_u16(&mut pos)? as usize;
            let suites_end = pos + suites_len;
            if suites_end > end {
                return Err("truncated symmetric suites".into());
            }
            while pos + 4 <= suites_end {
                let kdf = rd_u16(&mut pos)?;
                let aead = rd_u16(&mut pos)?;
                if kdf == KDF_ID && aead == AEAD_ID {
                    return Ok(Self { key_id, public_key });
                }
            }
            pos = end;
        }
        Err("no supported HPKE suite in OHTTP key configuration".into())
    }
}

/// Client-side state needed to decrypt one response (RFC 9458 §4.4).
struct ResponseContext {
    enc: Vec<u8>,
    secret: [u8; N_K],
}

impl ResponseContext {
    fn decapsulate(&self, enc_response: &[u8]) -> Result<Vec<u8>, String> {
        let nonce_len = N_N.max(N_K);
        if enc_response.len() < nonce_len + N_T {
            return Err(format!(
                "OHTTP response too short ({} bytes)",
                enc_response.len()
            ));
        }
        let (response_nonce, ct) = enc_response.split_at(nonce_len);
        let mut salt = self.enc.clone();
        salt.extend_from_slice(response_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.secret);
        let mut key = [0u8; N_K];
        hk.expand(b"key", &mut key).map_err(|_| "hkdf expand key")?;
        let mut nonce = [0u8; N_N];
        hk.expand(b"nonce", &mut nonce)
            .map_err(|_| "hkdf expand nonce")?;
        Aes128Gcm::new_from_slice(&key)
            .map_err(|_| "aead key")?
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: b"" })
            .map_err(|_| "OHTTP response authentication failed".to_string())
    }
}

/// RFC 9458 §4.3 — encapsulate a Binary HTTP request. Returns `hdr || enc || ct` and the
/// context for the matching response.
fn encapsulate(key: &KeyConfig, plaintext: &[u8]) -> Result<(Vec<u8>, ResponseContext), String> {
    let hdr = key.header();
    let mut info = Vec::with_capacity(REQUEST_LABEL.len() + 1 + hdr.len());
    info.extend_from_slice(REQUEST_LABEL);
    info.push(0x00);
    info.extend_from_slice(&hdr);

    let pk = <OhttpKem as Kem>::PublicKey::from_bytes(&key.public_key)
        .map_err(|e| format!("invalid gateway public key: {e:?}"))?;
    let mut rng = OsRng.unwrap_err();
    let (encapped, mut ctx) = hpke::setup_sender::<OhttpAead, OhttpKdf, OhttpKem, _>(
        &OpModeS::Base,
        &pk,
        &info,
        &mut rng,
    )
    .map_err(|e| format!("hpke setup_sender: {e:?}"))?;
    let ct = ctx
        .seal(plaintext, b"")
        .map_err(|e| format!("hpke seal: {e:?}"))?;
    let mut secret = [0u8; N_K];
    ctx.export(RESPONSE_LABEL, &mut secret)
        .map_err(|e| format!("hpke export: {e:?}"))?;

    let enc = encapped.to_bytes().to_vec();
    let mut out = Vec::with_capacity(hdr.len() + enc.len() + ct.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok((out, ResponseContext { enc, secret }))
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

struct OhttpClient {
    gateway_host: String,
    relay: HttpsTarget,
    keys: HttpsTarget,
    key_config: Mutex<Option<KeyConfig>>,
    tls: Arc<rustls::ClientConfig>,
    dialer: Dialer,
    /// One multiplexed HTTP/2 connection per `host:port`, shared by all concurrent RPCs. Opening a
    /// TCP+TLS connection per call is both slow and, on the Android emulator's user-mode network
    /// stack, a reliable way to crash qemu under connection churn. Over Tor this matters even
    /// more: every new connection would be a new circuit build.
    h2_pool: Mutex<HashMap<String, http2::SendRequest<Full<Bytes>>>>,
    /// Optional client trace ID generator. When set, every relay POST carries X-Client-Trace-Id.
    client_trace: Option<client_trace::ClientTrace>,
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
            relay: parse_https(relay_url)?,
            keys: parse_https(&format!("https://{gateway_host}/ohttp-configs"))?,
            key_config: Mutex::new(None),
            tls: Arc::new(tls),
            dialer,
            h2_pool: Mutex::new(HashMap::new()),
            client_trace: client_trace_prefix.map(|p| client_trace::ClientTrace::new(&p)),
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
        content_type: Option<&str>,
        accept: &str,
        body: Vec<u8>,
    ) -> Result<Request<Full<Bytes>>, String> {
        let uri = format!("https://{}:{}{}", target.host, target.port, target.path);
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, &target.host)
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, accept)
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        // Add client trace ID to relay POSTs only (not key config fetches)
        if content_type == Some("message/ohttp-req")
            && let Some(ref trace) = self.client_trace
        {
            req = req.header("X-Client-Trace-Id", trace.next());
        }
        req.body(Full::new(Bytes::from(body)))
            .map_err(|e| format!("build request: {e}"))
    }

    /// One HTTPS exchange: multiplexed over the pooled h2 connection when available, otherwise a
    /// fresh HTTP/1.1 connection. A stale pooled connection is dropped and retried once.
    async fn https(
        &self,
        target: &HttpsTarget,
        method: Method,
        content_type: Option<&str>,
        accept: &str,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Bytes), String> {
        for attempt in 0..2 {
            let req =
                self.build_request(target, method.clone(), content_type, accept, body.clone())?;
            let resp = match self.h2_sender(target).await? {
                Some(mut sender) => {
                    if let Err(e) = sender.ready().await {
                        self.h2_pool
                            .lock()
                            .await
                            .remove(&format!("{}:{}", target.host, target.port));
                        if attempt == 0 {
                            tracing::debug!(err = %e, "ohttp: pooled h2 not ready; reconnecting");
                            continue;
                        }
                        return Err(format!("h2 ready {}: {e}", target.host));
                    }
                    match sender.send_request(req).await {
                        Ok(r) => r.map(|b| b.boxed()),
                        Err(e) => {
                            self.h2_pool
                                .lock()
                                .await
                                .remove(&format!("{}:{}", target.host, target.port));
                            if attempt == 0 {
                                tracing::debug!(err = %e, "ohttp: h2 send failed; reconnecting");
                                continue;
                            }
                            return Err(format!("h2 send {}: {e}", target.host));
                        }
                    }
                }
                None => {
                    let (tls, _) = self.tls_connect(target).await?;
                    let (mut sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(tls))
                            .await
                            .map_err(|e| format!("http1 handshake: {e}"))?;
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    sender
                        .send_request(req)
                        .await
                        .map_err(|e| format!("send {}: {e}", target.host))?
                        .map(|b| b.boxed())
                }
            };
            let status = resp.status();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| format!("read {}: {e}", target.host))?
                .to_bytes();
            return Ok((status, bytes));
        }
        Err(format!("https {}: retries exhausted", target.host))
    }

    async fn key_config(&self, refresh: bool) -> Result<KeyConfig, String> {
        if !refresh && let Some(k) = self.key_config.lock().await.as_ref() {
            return Ok(k.clone());
        }
        let (status, doc) = self
            .https(
                &self.keys,
                Method::GET,
                None,
                "application/ohttp-keys",
                Vec::new(),
            )
            .await?;
        if status != StatusCode::OK {
            return Err(format!("key config fetch: HTTP {status}"));
        }
        let cfg = KeyConfig::parse_supported(&doc)?;
        tracing::info!(gateway = %self.gateway_host, key_id = cfg.key_id, via_tor = self.dialer.is_tor(), "ohttp: key config loaded");
        *self.key_config.lock().await = Some(cfg.clone());
        Ok(cfg)
    }

    /// Encapsulate + relay + decapsulate. Retries once with a fresh key config when the gateway
    /// rejects the request (HTTP 400), which is what key rotation looks like from here.
    async fn round_trip(&self, bhttp_request: &[u8]) -> Result<Vec<u8>, String> {
        let mut key = self.key_config(false).await?;
        for attempt in 0..2 {
            let (enc_req, ctx) = encapsulate(&key, bhttp_request)?;
            let (status, body) = self
                .https(
                    &self.relay,
                    Method::POST,
                    Some("message/ohttp-req"),
                    "message/ohttp-res",
                    enc_req,
                )
                .await?;
            match status {
                StatusCode::OK => return ctx.decapsulate(&body),
                StatusCode::BAD_REQUEST if attempt == 0 => {
                    tracing::warn!(
                        detail = %String::from_utf8_lossy(&body[..body.len().min(160)]),
                        "ohttp: gateway rejected request; refreshing key config"
                    );
                    key = self.key_config(true).await?;
                }
                other => {
                    return Err(format!(
                        "relay/gateway HTTP {other}: {}",
                        String::from_utf8_lossy(&body[..body.len().min(160)])
                    ));
                }
            }
        }
        Err("ohttp: gateway rejected request after key refresh".into())
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

        let mut msg = bhttp::Message::request(
            parts.method.as_str().as_bytes().to_vec(),
            b"https".to_vec(),
            self.gateway_host.as_bytes().to_vec(),
            path.as_bytes().to_vec(),
        );
        for (name, value) in &parts.headers {
            if forward_header(name) {
                msg.put_header(name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec());
            }
        }
        msg.write_content(&body);
        let mut plaintext = Vec::with_capacity(body.len() + 256);
        if let Err(e) = msg.write_bhttp(bhttp::Mode::KnownLength, &mut plaintext) {
            return grpc_error(GRPC_INTERNAL, &format!("bhttp encode: {e:?}"));
        }

        let started = std::time::Instant::now();
        let response =
            match tokio::time::timeout(ROUND_TRIP_TIMEOUT, self.round_trip(&plaintext)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::warn!(path = %path, err = %e, "ohttp: round trip failed");
                    return grpc_error(GRPC_UNAVAILABLE, &format!("ohttp: {e}"));
                }
                Err(_) => {
                    tracing::warn!(path = %path, "ohttp: round trip timed out");
                    return grpc_error(GRPC_UNAVAILABLE, "ohttp: round trip timed out");
                }
            };

        let msg = match bhttp::Message::read_bhttp::<_, Cursor<Vec<u8>>>(&mut Cursor::new(response))
        {
            Ok(m) => m,
            Err(e) => return grpc_error(GRPC_INTERNAL, &format!("bhttp decode: {e:?}")),
        };
        let http_status = msg.control().status().map(|s| s.code()).unwrap_or(200);
        let mut headers = HeaderMap::new();
        let mut trailers = HeaderMap::new();
        for field in msg.header().iter() {
            let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(field.name()),
                HeaderValue::from_bytes(field.value()),
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
        tracing::debug!(
            path = %path,
            http_status,
            grpc_status = ?trailers.get("grpc-status"),
            bytes = msg.content().len(),
            ms = started.elapsed().as_millis() as u64,
            "ohttp: rpc complete"
        );

        let content = Bytes::copy_from_slice(msg.content());
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

    #[test]
    fn parses_rfc9458_key_config_document() {
        // Length(41) || key_id=1 || kem=0x0020 || pk[32] || suites_len=4 || kdf=1 || aead=1
        let mut doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        doc.extend_from_slice(&[0xAB; 32]);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);
        let cfg = KeyConfig::parse_supported(&doc).expect("parse");
        assert_eq!(cfg.key_id, 1);
        assert_eq!(cfg.public_key, [0xAB; 32]);
        assert_eq!(cfg.header(), [1, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn rejects_unsupported_suite() {
        let mut doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        doc.extend_from_slice(&[0x01; 32]);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x00, 0x03]);
        assert!(KeyConfig::parse_supported(&doc).is_err());
    }

    #[test]
    fn relay_mapping_covers_both_gateways() {
        assert!(relay_for("ohttp-gateway-testnet.example").is_some());
        assert!(relay_for("ohttp-gateway.example").is_some());
        assert!(relay_for("zec.rocks").is_none());
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

/// Client trace ID generator for debug request tracking (Rust side, bulk sync path).
/// Format: `<prefix>-<sessionUuid>-<seq>` where seq is zero-padded 6 digits, total ≤ 64 chars.
/// The session UUID is generated once when the generator is created.
mod client_trace {
    use std::sync::atomic::{AtomicU64, Ordering};
    use uuid::Uuid;

    pub struct ClientTrace {
        prefix: String,
        session_uuid: Uuid,
        counter: AtomicU64,
    }

    impl ClientTrace {
        pub fn new(prefix: &str) -> Self {
            let sanitized = sanitize_prefix(prefix);
            Self {
                prefix: sanitized,
                session_uuid: Uuid::new_v4(),
                counter: AtomicU64::new(0),
            }
        }

        pub fn next(&self) -> String {
            let seq = self.counter.fetch_add(1, Ordering::Relaxed);
            let full = format!("{}-{}-{:06}", self.prefix, self.session_uuid, seq);
            if full.len() <= 64 {
                full
            } else {
                full[..64].to_string()
            }
        }
    }

    fn sanitize_prefix(prefix: &str) -> String {
        // Keep only [A-Za-z0-9._:-], ensure first char is alphanumeric
        let cleaned: String = prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
            .collect();
        if cleaned.is_empty() {
            return "trace".to_string();
        }
        if cleaned.chars().next().unwrap().is_ascii_alphanumeric() {
            cleaned
        } else {
            // Drop leading non-alphanumeric
            let result: String = cleaned
                .chars()
                .skip_while(|c| !c.is_ascii_alphanumeric())
                .collect();
            if result.is_empty() {
                "trace".to_string()
            } else {
                result
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_sanitize_prefix() {
            assert_eq!(sanitize_prefix("test-wallet"), "test-wallet");
            assert_eq!(sanitize_prefix("test@wallet#123"), "testwallet123");
            assert_eq!(sanitize_prefix("___abc"), "abc");
            assert_eq!(sanitize_prefix(""), "trace");
            assert_eq!(sanitize_prefix("___"), "trace");
        }

        #[test]
        fn test_trace_format() {
            let trace = ClientTrace::new("yassi");
            let id1 = trace.next();
            let id2 = trace.next();
            // Format: yassi-<uuid>-000000
            assert!(id1.starts_with("yassi-"));
            assert!(id1.len() <= 64);
            // Sequence must increment
            let parts1: Vec<&str> = id1.rsplitn(2, '-').collect();
            let parts2: Vec<&str> = id2.rsplitn(2, '-').collect();
            assert_eq!(parts1[0], "000000");
            assert_eq!(parts2[0], "000001");
        }

        #[test]
        fn test_truncation() {
            let long_prefix = "a".repeat(60);
            let trace = ClientTrace::new(&long_prefix);
            let id = trace.next();
            assert_eq!(id.len(), 64);
        }
    }
}
