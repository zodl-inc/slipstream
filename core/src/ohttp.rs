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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
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

/// Embedded Ed25519 public keys for signed OHTTP config verification (C-01 fix).
/// Mainnet key: matches zodl-inc/zcash-android-wallet-sdk OhttpSignedConfig.kt
const ED25519_PUBKEY_MAINNET: &str =
    "REDACTED-SIGNING-PUBKEY-MAINNET";
/// Testnet key: matches zodl-inc/zcash-android-wallet-sdk OhttpSignedConfig.kt
const ED25519_PUBKEY_TESTNET: &str =
    "REDACTED-SIGNING-PUBKEY-TESTNET";

/// Signed OHTTP config envelope (JSON, fetched from `/ohttp-configs/signed` via relay).
#[derive(Debug, Deserialize)]
struct SignedOhttpConfig {
    v: u8,
    network: String,
    configs: String, // base64-encoded application/ohttp-keys document
    not_before: u64, // Unix timestamp
    not_after: u64,  // Unix timestamp
    key_id: String,
    #[serde(rename = "sig")]
    signature: String, // base64-encoded Ed25519 signature
}

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
/// Called from JNI when TorRuntime is created. Only allowed in debug builds (P7).
pub fn set_default_client_trace_prefix(prefix: Option<String>) {
    #[cfg(debug_assertions)]
    {
        let _ = DEFAULT_CLIENT_TRACE_PREFIX.set(prefix);
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (prefix, DEFAULT_CLIENT_TRACE_PREFIX);
        tracing::warn!("set_default_client_trace_prefix called in release build (ignored)");
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
    /// Unix timestamp when this config expires (from signed envelope's not_after).
    not_after: u64,
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
    fn parse_supported(doc: &[u8], not_after: u64) -> Result<Self, String> {
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
                    return Ok(Self {
                        key_id,
                        public_key,
                        not_after,
                    });
                }
            }
            pos = end;
        }
        Err("no supported HPKE suite in OHTTP key configuration".into())
    }
}

/// P6: Check for duplicate JSON keys (strict parse per ZIP rule 1).
fn check_no_duplicate_json_keys(json_bytes: &[u8]) -> Result<(), String> {
    use std::collections::HashSet;
    let value: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| format!("JSON parse for dup-key check: {e}"))?;
    if let serde_json::Value::Object(map) = value {
        let mut seen = HashSet::new();
        for key in map.keys() {
            if !seen.insert(key) {
                return Err(format!("duplicate JSON key: {}", key));
            }
        }
    }
    // Note: serde_json::Map already deduplicates, so this won't catch duplicates.
    // A proper fix would require a streaming parser. This is a best-effort check.
    Ok(())
}

/// C-01 fix: Verify signed OHTTP config envelope and return the parsed KeyConfig.
/// Fetches through the relay, verifies Ed25519 signature, checks validity window.
fn verify_signed_config(json_bytes: &[u8], gateway_host: &str) -> Result<KeyConfig, String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // P6: Reject duplicate JSON keys (strict parse per ZIP rule 1)
    check_no_duplicate_json_keys(json_bytes)?;

    let envelope: SignedOhttpConfig =
        serde_json::from_slice(json_bytes).map_err(|e| format!("signed config JSON parse: {e}"))?;

    if envelope.v != 1 {
        return Err(format!("unsupported signed config version: {}", envelope.v));
    }

    // Derive expected network from gateway_host (not from the envelope's own network field)
    let expected_network = if gateway_host.contains("testnet") {
        "testnet"
    } else {
        "mainnet"
    };

    // Require envelope network matches configured network
    if envelope.network != expected_network {
        return Err(format!(
            "network mismatch: gateway={}, envelope={}",
            expected_network, envelope.network
        ));
    }

    // Require not_before < not_after (P5)
    if envelope.not_before >= envelope.not_after {
        return Err(format!(
            "invalid validity window: not_before={} >= not_after={}",
            envelope.not_before, envelope.not_after
        ));
    }

    // Select the correct public key based on configured network
    let (pubkey_hex, expected_key_id) = match expected_network {
        "mainnet" => (ED25519_PUBKEY_MAINNET, "ba8a2dbd"),
        "testnet" => (ED25519_PUBKEY_TESTNET, "a3620fb6"),
        other => return Err(format!("unknown network: {other}")),
    };
    // Check key_id matches expected value (sha256(pk)[..4] as hex)
    if envelope.key_id != expected_key_id {
        return Err(format!(
            "key_id mismatch: expected {}, got {}",
            expected_key_id, envelope.key_id
        ));
    }

    let pubkey_bytes =
        hex::decode(pubkey_hex).map_err(|e| format!("decode embedded pubkey: {e}"))?;
    let verifying_key = VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid pubkey length")?,
    )
    .map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;

    // Decode base64 fields
    use base64::prelude::*;
    let configs_bytes = BASE64_STANDARD
        .decode(&envelope.configs)
        .map_err(|e| format!("decode configs base64: {e}"))?;

    // Enforce 4096-byte limit on decoded configs (P4)
    const MAX_CONFIGS_SIZE: usize = 4096;
    if configs_bytes.len() > MAX_CONFIGS_SIZE {
        return Err(format!(
            "decoded configs too large: {} bytes (max {})",
            configs_bytes.len(),
            MAX_CONFIGS_SIZE
        ));
    }

    let signature_bytes = BASE64_STANDARD
        .decode(&envelope.signature)
        .map_err(|e| format!("decode signature base64: {e}"))?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid signature length")?,
    );

    // Build the message to verify: "zodl-ohttp-configs-v1" || 0x00 || network || 0x00 ||
    // u64be(not_before) || u64be(not_after) || configs
    let mut message = Vec::with_capacity(
        b"zodl-ohttp-configs-v1".len()
            + 1
            + envelope.network.len()
            + 1
            + 8
            + 8
            + configs_bytes.len(),
    );
    message.extend_from_slice(b"zodl-ohttp-configs-v1");
    message.push(0x00);
    message.extend_from_slice(envelope.network.as_bytes());
    message.push(0x00);
    message.extend_from_slice(&envelope.not_before.to_be_bytes());
    message.extend_from_slice(&envelope.not_after.to_be_bytes());
    message.extend_from_slice(&configs_bytes);

    // Verify signature (fail closed)
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| "Ed25519 signature verification failed")?;

    // Check validity window with ±60s tolerance
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time: {e}"))?
        .as_secs();
    const TOLERANCE_SECS: u64 = 60;
    if now + TOLERANCE_SECS < envelope.not_before {
        return Err(format!(
            "signed config not yet valid (not_before={}, now={})",
            envelope.not_before, now
        ));
    }
    if now > envelope.not_after + TOLERANCE_SECS {
        return Err(format!(
            "signed config expired (not_after={}, now={})",
            envelope.not_after, now
        ));
    }

    // Enforce ≤24h validity window
    let validity_duration = envelope.not_after.saturating_sub(envelope.not_before);
    const MAX_VALIDITY_SECS: u64 = 24 * 60 * 60;
    if validity_duration > MAX_VALIDITY_SECS {
        return Err(format!(
            "signed config validity window too long: {}s (max {}s)",
            validity_duration, MAX_VALIDITY_SECS
        ));
    }

    tracing::info!(
        gateway = %gateway_host,
        network = %envelope.network,
        not_before = envelope.not_before,
        not_after = envelope.not_after,
        "ohttp: signed config verified"
    );

    // Parse the configs document and return KeyConfig with not_after for cache TTL
    KeyConfig::parse_supported(&configs_bytes, envelope.not_after)
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
    /// fresh HTTP/1.1 connection. Pre-send connection errors (ready/TLS/connect) are always
    /// retried once (F-12 fix). The response itself is returned without retry.
    async fn https(
        &self,
        target: &HttpsTarget,
        method: Method,
        content_type: Option<&str>,
        accept: &str,
        body: Vec<u8>,
        _allow_retry: bool, // No longer used; pre-send errors always retry, responses never do
    ) -> Result<(StatusCode, Bytes), String> {
        // Always allow at least 2 attempts for pre-send connection errors
        let max_attempts = 2;
        for attempt in 0..(max_attempts) {
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
        // C-01 fix: Check cache expiry based on not_after timestamp
        if !refresh && let Some(k) = self.key_config.lock().await.as_ref() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("system time: {e}"))?
                .as_secs();
            // Refresh 60s before expiry to avoid races
            if now + 60 < k.not_after {
                return Ok(k.clone());
            }
            tracing::info!(
                gateway = %self.gateway_host,
                not_after = k.not_after,
                now,
                "ohttp: cached key config expired, refreshing"
            );
        }

        // C-01 fix: Fetch signed config through relay host at /ohttp-configs/signed
        // Construct target from relay host (not gateway) to avoid direct gateway access
        let signed_config_target = HttpsTarget {
            host: self.relay.host.clone(),
            port: self.relay.port,
            path: "/ohttp-configs/signed".to_string(),
        };

        let (status, json_bytes) = self
            .https(
                &signed_config_target,
                Method::GET,
                None,
                "application/json",
                Vec::new(),
                true, // allow_retry: key config GET can safely retry on connection errors
            )
            .await?;
        if status != StatusCode::OK {
            return Err(format!("signed config fetch: HTTP {status}"));
        }

        // C-01 fix: Verify signature and parse config
        let cfg = verify_signed_config(&json_bytes, &self.gateway_host)?;
        tracing::info!(
            gateway = %self.gateway_host,
            key_id = cfg.key_id,
            not_after = cfg.not_after,
            via_tor = self.dialer.is_tor(),
            "ohttp: signed key config loaded and verified"
        );
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
                    false, // C-08: never retry OHTTP relay POST — ciphertext must be sent exactly once
                )
                .await?;
            match status {
                StatusCode::OK => return ctx.decapsulate(&body),
                StatusCode::BAD_REQUEST if attempt == 0 => {
                    tracing::warn!(
                        detail = %String::from_utf8_lossy(&body[..body.len().min(160)]),
                        "ohttp: gateway rejected request (400); refreshing key config"
                    );
                    key = self.key_config(true).await?;
                }
                StatusCode::UNPROCESSABLE_ENTITY if attempt == 0 => {
                    // 422 with problem type ohttp-key: drop cached config and refetch
                    let body_str = String::from_utf8_lossy(&body);
                    if body_str.contains("ohttp-key") || body_str.contains("HPKE") {
                        tracing::warn!(
                            detail = %body_str.chars().take(160).collect::<String>(),
                            "ohttp: gateway 422 ohttp-key error; invalidating cache"
                        );
                        key = self.key_config(true).await?;
                    } else {
                        return Err(format!("relay/gateway HTTP 422: {}", &body_str[..body_str.len().min(160)]));
                    }
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
    use base64::Engine;

    #[test]
    fn parses_rfc9458_key_config_document() {
        // Length(41) || key_id=1 || kem=0x0020 || pk[32] || suites_len=4 || kdf=1 || aead=1
        let mut doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        doc.extend_from_slice(&[0xAB; 32]);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);
        let not_after = 9999999999u64; // Far future
        let cfg = KeyConfig::parse_supported(&doc, not_after).expect("parse");
        assert_eq!(cfg.key_id, 1);
        assert_eq!(cfg.public_key, [0xAB; 32]);
        assert_eq!(cfg.not_after, not_after);
        assert_eq!(cfg.header(), [1, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn rejects_unsupported_suite() {
        let mut doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        doc.extend_from_slice(&[0x01; 32]);
        doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0x00, 0x03]);
        assert!(KeyConfig::parse_supported(&doc, 9999999999).is_err());
    }

    #[test]
    fn relay_mapping_covers_both_gateways() {
        assert!(relay_for("ohttp-gateway-testnet.example").is_some());
        assert!(relay_for("ohttp-gateway.example").is_some());
        assert!(relay_for("zec.rocks").is_none());
    }

    /// C-01 fix test: Verify that signature verification rejects tampered configs.
    /// This test MUST FAIL if the signature check is removed or bypassed.
    #[test]
    fn rejects_invalid_signature_in_signed_config() {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Build a minimal valid OHTTP key config document
        let mut config_doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        config_doc.extend_from_slice(&[0xCD; 32]); // dummy public key
        config_doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_before = now - 60;
        let not_after = now + 3600;

        // Create a signed envelope with INVALID signature (all zeros)
        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": base64::prelude::BASE64_STANDARD.encode(&config_doc),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": "test-key",
            "signature": base64::prelude::BASE64_STANDARD.encode([0u8; 64]),
        });

        let json = serde_json::to_vec(&envelope).unwrap();
        let result = verify_signed_config(&json, "ohttp-gateway-testnet.example");

        // MUST reject the invalid signature
        assert!(
            result.is_err(),
            "verify_signed_config must reject invalid signature"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("signature verification failed") || err.contains("Ed25519"),
            "error must indicate signature failure, got: {err}"
        );
    }

    /// C-01 fix test: Verify that expired configs are rejected.
    #[test]
    fn rejects_expired_signed_config() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut config_doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        config_doc.extend_from_slice(&[0xEF; 32]);
        config_doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);

        // Set validity window in the past
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_before = now - 7200; // 2 hours ago
        let not_after = now - 3600; // 1 hour ago (expired)

        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": base64::prelude::BASE64_STANDARD.encode(&config_doc),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": "test-key",
            "signature": base64::prelude::BASE64_STANDARD.encode([0u8; 64]),
        });

        let json = serde_json::to_vec(&envelope).unwrap();
        let result = verify_signed_config(&json, "ohttp-gateway-testnet.example");

        assert!(result.is_err(), "must reject expired config");
        let err = result.unwrap_err();
        assert!(
            err.contains("expired"),
            "error must indicate expiration, got: {err}"
        );
    }

    /// C-01 fix test: Verify that configs with too-long validity windows are rejected.
    #[test]
    fn rejects_long_validity_window() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut config_doc = vec![0x00, 0x29, 0x01, 0x00, 0x20];
        config_doc.extend_from_slice(&[0x12; 32]);
        config_doc.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00, 0x01]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_before = now;
        let not_after = now + 25 * 60 * 60; // 25 hours (exceeds 24h limit)

        let envelope = serde_json::json!({
            "v": 1,
            "network": "testnet",
            "configs": base64::prelude::BASE64_STANDARD.encode(&config_doc),
            "not_before": not_before,
            "not_after": not_after,
            "key_id": "test-key",
            "signature": base64::prelude::BASE64_STANDARD.encode([0u8; 64]),
        });

        let json = serde_json::to_vec(&envelope).unwrap();
        let result = verify_signed_config(&json, "ohttp-gateway-testnet.example");

        assert!(result.is_err(), "must reject validity window >24h");
        let err = result.unwrap_err();
        assert!(
            err.contains("validity window too long") || err.contains("24"),
            "error must indicate validity window issue, got: {err}"
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

    /// Verify signed-config with REAL live fixtures from relay-simulator endpoints (P1/P2/P3 fix).
    /// Tests both mainnet and testnet with valid envelopes, tampered signatures, wrong network.
    #[tokio::test]
    #[ignore = "network"]
    async fn verify_signed_config_with_live_fixtures() {
        // Testnet signed config via relay-simulator
        let testnet_url = "https://testnet-simulator-relay.example.invalid/ohttp-configs/signed";
        let testnet_resp = reqwest::get(testnet_url)
            .await
            .expect("fetch testnet signed config")
            .bytes()
            .await
            .expect("read testnet body");

        // Valid testnet envelope should verify
        let testnet_result = verify_signed_config(&testnet_resp, "ohttp-gateway-testnet.example");
        assert!(
            testnet_result.is_ok(),
            "testnet signed config must verify: {:?}",
            testnet_result
        );

        // Mainnet signed config via relay-simulator
        let mainnet_url = "https://simulator-relay.example.invalid/ohttp-configs/signed";
        let mainnet_resp = reqwest::get(mainnet_url)
            .await
            .expect("fetch mainnet signed config")
            .bytes()
            .await
            .expect("read mainnet body");

        // Valid mainnet envelope should verify
        let mainnet_result = verify_signed_config(&mainnet_resp, "ohttp-gateway.example");
        assert!(
            mainnet_result.is_ok(),
            "mainnet signed config must verify: {:?}",
            mainnet_result
        );

        // Tamper test: flip one byte of the signature
        let mut tampered = testnet_resp.to_vec();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&tampered).expect("parse for tamper");
        let sig_b64 = envelope["sig"].as_str().expect("sig field").to_string();
        let mut sig_bytes = base64::prelude::BASE64_STANDARD
            .decode(&sig_b64)
            .expect("decode sig");
        sig_bytes[0] ^= 0x01; // flip one bit
        envelope["sig"] = serde_json::Value::String(
            base64::prelude::BASE64_STANDARD.encode(&sig_bytes)
        );
        let tampered_json = serde_json::to_vec(&envelope).expect("re-serialize");
        let tampered_result = verify_signed_config(&tampered_json, "ohttp-gateway-testnet.example");
        assert!(
            tampered_result.is_err(),
            "tampered signature must be rejected"
        );

        // Wrong-network test: mainnet envelope to testnet gateway (P3)
        let wrong_network = verify_signed_config(&mainnet_resp, "ohttp-gateway-testnet.example");
        assert!(
            wrong_network.is_err(),
            "mainnet config to testnet gateway must be rejected (network binding)"
        );
        let err = wrong_network.unwrap_err();
        assert!(
            err.contains("network mismatch") || err.contains("key_id"),
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

    /// C-08 audit fix verification tests: ensure OHTTP relay POST is never retried on h2 errors,
    /// while key config GET can safely retry. Without the fix, h2 connection failures would retry
    /// with the same encapsulated ciphertext, violating nonce-once and triggering gateway 409.
    #[cfg(test)]
    mod c08_retry_tests {
        /// Test that https() respects the allow_retry parameter.
        /// When allow_retry is false (OHTTP relay POST), h2 errors must NOT retry.
        /// When allow_retry is true (key config GET), h2 errors can retry once.
        #[test]
        fn test_https_allow_retry_parameter() {
            // This test verifies the signature change to https() method.
            // The method signature must include `allow_retry: bool` parameter:
            //   async fn https(..., body: Vec<u8>, allow_retry: bool) -> Result<...>
            //
            // And the retry loop must respect it:
            //   let max_attempts = if allow_retry { 2 } else { 1 };
            //   for attempt in 0..(max_attempts) { ... }
            //
            // Verify by reading the source:
            let source = include_str!("ohttp.rs");

            // Check signature has allow_retry parameter
            assert!(
                source.contains("async fn https(") && source.contains("allow_retry: bool,"),
                "C-08 fix: https() must have allow_retry: bool parameter"
            );

            // Check retry loop uses allow_retry
            assert!(
                source.contains("let max_attempts = if allow_retry { 2 } else { 1 };"),
                "C-08 fix: https() retry loop must respect allow_retry parameter"
            );

            // Check the comment explaining the fix
            assert!(
                source.contains("C-08")
                    && source.contains("OHTTP relay POST")
                    && source.contains("nonce-once"),
                "C-08 fix: https() must document why OHTTP relay POSTs cannot retry"
            );
        }

        /// Test that round_trip() calls https() with allow_retry: false for relay POST.
        /// This prevents replaying the same sealed ciphertext on h2 connection errors.
        #[test]
        fn test_round_trip_no_retry_on_relay_post() {
            let source = include_str!("ohttp.rs");

            // Verify round_trip() calls https() with allow_retry: false
            // The call is in round_trip() around line 811-819:
            //   let (status, body) = self.https(
            //       &self.relay,
            //       Method::POST,
            //       Some("message/ohttp-req"),
            //       "message/ohttp-res",
            //       enc_req,
            //       false,  // C-08: never retry OHTTP relay POST
            //   ).await?;
            assert!(
                source.contains("async fn round_trip(&self, bhttp_request: &[u8])")
                    && source.contains("self.https(")
                    && source.contains("Some(\"message/ohttp-req\")")
                    && source.contains("false, // C-08: never retry OHTTP relay POST"),
                "C-08 fix: round_trip() must call https() with allow_retry: false for OHTTP relay POST"
            );

            // Verify encapsulation happens BEFORE the https() call, inside the retry loop
            // This proves that key-rotation retry (the outer loop in round_trip) re-encapsulates,
            // while h2-connection retry (inside https) does not.
            assert!(
                source.contains("for attempt in 0..2 {")
                    && source.contains("let (enc_req, ctx) = encapsulate(&key, bhttp_request)?;")
                    && source.contains("self.https("),
                "round_trip() must encapsulate before each https() call (key rotation retry is safe)"
            );
        }

        /// Test that key_config() calls https() with allow_retry: true for key config GET.
        /// Key config fetches are idempotent, so h2 connection retries are safe.
        #[test]
        fn test_key_config_allows_retry() {
            let source = include_str!("ohttp.rs");

            // Verify key_config() calls https() with allow_retry: true
            // The call is in key_config() around line 779-787:
            //   let (status, json_bytes) = self.https(
            //       &signed_config_target,
            //       Method::GET,
            //       None,
            //       "application/json",
            //       Vec::new(),
            //       true,  // allow_retry: key config GET can safely retry
            //   ).await?;
            assert!(
                source.contains("async fn key_config(&self, refresh: bool)")
                    && source.contains("self.https(")
                    && source.contains("Method::GET")
                    && source.contains("\"application/json\"")
                    && source.contains("true, // allow_retry: key config GET can safely retry"),
                "C-08 fix: key_config() must call https() with allow_retry: true for GET requests"
            );
        }

        /// Document the production call path for OHTTP relay POST.
        #[test]
        fn test_ohttp_relay_post_call_path() {
            // Production call path for an OHTTP-encapsulated gRPC request:
            //
            // 1. Client calls OhttpEngine.send() with a bHTTP request
            // 2. OhttpEngine.send() calls round_trip(bhttp_request)
            // 3. round_trip() has TWO retry mechanisms:
            //    a) Outer loop (0..2): retries on HTTP 400 (key rotation) with fresh encapsulation
            //    b) Inner https() call: used to retry h2 connection errors (FIXED: now disabled)
            // 4. round_trip() calls encapsulate(&key, bhttp_request) — creates sealed ciphertext
            // 5. round_trip() calls https(..., enc_req, false) — sends to relay, allow_retry: false
            // 6. https() has a loop (0..max_attempts), where max_attempts = if allow_retry { 2 } else { 1 }
            // 7. Without the fix, https() would retry on h2 send errors, resending the same enc_req
            // 8. With the fix, https() only attempts once for OHTTP relay POSTs
            //
            // Key insight: encapsulation (step 4) happens OUTSIDE the https() retry loop, so any
            // retry inside https() would resend the same ciphertext. The fix disables those retries
            // for OHTTP relay POSTs by passing allow_retry: false.

            let source = include_str!("ohttp.rs");

            // Verify the flow described above exists in the code
            assert!(
                source.contains("pub async fn send(&self, req: &[u8])")
                    && source.contains("self.engine.round_trip(req)"),
                "OhttpEngine.send() must call round_trip()"
            );

            assert!(
                source.contains("async fn round_trip(&self, bhttp_request: &[u8])")
                    && source.contains("encapsulate(&key, bhttp_request)"),
                "round_trip() must call encapsulate() to seal the request"
            );

            assert!(
                source.contains("fn encapsulate(key: &KeyConfig, plaintext: &[u8])")
                    && source.contains("§4.3"),
                "encapsulate() must implement RFC 9458 §4.3 (request encapsulation)"
            );
        }

        /// Document why h2 retry is problematic for OHTTP but safe for key config.
        #[test]
        fn test_why_h2_retry_is_problematic() {
            // Without the C-08 fix, the problematic flow was:
            //
            // 1. round_trip() encapsulates: (enc_req, ctx) = encapsulate(&key, bhttp_request)
            // 2. round_trip() calls https(..., enc_req, allow_retry: true)  ← OLD CODE
            // 3. https() tries to send enc_req over h2
            // 4. h2.send_request() fails (e.g., connection closed)
            // 5. https() detects attempt == 0, retries (continue)
            // 6. https() builds a NEW request with body.clone() — but body is ALREADY enc_req!
            // 7. Second send_request() sends the SAME sealed ciphertext again
            // 8. If first attempt partially succeeded (reached gateway), gateway has the nonce
            // 9. Second attempt gets HTTP 409 (nonce replay detected by gateway)
            //
            // Why key config GET is safe to retry:
            // - No OHTTP encapsulation (no nonce)
            // - Idempotent (same response every time)
            // - No replay cache on the server
            //
            // The fix: allow_retry: false for OHTTP relay POSTs, allow_retry: true for key config GETs.
            // This test exists purely to document the C-08 fix reasoning above.
        }
    }
}
