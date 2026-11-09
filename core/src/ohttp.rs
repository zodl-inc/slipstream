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
//! replies with a normal gRPC response (headers + body + trailers). The connector-created
//! [`crate::grpc::LwdTransport`] retains local origin before tonic parses error statuses. Responses are Chunked OHTTP: the gateway seals
//! them chunk by chunk as lightwalletd streams, and this module decodes them the same way, so a
//! server-streaming RPC delivers its first message before the response has ended.
//!
//! The protocol itself (RFC 9458 §4.3/§4.4 with the suite DHKEM(X25519, HKDF-SHA256) /
//! HKDF-SHA256 / AES-128-GCM, Binary HTTP, signed key-configuration verification, key selection,
//! outer-status classification and size limits) is the shared sans-IO `zodl-ohttp-client` crate,
//! driven with its `ClientProfile::SLIPSTREAM` (gRPC) and `ClientProfile::SLIPSTREAM_HTTP`
//! ([`http_round_trip`]) profiles. This module keeps the I/O: the dialer, the pooled h2 sender,
//! timeouts and the mapping to gRPC. The gateway carries the gRPC status in the
//! Binary HTTP trailer section when lightwalletd streamed it, and in the header section when the
//! answer was trailers-only or collected first (a cache hit); this module puts it into the HTTP/2
//! trailers either way, where tonic reads it.
//!
//! **Tor.** The TCP leg to the relay (and the one-off `/ohttp-configs/signed` key fetch) is
//! opened through a [`Dialer`]: [`Dialer::Direct`] uses the device's own connection,
//! [`Dialer::Tor`] opens an arti stream so the relay only ever sees a Tor exit IP. Everything
//! above TCP (TLS to the relay, HPKE to the gateway) is identical in both cases.
//!
//! **Configuration.** Which hosts are gateways, and their relays, signing keys and keys DNS
//! names, come from the [`OhttpNetworks`] the application passes in (to `EngineConfig::new`
//! for the engine, or to each function here). Nothing is compiled in and no static holds it. A
//! network without a configuration has OHTTP off: its gateway host is a plain server.

mod direct_dial;

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

use crate::transport_health::{
    self, HealthOutcome, HealthRequest, HealthRoute, HealthScope, HealthStage,
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
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::DuplexStream;
use tokio::sync::Mutex;
use tower_service::Service;
pub use zcash_protocol::consensus::NetworkType;
#[cfg(test)]
use zodl_ohttp_client::CONTENT_TYPE_CHUNKED_RES;
use zodl_ohttp_client::{
    BhttpRequest, BhttpResponse, ChunkedResponseDecoder, ClientProfile, DOH_RESOLVERS,
    GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES, GATEWAY_MAX_SEALED_RESPONSE_BYTES, KeyConfig, Network,
    NetworkRule, RelayBackoff, ResponseEvent, SignedKeys, SizeGuard, check_size, doh_query_url,
    encapsulate_chunked_request, envelope_from_doh_json, signed_config_url, verify_signed_config,
};
/// The OHTTP configuration the application passes in: [`OhttpNetworks`] holds an
/// [`OhttpConfig`] (gateway host, relay URL, keys DNS name, signing key) for each network that
/// has OHTTP on.
pub use zodl_ohttp_client::{
    ConfigError, ConfigField, OhttpConfig, OhttpConfigParams, OhttpNetworks,
};

#[cfg(feature = "client-trace")]
use zodl_ohttp_client::ClientTrace;

/// In-memory pipe capacity between tonic and the in-process h2 server.
const DUPLEX_BUF: usize = 4 << 20;
/// Whole OHTTP round trip (encapsulate → relay → gateway → lightwalletd → back). The engine's own
/// `UNARY_TIMEOUT` (30 s) bounds the wait for response headers, so this only matters for large
/// streams; the gateway itself gives lightwalletd 80 s.
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(100);

/// Idle timeout between chunks in a streaming OHTTP response. A healthy stream delivers chunks
/// continuously; 30 s of silence means the connection is dead, so a call given up after that
/// silence also marks its pooled connection dead (see [`H2InFlight::dead_if_given_up_after`]).
const CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared bound on DNS resolution and all direct TCP attempts to the relay.
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The pause an outer 429 without a `Retry-After` starts (the ZIP's reference default). The
/// Android and Swift transports keep the same value under the same name, so the three clients
/// back off alike from a relay that does not say for how long.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(30);

/// The most that is read of an outer answer that is not a success (a relay or gateway error
/// page), whatever ceiling the caller set for the sealed answer: enough for the start of the
/// message quoted in the error. The status is the answer there, so a long error page is cut,
/// never refused as too large (see [`read_error_body`]).
const ERROR_BODY_GUARD_BYTES: usize = 64 * 1024;

/// Longest a pooled relay connection is reused with Tor off: connection lifetime is linkable
/// metadata the relay sees, so a long-lived wallet process moves to a fresh connection now and
/// then. In-flight requests finish on the old one.
const H2_MAX_CONNECTION_AGE: Duration = Duration::from_secs(10 * 60);

/// A pooled relay connection on which a prompt call ([`HeadWait::Prompt`]) is waiting on the
/// network and no frame of any call has arrived for this long is taken as stalled: new calls
/// dial a new connection. Below the engine's 30 s unary deadline, so the retry of a call stuck
/// on a connection that died silently (mobile network handoff) dials a new one. A prompt call
/// given up while still waiting on the network, with nothing arriving on the connection for
/// [`H2_DEAD_IF_GIVEN_UP_AFTER`] since it started waiting, marks the connection dead (see
/// [`H2InFlight`]), so a connection that died shortly before a call's deadline is not reused
/// by its retry either; a frame for another call in the meantime keeps it alive.
///
/// A slow connection whose calls keep receiving frames is never taken as stalled. Frames count
/// when the reader polls them, and a call whose reader has a frame and has not asked for the
/// next one does not count as waiting, so a reader that pauses (a fetch worker parked on its
/// ahead budget) never makes the connection look stalled. One connection cannot tell a lone
/// call queued behind a saturated link (over Tor, other circuits on the same guard) from a dead
/// connection: in both nothing arrives. Evidence from other connections could, but a handoff
/// kills them all at once; the cost of a wrong guess is one new connection, never a cut call,
/// because leaving the pool does not close a connection and the calls on it finish there.
const H2_STALL_AFTER: Duration = Duration::from_secs(20);

/// [`H2_STALL_AFTER`] for the mempool long poll ([`HeadWait::LongPoll`]): longer than the
/// longest silence a healthy gateway allows it, which answers or closes within 25 s of the
/// request (`LONG_POLL_MAX_INITIAL_SILENCE_SECS`), 3 s after a transaction, and at 80 s in any
/// case; the 10 s over that cover the request's and the answer's way through the relay (over
/// Tor on a busy link, several seconds). A long poll silent for longer is on a dead
/// connection; one given up while waiting after such a silence marks it dead.
const H2_LONG_POLL_STALL_AFTER: Duration = Duration::from_secs(35);

/// A direct pooled relay connection with no call in flight for this long is not reused (the
/// next call dials a new one) and leaves the pool by itself. A connection that died while idle
/// (a network handoff with nothing in flight) cannot show it through its frames, and would
/// otherwise take the next call until it stalls; a new direct connection costs only a TLS
/// handshake. This also applies to a connection opened by `warm_up` that no call used within
/// this time. Direct connections also find an idle death sooner through TCP keep-alive
/// ([`DIRECT_TCP_KEEPALIVE_TIME`]). Over Tor an idle connection stays reusable (see
/// `h2_sender`): a new one costs a stream and a TLS handshake through a circuit, and on a slow
/// link those dials often time out.
const H2_IDLE_REUSE: Duration = Duration::from_secs(30);

/// How long a prompt call must have waited with nothing arriving on its connection for giving
/// it up to mark the connection dead (see [`H2InFlight`]). Short, so a connection that died a
/// few seconds before a call's deadline is not reused by the retry; long enough that a call
/// cut on purpose while its data flows (a fetch kick, a stream cut) leaves its connection
/// alone.
const H2_DEAD_IF_GIVEN_UP_AFTER: Duration = Duration::from_secs(5);

/// TCP keep-alive on a direct relay connection: after this long with nothing sent or received,
/// the kernel probes the peer every [`DIRECT_TCP_KEEPALIVE_INTERVAL`] and closes the socket
/// after [`DIRECT_TCP_KEEPALIVE_RETRIES`] unanswered probes, about 11 s after the connection
/// went quiet. The probes are TCP-level, answered by the peer's kernel and sent only while the
/// connection carries no data, so unlike an HTTP/2 PING they never queue behind data in
/// flight. A connection that died while idle is then closed (`is_closed`) before most calls
/// could reuse it. Over Tor the socket is arti's connection to the guard, and noticing a dead
/// guard is arti's.
const DIRECT_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(5);
/// See [`DIRECT_TCP_KEEPALIVE_TIME`].
const DIRECT_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);
/// See [`DIRECT_TCP_KEEPALIVE_TIME`].
const DIRECT_TCP_KEEPALIVE_RETRIES: u32 = 3;

/// Whether a call's response is expected promptly or is a long poll; each has its own stall
/// bound ([`H2_STALL_AFTER`], [`H2_LONG_POLL_STALL_AFTER`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadWait {
    /// Every call but the long poll: its head follows the request within seconds and its body
    /// keeps arriving.
    Prompt,
    /// `GetMempoolStream`, a long poll: the gateway answers once lightwalletd sends the first
    /// transaction and may then send nothing for a while.
    LongPoll,
}

// A call stuck on a dead connection must leave it before the engine retries the call, and a
// healthy long poll is never silent as long as the long-poll bound.
const _: () = assert!(H2_STALL_AFTER.as_secs() < crate::grpc::UNARY_TIMEOUT.as_secs());
const _: () = assert!(H2_LONG_POLL_STALL_AFTER.as_secs() >= 25 + 10);

impl HeadWait {
    /// The head wait of a request to the inner `path`.
    fn for_path(path: &[u8]) -> Self {
        if path.ends_with(b"/GetMempoolStream") {
            Self::LongPoll
        } else {
            Self::Prompt
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Prompt => 0,
            Self::LongPoll => 1,
        }
    }

    /// How long a waiting call of this kind may see nothing arrive before its connection counts
    /// as stalled.
    fn stall_after(self) -> Duration {
        match self {
            Self::Prompt => H2_STALL_AFTER,
            Self::LongPoll => H2_LONG_POLL_STALL_AFTER,
        }
    }
}

/// Trailers-only metadata the in-process server attaches to a gRPC error so that the engine can
/// tell an OHTTP outcome from an unreachable server (read and stripped by
/// `LwdTransport::local_status`). It never leaves the process.
pub(crate) const OHTTP_OUTCOME_HEADER: &str = "x-ohttp-outcome";
/// Reserved obsolete authentication field; always strip it from peer metadata.
const OHTTP_OUTCOME_AUTH_HEADER: &str = "x-ohttp-outcome-auth";

/// An inner 403: the gateway refused this operation by policy.
pub(crate) const OUTCOME_POLICY_DENIED: &str = "policy-denied";
/// An outer 429, or a request held back while the relay's `Retry-After` pause runs.
pub(crate) const OUTCOME_RATE_LIMITED: &str = "rate-limited";
/// An outer 413, or a sealed request over 10 MiB that was not sent.
pub(crate) const OUTCOME_TOO_LARGE: &str = "too-large";

/// Verified key configurations shared by every connection to the same gateway through the same
/// relay under the same configuration, so that a new connection (a tip probe, a fetch worker, an
/// isolated Tor client) does not fetch the signed configuration again while it is valid. Entries
/// end at `not_after`.
static SHARED_KEYS: OnceLock<std::sync::Mutex<HashMap<SharedKeyId, CachedKey>>> = OnceLock::new();

/// What a verified key configuration in [`SHARED_KEYS`] is good for: one gateway, fetched
/// through one relay ([`OhttpClient::backoff_key`]), checked under one configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SharedKeyId {
    gateway_host: String,
    relay: String,
    configuration: Option<ConfigurationKey>,
}

/// Every value of the configuration a client works under: its gateway's network and that
/// network's gateway host, relay URL, keys DNS name and signing key. The cache keys hold the
/// values themselves (an [`OhttpConfig`] is not `Hash`), so that nothing cached under one
/// configuration serves another, a key verified under another signer included. The Tor
/// client's shared connections are kept with it too (`connector::TorConn`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct ConfigurationKey {
    network: &'static str,
    gateway_host: String,
    relay_url: String,
    keys_dns_name: String,
    signing_pubkey: [u8; 32],
}

/// Shows the network only, so that no log line or panic message can carry a configured value.
impl std::fmt::Debug for ConfigurationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigurationKey")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl ConfigurationKey {
    /// The key of the configuration `networks` has for `gateway_host`'s network; `None` for a
    /// host that is not the gateway of a configured network.
    pub(crate) fn of(networks: &OhttpNetworks, gateway_host: &str) -> Option<Self> {
        let network = gateway_network(networks, gateway_host).ok()?;
        let config = networks.get(network)?;
        Some(Self {
            network: network.as_str(),
            gateway_host: config.gateway_host().to_owned(),
            relay_url: config.relay_url().to_owned(),
            keys_dns_name: config.keys_dns_name().to_owned(),
            signing_pubkey: config.signing_pubkey().to_bytes(),
        })
    }
}

fn shared_keys() -> std::sync::MutexGuard<'static, HashMap<SharedKeyId, CachedKey>> {
    SHARED_KEYS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Process-wide default client trace prefix for OHTTP connections (set once from JNI).
#[cfg(feature = "client-trace")]
static DEFAULT_CLIENT_TRACE_PREFIX: OnceLock<Option<String>> = OnceLock::new();

/// Process-wide cache of OHTTP clients for Direct-dialer connections only. Each cached client
/// pools HTTP/2 connections and verified key configs per gateway. Tor-dialer clients are never
/// cached (fresh client per call) to avoid linking requests across isolated circuits.
static CLIENT_CACHE: OnceLock<std::sync::Mutex<HashMap<ClientCacheKey, Arc<OhttpClient>>>> =
    OnceLock::new();

/// Cache key for OHTTP clients: gateway host, relay URL, the configuration the client works
/// under, trace prefix, and profile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ClientCacheKey {
    gateway_host: String,
    relay_url: String,
    configuration: Option<ConfigurationKey>,
    trace_prefix: Option<String>,
    /// Profile identified by which const it equals (1=ANDROID, 2=IOS, 3=SLIPSTREAM,
    /// 4=SLIPSTREAM_HTTP, 5=LIBRARY). Any other profile has no key and is never cached.
    profile_id: u8,
}

impl ClientCacheKey {
    fn new(
        networks: &OhttpNetworks,
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

        // Without `client-trace` the prefix is dropped by the client, so it must not split the cache.
        #[cfg(not(feature = "client-trace"))]
        let trace_prefix = trace_prefix.and(None);
        Some(Self {
            gateway_host: gateway_host.to_string(),
            relay_url: relay_url.to_string(),
            configuration: ConfigurationKey::of(networks, gateway_host),
            trace_prefix,
            profile_id,
        })
    }
}

/// Set the default client trace prefix for all OHTTP connections without an explicit prefix.
/// Called from JNI/FFI when the engine or TorRuntime is created.
///
/// Only available when the `client-trace` feature is enabled. Release builds MUST NOT enable
/// this feature (ZIP conformance). The Android SDK enables `client-trace` only when its own
/// `BuildConfig.DEBUG` is true; the Swift SDK only under `#if DEBUG`. Without the feature this
/// function is a no-op that ignores its argument, keeping the API surface unchanged.
#[cfg(feature = "client-trace")]
pub fn set_default_client_trace_prefix(prefix: Option<String>) {
    let _ = DEFAULT_CLIENT_TRACE_PREFIX.set(prefix);
}

#[cfg(not(feature = "client-trace"))]
pub fn set_default_client_trace_prefix(_prefix: Option<String>) {
    // No-op when client-trace is disabled
}

/// Get the default client trace prefix (returns None when client-trace is disabled).
#[cfg(feature = "client-trace")]
fn get_default_client_trace_prefix() -> Option<String> {
    DEFAULT_CLIENT_TRACE_PREFIX
        .get()
        .and_then(|opt| opt.clone())
}

#[cfg(not(feature = "client-trace"))]
fn get_default_client_trace_prefix() -> Option<String> {
    None
}

/// Get or create a cached OHTTP client for the given parameters. **Privacy:** only
/// `Dialer::Direct` clients are cached (keyed by gateway_host + relay_url + the configuration
/// of the gateway's network + trace_prefix + profile); `Dialer::Tor` always creates a fresh
/// client to avoid linking requests across isolated circuits or leaking the device IP when the
/// caller asked for Tor.
async fn get_or_create_client(
    networks: &OhttpNetworks,
    gateway_host: &str,
    relay_url: &str,
    dialer: Dialer,
    client_trace_prefix: Option<String>,
    profile: ClientProfile,
) -> Result<Arc<OhttpClient>, String> {
    cached_or_new_client(
        networks,
        gateway_host,
        relay_url,
        dialer,
        client_trace_prefix,
        profile,
    )
}

/// Synchronous core of [`get_or_create_client`], also used by [`OhttpConnector`] so that every
/// gRPC channel of a Direct-dialer session shares one client, and with it one pooled h2
/// connection to the relay, instead of a TLS handshake per channel.
fn cached_or_new_client(
    networks: &OhttpNetworks,
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
            networks,
            gateway_host,
            relay_url,
            client_trace_prefix.clone(),
            profile,
        )
    };
    let Some(key) = key else {
        return Ok(Arc::new(OhttpClient::new(
            networks,
            gateway_host,
            relay_url,
            dialer,
            client_trace_prefix,
            profile,
        )?));
    };

    // Direct clients are cached per (gateway_host, relay_url, configuration, trace_prefix,
    // profile)
    let cache = CLIENT_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(client) = map.get(&key) {
        return Ok(Arc::clone(client));
    }

    // Create and cache a new Direct-dialer client
    let client = Arc::new(OhttpClient::new(
        networks,
        gateway_host,
        relay_url,
        dialer,
        client_trace_prefix,
        profile,
    )?);
    map.insert(key, Arc::clone(&client));
    Ok(client)
}

/// Why a host is refused where an OHTTP gateway is needed. It does not repeat the host.
const NOT_A_GATEWAY: &str = "no OHTTP network configured for this gateway host";

/// Relay URL for a given gateway host, or `None` when `gateway_host` is not the gateway of a
/// network `networks` configures: OHTTP is off for that host, which is a plain server. One relay
/// per gateway: mainnet and testnet gateways use different HPKE keys, and an RFC 9458 relay has
/// a single fixed gateway target.
///
/// Gateway hosts, relay URLs, signing keys and keys DNS names come from the configuration the
/// application passes in; nothing is compiled in. Host names are compared ignoring ASCII case.
pub fn relay_for<'a>(networks: &'a OhttpNetworks, gateway_host: &str) -> Option<&'a str> {
    networks.relay_for(&gateway_host.to_ascii_lowercase())
}

/// The relay of `gateway_host`, or [`NOT_A_GATEWAY`] for a host that is not a configured
/// gateway.
fn configured_relay<'a>(
    networks: &'a OhttpNetworks,
    gateway_host: &str,
) -> Result<&'a str, String> {
    relay_for(networks, gateway_host).ok_or_else(|| NOT_A_GATEWAY.to_owned())
}

/// `host` for an info-level log line: a configured gateway host, an endpoint value of the
/// application's configuration, is shown only as `ohttp-gateway`.
pub(crate) fn log_host<'a>(networks: &OhttpNetworks, host: &'a str) -> &'a str {
    if relay_for(networks, host).is_some() {
        "ohttp-gateway"
    } else {
        host
    }
}

/// A configured gateway host as an error message names it: its network and `ohttp-gateway`.
/// Error messages reach info-level lines through `%err`, so they carry no endpoint value.
pub(crate) fn gateway_label(networks: &OhttpNetworks, host: &str) -> &'static str {
    match gateway_network(networks, host) {
        Ok(Network::Mainnet) => "mainnet ohttp-gateway",
        Ok(Network::Testnet) => "testnet ohttp-gateway",
        Err(_) => "ohttp-gateway",
    }
}

/// The configuration of `gateway_host`'s network alone, OHTTP off for the other one; OHTTP off
/// for both for a host that is not a configured gateway. A client keeps this, not the whole
/// configuration, so that what it works under is exactly what its cache keys hold.
fn gateway_configuration(networks: &OhttpNetworks, gateway_host: &str) -> OhttpNetworks {
    let config = |network| networks.get(network).cloned();
    match gateway_network(networks, gateway_host) {
        Ok(Network::Mainnet) => OhttpNetworks::new(config(Network::Mainnet), None),
        Ok(Network::Testnet) => OhttpNetworks::new(None, config(Network::Testnet)),
        Err(_) => Ok(OhttpNetworks::default()),
    }
    .expect("the configuration of one network shares no value with another")
}

/// `message` with every spelling of `host` (ignoring ASCII case) replaced by `label`: an inner
/// error (a TLS name mismatch, a Tor stream failure) may name the peer itself.
fn redact_host(message: impl std::fmt::Display, host: &str, label: &str) -> String {
    let message = message.to_string();
    if host.is_empty() {
        return message;
    }
    let lower = message.to_ascii_lowercase();
    let needle = host.to_ascii_lowercase();
    let mut out = String::with_capacity(message.len());
    let mut rest = 0;
    for (at, _) in lower.match_indices(&needle) {
        out.push_str(&message[rest..at]);
        out.push_str(label);
        rest = at + needle.len();
    }
    out.push_str(&message[rest..]);
    out
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

/// Turns on TCP keep-alive on a direct relay socket (see [`DIRECT_TCP_KEEPALIVE_TIME`]). A
/// failure only loses the earlier detection of an idle dead connection.
fn set_tcp_keepalive(tcp: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new().with_time(DIRECT_TCP_KEEPALIVE_TIME);
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    ))]
    let keepalive = keepalive
        .with_interval(DIRECT_TCP_KEEPALIVE_INTERVAL)
        .with_retries(DIRECT_TCP_KEEPALIVE_RETRIES);
    if let Err(e) = socket2::SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        tracing::debug!(err = %e, "ohttp: could not turn on TCP keep-alive");
    }
}

impl Dialer {
    pub fn is_tor(&self) -> bool {
        matches!(self, Dialer::Tor(_))
    }

    /// Opens a stream to `host`. Errors name the peer as `label`; the host is logged at debug.
    async fn dial(&self, host: &str, port: u16, label: &str) -> Result<BoxedIo, String> {
        match self {
            Dialer::Direct => {
                let tcp = direct_dial::connect(
                    tokio::net::lookup_host((host, port)),
                    tokio::net::TcpStream::connect,
                )
                .await
                .map_err(|_| {
                    tracing::debug!(host, port, "ohttp: connect timed out");
                    format!(
                        "connect {label}: exceeded {}s",
                        DIRECT_DIAL_TIMEOUT.as_secs()
                    )
                })?
                .map_err(|e| {
                    tracing::debug!(host, port, err = %e, "ohttp: connect failed");
                    format!("connect {label}: {}", redact_host(&e, host, label))
                })?;
                let _ = tcp.set_nodelay(true);
                set_tcp_keepalive(&tcp);
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
                                port,
                                attempt,
                                ms = started.elapsed().as_millis() as u64,
                                "ohttp: dialled through Tor"
                            );
                            return Ok(Box::new(stream));
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(attempt, err = %e, "ohttp: tor dial failed — retrying on a fresh circuit");
                            tracing::debug!(host, port, attempt, err = %e, "ohttp: tor connect failed");
                            last_err =
                                format!("tor connect {label}: {}", redact_host(&e, host, label));
                        }
                        Err(_) => {
                            tracing::warn!(
                                attempt,
                                timeout_secs = TOR_DIAL_TIMEOUT.as_secs(),
                                "ohttp: tor dial timed out — retrying on a fresh circuit"
                            );
                            last_err = format!(
                                "tor connect {label}: exceeded {}s",
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
    health: Option<Arc<RequestHealth>>,
}

impl OhttpConnector {
    pub(crate) fn health_route(&self) -> HealthRoute {
        HealthRoute {
            gateway_host: self.client.gateway_host.clone(),
            relay_url: self.client.relay_url.clone(),
            via_tor: self.client.dialer.is_tor(),
        }
    }

    pub(crate) fn request_health(&self) -> Arc<RequestHealth> {
        Arc::new(RequestHealth::new(&self.client))
    }

    pub(crate) fn bound_to(&self, health: Arc<RequestHealth>) -> Self {
        Self {
            client: self.client.clone(),
            health: Some(health),
        }
    }

    /// Direct dialer: the relay sees the device IP. The relay, signing key, keys DNS name and
    /// network of `gateway_host` come from `networks`; a host that is not the gateway of a
    /// configured network is an error.
    pub fn new(networks: &OhttpNetworks, gateway_host: &str) -> Result<Self, String> {
        Self::with_dialer(
            networks,
            gateway_host,
            Dialer::Direct,
            get_default_client_trace_prefix(),
        )
    }

    /// Direct dialer with a client of its own (its own pooled relay connection), for bulk block
    /// streams: see [`crate::grpc::connect_dedicated`]. Configured as [`Self::new`].
    pub fn dedicated(networks: &OhttpNetworks, gateway_host: &str) -> Result<Self, String> {
        let relay_url = configured_relay(networks, gateway_host)?;
        Ok(Self {
            health: None,
            client: Arc::new(OhttpClient::new(
                networks,
                gateway_host,
                relay_url,
                Dialer::Direct,
                get_default_client_trace_prefix(),
                ClientProfile::SLIPSTREAM,
            )?),
        })
    }

    /// Connector whose TCP legs (relay POSTs and the gateway key fetch) go through `dialer`.
    /// Configured as [`Self::new`].
    pub fn with_dialer(
        networks: &OhttpNetworks,
        gateway_host: &str,
        dialer: Dialer,
        client_trace_prefix: Option<String>,
    ) -> Result<Self, String> {
        let relay_url = configured_relay(networks, gateway_host)?;
        // Direct: the process-wide client, so channels reuse one h2 connection to the relay.
        // Tor: a fresh client, as before (circuit isolation).
        Ok(Self {
            health: None,
            client: cached_or_new_client(
                networks,
                gateway_host,
                relay_url,
                dialer,
                client_trace_prefix.or_else(get_default_client_trace_prefix),
                ClientProfile::SLIPSTREAM,
            )?,
        })
    }

    /// Eagerly fetch the gateway key configuration and open the pooled h2 connection to the
    /// relay, so that the caller can bound (and retry on a fresh circuit) the slow part of a Tor
    /// connect instead of paying it inside the first RPC's deadline. Idempotent.
    pub async fn warm_up(&self) -> Result<(), String> {
        self.warm_up_inner()
            .await
            .map_err(RoundTripError::into_message)
    }

    /// Engine connection setup preserves a relay pause as backoff, rather than an
    /// unreachable endpoint. The public string-returning API remains compatible.
    pub(crate) async fn warm_up_typed(&self) -> Result<(), crate::error::SlipstreamError> {
        self.warm_up_inner().await.map_err(Into::into)
    }

    async fn warm_up_inner(&self) -> Result<(), RoundTripError> {
        let health = crate::grpc::current_owner_health()
            .filter(|health| health.route == self.health_route())
            .unwrap_or_else(|| {
                Arc::new(RequestHealth::for_scope(&self.client, HealthScope::Route))
            });
        let result = self.warm_up_observed(&health).await;
        match &result {
            Ok(()) => health.finish(HealthOutcome::Inconclusive, HealthStage::Complete),
            Err(error) => health.error(&self.client, error),
        }
        result
    }

    async fn warm_up_observed(&self, health: &RequestHealth) -> Result<(), RoundTripError> {
        // A cached key must not bypass a known relay pause and open another circuit.
        self.client.check_relay_pause()?;
        self.client.key_config_observed(false, Some(health)).await?;
        self.client.check_relay_pause()?;
        health.boundary(HealthStage::Connection);
        if self
            .client
            .h2_sender(&self.client.relay)
            .await
            .map_err(|error| {
                if matches!(error, HttpsError::Configuration(_)) {
                    health.classify(HealthOutcome::ConfigurationFailure);
                }
                RoundTripError::Transport(error.into_message())
            })?
            .is_none()
        {
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
        let health = self.health.clone();
        Box::pin(async move {
            let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let client = Arc::clone(&client);
                    let health = health.clone();
                    async move { Ok::<_, Infallible>(client.handle(req, health).await) }
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

/// The network whose configured gateway is `gateway_host`, ignoring case: the network comes
/// from the configuration, never from the host name. The envelope and wallet must both use that
/// network (`EngineConfig::validate`, [`http_round_trip`]). The two networks of an
/// [`OhttpNetworks`] never share a gateway host, so the answer is never ambiguous.
pub(crate) fn gateway_network(
    networks: &OhttpNetworks,
    gateway_host: &str,
) -> Result<Network, String> {
    NetworkRule::KnownHosts
        .network_for(networks, &gateway_host.to_ascii_lowercase())
        .map_err(|_| NOT_A_GATEWAY.to_owned())
}

/// Refuses an OHTTP gateway that serves another network than `network`: its calls would reach
/// the wrong chain, under a key configuration signed for that chain. Regtest has no gateway.
pub(crate) fn check_gateway_network(
    networks: &OhttpNetworks,
    gateway_host: &str,
    network: NetworkType,
) -> Result<(), String> {
    let gateway = gateway_network(networks, gateway_host)?;
    let wallet = match network {
        NetworkType::Main => Some(Network::Mainnet),
        NetworkType::Test => Some(Network::Testnet),
        NetworkType::Regtest => None,
    };
    if wallet == Some(gateway) {
        Ok(())
    } else {
        Err(format!(
            "OHTTP gateway serves {}, not this wallet's network",
            gateway.as_str()
        ))
    }
}

/// Verify a signed key-configuration envelope for `gateway_host` under `profile` (the network
/// `networks` gives the host, the signing key it configures for that network, the validity
/// window at `now`, the signature) and pick the key out of it. Pure: the fetch and the cache are
/// the caller's.
fn open_signed_keys(
    networks: &OhttpNetworks,
    profile: &ClientProfile,
    json: &[u8],
    gateway_host: &str,
    now: u64,
) -> Result<CachedKey, String> {
    let network = gateway_network(networks, gateway_host)?;
    let keys = verify_signed_config(networks, json, network, now, &profile.signed_config)
        .map_err(|e| e.to_string())?;
    select_signed_key(profile, &keys)
}

/// The key `profile` selects from the document of a checked envelope, kept until the envelope
/// ends.
fn select_signed_key(profile: &ClientProfile, keys: &SignedKeys) -> Result<CachedKey, String> {
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
    let uri: Uri = url
        .parse()
        .map_err(|e| format!("bad relay/gateway URL: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err("relay/gateway URL must be https".into());
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
    /// The activity of the pooled connection the answer came on (`None` for one that is not
    /// pooled), for [`pump_chunked_body`] to retire it when it gives the body up as silent.
    activity: Option<Arc<H2Activity>>,
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
    /// Size policy refusal; it retains the legacy UNAVAILABLE gRPC mapping.
    TooLarge(String),
}

impl PumpError {
    fn transport(msg: impl Into<String>) -> Self {
        PumpError::Transport(msg.into())
    }

    fn decode(msg: impl Into<String>) -> Self {
        PumpError::Decode(msg.into())
    }
}

/// Streaming half of [`OhttpClient::round_trip_stream_once_observed`]: reads the relay body frame by
/// frame, enforces the response size bound, feeds the chunked decoder and forwards its events.
/// It stops as soon as the receiver is gone (the RPC was cancelled or timed out) and drops the
/// body, even while an incomplete chunk produces no events, so a dropped call stops reading
/// ciphertext from the relay.
async fn pump_chunked_body(
    mut body_stream: BoxBody<Bytes, hyper::Error>,
    mut decoder: ChunkedResponseDecoder,
    mut guard: SizeGuard,
    tx: tokio::sync::mpsc::Sender<Result<ResponseEvent, PumpError>>,
    activity: Option<Arc<H2Activity>>,
) {
    loop {
        // Before the frame wait (and its timer) starts, so before the body's own wait clock.
        let waiting_from = std::time::Instant::now();
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
                                let _ = tx.send(Err(PumpError::TooLarge(format!("response too large: {e}")))).await;
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
                        if let Some(activity) = &activity {
                            activity.given_up_silent_since(waiting_from);
                        }
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

/// What [`run_exchange_chunked_observed`] needs from the relay's answer to one sealed POST, whatever
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
    /// Local HTTP request construction failed, before any network operation.
    Configuration(String),
    /// Failure while reading an outer response whose headers have already arrived.
    Read(String),
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
            | HttpsError::Configuration(m)
            | HttpsError::Read(m)
            | HttpsError::RelayPaused(m)
            | HttpsError::TooLarge(m) => m,
        }
    }

    /// `label` names the peer; `target_host` is only redacted out of the inner error.
    fn classify_tls_error(error: std::io::Error, target_host: &str, label: &str) -> Self {
        let rejected = error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<rustls::Error>())
            .is_some_and(|error| {
                matches!(
                    error,
                    rustls::Error::InvalidCertificate(_)
                        | rustls::Error::NoCertificatesPresented
                        | rustls::Error::UnsupportedNameType
                        | rustls::Error::PeerIncompatible(_)
                )
            });
        tracing::debug!(host = target_host, err = %error, "ohttp: tls failed");
        let message = format!("tls {label}: {}", redact_host(&error, target_host, label));
        if rejected {
            Self::Configuration(message)
        } else {
            Self::Other(message)
        }
    }

    /// Classifies a `send_request` error. It never returns `PreSend`: this code does not
    /// currently distinguish a request that was never written from one that may have reached the
    /// relay, so every send error is treated as potentially post-send (`Other`) and never resealed
    /// or re-POSTed, to avoid repeating a request with side effects (ZIP Gateway rule 11). Only
    /// `ready()` failures, classified at their own call sites, are `PreSend`.
    fn classify_send_error(e: impl std::fmt::Display, target_host: &str, label: &str) -> Self {
        HttpsError::Other(format!(
            "h2 send {label}: {}",
            redact_host(e, target_host, label)
        ))
    }
}

/// Reads `body` to its end into memory, within `guard`. `declared_len` is the length the peer
/// announced (`Content-Length`): a length past the guard's limit is refused before a frame is
/// pulled. Each data frame is counted with `guard` before it is buffered, so the read stops at
/// the first one that goes past the limit and the frames behind it are never pulled from the
/// peer. Both refusals are [`HttpsError::TooLarge`]. A read error, or [`CHUNK_IDLE_TIMEOUT`]
/// without a frame, is [`HttpsError::Read`]. `label` names the peer in the messages.
async fn read_body_capped<B>(
    mut body: B,
    declared_len: Option<u64>,
    mut guard: SizeGuard,
    label: &str,
) -> Result<Vec<u8>, HttpsError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if let Some(declared) = declared_len {
        guard
            .check_declared(declared)
            .map_err(|e| HttpsError::TooLarge(format!("read {label}: {e}")))?;
    }
    let mut bytes = Vec::new();
    loop {
        let Some(frame) = tokio::time::timeout(CHUNK_IDLE_TIMEOUT, body.frame())
            .await
            .map_err(|_| {
                HttpsError::Read(format!(
                    "read {label}: idle timeout ({}s without data)",
                    CHUNK_IDLE_TIMEOUT.as_secs()
                ))
            })?
        else {
            break;
        };
        let frame = frame.map_err(|e| HttpsError::Read(format!("read {label}: {e}")))?;
        if let Ok(data) = frame.into_data() {
            guard
                .push(data.len())
                .map_err(|e| HttpsError::TooLarge(format!("read {label}: {e}")))?;
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

/// Reads the body of an outer answer that is not a success (an error page), up to
/// [`ERROR_BODY_GUARD_BYTES`] and whatever the caller's ceiling for the sealed answer: the
/// status is the answer, the body only illustrates it. A longer body is cut there (the frames
/// behind the cut are not pulled from the peer), and a body that cannot be read to its end
/// (a read error, [`CHUNK_IDLE_TIMEOUT`] without a frame) gives what had arrived. So an outer
/// 429 or 503 is reported with its status, and never as too large or as a failed read, even
/// when the caller allows only a small answer. `host` names the peer in the log line.
async fn read_error_body<B>(mut body: B, host: &str) -> Vec<u8>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut bytes = Vec::new();
    while bytes.len() < ERROR_BODY_GUARD_BYTES {
        let frame = match tokio::time::timeout(CHUNK_IDLE_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::debug!(host, err = %e, "ohttp: error page not read to its end");
                break;
            }
            Err(_) => {
                tracing::debug!(host, "ohttp: error page not read to its end (idle timeout)");
                break;
            }
        };
        if let Ok(data) = frame.into_data() {
            let room = ERROR_BODY_GUARD_BYTES - bytes.len();
            bytes.extend_from_slice(&data[..data.len().min(room)]);
        }
    }
    bytes
}

/// One logical call across immediate resealing/key/freshness recovery. Classification is
/// carried from the boundary that knows it, never reconstructed from an error string.
pub(crate) struct RequestHealth {
    pub(crate) ticket: HealthRequest,
    route: HealthRoute,
    started: tokio::time::Instant,
    state: std::sync::Mutex<(HealthStage, Option<HealthOutcome>, bool)>,
}

impl RequestHealth {
    fn new(client: &OhttpClient) -> Self {
        let scope = if client.profile == ClientProfile::SLIPSTREAM {
            HealthScope::Lightwalletd
        } else {
            HealthScope::Other
        };
        Self::for_scope(client, scope)
    }

    fn for_scope(client: &OhttpClient, scope: HealthScope) -> Self {
        Self::for_route(
            HealthRoute {
                gateway_host: client.gateway_host.clone(),
                relay_url: client.relay_url.clone(),
                via_tor: client.dialer.is_tor(),
            },
            scope,
        )
    }

    pub(crate) fn for_route(route: HealthRoute, scope: HealthScope) -> Self {
        Self {
            started: tokio::time::Instant::now(),
            ticket: transport_health::begin_request(&route, scope),
            route,
            state: std::sync::Mutex::new((HealthStage::Connection, None, false)),
        }
    }

    fn boundary(&self, stage: HealthStage) {
        let mut state = self.state.lock().unwrap();
        state.0 = stage;
        state.1 = None;
    }

    fn classify(&self, outcome: HealthOutcome) {
        self.state.lock().unwrap().1 = Some(outcome);
    }

    fn observe_grpc_status(&self, status: Option<&str>) {
        // Retain only canonical non-success standard statuses. A later authenticated
        // success or malformed status replaces the candidate without completing the call.
        self.state.lock().unwrap().1 = match status {
            Some(
                status @ ("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" | "12"
                | "13" | "14" | "15" | "16"),
            ) => Some(grpc_health(Some(status))),
            _ => None,
        };
    }

    fn finish_body_failure(&self, fallback: HealthOutcome) {
        let known = self.state.lock().unwrap().1;
        self.finish(known.unwrap_or(fallback), HealthStage::ResponseBody);
    }

    fn error(&self, client: &OhttpClient, error: &RoundTripError) {
        let (stage, classified, _) = *self.state.lock().unwrap();
        let outcome = match error {
            RoundTripError::RateLimited { retry_after, .. } => {
                rate_limit_outcome(client, *retry_after)
            }
            RoundTripError::TooLarge(_)
            | RoundTripError::ResponseTooLarge(_)
            | RoundTripError::Decode(_) => HealthOutcome::ResponseRejected,
            RoundTripError::Transport(_) => {
                classified.unwrap_or(HealthOutcome::TransportUnavailable)
            }
        };
        self.finish(outcome, stage);
    }

    pub(crate) fn timeout_at(&self, budget: Duration) -> tokio::time::Instant {
        self.started + budget
    }

    pub(crate) fn deadline(&self, stage: HealthStage) {
        let (observed_stage, known, _) = *self.state.lock().unwrap();
        self.finish(
            known.unwrap_or(HealthOutcome::TransportUnavailable),
            if known.is_some() {
                observed_stage
            } else {
                stage
            },
        );
    }

    fn finish(&self, outcome: HealthOutcome, stage: HealthStage) {
        let mut state = self.state.lock().unwrap();
        if !state.2 {
            self.ticket.record(outcome, stage);
            state.2 = true;
        }
    }
}

impl Drop for RequestHealth {
    fn drop(&mut self) {
        let (stage, _, finished) = *self.state.lock().unwrap();
        if !finished {
            self.ticket.record(HealthOutcome::Cancelled, stage);
        }
    }
}

fn rate_limit_outcome(client: &OhttpClient, asked: Option<Duration>) -> HealthOutcome {
    let wait = RelayBackoff::global()
        .remaining(&client.backoff_key())
        .unwrap_or_else(|| asked.unwrap_or(DEFAULT_RETRY_AFTER));
    HealthOutcome::RateLimited {
        retry_not_before_nanoseconds: transport_health::monotonic_time_nanoseconds()
            .saturating_add(wait.as_nanos().min(u64::MAX as u128) as u64),
    }
}

fn classify_outer(status: StatusCode) -> HealthOutcome {
    match status.as_u16() {
        401 | 403 | 407 | 451 => HealthOutcome::PolicyRejected,
        400 | 404 | 405 | 406 | 409 | 415 | 422 | 426 | 501 | 505 => {
            HealthOutcome::ConfigurationFailure
        }
        413 => HealthOutcome::ResponseRejected,
        code if code >= 500 => HealthOutcome::TransportUnavailable,
        _ => HealthOutcome::ResponseRejected,
    }
}

fn header_map_from_fields(fields: &[(Vec<u8>, Vec<u8>)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }
    headers
}

fn grpc_health(status: Option<&str>) -> HealthOutcome {
    match status {
        Some("0") => HealthOutcome::Usable,
        Some("1") => HealthOutcome::Cancelled,
        Some("4" | "14") => HealthOutcome::BackendUnavailable,
        Some("7" | "16") => HealthOutcome::PolicyRejected,
        Some("12") => HealthOutcome::ConfigurationFailure,
        _ => HealthOutcome::ResponseRejected,
    }
}

fn inner_health(
    status: u16,
    headers: &HeaderMap,
    grpc: bool,
    complete: bool,
) -> Option<HealthOutcome> {
    match status {
        401 | 403 | 407 | 451 => Some(HealthOutcome::PolicyRejected),
        429 => Some(HealthOutcome::RateLimited {
            retry_not_before_nanoseconds: transport_health::monotonic_time_nanoseconds()
                .saturating_add(
                    retry_after(headers)
                        .unwrap_or(DEFAULT_RETRY_AFTER)
                        .as_nanos() as u64,
                ),
        }),
        426 | 501 | 505 => Some(HealthOutcome::ConfigurationFailure),
        500..=599 => Some(HealthOutcome::BackendUnavailable),
        400..=499 => Some(HealthOutcome::ResponseRejected),
        _ if grpc
            && (status != 200
                || !headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc"))) =>
        {
            Some(HealthOutcome::ResponseRejected)
        }
        _ if complete => Some(if grpc {
            grpc_health(headers.get("grpc-status").and_then(|v| v.to_str().ok()))
        } else {
            HealthOutcome::Usable
        }),
        _ => None,
    }
}

/// DNS fallback errors do not replace the original relay error that key recovery returns.
#[derive(Clone, Copy)]
enum HttpsHealthRole {
    RelayPost,
    KeyConfiguration,
    KeyFallback,
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

impl From<RoundTripError> for crate::error::SlipstreamError {
    fn from(error: RoundTripError) -> Self {
        match error {
            RoundTripError::Transport(detail) => Self::Transport(detail),
            RoundTripError::Decode(_) => Self::MisbehavingServer,
            RoundTripError::RateLimited { detail, .. } => Self::RateLimited(detail),
            RoundTripError::TooLarge(detail) | RoundTripError::ResponseTooLarge(detail) => {
                Self::RequestTooLarge(detail)
            }
        }
    }
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
///
/// The 256th assumes the gateway's 16 KiB chunks (`chunk_size` in the gateway's `hpke.rs`, about
/// 19 bytes of tag and length prefix per chunk, under 1/862; a padded final chunk is at most
/// one more). A gateway that sealed much smaller chunks would need more room here: a body within
/// `max_response_bytes` could otherwise be refused by this ceiling before it is opened.
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

/// Sealed bytes decoded per push of a buffered answer: the gateway's chunk size, so that the
/// decoded total is checked against the caller's ceiling about once per chunk.
const DECODE_SLICE_BYTES: usize = 16 * 1024;

/// The events of an answer as it is decoded, with the running length of its body checked against
/// `max`, the ceiling the caller set (`None`: none): the first `Data` event past it is refused,
/// so no later slice of the sealed answer is decoded and nothing past that event is kept.
struct AnswerEvents {
    events: Vec<ResponseEvent>,
    body_len: usize,
    max: Option<usize>,
}

impl AnswerEvents {
    fn new(max: Option<usize>) -> Self {
        Self {
            events: Vec::new(),
            body_len: 0,
            max,
        }
    }

    fn extend(&mut self, events: Vec<ResponseEvent>) -> Result<(), RoundTripError> {
        for event in events {
            if let ResponseEvent::Data(data) = &event {
                self.body_len += data.len();
                check_response_body(self.body_len, self.max)?;
            }
            self.events.push(event);
        }
        Ok(())
    }
}

/// The opened answer as the [`BhttpResponse`] a round trip returns (header fields as bytes), once
/// its body is checked against `max_response_bytes`, the ceiling the caller set.
fn bhttp_response_within(
    response: zodl_ohttp_client::Response,
    max_response_bytes: Option<usize>,
) -> Result<BhttpResponse, RoundTripError> {
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

#[cfg(test)]
async fn run_exchange_chunked<A, P, PF, R, RF>(
    key: KeyConfig,
    request: &BhttpRequest,
    post: P,
    refetch: R,
) -> Result<(ChunkedResponseDecoder, A), RoundTripError>
where
    A: OuterAnswer,
    P: FnMut(Vec<u8>) -> PF,
    PF: Future<Output = Result<A, HttpsError>>,
    R: FnMut() -> RF,
    RF: Future<Output = Result<KeyConfig, RoundTripError>>,
{
    run_exchange_chunked_observed(key, request, post, refetch, None).await
}

/// The relay POST loop for chunked OHTTP. Returns the decoder and the relay's answer (buffered
/// or streamed, per `post`). **Every post is sealed afresh** (a new ephemeral key, so new
/// ciphertext): the gateway answers a repeated ciphertext with 409. A pre-send transport failure
/// is retried once; an outer 400 or 422 refetches the key and retries once. An answer that a
/// size guard refused ([`HttpsError::TooLarge`]) is final: [`RoundTripError::ResponseTooLarge`],
/// not posted again. Only a success answer can be refused so: an error page is read within a
/// fixed 64 KiB guard and keeps its status (see [`read_error_body`]).
///
/// The caller's dispatch hook is not called here but inside `post`, at the moment the sealed
/// request is handed to the relay connection: until then a post may still fail without having
/// sent anything.
async fn run_exchange_chunked_observed<A, P, PF, R, RF>(
    mut key: KeyConfig,
    request: &BhttpRequest,
    mut post: P,
    mut refetch: R,
    health: Option<&RequestHealth>,
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
        if let Some(health) = health {
            health.boundary(HealthStage::Connection);
        }
        let mut resent = false;
        let (opener, answer) = loop {
            let encoded =
                zodl_ohttp_client::encode_bhttp_request(request, &ClientProfile::SLIPSTREAM.encode)
                    .map_err(|e| {
                        if let Some(health) = health {
                            health.classify(HealthOutcome::ConfigurationFailure);
                        }
                        RoundTripError::Transport(e.to_string())
                    })?;
            let (sealed, opener) = encapsulate_chunked_request(&key, &encoded).map_err(|e| {
                if let Some(health) = health {
                    health.classify(HealthOutcome::ConfigurationFailure);
                }
                RoundTripError::Transport(e.to_string())
            })?;
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
                    if let Some(health) = health {
                        health.boundary(HealthStage::ResponseBody);
                    }
                    return Err(RoundTripError::ResponseTooLarge(detail));
                }
                Err(HttpsError::Read(detail)) => {
                    if let Some(health) = health {
                        // A body read failure does not invalidate a known rejected head.
                        let mut state = health.state.lock().unwrap();
                        if state.1.is_none() {
                            state.0 = HealthStage::ResponseBody;
                        }
                    }
                    return Err(RoundTripError::Transport(detail));
                }
                Err(HttpsError::Configuration(detail)) => {
                    if let Some(health) = health {
                        health.classify(HealthOutcome::ConfigurationFailure);
                    }
                    return Err(RoundTripError::Transport(detail));
                }
                Err(e) => return Err(RoundTripError::Transport(e.into_message())),
            }
        };
        let status = answer.status();
        if let Some(health) = health {
            health.boundary(HealthStage::ResponseHead);
            if status != StatusCode::OK {
                health.classify(classify_outer(status));
            }
        }

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

        // ZIP conformance: only 200 is success, other 2xx treated like 5xx (UNAVAILABLE)
        if status != StatusCode::OK {
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

        // On 200, decapsulate whatever the Content-Type (AEAD authenticates)
        if let Some(media_type) = answer.content_type() {
            tracing::debug!("ohttp: response media type: {media_type}");
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
    fn new(mut header_fields: HeaderMap) -> Self {
        header_fields.remove(OHTTP_OUTCOME_HEADER);
        header_fields.remove(OHTTP_OUTCOME_AUTH_HEADER);
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
            ) && name != OHTTP_OUTCOME_HEADER
                && name != OHTTP_OUTCOME_AUTH_HEADER
            {
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
            Err(PumpError::Transport(e) | PumpError::TooLarge(e)) => {
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

/// A pooled HTTP/2 sender to the relay, when its connection was opened, and how it is doing.
#[derive(Clone)]
struct PooledH2 {
    sender: http2::SendRequest<Full<Bytes>>,
    /// Identifies the connection, so a pool entry is only removed by calls or tasks of the
    /// connection it holds, never once a newer one has replaced it.
    id: u64,
    opened: std::time::Instant,
    activity: Arc<H2Activity>,
}

/// The next [`PooledH2::id`].
static NEXT_H2_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The pooled HTTP/2 relay connections of one client, by `host:port`.
type H2Pool = Mutex<HashMap<String, PooledH2>>;

impl PooledH2 {
    /// A connection that is about to be pooled under `key` in `pool`. Once it has had no call
    /// in flight for [`H2_IDLE_REUSE`] it leaves `pool` by itself (one task per connection,
    /// [`H2Activity::schedule_idle_eviction`]),
    /// so an idle connection nothing will reuse does not stay open (and, direct, keep sending
    /// TCP keep-alive probes). `pool` is `None` for a connection that is not pooled.
    fn new(
        sender: http2::SendRequest<Full<Bytes>>,
        pool: Option<(&Arc<H2Pool>, String)>,
        idle_limit: Option<Duration>,
    ) -> Self {
        let id = NEXT_H2_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let activity = Arc::new(H2Activity::new(
            pool.filter(|_| idle_limit.is_some())
                .map(|(pool, key)| (Arc::downgrade(pool), key, id)),
            idle_limit,
        ));
        activity.schedule_idle_eviction();
        Self {
            sender,
            id,
            opened: std::time::Instant::now(),
            activity,
        }
    }

    /// Whether a new call may use this connection: open, not past its age limit (Tor off), not
    /// dead or stalled ([`H2_STALL_AFTER`]), and not idle for [`H2_IDLE_REUSE`] or longer.
    fn reusable(&self, is_tor: bool) -> bool {
        !self.sender.is_closed()
            && (is_tor || self.opened.elapsed() < H2_MAX_CONNECTION_AGE)
            && self.activity.usable()
    }

    /// Sends `req` on this connection, counting the call in flight until its response body ends
    /// or is dropped, and telling the connection when the call waits on the network and when its
    /// head and frames arrive ([`H2Activity`]). That is how a connection that died silently is
    /// found: once a waiting call has seen nothing arrive for its bound ([`H2_STALL_AFTER`],
    /// [`H2_LONG_POLL_STALL_AFTER`] for the long poll), new calls dial a new connection, and a
    /// prompt call given up while still waiting marks the connection dead.
    async fn send(
        &mut self,
        req: Request<Full<Bytes>>,
        head_wait: HeadWait,
    ) -> Result<http::Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let mut in_flight = self.activity.start(head_wait);
        let response = match self.sender.send_request(req).await {
            Ok(response) => response,
            Err(e) => {
                // An error is an answer: the connection said something (the caller unpools it).
                in_flight.arrived();
                in_flight.answered = true;
                return Err(e);
            }
        };
        // The head arrived; the call waits again only when its reader asks for a body frame.
        in_flight.head_arrived = true;
        in_flight.arrived();
        Ok(response.map(|inner| TrackedBody { inner, in_flight }.boxed()))
    }
}

/// What the calls on one pooled connection show about it: how many are in flight, how many of
/// each kind are waiting on the network right now, since when none has been in flight, when a
/// frame last arrived, and whether a call was given up unanswered on it.
struct H2Activity {
    in_flight: std::sync::atomic::AtomicUsize,
    dead: std::sync::atomic::AtomicBool,
    times: std::sync::Mutex<H2Times>,
    /// The pool, key and id of the pooled connection, for the idle eviction.
    evict: Option<(std::sync::Weak<H2Pool>, String, u64)>,
    /// How long the connection may sit idle and still be reused ([`H2_IDLE_REUSE`] direct,
    /// `None` over Tor: see [`H2_IDLE_REUSE`]).
    idle_limit: Option<Duration>,
}

struct H2Times {
    /// Calls waiting for their head, or for a body frame they have asked for, by
    /// [`HeadWait::index`]. A call whose reader has a frame and has not asked for the next one is
    /// not waiting: its silence is the reader's, not the connection's.
    waiting: [usize; 2],
    /// When the first of the calls of each kind now waiting started to wait.
    waiting_since: [std::time::Instant; 2],
    /// When a response head or body frame last arrived.
    last_frame: std::time::Instant,
    /// When the connection last had no call in flight (or was opened).
    idle_since: std::time::Instant,
}

impl H2Times {
    /// How long the waiting calls of `kind` have seen nothing arrive.
    fn silence(&self, kind: HeadWait) -> Duration {
        let i = kind.index();
        self.last_frame.max(self.waiting_since[i]).elapsed()
    }

    /// Whether calls of `kind` are waiting and have seen nothing arrive for their stall bound.
    fn stalled(&self, kind: HeadWait) -> bool {
        self.waiting[kind.index()] > 0 && self.silence(kind) >= kind.stall_after()
    }
}

impl H2Activity {
    fn new(
        evict: Option<(std::sync::Weak<H2Pool>, String, u64)>,
        idle_limit: Option<Duration>,
    ) -> Self {
        let now = std::time::Instant::now();
        Self {
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            dead: std::sync::atomic::AtomicBool::new(false),
            times: std::sync::Mutex::new(H2Times {
                waiting: [0; 2],
                waiting_since: [now; 2],
                last_frame: now,
                idle_since: now,
            }),
            evict,
            idle_limit,
        }
    }

    /// The pool handed the connection to a caller that has not started its call yet (it still
    /// waits for the connection to be ready). Counts as use, under the pool lock, so the idle
    /// eviction (which checks under the same lock) cannot take out a connection a call is about
    /// to go to.
    fn handed_out(&self) {
        self.times().idle_since = std::time::Instant::now();
    }

    /// Whether the connection has had no call in flight for [`H2_IDLE_REUSE`].
    fn idle(&self) -> bool {
        self.idle_limit.is_some_and(|limit| {
            self.in_flight.load(std::sync::atomic::Ordering::Acquire) == 0
                && self.times().idle_since.elapsed() >= limit
        })
    }

    /// Starts the one task that takes the connection out of its pool once it has had no call
    /// in flight for [`H2_IDLE_REUSE`]. The task wakes when the connection would reach that
    /// idle time (or after [`H2_IDLE_REUSE`] while it is busy), and ends once it has removed
    /// the entry, or the entry is no longer this connection, or the connection is gone. Needs a
    /// tokio runtime; without one the connection only leaves the pool when replaced.
    fn schedule_idle_eviction(self: &Arc<Self>) {
        let Some((pool, key, id)) = self.evict.clone() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let activity = Arc::downgrade(self);
        runtime.spawn(async move {
            loop {
                let wait = match activity.upgrade() {
                    Some(a) if a.in_flight.load(std::sync::atomic::Ordering::Acquire) == 0 => {
                        H2_IDLE_REUSE.saturating_sub(a.times().idle_since.elapsed())
                    }
                    Some(_) => H2_IDLE_REUSE,
                    None => return,
                };
                tokio::time::sleep(wait + Duration::from_secs(1)).await;
                let (Some(pool), Some(activity)) = (pool.upgrade(), activity.upgrade()) else {
                    return;
                };
                let mut pool = pool.lock().await;
                if !pool.get(&key).is_some_and(|e| e.id == id) {
                    return;
                }
                if activity.idle() {
                    pool.remove(&key);
                    tracing::debug!(pool_key = %key, "ohttp: idle relay connection left the pool");
                    return;
                }
            }
        });
    }

    fn times(&self) -> std::sync::MutexGuard<'_, H2Times> {
        self.times.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Counts one call in flight until the returned guard drops (when its response body ends or
    /// is dropped, or the call fails). The call starts out waiting for its head.
    fn start(self: &Arc<Self>, head_wait: HeadWait) -> H2InFlight {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let mut call = H2InFlight {
            activity: Arc::clone(self),
            kind: head_wait,
            waiting: false,
            waiting_since: std::time::Instant::now(),
            head_arrived: false,
            answered: false,
        };
        call.wait();
        call
    }

    /// The body pump gave a call up after [`CHUNK_IDLE_TIMEOUT`] without a frame: marks the
    /// connection dead unless a frame for any call arrived after `since`, when the pump started
    /// to wait. The call's own drop may not: the pump's timer starts before the body is polled,
    /// so when it fires the call has been waiting a little less than its bound.
    fn given_up_silent_since(&self, since: std::time::Instant) {
        // Under `times`, like `H2InFlight::drop` (see `usable`).
        let times = self.times();
        if times.last_frame <= since {
            self.dead.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Whether new calls may still go to this connection: not dead, not idle for
    /// [`H2_IDLE_REUSE`], and not stalled (calls waiting on it while nothing has arrived for
    /// their stall bound).
    fn usable(&self) -> bool {
        use std::sync::atomic::Ordering;
        // One snapshot: `H2InFlight::drop` marks the connection dead, takes the call off
        // `in_flight` and resets `idle_since` while holding `times`, so `dead` is read under the
        // same lock. Read before taking it, a lookup racing the last stalled call's drop could
        // combine the old `dead == false` with the new idle state and hand out a dead connection.
        let times = self.times();
        if self.dead.load(Ordering::Acquire) {
            return false;
        }
        if self.in_flight.load(Ordering::Acquire) == 0 {
            return self
                .idle_limit
                .is_none_or(|limit| times.idle_since.elapsed() < limit);
        }
        !times.stalled(HeadWait::Prompt) && !times.stalled(HeadWait::LongPoll)
    }
}

/// One call in flight on a pooled connection (see [`H2Activity::start`]).
struct H2InFlight {
    activity: Arc<H2Activity>,
    kind: HeadWait,
    /// Whether the call is waiting on the network (counted in `H2Times::waiting`).
    waiting: bool,
    /// When the call last started waiting.
    waiting_since: std::time::Instant,
    /// Whether the response head arrived: the call now waits for body frames.
    head_arrived: bool,
    /// Whether the connection answered the call: its body ended, or an error came back.
    answered: bool,
}

impl H2InFlight {
    /// How long the connection must have been silent when the call is given up while waiting
    /// for that to mark it dead. A prompt call: [`H2_DEAD_IF_GIVEN_UP_AFTER`]. A long poll
    /// still waiting for its head: [`H2_LONG_POLL_STALL_AFTER`], the longest silence a healthy
    /// gateway allows. A long poll in its body: [`CHUNK_IDLE_TIMEOUT`], after which the body
    /// pump gives the stream up as dead, before the long-poll bound could be reached.
    fn dead_if_given_up_after(&self) -> Duration {
        match (self.kind, self.head_arrived) {
            (HeadWait::Prompt, _) => H2_DEAD_IF_GIVEN_UP_AFTER,
            (HeadWait::LongPoll, false) => H2_LONG_POLL_STALL_AFTER,
            (HeadWait::LongPoll, true) => CHUNK_IDLE_TIMEOUT,
        }
    }

    /// The call is waiting on the network. The first waiter of its kind starts that kind's
    /// silence clock, so earlier silence (a quiet long poll, a reader that paused) does not count
    /// against it.
    fn wait(&mut self) {
        if self.waiting {
            return;
        }
        let i = self.kind.index();
        let now = std::time::Instant::now();
        let mut times = self.activity.times();
        if times.waiting[i] == 0 {
            times.waiting_since[i] = now;
        }
        times.waiting[i] += 1;
        self.waiting = true;
        self.waiting_since = now;
    }

    /// Something arrived for the call: it no longer waits until its reader asks again.
    fn arrived(&mut self) {
        let mut times = self.activity.times();
        times.last_frame = std::time::Instant::now();
        if self.waiting {
            times.waiting[self.kind.index()] -= 1;
            self.waiting = false;
        }
    }
}

impl Drop for H2InFlight {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        let a = &self.activity;
        let mut times = a.times();
        if self.waiting {
            // Given up while waiting on the network, unanswered, with the connection silent (no
            // frame for any call) for the call's bound (`dead_if_given_up_after`): a prompt call
            // marks the connection dead after a short silence (it may have died just before the
            // call's deadline), a long poll only after a silence no healthy gateway, or the body
            // pump, accepts. The silence is the connection's now, counted from the later of the
            // last frame and the call starting to wait: a frame for another call shortly before
            // keeps the connection alive, one long before does not, and a call cut on purpose
            // while its data was flowing (a fetch kick) leaves it alone. Without this, the last
            // waiter leaving would make a stalled connection idle, and so reusable, again.
            let silent_for = times.last_frame.max(self.waiting_since).elapsed();
            if !self.answered && silent_for >= self.dead_if_given_up_after() {
                a.dead.store(true, Ordering::Release);
            }
            times.waiting[self.kind.index()] -= 1;
        }
        if a.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            times.idle_since = std::time::Instant::now();
        }
    }
}

/// A response body that keeps its call counted in flight on the pooled connection until the
/// body ends or is dropped, and tells the connection when the call waits on the network and
/// when a frame arrives.
struct TrackedBody {
    inner: Incoming,
    in_flight: H2InFlight,
}

impl hyper::body::Body for TrackedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Pending => this.in_flight.wait(),
            Poll::Ready(Some(Ok(_))) => this.in_flight.arrived(),
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                // The end, or an error frame (a reset stream): either way the connection answered.
                this.in_flight.arrived();
                this.in_flight.answered = true;
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

struct OhttpClient {
    gateway_host: String,
    relay_url: String,
    /// The configuration of the gateway's network alone ([`gateway_configuration`]): the
    /// network, signing key and keys DNS name its key configuration is checked and looked up
    /// under. None at all for a host that is not a configured gateway, whose client can only use
    /// a key it is given.
    ohttp: OhttpNetworks,
    relay: HttpsTarget,
    key_config: Mutex<Option<CachedKey>>,
    tls: Arc<rustls::ClientConfig>,
    dialer: Dialer,
    /// One multiplexed HTTP/2 connection per `host:port`, shared by all concurrent RPCs. Opening a
    /// TCP+TLS connection per call is both slow and, on the Android emulator's user-mode network
    /// stack, a reliable way to crash qemu under connection churn. Over Tor this matters even
    /// more: every new connection would be a new circuit build.
    /// Each with the time it was opened, see [`H2_MAX_CONNECTION_AGE`].
    h2_pool: Arc<H2Pool>,
    /// Per-key lock to prevent concurrent dials to the same target (single-flight semantics).
    /// Concurrent callers that find no live connection wait for one in-progress dial to complete
    /// and share its resulting sender, so the connection storm (70 dials in seconds with 70
    /// concurrent GetTransaction calls) never happens.
    dial_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Optional client trace ID generator. When set, every relay POST carries X-Client-Trace-Id.
    /// Only present when the `client-trace` feature is enabled.
    #[cfg(feature = "client-trace")]
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
        networks: &OhttpNetworks,
        gateway_host: &str,
        relay_url: &str,
        dialer: Dialer,
        client_trace_prefix: Option<String>,
        profile: ClientProfile,
    ) -> Result<Self, String> {
        // Without `client-trace` the prefix is dropped: release builds never send the header.
        #[cfg(not(feature = "client-trace"))]
        drop(client_trace_prefix);
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
        // Fresh connections must not carry a TLS session identity across connection rotations
        // or isolated Tor circuits. Keep normal certificate and hostname verification.
        tls.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            gateway_host: gateway_host.to_string(),
            relay_url: relay_url.to_string(),
            ohttp: gateway_configuration(networks, gateway_host),
            relay: parse_https(relay_url)?,
            key_config: Mutex::new(None),
            tls: Arc::new(tls),
            dialer,
            h2_pool: Arc::new(Mutex::new(HashMap::new())),
            dial_locks: Mutex::new(HashMap::new()),
            #[cfg(feature = "client-trace")]
            client_trace: client_trace_prefix.map(|p| ClientTrace::new(&p, &profile.trace)),
            profile,
        })
    }

    /// TCP (direct or via Tor, per the dialer) + TLS (ALPN h2 preferred) to `target`.
    async fn tls_connect(
        &self,
        target: &HttpsTarget,
    ) -> Result<(tokio_rustls::client::TlsStream<BoxedIo>, bool), HttpsError> {
        let label = self.peer_label(target);
        let io = self
            .dialer
            .dial(&target.host, target.port, label)
            .await
            .map_err(HttpsError::Other)?;
        let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| HttpsError::Configuration(format!("server name: {e}")))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
            .connect(server_name, io)
            .await
            .map_err(|e| HttpsError::classify_tls_error(e, &target.host, label))?;
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        Ok((tls, is_h2))
    }

    /// Pooled HTTP/2 sender for `target`, (re)connecting when there is none or it has closed.
    /// Returns `None` if the server does not negotiate h2 (caller falls back to HTTP/1.1).
    /// Single-flight per pool key: concurrent callers that find no live connection wait for
    /// one in-progress dial to complete and share its resulting sender (no connection storm).
    /// Tor-dialer clients are never cached across calls (fresh client per call) to preserve
    /// circuit isolation — this single-flight applies WITHIN one client's concurrent calls only.
    async fn h2_sender(&self, target: &HttpsTarget) -> Result<Option<PooledH2>, HttpsError> {
        let key = format!("{}:{}", target.host, target.port);

        // Fast path: check the pool without holding the dial lock.
        {
            let pool = self.h2_pool.lock().await;
            if let Some(entry) = pool.get(&key)
                && entry.reusable(self.dialer.is_tor())
            {
                entry.activity.handed_out();
                return Ok(Some(entry.clone()));
            }
        }

        // Slow path: acquire the per-key dial lock so that only one caller dials at a time.
        // Other concurrent callers wait here, then check the pool again (the first caller
        // has likely filled it by then). This prevents the connection storm.
        let dial_lock = {
            let mut locks = self.dial_locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _guard = dial_lock.lock().await;

        // Re-check the pool after acquiring the dial lock: a concurrent caller may have
        // dialed already while we waited.
        {
            let pool = self.h2_pool.lock().await;
            if let Some(entry) = pool.get(&key)
                && entry.reusable(self.dialer.is_tor())
            {
                entry.activity.handed_out();
                return Ok(Some(entry.clone()));
            }
        }

        // No live connection found: dial. The guard ensures only one caller per key reaches here.
        let (tls, is_h2) = self.tls_connect(target).await?;
        if !is_h2 {
            return Ok(None);
        }
        // A dead pooled connection (mobile network handoff: the TCP connection silently stops,
        // nothing errors) must stop taking calls before the engine's 30 s deadline, or every
        // call multiplexed on it waits that deadline out and the retries find the same dead
        // connection (device, hotspot: 23 tree states timed out together). The frames the calls
        // receive tell (`PooledH2::send`, `PooledH2::reusable`, H2_STALL_AFTER).
        //
        // No HTTP/2 keep-alive PINGs. hyper closes a connection whose PING answer is late even
        // while DATA keeps arriving (in `PingSent` it no longer looks at the read time), and on
        // a slow link the answer queues behind the data of every relay connection on that link:
        // with a 10 s, then 30 s timeout a phone over Tor on a ~2 Mbit/s link lost healthy
        // connections every 30 to 60 s, failing every block stream on them at once
        // (`KeepAliveTimedOut`, then "error reading a body from connection: broken pipe";
        // device tests 2026-10-30). No timeout is both long enough for that queue and short
        // enough to find a dead connection in time. A connection no longer pooled closes once
        // its last call ends (or its reader's idle timeout gives the call up) and its sender is
        // dropped; an idle one is never reused
        // (H2_IDLE_REUSE), so it needs no PING to keep a NAT entry warm either.
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|e| {
                let label = self.peer_label(target);
                HttpsError::Other(format!(
                    "h2 handshake {label}: {}",
                    redact_host(e, &target.host, label)
                ))
            })?;
        let host = target.host.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(host = %host, err = ?e, "ohttp: h2 connection ended");
            }
        });
        tracing::info!(
            via_tor = self.dialer.is_tor(),
            "ohttp: opened pooled h2 connection"
        );
        // Over Tor an idle connection stays pooled: a new one costs a stream and a TLS handshake
        // through a circuit that, on a slow link, often takes several 8 s dial attempts (device
        // test 2026-10-31: evicting idle Tor connections after 30 s made a pass fail on three
        // timed-out dials). A connection whose guard died while idle is found by its next call
        // instead (H2_STALL_AFTER, then H2_DEAD_IF_GIVEN_UP_AFTER).
        let idle_limit = (!self.dialer.is_tor()).then_some(H2_IDLE_REUSE);
        let entry = PooledH2::new(sender, Some((&self.h2_pool, key.clone())), idle_limit);
        let mut pool = self.h2_pool.lock().await;
        pool.insert(key, entry.clone());
        Ok(Some(entry))
    }

    /// Takes connection `id` out of the pool, unless a newer one has replaced it under
    /// `pool_key`. Returns whether it was removed.
    async fn unpool(&self, pool_key: &str, id: u64) -> bool {
        let mut pool = self.h2_pool.lock().await;
        let same = pool.get(pool_key).is_some_and(|e| e.id == id);
        if same {
            pool.remove(pool_key);
        }
        same
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
    /// The caller decides, and seals afresh. The body of a success answer is read by
    /// [`read_body_capped`] through `guard`: a declared length past the size cap, or the first
    /// frame that goes past it, ends the exchange as [`HttpsError::TooLarge`]. The body of any
    /// other status (an error page) is read by [`read_error_body`] within a fixed 64 KiB guard,
    /// cut there rather than refused, so the answer keeps its status whatever `guard` allows.
    ///
    /// `on_send` is called once, right before the request is handed to the connection: on h2
    /// when the connection is ready, on HTTP/1.1 when TLS and the handshake are done. A failure
    /// before that point (connect, TLS, handshake, a connection that is not ready) never calls
    /// it, so it marks the exchanges that may have reached the far end.
    #[allow(clippy::too_many_arguments)] // Explicit request inputs and per-attempt health attribution.
    async fn https_once<F: Fn()>(
        &self,
        target: &HttpsTarget,
        method: Method,
        headers: &[(&'static str, String)],
        body: Vec<u8>,
        guard: SizeGuard,
        on_send: &F,
        health: Option<&RequestHealth>,
        role: HttpsHealthRole,
    ) -> Result<RelayAnswer, HttpsError> {
        let head_wait = HeadWait::Prompt;
        let req = self
            .build_request(target, method, headers, body)
            .map_err(HttpsError::Configuration)?;
        let pool_key = format!("{}:{}", target.host, target.port);
        let resp = match self.h2_sender(target).await? {
            Some(mut entry) => {
                if let Err(e) = entry.sender.ready().await {
                    self.unpool(&pool_key, entry.id).await;
                    let label = self.peer_label(target);
                    return Err(HttpsError::PreSend(format!(
                        "h2 ready {label}: {}",
                        redact_host(e, &target.host, label)
                    )));
                }
                on_send();
                match entry.send(req, head_wait).await {
                    Ok(r) => r,
                    Err(e) => {
                        self.unpool(&pool_key, entry.id).await;
                        return Err(HttpsError::classify_send_error(
                            e,
                            &target.host,
                            self.peer_label(target),
                        ));
                    }
                }
            }
            None => {
                let (tls, _) = self.tls_connect(target).await?;
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
                    .map_err(|e| {
                        let label = self.peer_label(target);
                        HttpsError::Other(format!(
                            "send {label}: {}",
                            redact_host(e, &target.host, label)
                        ))
                    })?
                    .map(|b| b.boxed())
            }
        };
        let (parts, body) = resp.into_parts();
        let relay_exchange = match role {
            HttpsHealthRole::RelayPost | HttpsHealthRole::KeyConfiguration => true,
            HttpsHealthRole::KeyFallback => false,
        };
        if relay_exchange {
            self.note_retry_after(parts.status, &parts.headers);
        }
        let rejected_head = match role {
            HttpsHealthRole::RelayPost => parts.status != StatusCode::OK,
            HttpsHealthRole::KeyConfiguration => {
                !self.profile.outer.success.accepts(parts.status.as_u16())
            }
            HttpsHealthRole::KeyFallback => false,
        };
        if rejected_head
            && parts.status != StatusCode::TOO_MANY_REQUESTS
            && let Some(health) = health
        {
            // Keep the head provisional across key/freshness recovery, but do not
            // erase a known rejection if its error page outlives an owner deadline.
            if health.state.lock().unwrap().0 != HealthStage::KeyConfiguration {
                health.boundary(HealthStage::ResponseHead);
            }
            health.classify(classify_outer(parts.status));
        }
        if relay_exchange
            && parts.status == StatusCode::TOO_MANY_REQUESTS
            && let Some(health) = health
        {
            let stage = health.state.lock().unwrap().0;
            let stage = if stage == HealthStage::KeyConfiguration {
                stage
            } else {
                HealthStage::ResponseHead
            };
            health.finish(rate_limit_outcome(self, retry_after(&parts.headers)), stage);
        }
        let declared_len = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        // Only a success answer is read through the caller's guard: an error page is read
        // within the fixed small guard of `read_error_body`, so that its status, not its length,
        // is what the caller learns.
        let bytes = if parts.status.is_success() {
            read_body_capped(body, declared_len, guard, self.peer_label(target)).await?
        } else {
            read_error_body(body, &target.host).await
        };
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

    #[cfg(test)]
    async fn post_sealed<F: Fn()>(
        &self,
        body: Vec<u8>,
        guard: SizeGuard,
        on_send: &F,
    ) -> Result<RelayAnswer, HttpsError> {
        self.post_sealed_observed(body, guard, on_send, None).await
    }

    /// POST one sealed chunked request body to the relay. Returns buffered response, read
    /// through `guard` (the caller's choice, so a request that allows only a small answer does
    /// not buffer a large one). `on_send` is called as [`Self::https_once`] describes, so not
    /// when the relay's pause stops the post or the connection cannot be made ready.
    async fn post_sealed_observed<F: Fn()>(
        &self,
        body: Vec<u8>,
        guard: SizeGuard,
        on_send: &F,
        health: Option<&RequestHealth>,
    ) -> Result<RelayAnswer, HttpsError> {
        self.relay_pause_before_post()?;
        #[cfg(feature = "client-trace")]
        let trace = self.client_trace.as_ref().map(|t| t.next());
        #[cfg(not(feature = "client-trace"))]
        let trace: Option<String> = None;
        let headers = self.profile.headers.relay_post(trace.as_deref());
        self.https_once(
            &self.relay,
            Method::POST,
            &headers,
            body,
            guard,
            on_send,
            health,
            HttpsHealthRole::RelayPost,
        )
        .await
    }

    /// POST one sealed chunked request body to the relay. Returns the response with its body
    /// unread. `on_send` is called as for [`Self::post_sealed_observed`].
    async fn post_sealed_stream<F: Fn()>(
        &self,
        body: Vec<u8>,
        on_send: &F,
        head_wait: HeadWait,
    ) -> Result<RelayStream, HttpsError> {
        self.relay_pause_before_post()?;
        #[cfg(feature = "client-trace")]
        let trace = self.client_trace.as_ref().map(|t| t.next());
        #[cfg(not(feature = "client-trace"))]
        let trace: Option<String> = None;
        let headers = self.profile.headers.relay_post(trace.as_deref());
        self.https_once_stream(
            &self.relay,
            Method::POST,
            &headers,
            body,
            on_send,
            head_wait,
        )
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
        head_wait: HeadWait,
    ) -> Result<RelayStream, HttpsError> {
        let req = self
            .build_request(target, method, headers, body)
            .map_err(HttpsError::Configuration)?;
        let pool_key = format!("{}:{}", target.host, target.port);
        let (resp, activity) = match self.h2_sender(target).await? {
            Some(mut entry) => {
                let act = Some(Arc::clone(&entry.activity));
                if let Err(e) = entry.sender.ready().await {
                    self.unpool(&pool_key, entry.id).await;
                    let label = self.peer_label(target);
                    return Err(HttpsError::PreSend(format!(
                        "h2 ready {label}: {}",
                        redact_host(e, &target.host, label)
                    )));
                }
                on_send();
                match entry.send(req, head_wait).await {
                    Ok(r) => (r, act),
                    Err(e) => {
                        self.unpool(&pool_key, entry.id).await;
                        return Err(HttpsError::classify_send_error(
                            e,
                            &target.host,
                            self.peer_label(target),
                        ));
                    }
                }
            }
            None => {
                let (tls, _) = self.tls_connect(target).await?;
                let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .map_err(|e| HttpsError::Other(format!("http1 handshake: {e}")))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                on_send();
                let resp = sender
                    .send_request(req)
                    .await
                    .map_err(|e| {
                        let label = self.peer_label(target);
                        HttpsError::Other(format!(
                            "send {label}: {}",
                            redact_host(e, &target.host, label)
                        ))
                    })?
                    .map(|b| b.boxed());
                (resp, None)
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
            activity,
        })
    }

    /// The gateway's key configuration: the cached one while it is fresh, else fetched through
    /// the relay, with the DNS fallback of [`Self::key_config_from_dns`] when the relay fetch or
    /// its verification fails. A relay 429, or the relay's running pause, is
    /// [`RoundTripError::RateLimited`] as on a post, without the DNS fallback.
    #[cfg(test)]
    async fn key_config(&self, refresh: bool) -> Result<KeyConfig, RoundTripError> {
        self.key_config_observed(refresh, None).await
    }

    async fn key_config_observed(
        &self,
        refresh: bool,
        health: Option<&RequestHealth>,
    ) -> Result<KeyConfig, RoundTripError> {
        if let Some(health) = health {
            health.boundary(HealthStage::KeyConfiguration);
        }
        let shared_key = self.shared_key();
        {
            let mut cached = self.key_config.lock().await;
            if !refresh {
                let now = unix_now().map_err(RoundTripError::Transport)?;
                if let Some(k) = cached.as_ref() {
                    if self.profile.cache.is_fresh(Some(k.not_after), now) {
                        return Ok(k.config);
                    }
                    tracing::info!(
                        network = ?gateway_network(&self.ohttp, &self.gateway_host).ok(),
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

        // Resolve the configured signer before dispatch: a missing trust anchor cannot
        // be repaired by either a relay fetch or DNS fallback. A gateway's network has one
        // exactly when the configuration has that network.
        gateway_network(&self.ohttp, &self.gateway_host).map_err(|detail| {
            if let Some(health) = health {
                health.classify(HealthOutcome::ConfigurationFailure);
            }
            RoundTripError::Transport(detail)
        })?;

        // The relay's running pause, and a relay or signed config URL that is not https,
        // fail closed before any request and without the DNS fallback.
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
                        health,
                        HttpsHealthRole::KeyConfiguration,
                    )
                    .await
                {
                    Ok(answer) => break answer,
                    Err(HttpsError::PreSend(e)) if !resent => {
                        resent = true;
                        tracing::debug!(err = %e, "ohttp: key config fetch failed before send; retrying");
                    }
                    Err(HttpsError::Configuration(detail) | HttpsError::TooLarge(detail)) => {
                        if let Some(health) = health { health.classify(HealthOutcome::ConfigurationFailure); }
                        return Err(RoundTripError::Transport(detail));
                    }
                    Err(e) => return Err(RoundTripError::Transport(e.into_message())),
                }
            };
            if !self.profile.outer.success.accepts(answer.status.as_u16()) {
                if let Some(health) = health { health.classify(classify_outer(answer.status)); }
                return Err(RoundTripError::key_fetch_refused(
                    answer.status,
                    answer.retry_after,
                ));
            }

            let now = unix_now().map_err(RoundTripError::Transport)?;
            let cfg = open_signed_keys(
                &self.ohttp,
                &self.profile,
                &answer.body,
                &self.gateway_host,
                now,
            )
            .map_err(|e| {
                    if let Some(health) = health { health.classify(HealthOutcome::ConfigurationFailure); }
                    RoundTripError::Transport(format!("relay envelope verification failed: {e}"))
                })?;
            tracing::debug!("ohttp: key config fetched and verified from relay");
            Ok(cfg)
        }
        .await;

        let cfg = match relay_fetch_and_verify {
            Ok(cfg) => cfg,
            Err(relay_err) => self.key_config_from_dns_observed(relay_err, health).await?,
        };

        tracing::info!(
            network = ?gateway_network(&self.ohttp, &self.gateway_host).ok(),
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
    /// outside the configuration (no DNS record to fall back to), or `relay_err` has no
    /// fallback ([`relay_failure_has_dns_fallback`]), `relay_err` is returned. A relay pause begun
    /// meanwhile (another request's 429) holds the resolvers too.
    #[cfg(test)]
    async fn key_config_from_dns(
        &self,
        relay_err: RoundTripError,
    ) -> Result<CachedKey, RoundTripError> {
        self.key_config_from_dns_observed(relay_err, None).await
    }

    async fn key_config_from_dns_observed(
        &self,
        relay_err: RoundTripError,
        health: Option<&RequestHealth>,
    ) -> Result<CachedKey, RoundTripError> {
        if relay_failure_has_dns_fallback(&relay_err)
            && gateway_network(&self.ohttp, &self.gateway_host).is_ok()
        {
            tracing::info!(err = %relay_err, "ohttp: relay key config failed, trying DNS");
        }
        self.key_config_from_dns_with(relay_err, health, |envelope| {
            open_signed_keys(
                &self.ohttp,
                &self.profile,
                envelope,
                &self.gateway_host,
                unix_now()?,
            )
        })
        .await
    }

    async fn key_config_from_dns_with<F>(
        &self,
        relay_err: RoundTripError,
        health: Option<&RequestHealth>,
        verify: F,
    ) -> Result<CachedKey, RoundTripError>
    where
        F: Fn(&[u8]) -> Result<CachedKey, String>,
    {
        if !relay_failure_has_dns_fallback(&relay_err) {
            return Err(relay_err);
        }
        let Ok(network) = gateway_network(&self.ohttp, &self.gateway_host) else {
            return Err(relay_err);
        };
        let Some(dns_name) = self.ohttp.get(network).map(OhttpConfig::keys_dns_name) else {
            return Err(relay_err);
        };
        for resolver in DOH_RESOLVERS {
            self.check_relay_pause()?;
            let Some(doh_url) = doh_query_url(&self.ohttp, resolver, network) else {
                return Err(relay_err);
            };
            tracing::debug!(resolver = %resolver, dns_name = %dns_name, "ohttp: trying DoH resolver");

            let dns_result = async {
                let doh_body = self.fetch_dns_key_config(&doh_url, health).await?;
                let envelope = envelope_from_doh_json(&self.ohttp, &doh_body, network)
                    .map_err(|e| format!("parse error: {}", e))?;
                verify(&envelope).map_err(|e| format!("verification failed: {}", e))
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
    async fn fetch_dns_key_config(
        &self,
        doh_url: &str,
        health: Option<&RequestHealth>,
    ) -> Result<Vec<u8>, String> {
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
                health,
                HttpsHealthRole::KeyFallback,
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

    /// How an error message names the peer of `target`: `relay` for this client's relay, its
    /// configured gateway as [`gateway_label`], any other host (a DNS resolver) as `dns-resolver`.
    /// The host is an endpoint value of the configuration and goes to debug lines only.
    fn peer_label(&self, target: &HttpsTarget) -> &'static str {
        if target.host.eq_ignore_ascii_case(&self.relay.host) {
            "relay"
        } else if relay_for(&self.ohttp, &target.host).is_some() {
            gateway_label(&self.ohttp, &target.host)
        } else {
            "dns-resolver"
        }
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

    /// Key of this client's verified key configuration in [`SHARED_KEYS`]: its gateway, its
    /// relay ([`Self::backoff_key`]) and the configuration the key is checked under.
    fn shared_key(&self) -> SharedKeyId {
        SharedKeyId {
            gateway_host: self.gateway_host.clone(),
            relay: self.backoff_key(),
            configuration: ConfigurationKey::of(&self.ohttp, &self.gateway_host),
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
    /// waits for it. A 429 without a `Retry-After` (or with one in the HTTP-date form, which is
    /// not parsed) starts the [`DEFAULT_RETRY_AFTER`] pause.
    fn note_retry_after(&self, status: StatusCode, headers: &HeaderMap) {
        if status != StatusCode::TOO_MANY_REQUESTS {
            return;
        }
        let asked = retry_after(headers);
        let wait = asked.unwrap_or(DEFAULT_RETRY_AFTER);
        tracing::warn!(
            wait_secs = wait.as_secs(),
            retry_after_header = asked.is_some(),
            "ohttp: relay rate limit (429); holding requests through it"
        );
        RelayBackoff::global().note(&self.backoff_key(), wait);
    }

    /// [`Self::round_trip_once_observed`], sent once more (sealed afresh) when the gateway refused it
    /// as stale: an inner 400 with `ohttp-freshness: rejected` ("Request freshness" in the
    /// ZIP). That response carries the gateway clock, which the decoder has already learned,
    /// so the second attempt is stamped right even on a device whose clock is off. Never more
    /// than one retry per request.
    #[cfg(test)]
    async fn round_trip<D>(
        &self,
        request: &BhttpRequest,
        max_response_bytes: Option<usize>,
        on_dispatch: D,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        D: Fn(),
    {
        self.round_trip_observed(
            request,
            max_response_bytes,
            on_dispatch,
            Arc::new(RequestHealth::new(self)),
        )
        .await
    }

    async fn round_trip_observed<D>(
        &self,
        request: &BhttpRequest,
        max_response_bytes: Option<usize>,
        on_dispatch: D,
        health: Arc<RequestHealth>,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        D: Fn(),
    {
        let dispatch = once_dispatch(on_dispatch);
        let result = with_freshness_retry(
            || self.round_trip_once_observed(request, max_response_bytes, &dispatch, Some(&health)),
            |r: &BhttpResponse| zodl_ohttp_client::freshness::is_rejection(r.status, &r.headers),
        )
        .await;
        match &result {
            Ok(response) => {
                health.ticket.record_route_usable(HealthStage::Complete);
                let headers = header_map_from_fields(&response.headers);
                health.finish(
                    inner_health(
                        response.status,
                        &headers,
                        self.profile == ClientProfile::SLIPSTREAM,
                        true,
                    )
                    .unwrap_or(HealthOutcome::Usable),
                    HealthStage::Complete,
                );
            }
            Err(error) => health.error(self, error),
        }
        result
    }

    /// Encapsulate + relay + decapsulate with chunked OHTTP. The key configuration is
    /// fetched again, and the request sealed again, when the gateway rejects the request (outer
    /// 400 or 422). Decodes the chunked response and returns the inner message.
    ///
    /// `max_response_bytes` is the largest answer body the caller accepts. The sealed answer is
    /// read through a guard of [`sealed_response_ceiling`] bytes, so one that goes past it is
    /// not buffered further or opened ([`RoundTripError::ResponseTooLarge`]); the body it opens
    /// to is checked against `max_response_bytes` itself as it is decoded ([`AnswerEvents`]).
    /// `None` leaves only the general cap of the client's profile.
    ///
    /// `on_dispatch` is called right before the sealed request is written to the relay
    /// connection, after the relay-pause check and the connection setup (see
    /// [`Self::https_once`]). So a relay pause, a relay that cannot be reached and a connection
    /// that is not ready leave it uncalled, while a failure after it may have reached the relay.
    async fn round_trip_once_observed<D>(
        &self,
        request: &BhttpRequest,
        max_response_bytes: Option<usize>,
        on_dispatch: &D,
        health: Option<&RequestHealth>,
    ) -> Result<BhttpResponse, RoundTripError>
    where
        D: Fn(),
    {
        self.check_relay_pause()?;
        let key = self.key_config_observed(false, health).await?;
        let guard = match max_response_bytes {
            Some(max) => SizeGuard::new(Some(sealed_response_ceiling(max))),
            None => self.profile.limits.response_guard(),
        };
        let this = self;
        let (mut decoder, answer) = run_exchange_chunked_observed(
            key,
            request,
            move |body| this.post_sealed_observed(body, guard, on_dispatch, health),
            move || this.key_config_observed(true, health),
            health,
        )
        .await?;

        if let Some(health) = health {
            health.boundary(HealthStage::ResponseBody);
        }

        // Decode the buffered sealed answer a slice at a time, so that a body past the caller's
        // ceiling is refused as soon as the decoded total crosses it, not once it is decoded whole.
        let mut events = AnswerEvents::new(max_response_bytes);
        for slice in answer.body.chunks(DECODE_SLICE_BYTES) {
            events.extend(
                decoder
                    .push(slice)
                    .map_err(|e| RoundTripError::Decode(e.to_string()))?,
            )?;
        }
        events.extend(decoder.finish().map_err(|e| match e {
            zodl_ohttp_client::Error::Truncated => RoundTripError::Transport(e.to_string()),
            e => RoundTripError::Decode(e.to_string()),
        })?)?;

        // Collect events into a Response and convert to BhttpResponse
        let response = zodl_ohttp_client::collect_response(events.events)
            .map_err(|e| RoundTripError::Decode(e.to_string()))?;
        bhttp_response_within(response, max_response_bytes)
    }

    /// [`Self::round_trip_stream_once_observed`] with the same single retry as [`Self::round_trip_observed`] when
    /// the gateway refused the request as stale. The refusal is known from the head alone, so
    /// nothing of it reaches the caller.
    #[cfg(test)]
    async fn round_trip_stream<D>(
        &self,
        request: BhttpRequest,
        on_dispatch: D,
    ) -> Result<(u16, HeaderMap, EventStream), RoundTripError>
    where
        D: Fn(),
    {
        self.round_trip_stream_observed(request, on_dispatch, Arc::new(RequestHealth::new(self)))
            .await
    }

    async fn round_trip_stream_observed<D>(
        &self,
        request: BhttpRequest,
        on_dispatch: D,
        health: Arc<RequestHealth>,
    ) -> Result<(u16, HeaderMap, EventStream), RoundTripError>
    where
        D: Fn(),
    {
        let dispatch = once_dispatch(on_dispatch);
        // A refused first attempt is dropped (its decoding task ends with the receiver).
        let result = with_freshness_retry(
            || self.round_trip_stream_once_observed(request.clone(), &dispatch, Some(&health)),
            |(status, headers, _): &(u16, HeaderMap, EventStream)| {
                let fields: Vec<(&[u8], &[u8])> = headers
                    .iter()
                    .map(|(k, v)| (k.as_str().as_bytes(), v.as_bytes()))
                    .collect();
                zodl_ohttp_client::freshness::is_rejection(*status, &fields)
            },
        )
        .await;
        match result {
            Ok((status, headers, events)) => {
                health.ticket.record_route_usable(HealthStage::ResponseHead);
                health.boundary(HealthStage::ResponseBody);
                let initial = inner_health(
                    status,
                    &headers,
                    self.profile == ClientProfile::SLIPSTREAM,
                    false,
                );
                if let Some(outcome) = initial {
                    health.finish(outcome, HealthStage::ResponseHead);
                }
                let grpc = self.profile == ClientProfile::SLIPSTREAM;
                let header_status = headers
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let observe_grpc = grpc && initial.is_none();
                if observe_grpc {
                    health.observe_grpc_status(header_status.as_deref());
                }
                let observed = futures_util::stream::unfold(
                    (events, health, header_status),
                    move |(mut events, health, mut status)| async move {
                        use futures_util::StreamExt;
                        let event = events.next().await;
                        match &event {
                            Some(Ok(ResponseEvent::Trailers(fields))) => {
                                if let Some((_, value)) = fields
                                    .iter()
                                    .find(|(name, _)| name.eq_ignore_ascii_case("grpc-status"))
                                {
                                    status = Some(value.clone());
                                    if observe_grpc {
                                        health.observe_grpc_status(status.as_deref());
                                    }
                                }
                            }
                            Some(Ok(ResponseEvent::End)) => {
                                let outcome = if grpc {
                                    grpc_health(status.as_deref())
                                } else {
                                    HealthOutcome::Usable
                                };
                                health.finish(outcome, HealthStage::Complete);
                            }
                            Some(Err(PumpError::Transport(_))) => {
                                health.finish_body_failure(HealthOutcome::TransportUnavailable)
                            }
                            Some(Err(PumpError::Decode(_) | PumpError::TooLarge(_))) | None => {
                                health.finish_body_failure(HealthOutcome::ResponseRejected)
                            }
                            _ => {}
                        }
                        event.map(|event| (event, (events, health, status)))
                    },
                );
                Ok((status, headers, Box::pin(observed)))
            }
            Err(error) => {
                health.error(self, &error);
                Err(error)
            }
        }
    }

    /// Encapsulate + relay + stream-decode with chunked OHTTP. Returns the inner status and
    /// headers once the head has been decoded, and the remaining events (body, trailers, end)
    /// as they are decoded chunk by chunk: the first gRPC message is available before the
    /// response has been received in full. Same exchange loop as [`Self::round_trip_observed`]: every
    /// post is sealed afresh, an outer 400 or 422 refetches the key and retries once.
    /// `on_dispatch` is called as [`Self::round_trip_once_observed`] describes.
    async fn round_trip_stream_once_observed<D>(
        &self,
        request: BhttpRequest,
        on_dispatch: &D,
        health: Option<&RequestHealth>,
    ) -> Result<(u16, HeaderMap, EventStream), RoundTripError>
    where
        D: Fn(),
    {
        use futures_util::stream::StreamExt as _;
        use tokio::sync::mpsc;

        self.check_relay_pause()?;
        let key = self.key_config_observed(false, health).await?;
        let this = self;
        let head_wait = HeadWait::for_path(&request.path);
        let (decoder, answer) = run_exchange_chunked_observed(
            key,
            &request,
            move |body| this.post_sealed_stream(body, on_dispatch, head_wait),
            move || this.key_config_observed(true, health),
            health,
        )
        .await?;

        // Spawn task to decode chunks and forward events with idle timeout
        let (tx, rx) = mpsc::channel::<Result<ResponseEvent, PumpError>>(16);
        let guard = this.profile.limits.response_guard();

        tokio::spawn(pump_chunked_body(
            answer.body,
            decoder,
            guard,
            tx,
            answer.activity,
        ));

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
            Some(Err(PumpError::TooLarge(e))) => {
                if let Some(health) = health {
                    health.classify(HealthOutcome::ResponseRejected);
                }
                return Err(RoundTripError::Transport(e));
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
    async fn handle(
        &self,
        req: Request<Incoming>,
        health: Option<Arc<RequestHealth>>,
    ) -> Response<BoxBody<Bytes, Infallible>> {
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
        let health = health.unwrap_or_else(|| Arc::new(RequestHealth::new(self)));
        // Timeout only for getting the Head (status + headers)
        let (http_status, mut headers, events) = match tokio::time::timeout(
            ROUND_TRIP_TIMEOUT,
            self.round_trip_stream_observed(request, || {}, health.clone()),
        )
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
                health.deadline(HealthStage::ResponseHead);
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
    let mut request = BhttpRequest::new(method, gateway_host.to_ascii_lowercase(), path).body(body);
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

/// An extension call as Binary HTTP (RFC 9292), header names lowercased (ZIP #10: "Header names
/// MUST be lowercase").
fn http_bhttp_request(
    method: &str,
    target: HttpTarget,
    headers: &[(String, String)],
    body: &[u8],
) -> BhttpRequest {
    let mut request = BhttpRequest::new(method, target.host.to_ascii_lowercase(), target.path)
        .scheme(target.scheme)
        .body(body);
    for (name, value) in headers {
        request = request.header(name.to_ascii_lowercase(), value.as_str());
    }
    request
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
/// * `networks` - The application's OHTTP configuration: the gateway's network must have one,
///   which gives the relay, the signing key and the keys DNS name. Without it the call fails
///   before anything is sent.
/// * `gateway_host` - OHTTP gateway hostname (e.g., "ohttp-gateway.example"), in any letter case
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
/// A sealed response larger than the gateway's own 256 MiB cap (plus 1 MiB of framing) is
/// rejected while it is being read, before it is buffered or decrypted.
///
/// # Caching
/// The verified key configuration and HTTP/TLS connections to the relay are cached per gateway
/// host and configuration, avoiding repeated key fetches and TLS handshakes.
#[allow(clippy::too_many_arguments)] // the request's parts, plus where and how it is sent
pub async fn http_round_trip(
    networks: &OhttpNetworks,
    gateway_host: &str,
    network: NetworkType,
    dialer: Dialer,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let (target, relay_url) = http_target_and_relay(networks, gateway_host, network, url)?;
    http_round_trip_via(
        networks,
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
/// The answer is read only up to `max_response_bytes` plus room for its sealed framing (see the
/// argument below). A service that answers with much more fails as
/// [`HttpRoundTripError::ResponseTooLarge`] while the answer is being read, before it is
/// buffered in full or opened. One only a little past the ceiling, within that room, is read and
/// opened first, and then refused by the exact check on its body: the same error.
///
/// `on_dispatch` is called right before the sealed request is written to the relay connection:
/// after the key config fetch, the encapsulation, the relay-pause check and the connection setup.
/// This lets the caller distinguish failures that never sent ciphertext (key fetch,
/// encapsulation, a relay pause, a relay that cannot be reached, a connection that is not ready)
/// from those that may have (a failed write, relay transport, gateway processing).
///
/// # Arguments
/// * `networks` - The application's OHTTP configuration, as for [`http_round_trip`]
/// * `gateway_host` - OHTTP gateway hostname (e.g., "ohttp-gateway.example"), in any letter case
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
///   `max_response_bytes` itself. An outer answer that is not a success (a relay or gateway
///   error page) is read within a fixed 64 KiB guard instead and fails with its status
///   (`Failed`, e.g. "HTTP 429"), never as `ResponseTooLarge`.
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
/// # async fn demo(networks: &zodl_slipstream::ohttp::OhttpNetworks) -> Result<(), String> {
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use zodl_slipstream::ohttp::{
///     Dialer, HttpRoundTripError, NetworkType, http_round_trip_with_dispatch,
/// };
///
/// // `networks`: the application's OHTTP configuration, with mainnet's gateway.
/// let dispatched = AtomicBool::new(false);
/// match http_round_trip_with_dispatch(
///     networks,
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
    networks: &OhttpNetworks,
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
    let (target, relay_url) = http_target_and_relay(networks, gateway_host, network, url)
        .map_err(HttpRoundTripError::Failed)?;
    http_round_trip_via(
        networks,
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

/// What a plain HTTP round trip settles before anything is sent: `networks` configures the
/// gateway, which serves the wallet's network, `url` parses, and the gateway has a relay.
fn http_target_and_relay<'a>(
    networks: &'a OhttpNetworks,
    gateway_host: &str,
    network: NetworkType,
    url: &str,
) -> Result<(HttpTarget, &'a str), String> {
    check_gateway_network(networks, gateway_host, network)?;

    // Parse URL to extract scheme, host, path for BHTTP encoding
    let target = parse_http_target(url)?;

    // Get relay URL for this gateway
    let relay_url =
        relay_for(networks, gateway_host).ok_or("no relay configured for this gateway")?;

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
/// test can point it at a local relay instead of the configured one). The client works under
/// `networks`' configuration of the gateway's network.
/// `max_response_bytes` is the ceiling [`http_round_trip_with_dispatch`] describes; `None` sets
/// none of the caller's, which leaves the general cap of [`http_round_trip`]. `on_dispatch` is
/// called right before the sealed request is written to the relay connection, after the
/// relay-pause check and the connection setup, as [`http_round_trip_with_dispatch`] describes.
/// Setup errors and the 100 s bound are [`HttpRoundTripError::Failed`].
#[allow(clippy::too_many_arguments)] // one seam over the limit; bundling would hide the borrows
async fn http_round_trip_via<D>(
    networks: &OhttpNetworks,
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
        networks,
        gateway_host,
        relay_url,
        dialer,
        get_default_client_trace_prefix(),
        ClientProfile::SLIPSTREAM_HTTP,
    )
    .await
    .map_err(HttpRoundTripError::Failed)?;

    let request = http_bhttp_request(method, target, headers, body);

    let health = Arc::new(RequestHealth::new(&client));

    // Send through OHTTP relay (encapsulate, POST, decapsulate), the whole exchange bounded
    let response = tokio::time::timeout(
        ROUND_TRIP_TIMEOUT,
        client.round_trip_observed(&request, max_response_bytes, on_dispatch, health.clone()),
    )
    .await
    .map_err(|_| {
        health.deadline(HealthStage::ResponseHead);
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

/// [`grpc_error`] carrying an [`OHTTP_OUTCOME_HEADER`]. `LwdTransport` consumes the marker,
/// strips it on every channel and turns it into a typed local outcome only on local-bridge
/// transports; tonic's gRPC client never decodes it into `Status` metadata.
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
pub(crate) mod tests {
    /// The mainnet gateway host of [`example_networks`].
    pub(crate) fn mainnet_gateway() -> &'static str {
        MAINNET_GATEWAY
    }

    /// The testnet gateway host of [`example_networks`].
    pub(crate) fn testnet_gateway() -> &'static str {
        TESTNET_GATEWAY
    }

    pub(crate) fn bridge_outcome_status(outcome: &'static str) -> tonic::Status {
        let mut response = grpc_error_with(GRPC_UNAVAILABLE, "local bridge failure", Some(outcome));
        crate::grpc::bridge_outcome_status(response.headers_mut())
    }

    /// [`open_signed_keys`] under [`fixture_networks`]: the fixture envelopes are signed by a
    /// public synthetic signer, which only the tests configure; production takes its signing key
    /// from the application's configuration into this same verification boundary.
    fn open_fixture_signed_keys(
        profile: &ClientProfile,
        json: &[u8],
        gateway_host: &str,
        now: u64,
    ) -> Result<CachedKey, String> {
        open_signed_keys(&fixture_networks(), profile, json, gateway_host, now)
    }

    use super::*;

    /// The instant `by` before now, for the tests of `H2Activity` (it reads the real clock).
    fn back(by: Duration) -> std::time::Instant {
        std::time::Instant::now()
            .checked_sub(by)
            .expect("the clock is past the test offsets")
    }

    /// Makes every clock of `activity` read `by` ago.
    fn age(activity: &H2Activity, by: Duration) {
        let mut t = activity.times();
        t.last_frame = back(by);
        t.waiting_since = [back(by); 2];
    }

    fn is_dead(activity: &H2Activity) -> bool {
        activity.dead.load(std::sync::atomic::Ordering::Acquire)
    }

    #[test]
    fn a_waiting_prompt_call_with_no_frames_stalls_the_connection() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        assert!(activity.usable(), "just opened");
        let mut call = activity.start(HeadWait::Prompt);
        assert!(
            activity.usable(),
            "a call starting to wait gets the full window"
        );
        age(&activity, H2_STALL_AFTER + Duration::from_secs(1));
        call.waiting_since = back(H2_STALL_AFTER + Duration::from_secs(1));
        assert!(!activity.usable(), "waiting with nothing arriving: stalled");
        drop(call);
        assert!(
            is_dead(&activity),
            "given up while waiting with nothing since: dead"
        );
        assert!(!activity.usable());
    }

    #[test]
    fn a_lookup_racing_the_last_stalled_call_drop_never_sees_it_usable() {
        // Before and after the drop the connection is unusable (stalled, then dead); a lookup
        // during the drop must not see the old `dead == false` with the new idle state.
        let silent = H2_STALL_AFTER.max(H2_DEAD_IF_GIVEN_UP_AFTER) + Duration::from_secs(1);
        let mut accepted = 0usize;
        for _ in 0..20_000 {
            let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
            let mut call = activity.start(HeadWait::Prompt);
            age(&activity, silent);
            call.waiting_since = back(silent);
            assert!(!activity.usable(), "stalled before the drop");
            let probe = Arc::clone(&activity);
            let checker = std::thread::spawn(move || (0..64).filter(|_| probe.usable()).count());
            drop(call);
            accepted += checker.join().expect("checker thread");
            assert!(is_dead(&activity), "given up while stalled: dead");
        }
        assert_eq!(accepted, 0, "a dead connection was reported usable");
    }

    #[test]
    fn a_prompt_call_given_up_after_a_short_silence_marks_the_connection_dead() {
        // The head arrived late, the connection died, and the deadline came before the
        // silence reached the stall bound: the retry must not reuse it.
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut call = activity.start(HeadWait::Prompt);
        call.arrived();
        call.wait();
        activity.times().last_frame = back(H2_DEAD_IF_GIVEN_UP_AFTER + Duration::from_secs(2));
        call.waiting_since = back(H2_DEAD_IF_GIVEN_UP_AFTER + Duration::from_secs(1));
        drop(call);
        assert!(is_dead(&activity));
    }

    #[test]
    fn a_call_cut_on_purpose_right_away_does_not_mark_the_connection_dead() {
        // A fetch kick or stream cut drops a call that was just waiting for its next frame.
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut call = activity.start(HeadWait::Prompt);
        call.arrived();
        call.wait();
        drop(call);
        assert!(!is_dead(&activity));
    }

    #[test]
    fn a_call_given_up_while_another_call_receives_data_does_not_mark_dead() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut call = activity.start(HeadWait::Prompt);
        let mut other = activity.start(HeadWait::Prompt);
        // Waiting long enough that, without the other call's frame, giving it up marks dead.
        call.waiting_since = back(H2_STALL_AFTER + Duration::from_secs(1));
        other.arrived(); // a frame for the other call: the connection is alive
        drop(call);
        assert!(!is_dead(&activity));
        assert!(activity.usable());
    }

    #[test]
    fn a_call_given_up_long_after_another_calls_last_frame_marks_dead() {
        // Call A waits; call B gets its last frame early and ends; then nothing arrives. When
        // A is given up the connection has been silent past the stall bound: it must not turn
        // reusable once A, its last call, leaves.
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut call = activity.start(HeadWait::Prompt);
        let mut other = activity.start(HeadWait::Prompt);
        call.waiting_since = back(H2_STALL_AFTER + Duration::from_secs(10));
        activity.times().waiting_since = [back(H2_STALL_AFTER + Duration::from_secs(10)); 2];
        other.arrived();
        other.answered = true;
        activity.times().last_frame = back(H2_STALL_AFTER + Duration::from_secs(9));
        drop(other);
        assert!(!activity.usable(), "waiting with nothing arriving: stalled");
        drop(call);
        assert!(
            is_dead(&activity),
            "the old frame does not vouch for the connection"
        );
        assert!(!activity.usable(), "a stalled connection stays out of use");
    }

    #[test]
    fn a_long_poll_given_up_by_the_body_pump_marks_dead() {
        // The head arrived, then no body frame: the body pump drops the stream after
        // CHUNK_IDLE_TIMEOUT, before the long-poll stall bound.
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut poll = activity.start(HeadWait::LongPoll);
        poll.head_arrived = true;
        poll.arrived();
        poll.wait();
        age(&activity, CHUNK_IDLE_TIMEOUT);
        poll.waiting_since = back(CHUNK_IDLE_TIMEOUT);
        drop(poll);
        assert!(is_dead(&activity));
        assert!(!activity.usable(), "the next call dials a new connection");
    }

    /// The body pump's timer starts before the body is polled, so when it fires the call's own
    /// wait is a little short of [`CHUNK_IDLE_TIMEOUT`] and its drop alone does not mark the
    /// connection dead: the pump does. Paused time moves the pump's timer but not the real clock
    /// `H2Activity` reads, so here the call's wait is short of the bound by nearly all of it.
    #[tokio::test(start_paused = true)]
    async fn a_long_poll_the_body_pump_gives_up_on_retires_its_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A closed port: a call that does not reuse the pooled connection fails to dial.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let client = client_with_a_key_for_a_relay_on(port).await;
        let posts = Arc::new(AtomicUsize::new(0));
        serve_in_process_relay(&client, {
            let posts = Arc::clone(&posts);
            move |_req| {
                posts.fetch_add(1, Ordering::SeqCst);
                async {
                    // The outer head, then a body that stays silent.
                    let silent =
                        futures_util::stream::pending::<Result<Frame<Bytes>, Infallible>>();
                    let mut answer = Response::new(BodyExt::boxed(StreamBody::new(silent)));
                    answer.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static(CONTENT_TYPE_CHUNKED_RES),
                    );
                    answer
                }
            }
        })
        .await;
        let mempool = || {
            BhttpRequest::new(
                "POST",
                "gw.example",
                "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream",
            )
            .header("content-type", "application/grpc")
            .body(vec![0, 0, 0, 0, 0])
        };

        let started = tokio::time::Instant::now();
        let err = client
            .round_trip_stream(mempool(), || {})
            .await
            .err()
            .expect("a silent body is given up");
        assert!(matches!(err, RoundTripError::Transport(_)), "{err:?}");
        assert!(
            started.elapsed() >= CHUNK_IDLE_TIMEOUT,
            "given up by the pump"
        );
        let pooled = client
            .h2_pool
            .lock()
            .await
            .get(&format!("127.0.0.1:{port}"))
            .cloned()
            .expect("pooled");
        assert!(is_dead(&pooled.activity));
        assert!(
            !pooled.reusable(false),
            "the next call dials a new connection"
        );

        let _ = client.round_trip_stream(mempool(), || {}).await;
        assert_eq!(
            posts.load(Ordering::SeqCst),
            1,
            "the next call did not reuse it"
        );
    }

    #[test]
    fn the_body_pump_giving_up_leaves_a_connection_with_recent_frames_alone() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let since = back(Duration::from_millis(1));
        let mut other = activity.start(HeadWait::Prompt);
        other.arrived(); // a frame for another call after the pump started to wait
        activity.given_up_silent_since(since);
        assert!(!is_dead(&activity));
        activity.given_up_silent_since(std::time::Instant::now());
        assert!(is_dead(&activity));
    }

    #[test]
    fn a_prompt_call_after_a_quiet_long_poll_gets_its_own_window() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let _poll = activity.start(HeadWait::LongPoll);
        age(&activity, H2_STALL_AFTER + Duration::from_secs(1));
        let _call = activity.start(HeadWait::Prompt);
        assert!(
            activity.usable(),
            "the prompt window counts from the prompt call"
        );
    }

    #[test]
    fn a_long_poll_stalls_only_past_the_longest_healthy_silence() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut poll = activity.start(HeadWait::LongPoll);
        age(&activity, H2_STALL_AFTER + Duration::from_secs(1));
        assert!(activity.usable(), "a healthy gateway can be this quiet");
        age(&activity, H2_LONG_POLL_STALL_AFTER + Duration::from_secs(1));
        poll.waiting_since = back(H2_LONG_POLL_STALL_AFTER + Duration::from_secs(1));
        assert!(!activity.usable(), "no healthy gateway is this quiet");
        drop(poll);
        assert!(is_dead(&activity));
    }

    #[test]
    fn a_quiet_long_poll_given_up_early_or_an_answered_call_does_not_mark_dead() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut poll = activity.start(HeadWait::LongPoll);
        age(&activity, H2_STALL_AFTER + Duration::from_secs(1));
        poll.waiting_since = back(H2_STALL_AFTER + Duration::from_secs(1));
        drop(poll);
        assert!(!is_dead(&activity), "within the long-poll bound");

        let mut call = activity.start(HeadWait::Prompt);
        call.answered = true;
        drop(call);
        assert!(
            !is_dead(&activity),
            "an answered call proves the connection works"
        );
    }

    #[test]
    fn a_reader_that_paused_does_not_make_the_connection_look_stalled() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut call = activity.start(HeadWait::Prompt);
        call.arrived(); // a frame arrived; the reader has not asked for the next one yet
        age(&activity, H2_STALL_AFTER + Duration::from_secs(1));
        assert!(activity.usable(), "nobody waits on the network");
        call.answered = true;
        drop(call);
        assert!(!is_dead(&activity), "not waiting when it ended");
    }

    #[test]
    fn handing_a_connection_out_counts_as_use() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        activity.times().idle_since = back(H2_IDLE_REUSE + Duration::from_secs(1));
        assert!(activity.idle());
        activity.handed_out();
        assert!(!activity.idle(), "a caller is about to use it");
        assert!(activity.usable());
    }

    #[test]
    fn a_pooled_connection_idle_for_the_reuse_limit_is_not_reused() {
        let activity = Arc::new(H2Activity::new(None, Some(H2_IDLE_REUSE)));
        let mut first = activity.start(HeadWait::Prompt);
        let mut second = activity.start(HeadWait::Prompt);
        second.answered = true;
        drop(second);
        activity.times().idle_since = back(H2_IDLE_REUSE + Duration::from_secs(1));
        assert!(activity.usable(), "a call is still in flight: not idle");
        first.answered = true;
        drop(first);
        assert!(
            activity.usable(),
            "idle since the last call ended, not since it opened"
        );
        activity.times().idle_since = back(H2_IDLE_REUSE + Duration::from_secs(1));
        assert!(!activity.usable(), "idle for the reuse limit");
        assert!(!is_dead(&activity));
    }

    #[test]
    fn only_the_mempool_long_poll_is_not_a_prompt_call() {
        assert_eq!(
            HeadWait::for_path(b"/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolStream"),
            HeadWait::LongPoll
        );
        for path in [
            &b"/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange"[..],
            b"/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState",
            b"/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetMempoolTx",
        ] {
            assert_eq!(HeadWait::for_path(path), HeadWait::Prompt);
        }
    }
    use base64::Engine;
    use std::cell::Cell;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zodl_ohttp_client::encode_bhttp_request;

    fn health_subscription(client: &OhttpClient) -> crate::transport_health::HealthSubscription {
        crate::transport_health::subscribe(
            crate::transport_health::HealthRoute {
                gateway_host: client.gateway_host.clone(),
                relay_url: client.relay_url.clone(),
                via_tor: client.dialer.is_tor(),
            },
            42,
            Arc::new(|_| {}),
        )
    }

    // Missing reporting here would hide a real failure until the session's retry escalation.
    #[tokio::test]
    async fn health_reports_logical_failures_before_returning_to_sync() {
        use crate::transport_health::{HealthOutcome, HealthScope};
        for (status, expected) in [
            (401, HealthOutcome::PolicyRejected),
            (403, HealthOutcome::PolicyRejected),
            (413, HealthOutcome::ResponseRejected),
            (426, HealthOutcome::ConfigurationFailure),
            (503, HealthOutcome::TransportUnavailable),
        ] {
            let client =
                client_with_a_key(&format!("https://health-status-{status}.invalid/relay")).await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |_| async move {
                let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                *answer.status_mut() = StatusCode::from_u16(status).unwrap();
                answer
            })
            .await;
            assert!(
                client
                    .round_trip(&test_request(), None, || {})
                    .await
                    .is_err()
            );
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == expected && o.scope == HealthScope::Other),
                "{status}: {snapshot:?}"
            );
        }
    }

    #[tokio::test]
    async fn health_rate_limit_retains_the_real_default_pause() {
        use crate::transport_health::{HealthOutcome, monotonic_time_nanoseconds};
        let client = client_with_a_key("https://health-rate-default.invalid/relay").await;
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            let mut answer = Response::new(Full::new(Bytes::new()).boxed());
            *answer.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            answer
        })
        .await;
        assert!(
            client
                .round_trip(&test_request(), None, || {})
                .await
                .is_err()
        );
        let now = monotonic_time_nanoseconds();
        assert!(subscription.snapshot().observations.iter().any(|o| matches!(o.outcome, HealthOutcome::RateLimited { retry_not_before_nanoseconds } if retry_not_before_nanoseconds > now + 29_000_000_000 && retry_not_before_nanoseconds <= now + 30_000_000_000)));
    }

    #[tokio::test]
    async fn health_bad_sealed_answer_is_not_a_socket_failure() {
        use crate::transport_health::HealthOutcome;
        let client = client_with_a_key("https://health-bad-sealed.invalid/relay").await;
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async { filler_answer(256) }).await;
        assert!(
            client
                .round_trip(&test_request(), None, || {})
                .await
                .is_err()
        );
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ResponseRejected)
        );
        assert!(
            !subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    fn fixture_private_key() -> <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey {
        use hpke::Deserializable;
        <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&[7; 32]).unwrap()
    }

    async fn health_fixture_client(name: &str, grpc: bool) -> OhttpClient {
        let profile = if grpc {
            ClientProfile::SLIPSTREAM
        } else {
            ClientProfile::SLIPSTREAM_HTTP
        };
        let client = OhttpClient::new(
            &example_networks(),
            "health-gateway.invalid",
            &format!("https://{name}.invalid/relay"),
            Dialer::Direct,
            None,
            profile,
        )
        .unwrap();
        cache_fixture_key(&client).await;
        client
    }

    /// Gives `client` the key `fixture_response` can decrypt for.
    async fn cache_fixture_key(client: &OhttpClient) {
        use hpke::{Kem, Serializable};
        let public: [u8; 32] = hpke::kem::X25519HkdfSha256::sk_to_pk(&fixture_private_key())
            .to_bytes()
            .into();
        *client.key_config.lock().await = Some(CachedKey {
            config: KeyConfig::select(&key_document(1, public)).unwrap(),
            not_after: unix_now().unwrap() + 3600,
        });
    }

    fn fixture_varint(bytes: &mut Vec<u8>, value: usize) {
        if value < 64 {
            bytes.push(value as u8);
        } else if value < 16384 {
            bytes.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
        } else {
            bytes.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes());
        }
    }

    fn fixture_field(bytes: &mut Vec<u8>, name: &str, value: &str) {
        fixture_varint(bytes, name.len());
        bytes.extend_from_slice(name.as_bytes());
        fixture_varint(bytes, value.len());
        bytes.extend_from_slice(value.as_bytes());
    }

    /// A hermetic gateway peer: derive the authenticated response keys from the actual
    /// sealed request, then seal a head/body chunk and a final trailers chunk.
    fn fixture_response(
        request: &[u8],
        status: u16,
        grpc_status: &str,
        content_type: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        fixture_response_with_statuses(
            request,
            status,
            None,
            Some(grpc_status),
            content_type,
            true,
            true,
        )
    }

    fn fixture_response_with_statuses(
        request: &[u8],
        status: u16,
        header_status: Option<&str>,
        trailer_status: Option<&str>,
        content_type: &str,
        body_message: bool,
        final_chunk: bool,
    ) -> (Vec<u8>, Vec<u8>) {
        fixture_response_with_fields(
            request,
            status,
            header_status,
            trailer_status,
            content_type,
            body_message,
            final_chunk,
            &[],
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn fixture_response_with_fields(
        request: &[u8],
        status: u16,
        header_status: Option<&str>,
        trailer_status: Option<&str>,
        content_type: &str,
        body_message: bool,
        final_chunk: bool,
        headers: &[(&str, &str)],
        trailers: &[(&str, &str)],
    ) -> (Vec<u8>, Vec<u8>) {
        use aes_gcm::{
            Aes128Gcm, Nonce,
            aead::{AeadInPlace, KeyInit},
        };
        use hpke::{Deserializable, OpModeR};
        let enc =
            <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&request[7..39])
                .unwrap();
        let mut info = b"message/bhttp chunked request\0".to_vec();
        info.extend_from_slice(&request[..7]);
        let context = hpke::setup_receiver::<
            hpke::aead::AesGcm128,
            hpke::kdf::HkdfSha256,
            hpke::kem::X25519HkdfSha256,
        >(&OpModeR::Base, &fixture_private_key(), &enc, &info)
        .unwrap();
        let mut secret = [0; 16];
        context
            .export(b"message/bhttp chunked response", &mut secret)
            .unwrap();
        let response_nonce = [11; 16];
        let mut salt = request[7..39].to_vec();
        salt.extend_from_slice(&response_nonce);
        let kdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &secret);
        let mut key = [0; 16];
        let mut nonce = [0; 12];
        kdf.expand(b"key", &mut key).unwrap();
        kdf.expand(b"nonce", &mut nonce).unwrap();
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut head = vec![3]; // indeterminate-length Binary HTTP response
        fixture_varint(&mut head, status as usize);
        fixture_field(&mut head, "content-type", content_type);
        if let Some(status) = header_status {
            fixture_field(&mut head, "grpc-status", status);
        }
        for (name, value) in headers {
            fixture_field(&mut head, name, value);
        }
        head.push(0); // end headers
        if body_message {
            head.push(5); // one empty gRPC message
            head.extend_from_slice(&[0; 5]);
        }
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut head)
            .unwrap();
        head.extend_from_slice(&tag);
        let mut first = response_nonce.to_vec();
        fixture_varint(&mut first, head.len());
        first.extend_from_slice(&head);
        let mut end = vec![0]; // end body
        if let Some(status) = trailer_status {
            fixture_field(&mut end, "grpc-status", status);
        }
        for (name, value) in trailers {
            fixture_field(&mut end, name, value);
        }
        end.push(0); // end trailers
        nonce[11] ^= 1;
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                if final_chunk { b"final" } else { b"" },
                &mut end,
            )
            .unwrap();
        end.extend_from_slice(&tag);
        let mut last = Vec::new();
        fixture_varint(&mut last, if final_chunk { 0 } else { end.len() });
        last.extend_from_slice(&end);
        (first, last)
    }

    #[tokio::test(start_paused = true)]
    async fn health_header_grpc_rejection_survives_tracked_rpc_deadline() {
        use futures_util::StreamExt;
        for (status, expected) in [
            ("7", HealthOutcome::PolicyRejected),
            ("16", HealthOutcome::PolicyRejected),
            ("12", HealthOutcome::ConfigurationFailure),
            ("4", HealthOutcome::BackendUnavailable),
            ("14", HealthOutcome::BackendUnavailable),
        ] {
            let client = Arc::new(
                health_fixture_client(&format!("health-header-deadline-{status}"), true).await,
            );
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |req| async move {
                let request = req.into_body().collect().await.unwrap().to_bytes();
                let (first, _) = fixture_response_with_statuses(
                    &request,
                    200,
                    Some(status),
                    None,
                    "application/grpc",
                    false,
                    true,
                );
                let frames = futures_util::stream::iter([Ok::<_, Infallible>(Frame::data(
                    Bytes::from(first),
                ))]);
                Response::new(BodyExt::boxed(StreamBody::new(
                    frames.chain(futures_util::stream::pending()),
                )))
            })
            .await;
            let raw = health_tonic_channel(client.clone()).await;
            let tracked = crate::grpc::TrackedConnection::ohttp(
                raw,
                OhttpConnector {
                    client,
                    health: None,
                },
                "http://health-gateway.invalid:443".into(),
            );
            let result = tracked
                .call(async |client| crate::grpc::get_latest_block_height(client).await)
                .await;
            assert!(
                matches!(result, Err(crate::error::SlipstreamError::Transport(ref message)) if message.contains("timed out after 30s")),
                "{status}: {result:?}"
            );
            let observations = subscription.snapshot().observations;
            assert!(
                observations.iter().any(|o| o.scope == HealthScope::Route
                    && o.outcome == HealthOutcome::Usable
                    && o.stage == HealthStage::ResponseHead),
                "{status}: {observations:?}"
            );
            let terminal: Vec<_> = observations
                .iter()
                .filter(|o| o.scope == HealthScope::Lightwalletd)
                .collect();
            assert_eq!(terminal.len(), 1, "{status}: {observations:?}");
            assert_eq!(terminal[0].outcome, expected, "{status}: {observations:?}");
            assert_eq!(terminal[0].stage, HealthStage::ResponseBody);
            assert!(
                !observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_header_grpc_rejection_survives_body_failure() {
        use futures_util::StreamExt;
        for (status, expected) in [
            ("1", HealthOutcome::Cancelled),
            ("2", HealthOutcome::ResponseRejected),
            ("3", HealthOutcome::ResponseRejected),
            ("4", HealthOutcome::BackendUnavailable),
            ("5", HealthOutcome::ResponseRejected),
            ("6", HealthOutcome::ResponseRejected),
            ("7", HealthOutcome::PolicyRejected),
            ("8", HealthOutcome::ResponseRejected),
            ("9", HealthOutcome::ResponseRejected),
            ("10", HealthOutcome::ResponseRejected),
            ("11", HealthOutcome::ResponseRejected),
            ("12", HealthOutcome::ConfigurationFailure),
            ("13", HealthOutcome::ResponseRejected),
            ("14", HealthOutcome::BackendUnavailable),
            ("15", HealthOutcome::ResponseRejected),
            ("16", HealthOutcome::PolicyRejected),
        ] {
            for failure in ["reset", "truncation", "corruption", "premature-end"] {
                let client =
                    health_fixture_client(&format!("health-header-body-{status}-{failure}"), true)
                        .await;
                let subscription = health_subscription(&client);
                serve_in_process_relay_with_body_error(&client, move |req| async move {
                    let request = req.into_body().collect().await.unwrap().to_bytes();
                    let (first, mut end) = fixture_response_with_statuses(
                        &request,
                        200,
                        Some(status),
                        None,
                        "application/grpc",
                        false,
                        true,
                    );
                    let first = futures_util::stream::iter([Ok::<_, std::io::Error>(Frame::data(
                        Bytes::from(first),
                    ))]);
                    let tail = futures_util::stream::once(async move {
                        // Let the authenticated head reach the consumer before the failure.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        match failure {
                            "reset" => Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "fixture body reset",
                            )),
                            "truncation" => {
                                end.pop();
                                Ok(Frame::data(Bytes::from(end)))
                            }
                            "corruption" => {
                                *end.last_mut().unwrap() ^= 1;
                                Ok(Frame::data(Bytes::from(end)))
                            }
                            _ => Ok(Frame::data(Bytes::new())),
                        }
                    });
                    Response::new(BodyExt::boxed(StreamBody::new(first.chain(Box::pin(tail)))))
                })
                .await;
                let (_, _, mut events) = client
                    .round_trip_stream(test_request(), || {})
                    .await
                    .unwrap();
                assert!(
                    subscription
                        .snapshot()
                        .observations
                        .iter()
                        .all(|o| o.scope == HealthScope::Route),
                    "no terminal result at head"
                );
                let mut errors = 0;
                let mut ended = false;
                let mut frames = GrpcFrames::new(header_fields(&[("grpc-status", status)]));
                let mut public_trailers = Vec::new();
                while let Some(event) = events.next().await {
                    if let Err(error) = &event {
                        errors += 1;
                        match failure {
                            "corruption" | "truncation" => assert!(
                                matches!(error, PumpError::Decode(message) if message.contains("finish decode"))
                            ),
                            "reset" => assert!(
                                matches!(error, PumpError::Transport(message) if message.contains("read chunk"))
                            ),
                            _ => assert!(
                                matches!(error, PumpError::Transport(message) if message.contains("incomplete response"))
                            ),
                        }
                    }
                    ended |= matches!(&event, Ok(ResponseEvent::End));
                    if let Some(frame) = frames.frame(event)
                        && let Ok(trailers) = frame.into_trailers()
                    {
                        public_trailers.push(trailers);
                    }
                }
                assert!(
                    !ended,
                    "{status}/{failure}: incomplete response must not complete"
                );
                assert_eq!(errors, 1, "{status}/{failure}");
                assert_eq!(public_trailers.len(), 1, "{status}/{failure}");
                assert_eq!(
                    grpc_status(&public_trailers[0]),
                    Some(if matches!(failure, "corruption" | "truncation") {
                        "13"
                    } else {
                        "14"
                    }),
                    "{status}/{failure}: the public gRPC body failure is unchanged",
                );
                drop(events);
                let observations = subscription.snapshot().observations;
                let terminal: Vec<_> = observations
                    .iter()
                    .filter(|o| o.scope == HealthScope::Lightwalletd)
                    .collect();
                assert_eq!(terminal.len(), 1, "{status}/{failure}: {observations:?}");
                assert_eq!(
                    terminal[0].outcome, expected,
                    "{status}/{failure}: {observations:?}"
                );
                assert_eq!(terminal[0].stage, HealthStage::ResponseBody);
                assert!(
                    !observations
                        .iter()
                        .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
                );
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_header_grpc_status_preserves_trailer_and_cancel_semantics() {
        use futures_util::StreamExt;
        for (name, header_status, trailer_status, content_type, mode, expected) in [
            (
                "trailer-success",
                Some("7"),
                Some("0"),
                "application/grpc",
                "complete",
                HealthOutcome::Usable,
            ),
            (
                "trailer-rejection",
                Some("12"),
                Some("16"),
                "application/grpc",
                "complete",
                HealthOutcome::PolicyRejected,
            ),
            (
                "header-only-rejection",
                Some("7"),
                None,
                "application/grpc",
                "complete",
                HealthOutcome::PolicyRejected,
            ),
            (
                "trailer-success-incomplete",
                Some("7"),
                Some("0"),
                "application/grpc",
                "incomplete-trailer",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "trailer-rejection-incomplete",
                Some("12"),
                Some("16"),
                "application/grpc",
                "incomplete-trailer",
                HealthOutcome::PolicyRejected,
            ),
            (
                "header-success",
                Some("0"),
                None,
                "application/grpc",
                "eof",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "header-absent",
                None,
                None,
                "application/grpc",
                "eof",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "header-malformed",
                Some("bogus"),
                None,
                "application/grpc",
                "eof",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "header-noncanonical",
                Some("07"),
                None,
                "application/grpc",
                "eof",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "header-out-of-range",
                Some("17"),
                None,
                "application/grpc",
                "eof",
                HealthOutcome::TransportUnavailable,
            ),
            (
                "nongrpc",
                Some("7"),
                None,
                "text/html",
                "eof",
                HealthOutcome::ResponseRejected,
            ),
            (
                "cancel",
                Some("7"),
                None,
                "application/grpc",
                "cancel",
                HealthOutcome::Cancelled,
            ),
        ] {
            let client =
                health_fixture_client(&format!("health-header-semantics-{name}"), true).await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |req| async move {
                let request = req.into_body().collect().await.unwrap().to_bytes();
                let (first, end) = fixture_response_with_statuses(
                    &request,
                    200,
                    header_status,
                    trailer_status,
                    content_type,
                    false,
                    mode != "incomplete-trailer",
                );
                let first = futures_util::stream::iter([Ok::<_, Infallible>(Frame::data(
                    Bytes::from(first),
                ))]);
                let tail = futures_util::stream::once(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if mode == "cancel" {
                        return std::future::pending().await;
                    }
                    Ok::<_, Infallible>(Frame::data(Bytes::from(if mode == "eof" {
                        Vec::new()
                    } else {
                        end
                    })))
                });
                Response::new(BodyExt::boxed(StreamBody::new(first.chain(Box::pin(tail)))))
            })
            .await;
            let (_, _, mut events) = client
                .round_trip_stream(test_request(), || {})
                .await
                .unwrap();
            let at_head = subscription.snapshot().observations;
            assert!(
                at_head
                    .iter()
                    .any(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Usable)
            );
            if content_type == "application/grpc" {
                assert!(
                    at_head.iter().all(|o| o.scope == HealthScope::Route),
                    "{name}: premature completion {at_head:?}"
                );
            }
            let mut ended = false;
            let mut errors = Vec::new();
            let mut public_trailers = Vec::new();
            let mut frames = GrpcFrames::new(header_status.map_or_else(HeaderMap::new, |status| {
                header_fields(&[("grpc-status", status)])
            }));
            if mode != "cancel" {
                while let Some(event) = events.next().await {
                    ended |= matches!(&event, Ok(ResponseEvent::End));
                    if let Err(error) = &event {
                        errors.push(match error {
                            PumpError::Transport(message)
                            | PumpError::Decode(message)
                            | PumpError::TooLarge(message) => message.clone(),
                        });
                    }
                    if let Some(frame) = frames.frame(event)
                        && let Ok(trailers) = frame.into_trailers()
                    {
                        public_trailers.push(trailers);
                    }
                }
                assert_eq!(ended, mode == "complete", "{name}");
                assert_eq!(
                    errors.len(),
                    usize::from(mode != "complete"),
                    "{name}: {errors:?}"
                );
                assert_eq!(public_trailers.len(), 1, "{name}: {public_trailers:?}");
                assert_eq!(
                    grpc_status(&public_trailers[0]),
                    if mode == "complete" {
                        trailer_status.or(header_status)
                    } else {
                        Some("14")
                    },
                    "{name}"
                );
            }
            drop(events);
            let observations = subscription.snapshot().observations;
            let terminal: Vec<_> = observations
                .iter()
                .filter(|o| o.scope == HealthScope::Lightwalletd)
                .collect();
            assert_eq!(terminal.len(), 1, "{name}: {observations:?}");
            assert_eq!(terminal[0].outcome, expected, "{name}: {observations:?}");
            assert_eq!(
                terminal[0].stage,
                if content_type != "application/grpc" {
                    HealthStage::ResponseHead
                } else if mode == "complete" {
                    HealthStage::Complete
                } else {
                    HealthStage::ResponseBody
                },
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn health_authenticated_backend_results_keep_route_success_and_scope() {
        use crate::transport_health::{HealthOutcome, HealthScope};
        for (status, grpc_status, content_type, expected) in [
            (200, "0", "application/grpc", HealthOutcome::Usable),
            (
                200,
                "14",
                "application/grpc",
                HealthOutcome::BackendUnavailable,
            ),
            (
                200,
                "3",
                "application/grpc",
                HealthOutcome::ResponseRejected,
            ),
            (403, "0", "text/plain", HealthOutcome::PolicyRejected),
            (200, "0", "text/html", HealthOutcome::ResponseRejected),
        ] {
            let client = health_fixture_client(
                &format!("health-inner-{status}-{grpc_status}-{}", content_type.len()),
                true,
            )
            .await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |req| async move {
                let request = req.into_body().collect().await.unwrap().to_bytes();
                let (mut bytes, end) =
                    fixture_response(&request, status, grpc_status, content_type);
                bytes.extend_from_slice(&end);
                Response::new(Full::new(Bytes::from(bytes)).boxed())
            })
            .await;
            let (_, _, mut events) = client
                .round_trip_stream(test_request(), || {})
                .await
                .unwrap();
            use futures_util::StreamExt;
            while events.next().await.is_some() {}
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Usable),
                "{snapshot:?}"
            );
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.scope == HealthScope::Lightwalletd && o.outcome == expected),
                "{snapshot:?}"
            );
            let ids: std::collections::HashSet<_> =
                snapshot.observations.iter().map(|o| o.request_id).collect();
            assert_eq!(ids.len(), 1, "one ticket spans route and backend evidence");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_stream_body_eof_idle_and_cancellation_are_distinct() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        use futures_util::StreamExt;
        for mode in ["eof", "idle", "cancel"] {
            let client = health_fixture_client(&format!("health-stream-{mode}"), true).await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |req| async move {
                let request = req.into_body().collect().await.unwrap().to_bytes();
                let (first, _) = fixture_response(&request, 200, "0", "application/grpc");
                let frames = futures_util::stream::iter([Ok::<_, Infallible>(Frame::data(
                    Bytes::from(first),
                ))]);
                let body = if mode == "eof" {
                    BodyExt::boxed(StreamBody::new(frames))
                } else {
                    BodyExt::boxed(StreamBody::new(
                        frames.chain(futures_util::stream::pending()),
                    ))
                };
                Response::new(body)
            })
            .await;
            let (_, _, mut events) = client
                .round_trip_stream(test_request(), || {})
                .await
                .unwrap();
            if mode == "cancel" {
                drop(events);
                tokio::task::yield_now().await;
            } else {
                while events.next().await.is_some() {}
            }
            let expected = if mode == "cancel" {
                HealthOutcome::Cancelled
            } else {
                HealthOutcome::TransportUnavailable
            };
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == expected && o.stage == HealthStage::ResponseBody),
                "{mode}: {snapshot:?}"
            );
        }
    }

    #[tokio::test]
    async fn health_key_verification_after_fallback_keeps_configuration_classification() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        // A real key fetch and refused in-process DNS resolvers preserve the original
        // typed verification failure without contacting any live endpoint.
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://health-key-verification.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .unwrap();
        let subscription = health_subscription(&client);
        let dns_queries = refuse_dns_queries(&client).await;
        serve_in_process_relay(&client, |_| async {
            Response::new(Full::new(Bytes::from_static(b"invalid signed envelope")).boxed())
        })
        .await;
        let error = client
            .round_trip_stream(test_request(), || {})
            .await
            .err()
            .expect("key fetch must fail");
        assert!(
            error
                .to_string()
                .contains("relay envelope verification failed"),
            "{error:?}"
        );
        assert_eq!(dns_queries.load(Ordering::SeqCst), DOH_RESOLVERS.len());
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ConfigurationFailure
                    && o.stage == HealthStage::KeyConfiguration)
        );
        assert!(
            !subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    async fn health_tonic_channel(client: Arc<OhttpClient>) -> tonic::transport::Channel {
        tonic::transport::Endpoint::from_shared(format!("http://{}:443", testnet_gateway()))
            .unwrap()
            .connect_with_connector(OhttpConnector {
                client,
                health: None,
            })
            .await
            .unwrap()
    }

    async fn health_tonic_client(client: Arc<OhttpClient>) -> crate::grpc::LwdClient {
        crate::grpc::LwdClient::new(crate::grpc::LwdTransport::local_bridge(
            health_tonic_channel(client).await,
        ))
    }

    // These tests catch classification depending on a factory task scope rather than the
    // bridge that produced the status. The relay and encrypted inner response are real.
    async fn outcome_fixture(
        name: &str,
        outer: u16,
        inner: u16,
    ) -> (Arc<OhttpClient>, Arc<AtomicUsize>) {
        let client = Arc::new(health_fixture_client(name, true).await);
        let dispatches = serve_outcome_relay(&client, outer, inner).await;
        (client, dispatches)
    }

    /// Puts the in-process relay of `outcome_fixture` behind `client` and counts its requests.
    async fn serve_outcome_relay(client: &OhttpClient, outer: u16, inner: u16) -> Arc<AtomicUsize> {
        let dispatches = Arc::new(AtomicUsize::new(0));
        let observed = dispatches.clone();
        serve_in_process_relay(client, move |request| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move {
                // Local provenance is never sent on the relay connection.
                assert!(!request.headers().contains_key("x-ohttp-outcome-auth"));
                assert!(!request.headers().contains_key(OHTTP_OUTCOME_HEADER));
                if outer != 200 {
                    let mut response = Response::new(Full::new(Bytes::new()).boxed());
                    *response.status_mut() = StatusCode::from_u16(outer).unwrap();
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                    return response;
                }
                let request = request.into_body().collect().await.unwrap().to_bytes();
                let (mut bytes, end) = fixture_response(&request, inner, "0", "application/grpc");
                bytes.extend_from_slice(&end);
                Response::new(Full::new(Bytes::from(bytes)).boxed())
            }
        })
        .await;
        dispatches
    }

    /// A connector over the client of `outcome_fixture`, for the Tor channel path.
    pub(crate) async fn outcome_connector(
        name: &str,
        outer: u16,
        inner: u16,
    ) -> (OhttpConnector, Arc<AtomicUsize>) {
        let (client, dispatches) = outcome_fixture(name, outer, inner).await;
        (
            OhttpConnector {
                client,
                health: None,
            },
            dispatches,
        )
    }

    /// Replaces the process-cached mainnet client of the public connect functions, and puts the
    /// previous entry back when dropped. Hold `PUBLIC_CONNECT_LOCK` while one exists. Tests use
    /// the mainnet key because the testnet cached client is permanently mutated by
    /// `health_follow_tip_owner_captures_the_selected_endpoint_deadline`.
    struct CachedClientOverride {
        key: ClientCacheKey,
        previous: Option<Arc<OhttpClient>>,
    }

    static PUBLIC_CONNECT_LOCK: Mutex<()> = Mutex::const_new(());

    impl CachedClientOverride {
        async fn install(gateway_host: &str, client: Arc<OhttpClient>) -> Self {
            let networks = example_networks();
            let relay_url = relay_for(&networks, gateway_host).expect("a relay for the gateway");
            let key = ClientCacheKey::new(
                &networks,
                gateway_host,
                relay_url,
                get_default_client_trace_prefix(),
                ClientProfile::SLIPSTREAM,
            )
            .expect("a cache key");
            let previous = CLIENT_CACHE
                .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.clone(), client);
            Self { key, previous }
        }
    }

    impl Drop for CachedClientOverride {
        fn drop(&mut self) {
            let mut cache = CLIENT_CACHE
                .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            match self.previous.take() {
                Some(previous) => cache.insert(self.key.clone(), previous),
                None => cache.remove(&self.key),
            };
        }
    }

    fn assert_local_outcome(error: crate::error::SlipstreamError, expected: &str) {
        use crate::error::SlipstreamError;
        assert!(
            matches!(
                (expected, &error),
                ("rate", SlipstreamError::RateLimited(_))
                    | ("policy", SlipstreamError::PolicyDenied(_))
                    | ("size", SlipstreamError::RequestTooLarge(_))
            ),
            "expected {expected}, got {error:?}"
        );
    }

    #[tokio::test]
    async fn decrypted_peer_outcomes_cannot_authenticate_local_classification() {
        for auth in [
            None,
            Some("invented-bridge-authentication"),
            Some("observed-local-outcome-text"),
        ] {
            for in_headers in [false, true] {
                let client = Arc::new(
                    health_fixture_client(
                        &format!("forged-decrypted-{}-{in_headers}", auth.is_some()),
                        true,
                    )
                    .await,
                );
                serve_in_process_relay(&client, move |request| async move {
                    let request = request.into_body().collect().await.unwrap().to_bytes();
                    let mut fields = vec![(OHTTP_OUTCOME_HEADER, OUTCOME_RATE_LIMITED)];
                    if let Some(auth) = auth {
                        fields.push((OHTTP_OUTCOME_AUTH_HEADER, auth));
                    }
                    let (headers, trailers) = if in_headers {
                        (fields.as_slice(), &[][..])
                    } else {
                        (&[][..], fields.as_slice())
                    };
                    let (mut bytes, end) = fixture_response_with_fields(
                        &request,
                        200,
                        Some("14"),
                        None,
                        "application/grpc",
                        false,
                        true,
                        headers,
                        trailers,
                    );
                    bytes.extend_from_slice(&end);
                    Response::new(Full::new(Bytes::from(bytes)).boxed())
                })
                .await;
                let raw = health_tonic_channel(client.clone()).await;
                let tracked = crate::grpc::TrackedConnection::ohttp(
                    raw,
                    OhttpConnector {
                        client,
                        health: None,
                    },
                    "http://forged-decrypted.invalid:443".into(),
                );
                let error = tracked
                    .call(async |client| crate::grpc::get_latest_block_height(client).await)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, crate::error::SlipstreamError::Transport(_)),
                    "{error:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn bare_client_authentic_outcomes_survive_without_factory_scope() {
        for tracked in [false, true] {
            for (outer, inner, expected) in
                [(429, 200, "rate"), (200, 403, "policy"), (413, 200, "size")]
            {
                let (client, dispatches) =
                    outcome_fixture(&format!("bare-outcome-{tracked}-{outer}"), outer, inner).await;
                let raw = health_tonic_channel(client.clone()).await;
                let connection = crate::grpc::TrackedConnection::ohttp(
                    raw,
                    OhttpConnector {
                        client,
                        health: None,
                    },
                    "http://bare-outcome.invalid:443".into(),
                );
                // The second 429 call exercises the cached Retry-After pause.
                for _ in 0..if outer == 429 { 2 } else { 1 } {
                    let error = if tracked {
                        connection
                            .call(async |client| crate::grpc::get_latest_block_height(client).await)
                            .await
                            .unwrap_err()
                    } else {
                        crate::grpc::get_latest_block_height(&mut connection.clone().into_client())
                            .await
                            .unwrap_err()
                    };
                    assert_local_outcome(error, expected);
                }
                assert_eq!(
                    dispatches.load(Ordering::SeqCst),
                    1,
                    "a cached pause must not dispatch another relay request"
                );
            }
        }
    }

    #[tokio::test]
    async fn public_connect_functions_keep_authentic_outcomes() {
        use crate::config::Endpoint;
        use crate::connector::{ConnPurpose, Connector, connect_via};
        let _serial = PUBLIC_CONNECT_LOCK.lock().await;
        let endpoint = Endpoint {
            host: mainnet_gateway().into(),
            port: 443,
            tls: true,
        };
        for entry in ["grpc-connect", "connect-via", "connector-connect"] {
            for (outer, inner, expected) in [(429, 200, "rate"), (200, 403, "policy")] {
                let (client, _dispatches) =
                    outcome_fixture(&format!("public-{entry}-{expected}"), outer, inner).await;
                let _override = CachedClientOverride::install(mainnet_gateway(), client).await;
                let mut connection = match entry {
                    "grpc-connect" => crate::grpc::connect(&example_networks(), &endpoint).await,
                    "connect-via" => {
                        connect_via(
                            &example_networks(),
                            &endpoint,
                            None,
                            ConnPurpose::MetadataUnique,
                        )
                        .await
                    }
                    _ => {
                        Connector::direct(Arc::new(example_networks()), endpoint.clone())
                            .connect(ConnPurpose::MetadataUnique)
                            .await
                    }
                }
                .expect("connect");
                let error = crate::grpc::get_latest_block_height(&mut connection)
                    .await
                    .unwrap_err();
                assert_local_outcome(error, expected);
            }
        }
    }

    #[tokio::test]
    async fn public_mempool_stream_keeps_rate_limit_after_pause() {
        use crate::config::Endpoint;
        let _serial = PUBLIC_CONNECT_LOCK.lock().await;
        let endpoint = Endpoint {
            host: mainnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let (client, dispatches) = outcome_fixture("public-mempool-pause", 429, 200).await;
        let _override = CachedClientOverride::install(mainnet_gateway(), client).await;
        let mut connection = crate::grpc::connect(&example_networks(), &endpoint)
            .await
            .expect("connect");
        let error = crate::grpc::get_latest_block_height(&mut connection)
            .await
            .unwrap_err();
        assert_local_outcome(error, "rate");
        let error = crate::grpc::open_mempool_stream(&mut connection)
            .await
            .unwrap_err();
        assert!(
            matches!(error, crate::error::SlipstreamError::RateLimited(_)),
            "{error:?}"
        );
        assert_eq!(
            dispatches.load(Ordering::SeqCst),
            1,
            "a cached pause must not dispatch another relay request"
        );
    }

    /// Covers `grpc::connect_dedicated` through the calls its body reduces to (`connect_tracked`
    /// with `shared = false`, then `into_client()`). The dedicated client is built fresh outside
    /// the process cache, so this needs neither `PUBLIC_CONNECT_LOCK` nor a cache restore.
    /// Policy only: a 429 here would pause the configured relay URL for the whole process.
    #[tokio::test]
    async fn dedicated_connection_keeps_policy_outcome() {
        use crate::config::Endpoint;
        let endpoint = Endpoint {
            host: mainnet_gateway().into(),
            port: 443,
            tls: true,
        };
        let connection = crate::grpc::connect_tracked(&example_networks(), &endpoint, false)
            .await
            .expect("connect");
        let client = connection
            .factory
            .as_ref()
            .expect("an OHTTP connection")
            .connector
            .client
            .clone();
        cache_fixture_key(&client).await;
        serve_outcome_relay(&client, 200, 403).await;
        let mut rpc = connection.into_client();
        let error = crate::grpc::get_latest_block_height(&mut rpc)
            .await
            .unwrap_err();
        assert_local_outcome(error, "policy");
    }

    #[tokio::test]
    async fn bare_stream_authentic_outcome_survives_scope_exit() {
        for tracked in [false, true] {
            for (outer, inner, expected) in
                [(429, 200, "rate"), (200, 403, "policy"), (413, 200, "size")]
            {
                let (client, _dispatches) =
                    outcome_fixture(&format!("bare-stream-{tracked}-{outer}"), outer, inner).await;
                let raw = health_tonic_channel(client.clone()).await;
                let connection = crate::grpc::TrackedConnection::ohttp(
                    raw,
                    OhttpConnector {
                        client,
                        health: None,
                    },
                    "http://bare-stream.invalid:443".into(),
                );
                let status = if tracked {
                    connection
                        .call(async |client| {
                            Ok(client
                                .get_mempool_stream(zcash_client_backend::proto::service::Empty {})
                                .await
                                .unwrap_err())
                        })
                        .await
                        .unwrap()
                } else {
                    connection
                        .into_client()
                        .get_mempool_stream(zcash_client_backend::proto::service::Empty {})
                        .await
                        .unwrap_err()
                };
                assert!(
                    !format!("{status:?}").contains("x-ohttp-outcome"),
                    "reserved provenance remained after HTTP/2 decoding"
                );
                // Classification happens after the stream-opening call's factory scope ended.
                assert_local_outcome(crate::grpc::status_err("unscoped stream", status), expected);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_real_outer_unary_deadline_reports_before_native_head_timeout() {
        use crate::transport_health::{HealthOutcome, HealthScope, HealthStage};
        let mut client = health_fixture_client("health-outer-deadline", true).await;
        client.gateway_host = testnet_gateway().into();
        // The explicit route scope must use this fixture relay, so construct it directly.
        let route = HealthRoute {
            gateway_host: client.gateway_host.clone(),
            relay_url: client.relay_url.clone(),
            via_tor: false,
        };
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            std::future::pending::<Response<BoxBody<Bytes, Infallible>>>().await
        })
        .await;
        let mut rpc = health_tonic_client(Arc::new(client)).await;
        let result = crate::grpc::with_ohttp_health_route(
            Some(route),
            crate::grpc::get_latest_block_height(&mut rpc),
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::error::SlipstreamError::Transport(_))
        ));
        let snapshot = subscription.snapshot();
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.scope == HealthScope::Lightwalletd
                    && o.outcome == HealthOutcome::TransportUnavailable
                    && o.stage == HealthStage::ResponseHead),
            "{snapshot:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_intentional_outer_cancellation_is_not_a_deadline() {
        use crate::transport_health::HealthOutcome;
        let client = Arc::new(health_fixture_client("health-outer-cancel", true).await);
        let route = HealthRoute {
            gateway_host: client.gateway_host.clone(),
            relay_url: client.relay_url.clone(),
            via_tor: false,
        };
        let subscription = health_subscription(&client);
        let started = Arc::new(tokio::sync::Notify::new());
        serve_in_process_relay(&client, {
            let started = started.clone();
            move |_| {
                started.notify_one();
                async { std::future::pending::<Response<BoxBody<Bytes, Infallible>>>().await }
            }
        })
        .await;
        let mut rpc = health_tonic_client(client).await;
        let task = tokio::spawn(async move {
            crate::grpc::with_ohttp_health_route(
                Some(route),
                crate::grpc::get_latest_block_height(&mut rpc),
            )
            .await
        });
        started.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(101)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    #[tokio::test]
    async fn health_native_initial_tip_catchup_and_mempool_errors_precede_retry() {
        use crate::transport_health::{HealthOutcome, HealthScope};
        for method in 0..4 {
            let client =
                Arc::new(health_fixture_client(&format!("health-rpc-{method}"), true).await);
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, |_| async {
                let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                answer
            })
            .await;
            let mut rpc = health_tonic_client(client).await;
            let error = match method {
                0 => crate::grpc::get_lightd_info(&mut rpc).await.err(),
                1 => crate::grpc::get_latest_block_height(&mut rpc).await.err(),
                2 => crate::grpc::get_tree_state(&mut rpc, 1).await.err(),
                _ => crate::grpc::open_mempool_stream(&mut rpc).await.err(),
            };
            assert!(matches!(
                error,
                Some(crate::error::SlipstreamError::Transport(_))
            ));
            assert!(
                subscription
                    .snapshot()
                    .observations
                    .iter()
                    .any(|o| o.scope == HealthScope::Lightwalletd
                        && o.outcome == HealthOutcome::TransportUnavailable)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_follow_tip_owner_captures_the_selected_endpoint_deadline() {
        use crate::transport_health::HealthOutcome;
        let gateway = testnet_gateway();
        let networks = example_networks();
        let relay = relay_for(&networks, gateway).unwrap();
        let client = get_or_create_client(
            &networks,
            gateway,
            relay,
            Dialer::Direct,
            get_default_client_trace_prefix(),
            ClientProfile::SLIPSTREAM,
        )
        .await
        .unwrap();
        cache_a_key(&client).await;
        let subscription = health_subscription(&client);
        let start = transport_health::monotonic_time_nanoseconds();
        serve_in_process_relay(&client, |_| async {
            std::future::pending::<Response<BoxBody<Bytes, Infallible>>>().await
        })
        .await;
        let config = crate::config::EngineConfig::new(
            crate::Network::TestNetwork,
            "/tmp/unused-health-tip.db".into(),
            crate::config::Endpoint {
                host: gateway.into(),
                port: 443,
                tls: true,
            },
            networks.clone(),
        );
        assert!(crate::engine::probe_tip(&config, None).await.is_err());
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| !o.historical
                    && o.started_at_nanoseconds >= start
                    && o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_native_head_deadline_is_availability_not_cancellation() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        let client = Arc::new(health_fixture_client("health-native-head-timeout", true).await);
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            std::future::pending::<Response<BoxBody<Bytes, Infallible>>>().await
        })
        .await;
        let mut rpc = health_tonic_client(client).await;
        assert!(crate::grpc::open_mempool_stream(&mut rpc).await.is_err());
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable
                    && o.stage == HealthStage::ResponseHead)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_external_http_deadline_is_availability_not_cancellation() {
        use crate::transport_health::HealthOutcome;
        let relay = "https://health-external-timeout.invalid/relay";
        let gateway = "health-external.invalid";
        let client = get_or_create_client(
            &example_networks(),
            gateway,
            relay,
            Dialer::Direct,
            get_default_client_trace_prefix(),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .unwrap();
        cache_a_key(&client).await;
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            std::future::pending::<Response<BoxBody<Bytes, Infallible>>>().await
        })
        .await;
        assert!(
            http_round_trip_via(
                &example_networks(),
                relay,
                gateway,
                Dialer::Direct,
                "GET",
                parse_http_target("https://origin.invalid/data").unwrap(),
                &[],
                &[],
                None,
                || {}
            )
            .await
            .is_err()
        );
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    #[tokio::test]
    async fn health_key_dns_fallback_preserves_typed_origin_failure() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://health-real-fallback.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .unwrap();
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            Response::new(Full::new(Bytes::from_static(b"bad envelope")).boxed())
        })
        .await;
        let lookups = Arc::new(AtomicUsize::new(0));
        for resolver in DOH_RESOLVERS {
            let target = parse_https(
                &doh_query_url(&example_networks(), resolver, Network::Testnet)
                    .expect("configured DNS"),
            )
            .unwrap();
            let peer = OhttpClient::new(
                &example_networks(),
                "unused.invalid",
                &format!("https://{}:{}{}", target.host, target.port, target.path),
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .unwrap();
            let lookups = lookups.clone();
            serve_in_process_relay(&peer, move |_| {
                lookups.fetch_add(1, Ordering::SeqCst);
                async {
                    let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                    *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    answer
                }
            })
            .await;
            let key = format!("{}:{}", target.host, target.port);
            let sender = peer.h2_pool.lock().await.remove(&key).unwrap();
            client.h2_pool.lock().await.insert(key, sender);
        }
        assert!(
            client
                .round_trip_stream(test_request(), || {})
                .await
                .is_err()
        );
        assert_eq!(lookups.load(Ordering::SeqCst), DOH_RESOLVERS.len());
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ConfigurationFailure
                    && o.stage == HealthStage::KeyConfiguration)
        );
    }

    #[tokio::test]
    async fn health_warmup_failure_is_reported_before_connect_retry() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        let client = Arc::new(
            OhttpClient::new(
                &example_networks(),
                testnet_gateway(),
                "https://health-warmup.invalid/relay",
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .unwrap(),
        );
        let subscription = health_subscription(&client);
        // A relay key failure can recover through DNS. Keep both sources inside this
        // failure fixture so deployed DNS cannot turn the expected failure into success.
        let dns_queries = refuse_dns_queries(&client).await;
        serve_in_process_relay(&client, |_| async {
            let mut answer = Response::new(Full::new(Bytes::new()).boxed());
            *answer.status_mut() = StatusCode::FORBIDDEN;
            answer
        })
        .await;
        assert!(
            OhttpConnector {
                client,
                health: None
            }
            .warm_up_typed()
            .await
            .is_err()
        );
        assert_eq!(dns_queries.load(Ordering::SeqCst), DOH_RESOLVERS.len());

        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::PolicyRejected
                    && o.stage == HealthStage::KeyConfiguration)
        );
    }

    #[tokio::test]
    async fn health_invalid_outbound_header_is_configuration_not_transport() {
        use crate::transport_health::HealthOutcome;
        let client = health_fixture_client("health-bad-header", false).await;
        let subscription = health_subscription(&client);
        // This invalid authority reaches the actual outbound HTTP request builder.
        // It must retain the public error while avoiding an availability diagnosis.
        let mut client = client;
        client.relay.host = "invalid\nrelay".into();
        assert!(
            client
                .round_trip(&test_request(), None, || {})
                .await
                .is_err()
        );
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ConfigurationFailure)
        );
    }

    #[tokio::test]
    async fn health_stream_size_guard_rejection_keeps_legacy_error_and_is_not_unavailable() {
        use crate::transport_health::HealthOutcome;
        let mut client = health_fixture_client("health-stream-size", true).await;
        client.profile.limits.max_sealed_response_bytes = Some(1);
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async { filler_answer(64) }).await;
        assert!(matches!(
            client.round_trip_stream(test_request(), || {}).await,
            Err(RoundTripError::Transport(_))
        ));
        let snapshot = subscription.snapshot();
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ResponseRejected)
        );
        assert!(
            !snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    #[tokio::test]
    async fn health_warmup_success_does_not_claim_backend_usability() {
        use crate::transport_health::{HealthOutcome, HealthScope};
        let client = Arc::new(health_fixture_client("health-warmup-success", true).await);
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            unreachable!("cached key and pooled connection need no HTTP request")
        })
        .await;
        OhttpConnector {
            client,
            health: None,
        }
        .warm_up_typed()
        .await
        .unwrap();
        let snapshot = subscription.snapshot();
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Inconclusive)
        );
        assert!(
            !snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::Usable)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_buffered_read_deadline_is_at_the_body_boundary() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        let client = health_fixture_client("health-buffered-read", false).await;
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            Response::new(BodyExt::boxed(StreamBody::new(
                futures_util::stream::pending::<Result<Frame<Bytes>, Infallible>>(),
            )))
        })
        .await;
        assert!(
            client
                .round_trip(&test_request(), None, || {})
                .await
                .is_err()
        );
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable
                    && o.stage == HealthStage::ResponseBody)
        );
    }

    #[test]
    fn health_tls_certificate_rejection_is_typed_before_its_message_is_erased() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert!(matches!(
            HttpsError::classify_tls_error(error, "relay.invalid", "relay"),
            HttpsError::Configuration(_)
        ));
        let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "TLS peer closed");
        assert!(matches!(
            HttpsError::classify_tls_error(error, "relay.invalid", "relay"),
            HttpsError::Other(_)
        ));
    }

    #[tokio::test]
    async fn health_oversized_signed_config_is_configuration_failure() {
        use crate::transport_health::{HealthOutcome, HealthStage};
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://health-config-size-relay.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .unwrap();
        let subscription = health_subscription(&client);
        let dns_queries = refuse_dns_queries(&client).await;
        serve_in_process_relay(&client, |_| async { filler_answer(64 * 1024 + 1) }).await;
        let error = client
            .round_trip_stream(test_request(), || {})
            .await
            .err()
            .expect("key fetch must fail");
        assert!(error.to_string().contains("65536"), "{error:?}");
        assert_eq!(dns_queries.load(Ordering::SeqCst), DOH_RESOLVERS.len());
        assert!(
            subscription
                .snapshot()
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ConfigurationFailure
                    && o.stage == HealthStage::KeyConfiguration)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_collected_rpc_idle_deadline_wins_while_ciphertext_still_arrives() {
        use crate::transport_health::{HealthOutcome, HealthScope, HealthStage};
        use futures_util::StreamExt;
        let client = Arc::new(health_fixture_client("health-collected-idle", true).await);
        let route = HealthRoute {
            gateway_host: client.gateway_host.clone(),
            relay_url: client.relay_url.clone(),
            via_tor: false,
        };
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |req| async move {
            let request = req.into_body().collect().await.unwrap().to_bytes();
            let (first, end) = fixture_response(&request, 200, "0", "application/grpc");
            let first =
                futures_util::stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from(first)))]);
            // Authenticated non-final head/message, followed by an unfinished final
            // chunk. Ciphertext every 10s keeps native read-idle alive while the
            // actual gRPC message stream is silent for its full 30s budget.
            let fragments = futures_util::stream::unfold((0, end), |(index, end)| async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if index >= 3 {
                    return std::future::pending().await;
                }
                Some((
                    Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(
                        &end[index..index + 1],
                    ))),
                    (index + 1, end),
                ))
            });
            Response::new(BodyExt::boxed(StreamBody::new(first.chain(fragments))))
        })
        .await;
        let mut rpc = health_tonic_client(client).await;
        let result = crate::grpc::with_ohttp_health_route(
            Some(route),
            crate::grpc::get_taddress_txids(
                &mut rpc,
                zcash_client_backend::proto::service::TransparentAddressBlockFilter::default(),
                None,
            ),
        )
        .await;
        assert!(result.is_err());
        let snapshot = subscription.snapshot();
        let head = snapshot
            .observations
            .iter()
            .find(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Usable)
            .unwrap();
        let failure = snapshot
            .observations
            .iter()
            .find(|o| {
                o.scope == HealthScope::Lightwalletd
                    && o.outcome == HealthOutcome::TransportUnavailable
            })
            .expect("outer message deadline is reported before native read idle");
        assert_eq!(failure.stage, HealthStage::ResponseBody);
        assert!(failure.started_at_nanoseconds < head.observed_at_nanoseconds);
    }

    #[tokio::test]
    async fn health_rate_limit_is_visible_while_the_error_body_is_stalled() {
        use crate::transport_health::HealthOutcome;
        let client = Arc::new(health_fixture_client("health-rate-stalled", false).await);
        let subscription = health_subscription(&client);
        let reading = Arc::new(tokio::sync::Notify::new());
        serve_in_process_relay(&client, {
            let reading = reading.clone();
            move |_| {
                let reading = reading.clone();
                async move {
                    let body = futures_util::stream::poll_fn(move |_| {
                        reading.notify_one();
                        std::task::Poll::Pending::<Option<Result<Frame<Bytes>, Infallible>>>
                    });
                    let mut answer = Response::new(BodyExt::boxed(StreamBody::new(body)));
                    *answer.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    answer
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                    answer
                }
            }
        })
        .await;
        let backoff_key = client.backoff_key();
        let task =
            tokio::spawn(async move { client.round_trip(&test_request(), None, || {}).await });
        reading.notified().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while RelayBackoff::global().remaining(&backoff_key).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the real client consumed the rate-limit response head");
        assert!(!task.is_finished());
        let snapshot = subscription.snapshot();
        let now = transport_health::monotonic_time_nanoseconds();
        assert!(snapshot.observations.iter().any(|o| matches!(o.outcome, HealthOutcome::RateLimited { retry_not_before_nanoseconds } if retry_not_before_nanoseconds > now + 59_000_000_000 && retry_not_before_nanoseconds <= now + 60_000_000_000)));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn health_oversized_logical_request_is_rejected_without_dispatch() {
        use crate::transport_health::HealthOutcome;
        let client = health_fixture_client("health-request-size", false).await;
        let subscription = health_subscription(&client);
        serve_in_process_relay(&client, |_| async {
            panic!("oversized request must never reach the relay")
        })
        .await;
        let request = test_request().body(vec![0; GATEWAY_MAX_ENCAPSULATED_REQUEST_BYTES + 1]);
        let dispatched = AtomicBool::new(false);
        assert!(matches!(
            client
                .round_trip(&request, None, || {
                    dispatched.store(true, Ordering::SeqCst);
                })
                .await,
            Err(RoundTripError::TooLarge(_))
        ));
        assert!(!dispatched.load(Ordering::SeqCst));
        let snapshot = subscription.snapshot();
        assert!(
            snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::ResponseRejected)
        );
        assert!(
            !snapshot
                .observations
                .iter()
                .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
        );
    }

    #[tokio::test]
    async fn health_external_http_keeps_backend_status_and_route_success_separate() {
        use crate::transport_health::{HealthOutcome, HealthScope};
        for (status, expected) in [
            (200, HealthOutcome::Usable),
            (503, HealthOutcome::BackendUnavailable),
            (403, HealthOutcome::PolicyRejected),
            (426, HealthOutcome::ConfigurationFailure),
            (400, HealthOutcome::ResponseRejected),
        ] {
            let client =
                health_fixture_client(&format!("health-http-backend-{status}"), false).await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |request| async move {
                let request = request.into_body().collect().await.unwrap().to_bytes();
                let (mut bytes, end) = fixture_response(&request, status, "0", "application/json");
                bytes.extend_from_slice(&end);
                Response::new(Full::new(Bytes::from(bytes)).boxed())
            })
            .await;
            let response = client
                .round_trip(&test_request(), None, || {})
                .await
                .unwrap();
            assert_eq!(response.status, status);
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.scope == HealthScope::Other && o.outcome == expected),
                "{snapshot:?}"
            );
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.scope == HealthScope::Route && o.outcome == HealthOutcome::Usable)
            );
            assert_eq!(
                snapshot
                    .observations
                    .iter()
                    .map(|o| o.request_id)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                1
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_final_buffered_rejections_survive_trickling_error_body_deadline() {
        for (status, expected) in [
            (403, HealthOutcome::PolicyRejected),
            (426, HealthOutcome::ConfigurationFailure),
            (413, HealthOutcome::ResponseRejected),
            (201, HealthOutcome::ResponseRejected),
        ] {
            let relay = format!("https://health-review-rejection-{status}.invalid/relay");
            let gateway = "health-review-rejection.invalid";
            let client = get_or_create_client(
                &example_networks(),
                gateway,
                &relay,
                Dialer::Direct,
                get_default_client_trace_prefix(),
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .await
            .unwrap();
            cache_a_key(&client).await;
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |_| async move {
                let body = futures_util::stream::unfold((), |_| async {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Some((
                        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"x"))),
                        (),
                    ))
                });
                let mut response = Response::new(BodyExt::boxed(StreamBody::new(body)));
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                response
            })
            .await;
            let result = http_round_trip_via(
                &example_networks(),
                &relay,
                gateway,
                Dialer::Direct,
                "POST",
                parse_http_target("https://origin.invalid/data").unwrap(),
                &[],
                b"body",
                None,
                || {},
            )
            .await;
            assert!(
                matches!(result, Err(HttpRoundTripError::Failed(message)) if message.contains("timed out after 100s"))
            );
            let snapshot = subscription.snapshot();
            assert!(
                snapshot.observations.iter().any(|o| o.outcome == expected),
                "{status}: {snapshot:?}"
            );
            assert!(
                !snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::TransportUnavailable),
                "{status}: {snapshot:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_buffered_unsupported_head_survives_body_idle() {
        assert_buffered_body_failure_health(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn health_buffered_unsupported_head_survives_body_read_error() {
        assert_buffered_body_failure_health(true).await;
    }

    async fn assert_buffered_body_failure_health(read_error: bool) {
        use futures_util::StreamExt;

        for status in [200, 201] {
            let relay = format!("https://health-body-failure-{status}-{read_error}.invalid/relay");
            let gateway = "health-body-failure.invalid";
            let client = get_or_create_client(
                &example_networks(),
                gateway,
                &relay,
                Dialer::Direct,
                get_default_client_trace_prefix(),
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .await
            .unwrap();
            cache_a_key(&client).await;
            let subscription = health_subscription(&client);
            let calls = Arc::new(AtomicUsize::new(0));
            serve_in_process_relay_with_body_error(&client, {
                let calls = calls.clone();
                move |request| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert_eq!(request.method(), Method::POST);
                        let first = futures_util::stream::iter([Ok::<_, std::io::Error>(
                            Frame::data(Bytes::from_static(b"x")),
                        )]);
                        let failure = futures_util::stream::once(async move {
                            if !read_error {
                                return std::future::pending().await;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "fixture body reset",
                            ))
                        });
                        let mut response = Response::new(BodyExt::boxed(StreamBody::new(
                            first.chain(Box::pin(failure)),
                        )));
                        *response.status_mut() = StatusCode::from_u16(status).unwrap();
                        response
                    }
                }
            })
            .await;
            let dispatches = AtomicUsize::new(0);
            let started = tokio::time::Instant::now();
            let result = http_round_trip_via(
                &example_networks(),
                &relay,
                gateway,
                Dialer::Direct,
                "POST",
                parse_http_target("https://origin.invalid/data").unwrap(),
                &[],
                b"body",
                None,
                || {
                    dispatches.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
            assert!(
                matches!(&result, Err(HttpRoundTripError::Failed(_))),
                "{result:?}"
            );
            let expected_message = format!(
                "read relay: {}",
                if read_error {
                    "error reading a body from connection"
                } else {
                    "idle timeout (30s without data)"
                },
            );
            assert!(
                matches!(&result, Err(HttpRoundTripError::Failed(message)) if message == &expected_message),
                "{result:?}",
            );
            assert_eq!(
                started.elapsed(),
                Duration::from_secs(if read_error { 1 } else { 30 }),
                "body failure precedes the unchanged 100-second exchange deadline: {result:?}",
            );
            assert_eq!(dispatches.load(Ordering::SeqCst), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 1, "no replay or key refetch");
            let snapshot = subscription.snapshot();
            let expected = if status == 200 {
                HealthOutcome::TransportUnavailable
            } else {
                HealthOutcome::ResponseRejected
            };
            assert_eq!(snapshot.observations.len(), 1, "{snapshot:?}");
            let observation = &snapshot.observations[0];
            assert_eq!(observation.scope, HealthScope::Other);
            assert_eq!(observation.outcome, expected, "{status}: {snapshot:?}");
            assert_eq!(
                observation.stage,
                if status == 200 {
                    HealthStage::ResponseBody
                } else {
                    HealthStage::ResponseHead
                },
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_tracked_unary_owner_preserves_native_key_rejection() {
        for (status, expected) in [
            (429, None),
            (403, Some(HealthOutcome::PolicyRejected)),
            (426, Some(HealthOutcome::ConfigurationFailure)),
            (413, Some(HealthOutcome::ResponseRejected)),
            (0, Some(HealthOutcome::TransportUnavailable)),
        ] {
            let client = Arc::new(
                OhttpClient::new(
                    &example_networks(),
                    testnet_gateway(),
                    &format!("https://health-owner-key-{status}.invalid/relay"),
                    Dialer::Direct,
                    None,
                    ClientProfile::SLIPSTREAM,
                )
                .unwrap(),
            );
            let subscription = health_subscription(&client);
            serve_in_process_relay(&client, move |request| async move {
                assert_eq!(request.method(), Method::GET);
                if status == 0 {
                    return std::future::pending().await;
                }
                let body = futures_util::stream::unfold((), |_| async {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Some((
                        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"x"))),
                        (),
                    ))
                });
                let mut response = Response::new(BodyExt::boxed(StreamBody::new(body)));
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                response
            })
            .await;
            let raw = health_tonic_channel(client.clone()).await;
            let tracked = crate::grpc::TrackedConnection::ohttp(
                raw,
                OhttpConnector {
                    client,
                    health: None,
                },
                "http://health-owner-rejection.invalid:443".into(),
            );
            let result = tracked
                .call(async |client| crate::grpc::get_latest_block_height(client).await)
                .await;
            assert!(
                matches!(result, Err(crate::error::SlipstreamError::Transport(message)) if message.contains("timed out after 30s"))
            );
            let snapshot = subscription.snapshot();
            assert!(
                snapshot.observations.iter().any(|o| expected.map_or(
                    matches!(o.outcome, HealthOutcome::RateLimited { .. }),
                    |expected| o.outcome == expected
                )),
                "{status}: {snapshot:?}"
            );
            assert_eq!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::TransportUnavailable),
                status == 0,
                "{status}: {snapshot:?}"
            );
            assert!(
                snapshot.observations.iter().all(|o| o.stage
                    == if status == 0 {
                        HealthStage::ResponseHead
                    } else {
                        HealthStage::KeyConfiguration
                    }),
                "{status}: {snapshot:?}"
            );
            assert_eq!(
                snapshot
                    .observations
                    .iter()
                    .map(|o| o.request_id)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                1
            );
        }
    }

    pub(crate) async fn connector_with_trickling_key_pause() -> (
        OhttpConnector,
        crate::transport_health::HealthSubscription,
        HealthRoute,
        Arc<AtomicUsize>,
    ) {
        let tor = arti_client::TorClient::builder()
            .create_unbootstrapped()
            .unwrap();
        let client = Arc::new(
            OhttpClient::new(
                &example_networks(),
                testnet_gateway(),
                "https://health-tor-owner-relay.invalid/relay",
                Dialer::Tor(tor),
                None,
                ClientProfile::SLIPSTREAM,
            )
            .unwrap(),
        );
        let subscription = health_subscription(&client);
        let connector = OhttpConnector {
            client: client.clone(),
            health: None,
        };
        let route = connector.health_route();
        let dispatches = Arc::new(AtomicUsize::new(0));
        serve_in_process_relay(&client, {
            let dispatches = dispatches.clone();
            move |request| {
                assert_eq!(request.method(), Method::GET);
                dispatches.fetch_add(1, Ordering::SeqCst);
                async {
                    let body = futures_util::stream::unfold((), |_| async {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        Some((
                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"x"))),
                            (),
                        ))
                    });
                    let mut response = Response::new(BodyExt::boxed(StreamBody::new(body)));
                    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                    response
                }
            }
        })
        .await;
        (connector, subscription, route, dispatches)
    }

    #[tokio::test(start_paused = true)]
    async fn health_recoverable_outer_rejection_resets_before_key_fetch_blackhole() {
        for status in [400, 422] {
            let relay = format!("https://health-reset-{status}.invalid/relay");
            let gateway = testnet_gateway();
            let client = get_or_create_client(
                &example_networks(),
                gateway,
                &relay,
                Dialer::Direct,
                get_default_client_trace_prefix(),
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .await
            .unwrap();
            cache_a_key(&client).await;
            let subscription = health_subscription(&client);
            let dispatches = Arc::new(AtomicUsize::new(0));
            serve_in_process_relay(&client, {
                let dispatches = dispatches.clone();
                move |request| {
                    dispatches.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if request.method() == Method::GET {
                            return std::future::pending().await;
                        }
                        let mut response = Response::new(Full::new(Bytes::new()).boxed());
                        *response.status_mut() = StatusCode::from_u16(status).unwrap();
                        response
                    }
                }
            })
            .await;
            assert!(
                http_round_trip_via(
                    &example_networks(),
                    &relay,
                    gateway,
                    Dialer::Direct,
                    "POST",
                    parse_http_target("https://origin.invalid/data").unwrap(),
                    &[],
                    &[],
                    None,
                    || {}
                )
                .await
                .is_err()
            );
            assert_eq!(
                dispatches.load(Ordering::SeqCst),
                2,
                "one POST then its permitted key recovery GET"
            );
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
            );
            assert!(
                !snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::ConfigurationFailure)
            );
        }
    }

    #[tokio::test]
    async fn health_recoverable_outer_rejection_emits_no_intermediate_failure_when_recovered() {
        for status in [400, 422] {
            let client = health_fixture_client(&format!("health-recovered-{status}"), false).await;
            let subscription = health_subscription(&client);
            let health = RequestHealth::new(&client);
            let calls = Arc::new(AtomicUsize::new(0));
            serve_in_process_relay(&client, {
                let calls = calls.clone();
                move |request| {
                    let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    async move {
                        if first {
                            let mut response = Response::new(Full::new(Bytes::new()).boxed());
                            *response.status_mut() = StatusCode::from_u16(status).unwrap();
                            return response;
                        }
                        let request = request.into_body().collect().await.unwrap().to_bytes();
                        let (mut bytes, end) =
                            fixture_response(&request, 200, "0", "application/json");
                        bytes.extend_from_slice(&end);
                        Response::new(Full::new(Bytes::from(bytes)).boxed())
                    }
                }
            })
            .await;
            let key = client.key_config.lock().await.as_ref().unwrap().config;
            let (mut decoder, answer) = run_exchange_chunked_observed(
                key,
                &test_request(),
                |body| {
                    client.post_sealed_observed(body, SizeGuard::new(None), &|| {}, Some(&health))
                },
                || async { Ok(key) },
                Some(&health),
            )
            .await
            .unwrap();
            let mut events = decoder.push(&answer.body).unwrap();
            events.extend(decoder.finish().unwrap());
            assert_eq!(
                zodl_ohttp_client::collect_response(events).unwrap().status,
                200
            );
            assert!(
                subscription.snapshot().observations.is_empty(),
                "successful immediate recovery publishes no intermediate logical failure"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn health_concurrent_tracked_owners_keep_rejection_and_blackhole_independent() {
        let client = Arc::new(health_fixture_client("health-concurrent-owners", true).await);
        let subscription = health_subscription(&client);
        let dispatches = Arc::new(AtomicUsize::new(0));
        serve_in_process_relay(&client, {
            let dispatches = dispatches.clone();
            move |_| {
                let call = dispatches.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call > 0 {
                        return std::future::pending().await;
                    }
                    let mut response = Response::new(Full::new(Bytes::new()).boxed());
                    *response.status_mut() = StatusCode::FORBIDDEN;
                    response
                }
            }
        })
        .await;
        let key = format!("{}:{}", client.relay.host, client.relay.port);
        let opened = client.h2_pool.lock().await.get(&key).unwrap().opened;
        let raw = health_tonic_channel(client.clone()).await;
        let tracked = crate::grpc::TrackedConnection::ohttp(
            raw,
            OhttpConnector {
                client: client.clone(),
                health: None,
            },
            "http://health-concurrent-owners.invalid:443".into(),
        );
        assert!(Arc::ptr_eq(
            &client,
            &tracked.factory.as_ref().unwrap().connector.client
        ));
        let (first, second) = tokio::join!(
            tracked.call(async |client| crate::grpc::get_latest_block_height(client).await),
            tracked.call(async |client| crate::grpc::get_latest_block_height(client).await)
        );
        assert!(first.is_err() && second.is_err());
        let snapshot = subscription.snapshot();
        let rejection = snapshot
            .observations
            .iter()
            .find(|o| o.outcome == HealthOutcome::PolicyRejected)
            .unwrap();
        let timeout = snapshot
            .observations
            .iter()
            .find(|o| o.outcome == HealthOutcome::TransportUnavailable)
            .unwrap();
        assert_ne!(rejection.request_id, timeout.request_id);
        assert_eq!(dispatches.load(Ordering::SeqCst), 2);
        assert_eq!(
            client.h2_pool.lock().await.get(&key).unwrap().opened,
            opened,
            "the actual relay h2 connection is reused"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn health_tracked_cancellation_isolated_and_actual_tor_transport_reused() {
        for via_tor in [false, true] {
            let mut client =
                health_fixture_client(&format!("health-tracked-cancel-{via_tor}"), true).await;
            if via_tor {
                client.dialer = Dialer::Tor(
                    arti_client::TorClient::builder()
                        .create_unbootstrapped()
                        .unwrap(),
                );
            }
            let client = Arc::new(client);
            let subscription = health_subscription(&client);
            let dispatches = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(tokio::sync::Notify::new());
            serve_in_process_relay(&client, {
                let dispatches = dispatches.clone();
                let started = started.clone();
                move |request| {
                    let first = dispatches.fetch_add(1, Ordering::SeqCst) == 0;
                    let started = started.clone();
                    async move {
                        if first {
                            started.notify_one();
                            return std::future::pending().await;
                        }
                        let request = request.into_body().collect().await.unwrap().to_bytes();
                        let (mut bytes, end) =
                            fixture_response(&request, 200, "0", "application/grpc");
                        bytes.extend_from_slice(&end);
                        Response::new(Full::new(Bytes::from(bytes)).boxed())
                    }
                }
            })
            .await;
            let key = format!("{}:{}", client.relay.host, client.relay.port);
            let opened = client.h2_pool.lock().await.get(&key).unwrap().opened;
            let raw = health_tonic_channel(client.clone()).await;
            let tracked = crate::grpc::TrackedConnection::ohttp(
                raw,
                OhttpConnector {
                    client: client.clone(),
                    health: None,
                },
                "http://health-tracked-cancel.invalid:443".into(),
            );
            let original = &tracked.factory.as_ref().unwrap().connector.client;
            assert!(Arc::ptr_eq(&client, original));
            if let (Dialer::Tor(first), Dialer::Tor(second)) = (&client.dialer, &original.dialer) {
                assert!(Arc::ptr_eq(first, second));
            }
            let cancelled = tracked.clone();
            let task = tokio::spawn(async move {
                cancelled
                    .call(async |client| crate::grpc::get_latest_block_height(client).await)
                    .await
            });
            started.notified().await;
            let wall_start = std::time::Instant::now();
            assert_eq!(
                tracked
                    .call(async |client| crate::grpc::get_latest_block_height(client).await)
                    .await
                    .unwrap(),
                0
            );
            eprintln!(
                "tracked local-pipe plus hermetic RPC round-trip via_tor={via_tor}: {} us",
                wall_start.elapsed().as_micros()
            );
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(Duration::from_secs(101)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            let snapshot = subscription.snapshot();
            assert!(
                snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::Cancelled),
                "{snapshot:?}"
            );
            assert!(snapshot.observations.iter().any(
                |o| o.scope == HealthScope::Lightwalletd && o.outcome == HealthOutcome::Usable
            ));
            assert!(
                !snapshot
                    .observations
                    .iter()
                    .any(|o| o.outcome == HealthOutcome::TransportUnavailable)
            );
            assert_eq!(
                dispatches.load(Ordering::SeqCst),
                2,
                "no observation-only dispatch/replay"
            );
            assert_eq!(
                client.h2_pool.lock().await.get(&key).unwrap().opened,
                opened
            );
        }
    }

    #[test]
    fn typed_warm_up_errors_use_variants_instead_of_message_text() {
        use crate::error::SlipstreamError;

        let transport = SlipstreamError::from(RoundTripError::Transport(
            "HTTP 429 mentioned by an unrelated transport failure".into(),
        ));
        assert!(matches!(transport, SlipstreamError::Transport(_)));
        assert!(transport.is_transient());
        assert!(transport.counts_as_unreachable());

        let rate_limit = SlipstreamError::from(RoundTripError::RateLimited {
            detail: "pause".into(),
            retry_after: None,
        });
        assert!(matches!(rate_limit, SlipstreamError::RateLimited(_)));
        assert!(rate_limit.is_transient());
        assert!(!rate_limit.counts_as_unreachable());

        let decode = SlipstreamError::from(RoundTripError::Decode("invalid answer".into()));
        assert!(matches!(decode, SlipstreamError::MisbehavingServer));
        assert!(!decode.is_transient());

        for error in [
            RoundTripError::TooLarge("request limit".into()),
            RoundTripError::ResponseTooLarge("response limit".into()),
        ] {
            let error = SlipstreamError::from(error);
            assert!(matches!(error, SlipstreamError::RequestTooLarge(_)));
            assert!(!error.is_transient());
            assert!(!error.counts_as_unreachable());
        }
    }

    /// `http_round_trip` refuses a gateway of another network before anything is sent.
    #[tokio::test]
    async fn http_round_trip_refuses_a_gateway_of_another_network() {
        let dispatched = std::sync::atomic::AtomicBool::new(false);
        let err = http_round_trip_with_dispatch(
            &example_networks(),
            mainnet_gateway(),
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
        assert!(
            check_gateway_network(&example_networks(), mainnet_gateway(), NetworkType::Main)
                .is_ok()
        );
        assert!(
            check_gateway_network(&example_networks(), testnet_gateway(), NetworkType::Test)
                .is_ok()
        );
        assert!(
            check_gateway_network(&example_networks(), testnet_gateway(), NetworkType::Main)
                .is_err()
        );
        assert!(
            check_gateway_network(&example_networks(), mainnet_gateway(), NetworkType::Regtest)
                .is_err()
        );
        assert!(
            check_gateway_network(&example_networks(), "gw.example", NetworkType::Main).is_err()
        );
    }

    #[test]
    fn send_errors_are_never_pre_send() {
        // A send error cannot prove the request was not delivered, so it must not be retried.
        match HttpsError::classify_send_error(
            "stream to Relay.Example closed",
            "relay.example",
            "relay",
        ) {
            HttpsError::Other(m) => assert_eq!(m, "h2 send relay: stream to relay closed"),
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

    /// The gateway identity follows the configuration passed in, network by network: with both,
    /// one or neither configured, each configured gateway maps to its own relay and network in
    /// any letter case, lookalikes and the gateway of an unconfigured network map to nothing,
    /// and a gateway of the other network is refused.
    #[test]
    fn gateway_identity_follows_the_passed_configuration() {
        let example = example_networks();
        let mainnet = example.get(Network::Mainnet).cloned();
        let testnet = example.get(Network::Testnet).cloned();
        for (mainnet_on, testnet_on) in [(true, true), (true, false), (false, true), (false, false)]
        {
            let networks = OhttpNetworks::new(
                mainnet.clone().filter(|_| mainnet_on),
                testnet.clone().filter(|_| testnet_on),
            )
            .expect("networks");
            for (host, network, relay, wallet, other, on) in [
                (
                    MAINNET_GATEWAY,
                    Network::Mainnet,
                    MAINNET_RELAY,
                    NetworkType::Main,
                    NetworkType::Test,
                    mainnet_on,
                ),
                (
                    TESTNET_GATEWAY,
                    Network::Testnet,
                    TESTNET_RELAY,
                    NetworkType::Test,
                    NetworkType::Main,
                    testnet_on,
                ),
            ] {
                for spelling in [host.to_owned(), host.to_ascii_uppercase()] {
                    assert_eq!(relay_for(&networks, &spelling), on.then_some(relay));
                    assert_eq!(
                        gateway_network(&networks, &spelling).ok(),
                        on.then_some(network)
                    );
                    assert_eq!(
                        check_gateway_network(&networks, &spelling, wallet).is_ok(),
                        on
                    );
                    assert!(check_gateway_network(&networks, &spelling, other).is_err());
                    assert!(
                        check_gateway_network(&networks, &spelling, NetworkType::Regtest).is_err()
                    );
                }
                for lookalike in [format!("prefix.{host}"), format!("{host}.attacker.invalid")] {
                    assert_eq!(relay_for(&networks, &lookalike), None);
                    assert!(gateway_network(&networks, &lookalike).is_err());
                }
            }
            assert_eq!(relay_for(&networks, "unknown-gateway.invalid"), None);
            assert!(gateway_network(&networks, "unknown-gateway.invalid").is_err());
        }

        // The network comes from the configuration, never from the host name: the example
        // values with the networks swapped make the host with `testnet` in its name mainnet's.
        let swapped = OhttpNetworks::new(
            Some(
                OhttpConfig::new(OhttpConfigParams {
                    gateway_host: TESTNET_GATEWAY,
                    relay_url: TESTNET_RELAY,
                    keys_dns_name: TESTNET_KEYS_DNS_NAME,
                    signing_pubkey: TESTNET_SIGNING_KEY,
                })
                .expect("a configuration"),
            ),
            Some(
                OhttpConfig::new(OhttpConfigParams {
                    gateway_host: MAINNET_GATEWAY,
                    relay_url: MAINNET_RELAY,
                    keys_dns_name: MAINNET_KEYS_DNS_NAME,
                    signing_pubkey: MAINNET_SIGNING_KEY,
                })
                .expect("a configuration"),
            ),
        )
        .expect("networks");
        assert_eq!(
            gateway_network(&swapped, TESTNET_GATEWAY),
            Ok(Network::Mainnet)
        );
        assert_eq!(
            gateway_network(&swapped, MAINNET_GATEWAY),
            Ok(Network::Testnet)
        );
        assert!(check_gateway_network(&swapped, TESTNET_GATEWAY, NetworkType::Main).is_ok());
        assert_eq!(
            gateway_label(&swapped, TESTNET_GATEWAY),
            "mainnet ohttp-gateway"
        );
    }

    #[test]
    fn relay_mapping_covers_both_gateways() {
        assert!(relay_for(&example_networks(), testnet_gateway()).is_some());
        assert!(relay_for(&example_networks(), mainnet_gateway()).is_some());
        assert!(relay_for(&example_networks(), "zec.rocks").is_none());
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
            "key_id": "1325b850",
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
        let err =
            open_fixture_signed_keys(&ClientProfile::SLIPSTREAM, &json, testnet_gateway(), now)
                .expect_err("verify must reject an invalid signature");
        assert!(err.contains("bad signature"), "got: {err}");
    }

    /// C-01 fix test: Verify that expired configs are rejected.
    #[test]
    fn rejects_expired_signed_config() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now - 7200, now - 3600);
        let err =
            open_fixture_signed_keys(&ClientProfile::SLIPSTREAM, &json, testnet_gateway(), now)
                .expect_err("must reject expired config");
        assert!(err.contains("validity window"), "got: {err}");
    }

    /// C-01 fix test: Verify that configs with too-long validity windows are rejected.
    #[test]
    fn rejects_long_validity_window() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now, now + 25 * 60 * 60);
        let err =
            open_fixture_signed_keys(&ClientProfile::SLIPSTREAM, &json, testnet_gateway(), now)
                .expect_err("must reject validity window >24h");
        assert!(err.contains("longer than a day"), "got: {err}");
    }

    /// The envelope is checked against the network the gateway host names: a testnet envelope
    /// does not verify for the mainnet gateway.
    #[test]
    fn rejects_envelope_for_the_other_network() {
        let now = unix_now().unwrap();
        let json = unsigned_testnet_envelope(now - 60, now + 3600);
        let err =
            open_fixture_signed_keys(&ClientProfile::SLIPSTREAM, &json, mainnet_gateway(), now)
                .expect_err("network binding");
        assert!(err.contains("signed for"), "got: {err}");

        let mut mainnet_envelope: serde_json::Value = serde_json::from_slice(&json).unwrap();
        mainnet_envelope["network"] = serde_json::json!("mainnet");
        let err = open_fixture_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &serde_json::to_vec(&mainnet_envelope).unwrap(),
            testnet_gateway(),
            now,
        )
        .expect_err("testnet must reject a mainnet envelope before checking its signature");
        assert!(
            err.contains("signed for mainnet, not testnet"),
            "got: {err}"
        );
    }

    // Decode known-length BHTTP independently of the request builder under test.
    fn decode_wire_request(mut wire: &[u8]) -> BhttpRequest {
        fn integer(wire: &mut &[u8]) -> usize {
            let width = 1usize << (wire[0] >> 6);
            let mut value = usize::from(wire[0] & 0x3f);
            for byte in &wire[1..width] {
                value = (value << 8) | usize::from(*byte);
            }
            *wire = &wire[width..];
            value
        }
        fn field(wire: &mut &[u8]) -> Vec<u8> {
            let len = integer(wire);
            let value = wire[..len].to_vec();
            *wire = &wire[len..];
            value
        }
        assert_eq!(integer(&mut wire), 0, "known-length request framing");
        let method = field(&mut wire);
        let scheme = field(&mut wire);
        let authority = field(&mut wire);
        let path = field(&mut wire);
        let section = field(&mut wire);
        let mut section = section.as_slice();
        let mut headers = Vec::new();
        while !section.is_empty() {
            headers.push((field(&mut section), field(&mut section)));
        }
        let body = field(&mut wire);
        assert!(field(&mut wire).is_empty(), "empty trailers");
        assert!(wire.is_empty(), "no trailing bytes");
        BhttpRequest {
            method,
            scheme,
            authority,
            path,
            headers,
            body,
        }
    }

    #[test]
    fn grpc_request_mixed_case_authority_is_lowercase_on_wire() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("grpc-timeout", HeaderValue::from_static("5S"));
        headers.insert("x-secret", HeaderValue::from_static("Value-AbC"));
        for (authority, expected) in [
            ("MiXeD.Gateway.Example", b"mixed.gateway.example".as_slice()),
            (
                "MiXeD.Gateway.Example:8443",
                b"mixed.gateway.example:8443".as_slice(),
            ),
        ] {
            let request = grpc_request(
                authority,
                "POST",
                "/CaseSensitive/Path?Token=AbC",
                &headers,
                b"Body-AbC",
            );
            let wire =
                encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM.encode).expect("encode");
            let decoded = decode_wire_request(&wire);
            assert_eq!(decoded.authority, expected);
            assert_eq!(decoded.method, b"POST");
            assert_eq!(decoded.scheme, b"https");
            assert_eq!(decoded.path, b"/CaseSensitive/Path?Token=AbC");
            assert_eq!(decoded.body, b"Body-AbC");
            assert!(
                decoded
                    .headers
                    .contains(&(b"content-type".to_vec(), b"application/grpc".to_vec()))
            );
            assert!(
                decoded
                    .headers
                    .contains(&(b"grpc-timeout".to_vec(), b"5S".to_vec()))
            );
            assert!(!decoded.headers.iter().any(|(name, _)| name == b"x-secret"));
        }
    }

    #[test]
    fn extension_request_mixed_case_authority_is_lowercase_on_wire() {
        let target =
            parse_http_target("https://MiXeD.Gateway.Example/CaseSensitive/Path?Token=AbC")
                .expect("target");
        let headers = [("X-Custom".to_string(), "Value-AbC".to_string())];
        let request = http_bhttp_request("POST", target, &headers, b"Body-AbC");
        let wire =
            encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM_HTTP.encode).expect("encode");
        let decoded = decode_wire_request(&wire);
        assert_eq!(decoded.authority, b"mixed.gateway.example");
        assert_eq!(decoded.method, b"POST");
        assert_eq!(decoded.scheme, b"https");
        assert_eq!(decoded.path, b"/CaseSensitive/Path?Token=AbC");
        assert_eq!(decoded.body, b"Body-AbC");
        assert!(
            decoded
                .headers
                .contains(&(b"x-custom".to_vec(), b"Value-AbC".to_vec()))
        );
        assert!(!decoded.headers.iter().any(|(name, _)| name == b"X-Custom"));
    }

    #[test]
    fn grpc_request_forwards_only_grpc_headers_in_lower_case() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("grpc-timeout", HeaderValue::from_static("5S"));
        headers.insert("x-secret", HeaderValue::from_static("hunter2"));
        headers.insert(
            OHTTP_OUTCOME_AUTH_HEADER,
            HeaderValue::from_static("invented-or-replayed-authentication"),
        );
        headers.insert(
            OHTTP_OUTCOME_HEADER,
            HeaderValue::from_static(OUTCOME_RATE_LIMITED),
        );
        let request = grpc_request("gw.example", "POST", "/a.B/C", &headers, b"xyz");
        assert_eq!(request.scheme, b"https");
        assert_eq!(request.authority, b"gw.example");
        assert_eq!(request.path, b"/a.B/C");
        assert_eq!(request.body, b"xyz");
        let encoded =
            encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM.encode).expect("encode");
        assert!(contains(&encoded, b"grpc-timeout"));
        assert!(contains(&encoded, b"content-type"));
        assert!(!contains(&encoded, b"x-secret"));
        assert!(!contains(&encoded, OHTTP_OUTCOME_HEADER.as_bytes()));
        assert!(!contains(&encoded, OHTTP_OUTCOME_AUTH_HEADER.as_bytes()));
        assert!(!contains(&encoded, b"invented-or-replayed-authentication"));
    }

    #[test]
    fn extension_calls_send_lowercase_header_names() {
        let target = parse_http_target("https://h.example/path").expect("target");
        let headers = [("X-Custom".to_string(), "1".to_string())];
        let request = http_bhttp_request("GET", target, &headers, b"");
        let http = encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM_HTTP.encode).unwrap();
        assert!(contains(&http, b"x-custom") && !contains(&http, b"X-Custom"));
        let grpc = encode_bhttp_request(&request, &ClientProfile::SLIPSTREAM.encode).unwrap();
        assert!(contains(&grpc, b"x-custom") && !contains(&grpc, b"X-Custom"));
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

    /// ZIP conformance: only 200 is success, other 2xx (201-299) treated like 5xx (UNAVAILABLE).
    #[tokio::test]
    async fn outer_2xx_other_than_200_are_errors() {
        for status in [201u16, 202, 204, 206, 226] {
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
            let Err(RoundTripError::Transport(message)) = result else {
                panic!("expected Transport error for {status}, got {result:?}");
            };
            assert!(
                message.starts_with(&format!("relay/gateway HTTP {status}")),
                "got: {message}"
            );
            assert_eq!(posts.get(), 1, "status {status}");
        }
    }

    /// ZIP conformance: on 200, decapsulate whatever the Content-Type (AEAD authenticates).
    /// The code no longer checks Content-Type; AEAD decapsulation will fail if the body is wrong.
    #[tokio::test]
    async fn outer_200_with_any_content_type_is_attempted() {
        // Content-Type is now ignored; a wrong body will fail at AEAD decapsulation
        let result = run_exchange(
            &ClientProfile::SLIPSTREAM,
            test_key(),
            &test_request(),
            |_body| async {
                Ok::<RelayAnswer, HttpsError>(RelayAnswer {
                    status: StatusCode::OK,
                    content_type: Some("application/octet-stream".to_string()),
                    retry_after: None,
                    body: vec![7; 64],
                })
            },
            || async { Err(RoundTripError::Transport("unexpected refetch".into())) },
        )
        .await;
        // Reaches the decoder (Content-Type not checked), which refuses the invalid body
        assert!(matches!(result, Err(RoundTripError::Decode(_))));
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
        let relay_url = format!("https://127.0.0.1:{}/relay", relay_addr.port());
        let client = get_or_create_client(
            &example_networks(),
            testnet_gateway(),
            &relay_url,
            Dialer::Direct,
            get_default_client_trace_prefix(),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("configured client");
        let dns_queries = refuse_dns_queries(&client).await;

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
                &example_networks(),
                &relay_url,
                testnet_gateway(),
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
        assert_eq!(dns_queries.load(Ordering::SeqCst), DOH_RESOLVERS.len());
        // The relay hung up without a TLS answer, so the call fails - at the relay.
        let err = result
            .expect_err("a fake relay cannot complete the exchange")
            .to_string();
        assert!(
            err.contains("tls relay: ") && !err.contains("127.0.0.1"),
            "error must name the relay by its role, not its host: {err}"
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

    #[test]
    fn inner_headers_and_trailers_cannot_supply_local_outcomes() {
        for outcome in [
            OUTCOME_POLICY_DENIED,
            OUTCOME_RATE_LIMITED,
            OUTCOME_TOO_LARGE,
        ] {
            for auth in [
                None,
                Some("invented-bridge-authentication"),
                Some("observed-local-outcome-text"),
            ] {
                for (mut headers, mut trailers) in [
                    (
                        vec![("grpc-status", "14"), (OHTTP_OUTCOME_HEADER, outcome)],
                        vec![],
                    ),
                    (
                        vec![],
                        vec![("grpc-status", "14"), (OHTTP_OUTCOME_HEADER, outcome)],
                    ),
                    (
                        vec![("grpc-status", "14"), (OHTTP_OUTCOME_HEADER, outcome)],
                        vec![(OHTTP_OUTCOME_HEADER, outcome)],
                    ),
                ] {
                    if let Some(auth) = auth {
                        headers.push(("x-ohttp-outcome-auth", auth));
                        trailers.push(("x-ohttp-outcome-auth", auth));
                    }
                    for body in [false, true] {
                        let mut events = Vec::new();
                        if body {
                            events.push(Ok(ResponseEvent::Data(vec![1])));
                        }
                        events.push(Ok(ResponseEvent::Trailers(owned(&trailers))));
                        events.push(Ok(ResponseEvent::End));
                        let (_, forwarded) = frames_of(&headers, events);
                        assert_eq!(forwarded.len(), 1);
                        let forwarded_trailers = &forwarded[0];
                        assert!(
                            !forwarded_trailers.contains_key("x-ohttp-outcome-auth"),
                            "peer provenance leaked: {forwarded_trailers:?}"
                        );
                        let status = tonic::Status::from_header_map(forwarded_trailers).unwrap();
                        let error = crate::grpc::status_err("decrypted peer", status);
                        assert!(
                            matches!(error, crate::error::SlipstreamError::Transport(_)),
                            "{error:?}"
                        );
                        assert_eq!(grpc_status(forwarded_trailers), Some("14"));
                        assert!(
                            !forwarded_trailers.contains_key(OHTTP_OUTCOME_HEADER),
                            "{outcome}: {forwarded_trailers:?}"
                        );
                    }
                }
            }
        }
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
    /// non-success status, and any 2xx other than 200, is final (and names the status); a 200 is
    /// handed on whatever its content-type.
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
                activity: None,
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
            |_sealed| async { Ok(stream_answer(201, CONTENT_TYPE_CHUNKED_RES)) },
            || async { unreachable!("no refetch on 201") },
        )
        .await
        .err()
        .expect("a 2xx other than 200 is final");
        assert!(
            matches!(&err, RoundTripError::Transport(m) if m.contains("201")),
            "{err:?}"
        );

        // A 200 is decapsulated whatever its content-type: the AEAD authenticates the body.
        let (_decoder, answer) = run_exchange_chunked(
            test_key(),
            &test_request(),
            |_sealed| async { Ok(stream_answer(200, "text/html")) },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .expect("a 200 with another content-type is handed back unread");
        assert_eq!(answer.status, StatusCode::OK);

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

        let networks = live_networks_from_env();
        let ep = crate::config::Endpoint {
            host: networks
                .get(Network::Testnet)
                .expect("testnet")
                .gateway_host()
                .into(),
            port: 443,
            tls: true,
        };
        let mut c = crate::grpc::connect(&networks, &ep)
            .await
            .expect("connect via ohttp");
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

    /// The name of the live tests' input of `field` for `network` (`MAINNET` or `TESTNET`):
    /// `OHTTP_E2E_<FIELD>_<NETWORK>`, as zodl-ohttp's e2e client names the deployed values.
    fn live_input(field: ConfigField, network: &str) -> String {
        format!(
            "OHTTP_E2E_{}_{network}",
            field.as_str().to_ascii_uppercase()
        )
    }

    /// Every input of the live tests: the four fields of each network.
    fn live_inputs() -> Vec<String> {
        ["MAINNET", "TESTNET"]
            .into_iter()
            .flat_map(|network| ConfigField::ALL.map(|field| live_input(field, network)))
            .collect()
    }

    /// The OHTTP configuration of the live tests: [`live_inputs`] as `read` returns them, read
    /// when the tests run and never compiled in. `read` is injected so that offline tests never
    /// touch the process environment. A missing or invalid input fails naming the variable,
    /// never a value.
    fn live_networks(
        mut read: impl FnMut(&str) -> Option<String>,
    ) -> Result<OhttpNetworks, String> {
        let mut network = |network: &str| -> Result<OhttpConfig, String> {
            let mut value = |field| {
                let name = live_input(field, network);
                read(&name)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| format!("set {name} for the live OHTTP tests"))
            };
            let gateway_host = value(ConfigField::GatewayHost)?;
            let relay_url = value(ConfigField::RelayUrl)?;
            let keys_dns_name = value(ConfigField::KeysDnsName)?;
            let signing_pubkey = value(ConfigField::SigningPubkey)?;
            OhttpConfig::new(OhttpConfigParams {
                gateway_host: &gateway_host,
                relay_url: &relay_url,
                keys_dns_name: &keys_dns_name,
                signing_pubkey: &signing_pubkey,
            })
            .map_err(|e| format!("{}: {e}", live_input(e.field(), network)))
        };
        let mainnet = network("MAINNET")?;
        let testnet = network("TESTNET")?;
        OhttpNetworks::new(Some(mainnet), Some(testnet)).map_err(|e| e.to_string())
    }

    /// [`live_networks`] from the process environment, for the live tests that run manually.
    fn live_networks_from_env() -> OhttpNetworks {
        live_networks(|name| std::env::var(name).ok()).unwrap_or_else(|error| panic!("{error}"))
    }

    /// The signed key-configuration URLs of the mainnet and testnet relays of `networks`.
    fn live_fixture_config_urls(networks: &OhttpNetworks) -> Result<[String; 2], String> {
        let url = |network: Network| -> Result<String, String> {
            let relay = networks
                .get(network)
                .ok_or("no live OHTTP configuration")?
                .relay_url();
            signed_config_url(relay, ClientProfile::SLIPSTREAM.signed_config_url)
                .map_err(|e| e.to_string())
        };
        Ok([url(Network::Mainnet)?, url(Network::Testnet)?])
    }

    /// [`live_inputs`] with the example configuration as their values.
    fn example_live_inputs() -> HashMap<String, String> {
        [
            (
                "MAINNET",
                [
                    MAINNET_GATEWAY,
                    MAINNET_RELAY,
                    MAINNET_KEYS_DNS_NAME,
                    MAINNET_SIGNING_KEY,
                ],
            ),
            (
                "TESTNET",
                [
                    TESTNET_GATEWAY,
                    TESTNET_RELAY,
                    TESTNET_KEYS_DNS_NAME,
                    TESTNET_SIGNING_KEY,
                ],
            ),
        ]
        .into_iter()
        .flat_map(|(network, values)| {
            ConfigField::ALL
                .into_iter()
                .zip(values)
                .map(move |(field, value)| (live_input(field, network), value.to_owned()))
        })
        .collect()
    }

    #[test]
    fn live_fixture_urls_use_injected_relays() {
        let inputs = example_live_inputs();
        assert_eq!(inputs.len(), live_inputs().len());
        let networks = live_networks(|name| inputs.get(name).cloned()).expect("live inputs");
        assert_eq!(networks, example_networks());
        assert_eq!(
            live_fixture_config_urls(&networks).expect("signed config URLs"),
            [
                "https://relay-mainnet.example/ohttp-configs/signed",
                "https://relay-testnet.example/ohttp-configs/signed",
            ]
        );
    }

    #[test]
    fn live_fixture_urls_require_each_input_without_disclosing_values() {
        let inputs = example_live_inputs();
        for missing in live_inputs() {
            for absent in [None, Some(String::new())] {
                let error = live_networks(|name| {
                    if name == missing {
                        absent.clone()
                    } else {
                        inputs.get(name).cloned()
                    }
                })
                .expect_err("missing live input must fail before network access");
                assert!(error.contains(&missing), "{error}");
                assert!(error.contains("set"), "{error}");
                for value in inputs.values() {
                    assert!(!error.contains(value.as_str()), "{error}");
                }
            }
        }
        // An invalid input is named with the rule it breaks, not with its value.
        let invalid_input = live_input(ConfigField::GatewayHost, "TESTNET");
        let invalid = "OHTTP-GATEWAY-TESTNET.example";
        let error = live_networks(|name| {
            if name == invalid_input {
                Some(invalid.to_owned())
            } else {
                inputs.get(name).cloned()
            }
        })
        .expect_err("an upper-case host is refused");
        assert!(error.contains(&invalid_input), "{error}");
        assert!(!error.contains(invalid), "{error}");
    }

    /// Verify signed-config with real live fixtures from environment-supplied relay endpoints.
    /// Tests both mainnet and testnet with valid envelopes, tampered signatures, wrong network.
    #[tokio::test]
    #[ignore = "network"]
    async fn verify_signed_config_with_live_fixtures() {
        let profile = ClientProfile::SLIPSTREAM;
        let now = unix_now().expect("clock");
        let networks = live_networks_from_env();
        let gateway = |network| {
            networks
                .get(network)
                .expect("a live configuration")
                .gateway_host()
                .to_owned()
        };
        let (mainnet_gateway, testnet_gateway) =
            (gateway(Network::Mainnet), gateway(Network::Testnet));
        let [mainnet_url, testnet_url] =
            live_fixture_config_urls(&networks).unwrap_or_else(|error| panic!("{error}"));

        // Testnet signed config: direct fetch for testing from the supplied relay.
        let testnet_resp = reqwest::get(testnet_url)
            .await
            .expect("fetch testnet signed config")
            .bytes()
            .await
            .expect("read testnet body");

        // Valid testnet envelope should verify
        let testnet_result =
            open_signed_keys(&networks, &profile, &testnet_resp, &testnet_gateway, now);
        assert!(
            testnet_result.is_ok(),
            "testnet signed config must verify: {:?}",
            testnet_result
        );

        // Mainnet signed config: direct fetch for testing from the supplied relay.
        let mainnet_resp = reqwest::get(mainnet_url)
            .await
            .expect("fetch mainnet signed config")
            .bytes()
            .await
            .expect("read mainnet body");

        // Valid mainnet envelope should verify
        let mainnet_result =
            open_signed_keys(&networks, &profile, &mainnet_resp, &mainnet_gateway, now);
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
        let tampered_result =
            open_signed_keys(&networks, &profile, &tampered_json, &testnet_gateway, now);
        assert!(
            tampered_result.is_err(),
            "tampered signature must be rejected"
        );

        // Wrong-network test: mainnet config to testnet gateway (P3)
        let wrong_network =
            open_signed_keys(&networks, &profile, &mainnet_resp, &testnet_gateway, now);
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

        let networks = live_networks_from_env();
        let ep = crate::config::Endpoint {
            host: networks
                .get(Network::Testnet)
                .expect("testnet")
                .gateway_host()
                .into(),
            port: 443,
            tls: true,
        };

        // Metadata purposes: isolated / default circuit.
        for purpose in [ConnPurpose::MetadataDefault, ConnPurpose::MetadataUnique] {
            let t = std::time::Instant::now();
            let mut c = tokio::time::timeout(
                Duration::from_secs(120),
                connect_via(&networks, &ep, Some(&tor), purpose),
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
            connect_via(&networks, &ep, Some(&tor), ConnPurpose::BulkFetch),
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
            &example_networks(),
            "test-gateway-cache.example",
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
            &example_networks(),
            "test-gateway-cache.example",
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

    fn loopback_tls_acceptor(
        version: &'static rustls::SupportedProtocolVersion,
    ) -> tokio_rustls::TlsAcceptor {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let certificate =
            CertificateDer::from(include_bytes!("../tests/fixtures/ohttp-tls/server.der").to_vec());
        // Public fixture key, used only by the local test server.
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/fixtures/ohttp-tls/server-key.der").to_vec(),
        ));
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .expect("fixture TLS version")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("fixture certificate and key");
        server.alpn_protocols = vec![b"h2".to_vec()];
        // The default server session cache and TLS 1.3 tickets offer resumption.
        tokio_rustls::TlsAcceptor::from(Arc::new(server))
    }

    fn trust_loopback_tls_ca(config: &rustls::ClientConfig) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                include_bytes!("../tests/fixtures/ohttp-tls/ca.der").to_vec(),
            ))
            .expect("fixture CA");
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("fixture certificate verifier");
        let mut config = config.clone();
        // Keep normal certificate, signature and hostname checks, with the test CA as its trust anchor.
        config.dangerous().set_certificate_verifier(verifier);
        config
    }

    /// Rotating a connection must not offer a reusable TLS identity to the relay, including
    /// reconnects within one isolated Tor client. Removing the resumption opt-out breaks this.
    #[tokio::test]
    async fn rotated_tls_connections_do_not_resume() {
        use rustls::HandshakeKind;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        tokio::time::timeout(Duration::from_secs(10), async {
            let tor = arti_client::TorClient::builder()
                .create_unbootstrapped()
                .expect("unbootstrapped Tor client");
            let mut observed = Vec::new();
            for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
                for via_tor in [false, true] {
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TLS");
                    let address = listener.local_addr().expect("TLS address");
                    let acceptor = loopback_tls_acceptor(version);
                    let server = tokio::spawn(async move {
                        let mut handshakes = Vec::new();
                        for _ in 0..2 {
                            let (tcp, _) = listener.accept().await.expect("accept TLS TCP");
                            let mut tls = acceptor.accept(tcp).await.expect("server handshake");
                            handshakes
                                .push(tls.get_ref().1.handshake_kind().expect("handshake kind"));
                            tls.write_all(&[42]).await.expect("write after tickets");
                            let mut ack = [0];
                            tls.read_exact(&mut ack)
                                .await
                                .expect("read acknowledgement");
                            assert_eq!(ack, [43]);
                            tls.shutdown().await.expect("server TLS close");
                        }
                        handshakes
                    });
                    let client = get_or_create_client(
                        &example_networks(),
                        "tls-rotation.example",
                        &format!("https://localhost:{}/relay", address.port()),
                        if via_tor {
                            Dialer::Tor(tor.isolated_client())
                        } else {
                            Dialer::Direct
                        },
                        None,
                        ClientProfile::SLIPSTREAM_HTTP,
                    )
                    .await
                    .expect("construct OHTTP client");
                    let connector = tokio_rustls::TlsConnector::from(Arc::new(
                        trust_loopback_tls_ca(&client.tls),
                    ));
                    let mut handshakes = Vec::new();
                    for _ in 0..2 {
                        // Exercise each constructor's actual TLS config over loopback instead
                        // of bootstrapping a live Tor network for its underlying byte stream.
                        let tcp = TcpStream::connect(address).await.expect("connect TLS TCP");
                        let name = rustls::pki_types::ServerName::try_from("localhost")
                            .expect("fixture hostname");
                        let mut tls = connector
                            .connect(name, tcp)
                            .await
                            .expect("client handshake");
                        let mut marker = [0];
                        // Reading application data processes the server's preceding TLS 1.3
                        // NewSessionTicket messages before the next fresh connection starts.
                        tls.read_exact(&mut marker)
                            .await
                            .expect("read after tickets");
                        assert_eq!(marker, [42]);
                        handshakes.push(tls.get_ref().1.handshake_kind().expect("handshake kind"));
                        tls.write_all(&[43]).await.expect("acknowledge server");
                        tls.shutdown().await.expect("client TLS close");
                    }
                    observed.push((
                        version.version,
                        via_tor,
                        handshakes,
                        server.await.expect("TLS server"),
                    ));
                }
            }
            // Collect every path before asserting so a failing run diagnoses both constructors.
            eprintln!("rotated TLS handshakes: {observed:?}");
            for (version, via_tor, client, server) in observed {
                assert_eq!(
                    client,
                    [HandshakeKind::Full, HandshakeKind::Full],
                    "client {version:?}, Tor={via_tor}"
                );
                assert_eq!(
                    server,
                    [HandshakeKind::Full, HandshakeKind::Full],
                    "server {version:?}, Tor={via_tor}"
                );
            }
        })
        .await
        .expect("loopback TLS regression deadline");
    }

    #[tokio::test]
    async fn ohttp_tls_rejects_untrusted_certificates_and_wrong_hostnames() {
        use tokio::net::TcpListener;

        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TLS");
            let port = listener.local_addr().expect("TLS address").port();
            let acceptor = loopback_tls_acceptor(&rustls::version::TLS13);
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await.expect("accept TLS TCP");
                    assert!(
                        acceptor.accept(tcp).await.is_err(),
                        "client must reject certificate"
                    );
                }
            });
            let mut client = OhttpClient::new(
                &example_networks(),
                "tls-rejection.example",
                &format!("https://localhost:{port}/relay"),
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .expect("OHTTP client");
            let target = parse_https(&format!("https://localhost:{port}/relay")).expect("target");
            let error = client
                .tls_connect(&target)
                .await
                .err()
                .expect("untrusted CA rejected");
            assert!(
                matches!(error, HttpsError::Configuration(_)),
                "{}",
                error.into_message()
            );

            client.tls = Arc::new(trust_loopback_tls_ca(&client.tls));
            // The fixture is trusted, but its SAN authorizes localhost, not the loopback IP.
            let target = parse_https(&format!("https://127.0.0.1:{port}/relay")).expect("target");
            let error = client
                .tls_connect(&target)
                .await
                .err()
                .expect("wrong hostname rejected");
            assert!(
                matches!(error, HttpsError::Configuration(_)),
                "{}",
                error.into_message()
            );
            server.await.expect("TLS rejection server");
        })
        .await
        .expect("loopback certificate rejection deadline");
    }

    /// Privacy: Tor-dialer clients are NEVER cached. A cached Direct client must not be returned
    /// to a Tor call (would leak device IP when caller asked for Tor), and Tor clients must not
    /// be cached (would link requests across isolated circuits).
    #[tokio::test]
    async fn tor_clients_never_cached_never_receive_direct_cache() {
        // Create and cache a Direct client
        let direct_client = get_or_create_client(
            &example_networks(),
            "test-gateway-tor-privacy.example",
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
            &example_networks(),
            "test-gateway-tor-privacy.example",
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
            &example_networks(),
            "test-gateway-tor-privacy.example",
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
            &example_networks(),
            "test-gateway-profile.example",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .await
        .expect("create SLIPSTREAM client");

        let client_slipstream_http = get_or_create_client(
            &example_networks(),
            "test-gateway-profile.example",
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
            &example_networks(),
            "test-gateway-trace.example",
            "https://relay.example/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client without trace prefix");

        let client_with_trace = get_or_create_client(
            &example_networks(),
            "test-gateway-trace.example",
            "https://relay.example/relay",
            Dialer::Direct,
            Some("test-prefix".to_string()),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("create client with trace prefix");

        // With `client-trace` the prefix is sent, so it keys its own client; without it the prefix
        // is dropped and both callers share one pooled client.
        #[cfg(feature = "client-trace")]
        assert!(
            !Arc::ptr_eq(&client_no_trace, &client_with_trace),
            "different trace prefixes must yield distinct cached clients"
        );
        #[cfg(not(feature = "client-trace"))]
        assert!(
            Arc::ptr_eq(&client_no_trace, &client_with_trace),
            "without client-trace a trace prefix must not split the cache"
        );

        // Same params → same client (cache hit)
        let client_same = get_or_create_client(
            &example_networks(),
            "test-gateway-trace.example",
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
            &example_networks(),
            "test-gateway-expiry.example",
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

    /// Gives `client` a key that is good for another hour, so that a round trip goes straight to
    /// the relay post.
    async fn cache_a_key(client: &OhttpClient) {
        *client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: unix_now().expect("time") + 3600,
        });
    }

    /// A client of the `SLIPSTREAM_HTTP` profile for the relay at `relay_url`, with a key (see
    /// [`cache_a_key`]).
    async fn client_with_a_key(relay_url: &str) -> OhttpClient {
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            relay_url,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .expect("client");
        cache_a_key(&client).await;
        client
    }

    /// [`client_with_a_key`] for a relay on loopback port `port`.
    async fn client_with_a_key_for_a_relay_on(port: u16) -> OhttpClient {
        client_with_a_key(&format!("https://127.0.0.1:{port}/relay")).await
    }

    async fn refuse_dns_queries(client: &OhttpClient) -> Arc<AtomicUsize> {
        let requests = Arc::new(AtomicUsize::new(0));
        for resolver in DOH_RESOLVERS {
            let url = doh_query_url(&example_networks(), resolver, Network::Testnet)
                .expect("configured DNS fixture");
            let target = parse_https(&url).unwrap();
            let peer = OhttpClient::new(
                &example_networks(),
                "unused.invalid",
                &url,
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .unwrap();
            let requests = requests.clone();
            serve_in_process_relay(&peer, move |_| {
                requests.fetch_add(1, Ordering::SeqCst);
                async {
                    let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                    *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    answer
                }
            })
            .await;
            let key = format!("{}:{}", target.host, target.port);
            let sender = peer.h2_pool.lock().await.remove(&key).unwrap();
            client.h2_pool.lock().await.insert(key, sender);
        }
        requests
    }

    /// Puts an in-process relay behind the pooled h2 connection of `client` to its relay, where
    /// `h2_sender` finds it before it dials anything (so no TLS). `handler` is called for each
    /// request the client sends the relay, and answers it.
    async fn serve_in_process_relay<H, Fut>(client: &OhttpClient, handler: H)
    where
        H: Fn(Request<Incoming>) -> Fut + Send + 'static,
        Fut: Future<Output = Response<BoxBody<Bytes, Infallible>>> + Send + 'static,
    {
        serve_in_process_relay_with_body_error(client, handler).await;
    }

    async fn serve_in_process_relay_with_body_error<H, Fut, E>(client: &OhttpClient, handler: H)
    where
        H: Fn(Request<Incoming>) -> Fut + Send + 'static,
        Fut: Future<Output = Response<BoxBody<Bytes, E>>> + Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let relay = hyper::service::service_fn(move |req: Request<Incoming>| {
            let answer = handler(req);
            async move { Ok::<_, Infallible>(answer.await) }
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
            PooledH2::new(sender, None, Some(H2_IDLE_REUSE)),
        );
    }

    /// Hermetic real connector for the Tor channel/retry boundary: a relay pause
    /// with a valid key already cached must stop warm-up before opening a channel.
    pub(crate) async fn connector_with_cached_relay_pause() -> OhttpConnector {
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://tor-warm-up-cached-pause.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        cache_a_key(&client).await;
        serve_in_process_relay(&client, |_req| async {
            panic!("a cached pause must prevent relay requests")
        })
        .await;
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &HeaderMap::new());
        OhttpConnector {
            health: None,
            client: Arc::new(client),
        }
    }

    /// No cached key: the real signed-config GET receives a relay 429 over in-process h2.
    pub(crate) async fn connector_with_fresh_key_fetch_rate_limit()
    -> (OhttpConnector, Arc<AtomicUsize>) {
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://tor-warm-up-fresh-key-429.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let gets = Arc::new(AtomicUsize::new(0));
        serve_in_process_relay(&client, {
            let gets = Arc::clone(&gets);
            move |req| {
                assert_eq!(req.method(), Method::GET);
                gets.fetch_add(1, Ordering::SeqCst);
                async {
                    let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                    *answer.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                    answer
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
                    answer
                }
            }
        })
        .await;
        (
            OhttpConnector {
                health: None,
                client: Arc::new(client),
            },
            gets,
        )
    }

    /// A relay's answer of `len` bytes of filler under the sealed-response media type, in 8 KiB
    /// frames and without a content length.
    fn filler_answer(len: usize) -> Response<BoxBody<Bytes, Infallible>> {
        let frames: Vec<Result<Frame<Bytes>, Infallible>> = (0..len)
            .step_by(8 * 1024)
            .map(|start| {
                let size = (len - start).min(8 * 1024);
                Ok(Frame::data(Bytes::from(vec![7u8; size])))
            })
            .collect();
        let mut answer = Response::new(BodyExt::boxed(StreamBody::new(
            futures_util::stream::iter(frames),
        )));
        answer.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_CHUNKED_RES),
        );
        answer
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
            &example_networks(),
            testnet_gateway(),
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
            &example_networks(),
            testnet_gateway(),
            "https://relay-hook-at-send-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let hook_calls = Arc::new(AtomicUsize::new(0));
        // How many times the hook had run when each request reached the relay.
        let seen_by_relay = Arc::new(StdMutex::new(Vec::<usize>::new()));
        serve_in_process_relay(&client, {
            let hook_calls = Arc::clone(&hook_calls);
            let seen_by_relay = Arc::clone(&seen_by_relay);
            move |_req| {
                seen_by_relay
                    .lock()
                    .unwrap()
                    .push(hook_calls.load(Ordering::SeqCst));
                async { Response::new(Full::new(Bytes::from_static(b"x")).boxed()) }
            }
        })
        .await;

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
            client.post_sealed_stream(vec![0u8; 32], &hook, HeadWait::Prompt),
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
        let networks = example_networks();
        let fut = http_round_trip_with_dispatch(
            &networks,
            testnet_gateway(),
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

    /// An error page is read within its fixed guard and cut there, not refused: the frame that
    /// crosses the guard is kept up to it and the frames behind are never pulled from the relay.
    #[tokio::test]
    async fn an_error_page_is_cut_at_its_guard_not_refused() {
        let (body, pulled) = counted_body(&[40 * 1024, 40 * 1024, 40 * 1024]);
        let bytes = read_error_body(body, "relay.test").await;
        assert_eq!(bytes.len(), ERROR_BODY_GUARD_BYTES);
        assert_eq!(
            pulled.load(Ordering::SeqCst),
            2,
            "the third frame was not pulled"
        );

        let (body, _) = counted_body(&[100, 100]);
        assert_eq!(read_error_body(body, "relay.test").await.len(), 200);
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

    /// One `round_trip` of a `SLIPSTREAM_HTTP` client with a key, whose relay is in-process (see
    /// [`serve_in_process_relay`]) and answers with `answer_len` bytes of filler (see
    /// [`filler_answer`]).
    async fn round_trip_to_a_relay_answering(
        answer_len: usize,
        max_response_bytes: Option<usize>,
    ) -> Result<BhttpResponse, RoundTripError> {
        let client = client_with_a_key("https://relay-answer-ceiling-test.invalid/relay").await;
        serve_in_process_relay(
            &client,
            move |_req| async move { filler_answer(answer_len) },
        )
        .await;

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

    /// The exact bound on an answer: its opened body is checked against the caller's ceiling
    /// The decoded body is refused by the `Data` event that takes it past the ceiling, with
    /// nothing behind that event kept; exactly the ceiling is let through, and without a ceiling
    /// everything is.
    #[test]
    fn a_decoded_body_is_refused_as_soon_as_it_passes_the_ceiling() {
        let head = || ResponseEvent::Head {
            status: 200,
            headers: Vec::new(),
        };
        let mut events = AnswerEvents::new(Some(10));
        events
            .extend(vec![head(), ResponseEvent::Data(vec![0u8; 6])])
            .expect("under the ceiling");
        events
            .extend(vec![ResponseEvent::Data(vec![0u8; 4])])
            .expect("exactly the ceiling");
        assert_eq!(events.body_len, 10);
        let err = events
            .extend(vec![
                ResponseEvent::Data(vec![0u8; 1]),
                ResponseEvent::Trailers(Vec::new()),
                ResponseEvent::End,
            ])
            .expect_err("one byte past the ceiling");
        assert!(
            matches!(&err, RoundTripError::ResponseTooLarge(m) if m.contains("11 > 10")),
            "{err:?}"
        );
        assert_eq!(events.events.len(), 3, "nothing past the refusal is kept");

        let mut unbounded = AnswerEvents::new(None);
        unbounded
            .extend(vec![
                head(),
                ResponseEvent::Data(vec![0u8; 11]),
                ResponseEvent::End,
            ])
            .expect("no ceiling of the caller's");
        assert_eq!(unbounded.body_len, 11);
        assert_eq!(unbounded.events.len(), 3);
    }

    /// before the answer is returned, and exactly the ceiling is let through. (The sealed
    /// ceiling has room to spare, so only this check refuses a body just past the ceiling.)
    #[test]
    fn an_opened_answer_is_returned_up_to_the_ceiling_and_refused_past_it() {
        let answer = |len: usize| zodl_ohttp_client::Response {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: vec![0u8; len],
        };

        let returned = bhttp_response_within(answer(10), Some(10)).expect("exactly the ceiling");
        assert_eq!(returned.status, 200);
        assert_eq!(returned.body.len(), 10);
        assert_eq!(
            returned.headers,
            vec![(b"content-type".to_vec(), b"text/plain".to_vec())]
        );

        let err =
            bhttp_response_within(answer(11), Some(10)).expect_err("one byte past the ceiling");
        assert!(
            matches!(&err, RoundTripError::ResponseTooLarge(m) if m.contains("11 > 10")),
            "{err:?}"
        );

        let returned = bhttp_response_within(answer(11), None).expect("no ceiling of the caller's");
        assert_eq!(returned.body.len(), 11);
    }

    /// An answer that announces a length past the guard is refused as soon as its head arrives,
    /// without waiting for a body. This relay never sends one, which is what tells the announced
    /// length from the count of the bytes read: a body that does arrive is refused the same
    /// way by either.
    #[tokio::test]
    async fn an_announced_length_past_the_guard_is_refused_without_waiting_for_the_body() {
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            "https://relay-announced-length-test.invalid/relay",
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        serve_in_process_relay(&client, |_req| async {
            let no_body = futures_util::stream::pending::<Result<Frame<Bytes>, Infallible>>();
            let mut answer = Response::new(BodyExt::boxed(StreamBody::new(no_body)));
            answer
                .headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(101u64));
            answer
        })
        .await;

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.post_sealed(vec![0u8; 32], SizeGuard::new(Some(100)), &|| {}),
        )
        .await
        .expect("refused from the head alone, not after a body that never comes")
        .err()
        .expect("past the guard");
        assert!(matches!(err, HttpsError::TooLarge(_)), "{err:?}");
    }

    /// The public functions carry the caller's ceiling down to the read of the answer, and tell
    /// its refusal apart. They use the client the cache holds for the gateway and its relay,
    /// which this test gives a key and an in-process relay: from `http_round_trip_with_dispatch`
    /// and `http_round_trip` to the read, the code is the production code. The relay answers
    /// with filler one byte past the sealed ceiling of a caller that allows no body, and far
    /// inside the general cap.
    #[tokio::test]
    async fn the_public_functions_carry_the_ceiling_to_the_read() {
        let gateway = testnet_gateway();
        let networks = example_networks();
        let relay_url = relay_for(&networks, gateway).expect("a relay for the testnet gateway");
        let client = get_or_create_client(
            &networks,
            gateway,
            relay_url,
            Dialer::Direct,
            get_default_client_trace_prefix(),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .await
        .expect("client");
        cache_a_key(&client).await;
        let answer_len = sealed_response_ceiling(0) + 1;
        serve_in_process_relay(
            &client,
            move |_req| async move { filler_answer(answer_len) },
        )
        .await;

        // A caller that allows no body: the answer is refused as it is read, and the request
        // had gone out by then.
        let dispatched = AtomicBool::new(false);
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            http_round_trip_with_dispatch(
                &networks,
                gateway,
                NetworkType::Test,
                Dialer::Direct,
                "POST",
                "https://origin.invalid/api",
                &[],
                b"{}",
                0,
                || dispatched.store(true, Ordering::SeqCst),
            ),
        )
        .await
        .expect("the round trip must finish")
        .expect_err("past the ceiling");
        assert!(
            matches!(err, HttpRoundTripError::ResponseTooLarge(_)),
            "{err:?}"
        );
        assert!(
            dispatched.load(Ordering::SeqCst),
            "the request had gone out"
        );

        // Without a ceiling of the caller's the same answer is read, and fails to open.
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            http_round_trip(
                &networks,
                gateway,
                NetworkType::Test,
                Dialer::Direct,
                "POST",
                "https://origin.invalid/api",
                &[],
                b"{}",
            ),
        )
        .await
        .expect("the round trip must finish")
        .expect_err("filler does not open");
        assert!(err.starts_with("bhttp decode:"), "{err}");

        // The cache is process-wide: forget the client that was given the in-process relay.
        let key = ClientCacheKey::new(
            &networks,
            gateway,
            relay_url,
            get_default_client_trace_prefix(),
            ClientProfile::SLIPSTREAM_HTTP,
        )
        .expect("a cache key");
        let removed = CLIENT_CACHE
            .get()
            .expect("the cache exists")
            .lock()
            .unwrap()
            .remove(&key);
        assert!(
            removed.is_some(),
            "the client was cached under the key the public functions use"
        );
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
                    activity: None,
                })
            },
            || async { unreachable!("no refetch on 200") },
        )
        .await
        .expect("a chunked 200 is handed back unread");

        let dropped = Arc::new(AtomicBool::new(false));
        let body = StreamBody::new(PendingBody(dropped.clone())).boxed();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ResponseEvent, PumpError>>(16);
        let task = tokio::spawn(pump_chunked_body(
            body,
            decoder,
            SizeGuard::new(None),
            tx,
            None,
        ));

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
                    activity: None,
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

    /// A 429 without a `Retry-After` starts the default pause (30 s, as in the ZIP), so a relay
    /// that does not say for how long is still backed off from; another status without the
    /// header starts none, and a `Retry-After` is taken at its word.
    #[tokio::test]
    async fn a_429_without_retry_after_starts_the_default_pause() {
        let relay = "https://relay-429-default-pause-test.invalid/relay";
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");

        client.note_retry_after(StatusCode::SERVICE_UNAVAILABLE, &HeaderMap::new());
        assert!(RelayBackoff::global().remaining(relay).is_none());

        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &HeaderMap::new());
        let left = RelayBackoff::global()
            .remaining(relay)
            .expect("the default pause");
        assert!(
            left > Duration::from_secs(29) && left <= DEFAULT_RETRY_AFTER,
            "{left:?}"
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("90"));
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);
        let left = RelayBackoff::global()
            .remaining(relay)
            .expect("the longer pause");
        assert!(left > Duration::from_secs(89), "{left:?}");
    }

    /// `client_with_a_key` whose in-process relay answers every post with `status` and a 1 MiB
    /// error page (declared length, so a size guard would refuse it before a frame), with the
    /// `retry_after` header when given.
    async fn client_of_a_relay_answering_an_error_page(
        relay: &str,
        status: StatusCode,
        retry_after: Option<&'static str>,
    ) -> OhttpClient {
        let client = client_with_a_key(relay).await;
        serve_in_process_relay(&client, move |_req| async move {
            let mut answer = Response::new(Full::new(Bytes::from(vec![b'e'; 1024 * 1024])).boxed());
            *answer.status_mut() = status;
            if let Some(value) = retry_after {
                answer
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static(value));
            }
            answer
        })
        .await;
        client
    }

    /// An outer status that is not a success keeps its class whatever the caller's ceiling: the
    /// error page is read within its own fixed guard, never refused as `ResponseTooLarge`. A 503
    /// whose page is far past `sealed_response_ceiling(0)` is `Transport` quoting the page and
    /// starts no pause; a 429 without `Retry-After` is `RateLimited` and starts the default pause.
    #[tokio::test]
    async fn an_oversized_error_page_keeps_its_status_under_a_small_ceiling() {
        let relay = "https://relay-error-page-503-test.invalid/relay";
        let client =
            client_of_a_relay_answering_an_error_page(relay, StatusCode::SERVICE_UNAVAILABLE, None)
                .await;
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            client.round_trip(&test_request(), Some(0), || {}),
        )
        .await
        .expect("the round trip must finish")
        .expect_err("a 503");
        match &err {
            RoundTripError::Transport(m) => {
                assert!(m.contains("503"), "{m}");
                assert!(m.contains("eee"), "the start of the page is quoted: {m}");
            }
            other => panic!("not the status: {other:?}"),
        }
        assert!(
            RelayBackoff::global().remaining(relay).is_none(),
            "a 503 starts no pause"
        );

        let relay = "https://relay-error-page-429-test.invalid/relay";
        let client =
            client_of_a_relay_answering_an_error_page(relay, StatusCode::TOO_MANY_REQUESTS, None)
                .await;
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            client.round_trip(&test_request(), Some(0), || {}),
        )
        .await
        .expect("the round trip must finish")
        .expect_err("a 429");
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
        let left = RelayBackoff::global()
            .remaining(relay)
            .expect("the default pause was noted");
        assert!(
            left > Duration::from_secs(29) && left <= DEFAULT_RETRY_AFTER,
            "{left:?}"
        );
    }

    /// The pause a 429 asked for holds every later request through that relay, from any
    /// client, before anything is fetched or posted.
    #[tokio::test]
    async fn a_relay_pause_holds_later_requests_without_posting() {
        let relay = "https://relay-pause-test.invalid/relay";
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
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
            &example_networks(),
            testnet_gateway(),
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
            &example_networks(),
            testnet_gateway(),
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

    /// A pause another request's 429 began while the relay fetch was in flight holds the DNS
    /// fallback too.
    #[tokio::test]
    async fn a_pause_begun_during_the_relay_fetch_holds_the_dns_fallback() {
        let relay = "https://relay-pause-dns-test.invalid/relay";
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        client.note_retry_after(StatusCode::TOO_MANY_REQUESTS, &headers);

        let err = client
            .key_config_from_dns(RoundTripError::Transport("relay down".into()))
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
            &example_networks(),
            testnet_gateway(),
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
                    activity: None,
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
        pump_chunked_body(body, decoder, SizeGuard::new(None), tx, None).await;
        assert!(matches!(
            rx.recv().await,
            Some(Err(PumpError::Transport(_)))
        ));
    }

    /// A public synthetic envelope survives split TXT decoding and the same signed-key
    /// verification/selection path used for relay and DNS responses.
    #[test]
    fn dns_response_parsing_and_verification() {
        let envelope = br#"{"v":1,"network":"testnet","configs":"ACkBACDNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzQAEAAEAAQ==","not_before":1700000000,"not_after":1700021600,"key_id":"1325b850","sig":"l7xx3/Q7BNFQfnt79s+enN5Lk6KC8S9f1mE9ZhSjaYGxqeSLRyuwgddKLBhwz1boZ2y2q7oWwkmGuUd5GllVDg=="}"#;
        let name = TESTNET_KEYS_DNS_NAME;
        let encoded = base64::prelude::BASE64_STANDARD.encode(envelope);
        let (first, second) = encoded.split_at(encoded.len() / 2);
        let answer = serde_json::to_vec(&serde_json::json!({
            "Status": 0,
            "Answer": [{
                "name": name, "type": 16, "TTL": 300,
                "data": format!("\"{first}\" \"{second}\""),
            }],
        }))
        .unwrap();
        let parsed = envelope_from_doh_json(&example_networks(), &answer, Network::Testnet)
            .expect("parse answer");
        assert_eq!(parsed, envelope);
        let keys = open_fixture_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &parsed,
            testnet_gateway(),
            1_700_000_060,
        )
        .expect("verify and select public test key");
        assert_eq!(keys.not_after, 1_700_021_600);
        assert_eq!(keys.config.key_id(), 1);
        let error = open_fixture_signed_keys(
            &ClientProfile::SLIPSTREAM,
            &parsed,
            mainnet_gateway(),
            1_700_000_060,
        )
        .expect_err("testnet envelope cannot authenticate mainnet");
        assert!(error.contains("signed for testnet"), "{error}");
    }

    // Each client owns its resolver pool; only its unique relay URL shares backoff.
    async fn dns_failure_fixture(
        label: &str,
        status: StatusCode,
        retry: Option<HeaderValue>,
        failure_position: usize,
        recover: bool,
    ) -> (OhttpClient, Arc<StdMutex<Vec<usize>>>) {
        let client = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
            &format!("https://{label}.invalid/relay"),
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .unwrap();
        let envelope = br#"{"v":1,"network":"testnet","configs":"ACkBACDNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NzQAEAAEAAQ==","not_before":1700000000,"not_after":1700021600,"key_id":"1325b850","sig":"l7xx3/Q7BNFQfnt79s+enN5Lk6KC8S9f1mE9ZhSjaYGxqeSLRyuwgddKLBhwz1boZ2y2q7oWwkmGuUd5GllVDg=="}"#;
        let encoded = base64::prelude::BASE64_STANDARD.encode(envelope);
        let answer = serde_json::to_vec(&serde_json::json!({
            "Status": 0,
            "Answer": [{
                "name": TESTNET_KEYS_DNS_NAME,
                "type": 16, "TTL": 300, "data": format!("\"{encoded}\""),
            }],
        }))
        .unwrap();
        let calls = Arc::new(StdMutex::new(Vec::new()));
        for (position, resolver) in DOH_RESOLVERS.iter().enumerate() {
            let target = parse_https(
                &doh_query_url(&example_networks(), resolver, Network::Testnet).unwrap(),
            )
            .unwrap();
            let peer = OhttpClient::new(
                &example_networks(),
                "unused.invalid",
                &format!("https://{}:{}{}", target.host, target.port, target.path),
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .unwrap();
            let calls = calls.clone();
            let answer = answer.clone();
            let retry = retry.clone();
            serve_in_process_relay(&peer, move |_| {
                calls.lock().unwrap().push(position);
                let mut response = Response::new(Full::new(Bytes::from(answer.clone())).boxed());
                if position == failure_position || !recover {
                    *response.status_mut() = if position == failure_position {
                        status
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    if let Some(retry) = &retry {
                        response.headers_mut().insert("retry-after", retry.clone());
                    }
                }
                async move { response }
            })
            .await;
            let key = format!("{}:{}", target.host, target.port);
            let sender = peer.h2_pool.lock().await.remove(&key).unwrap();
            client.h2_pool.lock().await.insert(key, sender);
        }
        (client, calls)
    }

    // A DNS error must not poison relay state, even when it carries Retry-After.
    #[tokio::test]
    async fn dns_429_does_not_pause_relay_or_finish_health() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            for retry in [None, Some(HeaderValue::from_static("90"))] {
                for (position, resolver) in DOH_RESOLVERS.iter().enumerate() {
                    let label = format!(
                        "dns-health-{}-{}-{position}",
                        status.as_u16(),
                        retry.is_some()
                    );
                    let (client, calls) =
                        dns_failure_fixture(&label, status, retry.clone(), position, false).await;
                    let other = OhttpClient::new(
                        &example_networks(),
                        testnet_gateway(),
                        &client.relay_url,
                        Dialer::Direct,
                        None,
                        ClientProfile::SLIPSTREAM,
                    )
                    .unwrap();
                    let health = RequestHealth::new(&client);
                    health.boundary(HealthStage::KeyConfiguration);
                    health.classify(HealthOutcome::ConfigurationFailure);
                    let url =
                        doh_query_url(&example_networks(), resolver, Network::Testnet).unwrap();
                    assert!(
                        client
                            .fetch_dns_key_config(&url, Some(&health))
                            .await
                            .is_err()
                    );
                    assert_eq!(*calls.lock().unwrap(), vec![position]);
                    assert!(
                        RelayBackoff::global()
                            .remaining(&client.backoff_key())
                            .is_none()
                    );
                    assert!(other.check_relay_pause().is_ok());
                    assert_eq!(
                        *health.state.lock().unwrap(),
                        (
                            HealthStage::KeyConfiguration,
                            Some(HealthOutcome::ConfigurationFailure),
                            false
                        )
                    );
                }
            }
        }
    }

    // The first resolver's 429 must not block a valid signed answer from the second.
    #[tokio::test]
    async fn dns_429_allows_next_resolver_recovery() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            for retry in [None, Some(HeaderValue::from_static("90"))] {
                let label = format!("dns-recovery-{}-{}", status.as_u16(), retry.is_some());
                let (client, calls) = dns_failure_fixture(&label, status, retry, 0, true).await;
                let health = RequestHealth::new(&client);
                health.boundary(HealthStage::KeyConfiguration);
                health.classify(HealthOutcome::ConfigurationFailure);
                let result = client
                    .key_config_from_dns_with(
                        RoundTripError::Transport("original relay failure".to_owned()),
                        Some(&health),
                        |envelope| {
                            open_fixture_signed_keys(
                                &client.profile,
                                envelope,
                                &client.gateway_host,
                                1_700_000_060,
                            )
                        },
                    )
                    .await;
                assert_eq!(*calls.lock().unwrap(), vec![0, 1]);
                assert_eq!(result.expect("second resolver recovers").config.key_id(), 1);
                assert!(
                    RelayBackoff::global()
                        .remaining(&client.backoff_key())
                        .is_none()
                );
                assert!(!health.state.lock().unwrap().2);
            }
        }
    }

    // Exhausting DNS must preserve the original relay error and typed classification.
    #[tokio::test]
    async fn dns_429_preserves_original_failure_when_fallback_exhausted() {
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            for retry in [None, Some(HeaderValue::from_static("90"))] {
                for position in 0..DOH_RESOLVERS.len() {
                    let label = format!(
                        "dns-exhausted-{}-{}-{position}",
                        status.as_u16(),
                        retry.is_some()
                    );
                    let (client, calls) =
                        dns_failure_fixture(&label, status, retry.clone(), position, false).await;
                    let subscription = health_subscription(&client);
                    let health = RequestHealth::new(&client);
                    health.boundary(HealthStage::KeyConfiguration);
                    health.classify(HealthOutcome::ConfigurationFailure);
                    let err = client
                        .key_config_from_dns_with(
                            RoundTripError::Transport("original relay failure".to_owned()),
                            Some(&health),
                            |envelope| {
                                open_fixture_signed_keys(
                                    &client.profile,
                                    envelope,
                                    &client.gateway_host,
                                    1_700_000_060,
                                )
                            },
                        )
                        .await
                        .expect_err("both resolvers fail");
                    assert_eq!(*calls.lock().unwrap(), vec![0, 1]);
                    assert!(
                        matches!(&err, RoundTripError::Transport(message) if message == "original relay failure")
                    );
                    assert!(
                        RelayBackoff::global()
                            .remaining(&client.backoff_key())
                            .is_none()
                    );
                    health.error(&client, &err);
                    let observations = subscription.snapshot().observations;
                    assert_eq!(observations.len(), 1);
                    assert_eq!(observations[0].outcome, HealthOutcome::ConfigurationFailure);
                    assert_eq!(observations[0].stage, HealthStage::KeyConfiguration);
                }
            }
        }
    }

    /// DNS resolvers are tried in order; the second succeeds when the first fails.
    #[test]
    fn dns_resolver_order() {
        let network = Network::Mainnet;
        let resolvers = DOH_RESOLVERS;
        assert_eq!(resolvers.len(), 2);
        assert!(resolvers[0].contains("cloudflare"));
        assert!(resolvers[1].contains("google"));

        let url0 =
            doh_query_url(&example_networks(), resolvers[0], network).expect("configured DNS");
        assert!(url0.contains("cloudflare-dns.com"));
        assert!(url0.contains(MAINNET_KEYS_DNS_NAME));
        assert!(url0.contains("type=TXT"));

        let url1 =
            doh_query_url(&example_networks(), resolvers[1], network).expect("configured DNS");
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

    /// A gateway outside the configuration has no DNS record: the relay error is kept and no
    /// resolver is queried.
    #[tokio::test]
    async fn an_unknown_gateway_keeps_the_relay_error_without_dns() {
        let client = OhttpClient::new(
            &example_networks(),
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
            &example_networks(),
            testnet_gateway(),
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("direct client");
        let tor = OhttpClient::new(
            &example_networks(),
            testnet_gateway(),
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

    /// The testnet values of [`example_networks`]: gateway host, relay URL, DNS TXT name and
    /// signing key.
    fn configured_testnet_endpoints() -> (&'static str, &'static str, &'static str, &'static str) {
        (
            TESTNET_GATEWAY,
            TESTNET_RELAY,
            TESTNET_KEYS_DNS_NAME,
            TESTNET_SIGNING_KEY,
        )
    }

    /// The INFO+ lines logged on this thread while the guard lives.
    #[derive(Clone, Default)]
    struct Lines(Arc<StdMutex<Vec<u8>>>);
    impl std::io::Write for Lines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Lines {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
        }
    }

    fn capture_info_logs() -> (Lines, tracing::subscriber::DefaultGuard) {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let lines = Lines::default();
        let guard = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer({
                        let lines = lines.clone();
                        move || lines.clone()
                    })
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            )
            .set_default();
        (lines, guard)
    }

    /// Info-level logs reach the device log in every build, so no INFO+ line may carry an
    /// endpoint value of the configuration: gateway host, relay URL or host, DNS TXT name,
    /// signing key.
    #[tokio::test]
    async fn info_logs_carry_no_endpoint_values() {
        let (lines, _logs) = capture_info_logs();

        let (gateway, relay, dns_name, signing_key) = configured_testnet_endpoints();
        // Opening the pipe of a gateway endpoint makes no network request.
        let endpoint = crate::config::Endpoint {
            host: gateway.into(),
            port: 443,
            tls: true,
        };
        let _channel = crate::grpc::connect(&example_networks(), &endpoint)
            .await
            .expect("open OHTTP pipe");

        // An expired key, then a relay and DoH resolvers that refuse the fetch.
        let client = OhttpClient::new(
            &example_networks(),
            gateway,
            relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        *client.key_config.lock().await = Some(CachedKey {
            config: test_key(),
            not_after: 0,
        });
        let refuse = |_req: Request<Incoming>| async {
            let mut answer = Response::new(Full::new(Bytes::new()).boxed());
            *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            answer
        };
        serve_in_process_relay(&client, refuse).await;
        for resolver in DOH_RESOLVERS {
            let peer = OhttpClient::new(
                &example_networks(),
                "unused.invalid",
                resolver,
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .expect("resolver client");
            serve_in_process_relay(&peer, refuse).await;
            let key = format!("{}:{}", peer.relay.host, peer.relay.port);
            let sender = peer.h2_pool.lock().await.remove(&key).expect("pooled");
            client.h2_pool.lock().await.insert(key, sender);
        }
        let _ = client
            .key_config(false)
            .await
            .expect_err("the fetch is refused");
        assert_eq!(log_host(&example_networks(), gateway), "ohttp-gateway");

        let logs = lines.text();
        for logged in [
            "lightwalletd via OHTTP",
            "cached key config expired",
            "trying DNS",
        ] {
            assert!(logs.contains(logged), "logged at info: {logged}");
        }
        let relay_host = parse_https(relay).expect("relay URL").host;
        for value in [gateway, relay, &relay_host, dns_name, signing_key] {
            // The value itself stays out of the failure message.
            assert!(
                !logs.contains(value),
                "an INFO+ line carries an endpoint value"
            );
        }
    }

    /// A relay that cannot be reached: its connect error is logged at info ("trying DNS") and
    /// returned to the caller, whose error lines log it too. Both name the peer as `relay`,
    /// never by its host. So do the other errors that name a gateway or relay.
    #[tokio::test]
    async fn connect_failures_carry_no_endpoint_values() {
        let (lines, _logs) = capture_info_logs();

        // A loopback port without a listener refuses the dial; no external network.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("address").port();
        drop(closed);
        let relay_host = "127.0.0.1";
        let relay = format!("https://{relay_host}:{port}/relay");
        let (gateway, _, _, _) = configured_testnet_endpoints();
        let client = OhttpClient::new(
            &example_networks(),
            gateway,
            &relay,
            Dialer::Direct,
            None,
            ClientProfile::SLIPSTREAM,
        )
        .expect("client");
        let refuse = |_req: Request<Incoming>| async {
            let mut answer = Response::new(Full::new(Bytes::new()).boxed());
            *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            answer
        };
        for resolver in DOH_RESOLVERS {
            let peer = OhttpClient::new(
                &example_networks(),
                "unused.invalid",
                resolver,
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM,
            )
            .expect("resolver client");
            serve_in_process_relay(&peer, refuse).await;
            let key = format!("{}:{}", peer.relay.host, peer.relay.port);
            let sender = peer.h2_pool.lock().await.remove(&key).expect("pooled");
            client.h2_pool.lock().await.insert(key, sender);
        }
        let err = client
            .key_config(false)
            .await
            .expect_err("the relay is unreachable")
            .into_message();
        assert!(err.starts_with("connect relay: "), "{err}");
        assert!(
            !err.contains(relay_host),
            "the error carries the relay host"
        );

        let logs = lines.text();
        assert!(logs.contains("trying DNS"), "logged at info: trying DNS");
        assert!(
            logs.contains("connect relay: "),
            "the connect error is logged"
        );
        assert!(
            !logs.contains(relay_host),
            "an INFO+ line carries the relay host"
        );

        // Errors that name a configured gateway carry its network, not its host.
        let wrong = check_gateway_network(&example_networks(), gateway, NetworkType::Main)
            .expect_err("testnet");
        assert!(
            !wrong.contains(gateway),
            "the error carries the gateway host"
        );
        assert_eq!(
            gateway_label(&example_networks(), gateway),
            "testnet ohttp-gateway"
        );
        // An inner error naming the peer, in any letter case, names its label instead.
        assert_eq!(
            redact_host("not valid for RELAY.example:443", "relay.example", "relay"),
            "not valid for relay:443"
        );
    }

    // ── The OHTTP configuration passed at runtime ───────────────────────────────────────────

    // The example configuration of the tests: RFC 2606 names, and the public keys of RFC 8032
    // §7.1 TEST 1 (mainnet) and TEST 2 (testnet) as signing keys.
    const MAINNET_GATEWAY: &str = "ohttp-gateway.example";
    const TESTNET_GATEWAY: &str = "ohttp-gateway-testnet.example";
    const MAINNET_RELAY: &str = "https://relay-mainnet.example/relay";
    const TESTNET_RELAY: &str = "https://relay-testnet.example/relay";
    const MAINNET_KEYS_DNS_NAME: &str = "mainnet.ohttp-keys.example";
    const TESTNET_KEYS_DNS_NAME: &str = "testnet.ohttp-keys.example";
    const MAINNET_SIGNING_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TESTNET_SIGNING_KEY: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    /// The public synthetic signer of the fixture envelopes (key id `1325b850`).
    const FIXTURE_SIGNING_KEY: &str =
        "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";

    /// Both networks on, with the example configuration.
    pub(crate) fn example_networks() -> OhttpNetworks {
        example_networks_signed_by(TESTNET_SIGNING_KEY)
    }

    /// [`example_networks`] with the fixture envelopes' signer as the testnet signing key, for
    /// the tests that verify those envelopes.
    fn fixture_networks() -> OhttpNetworks {
        example_networks_signed_by(FIXTURE_SIGNING_KEY)
    }

    /// [`example_networks`]' testnet configuration with another signing key, the RFC 8032 §7.1
    /// TEST 1 public key (the example mainnet key), and mainnet off: a configuration that differs
    /// from the example one for the testnet gateway only in its signing key.
    pub(crate) fn example_testnet_with_another_signer() -> OhttpNetworks {
        let testnet = OhttpConfig::new(OhttpConfigParams {
            gateway_host: TESTNET_GATEWAY,
            relay_url: TESTNET_RELAY,
            keys_dns_name: TESTNET_KEYS_DNS_NAME,
            signing_pubkey: MAINNET_SIGNING_KEY,
        })
        .expect("an example configuration");
        OhttpNetworks::new(None, Some(testnet)).expect("one network")
    }

    /// The example configuration with `testnet_signing_key` as the testnet signing key.
    fn example_networks_signed_by(testnet_signing_key: &str) -> OhttpNetworks {
        let config = |gateway_host, relay_url, keys_dns_name, signing_pubkey| {
            OhttpConfig::new(OhttpConfigParams {
                gateway_host,
                relay_url,
                keys_dns_name,
                signing_pubkey,
            })
            .expect("an example configuration")
        };
        OhttpNetworks::new(
            Some(config(
                MAINNET_GATEWAY,
                MAINNET_RELAY,
                MAINNET_KEYS_DNS_NAME,
                MAINNET_SIGNING_KEY,
            )),
            Some(config(
                TESTNET_GATEWAY,
                TESTNET_RELAY,
                TESTNET_KEYS_DNS_NAME,
                testnet_signing_key,
            )),
        )
        .expect("example networks")
    }

    /// A gateway host typed or stored in another letter case is still the configured gateway:
    /// host names are case insensitive, while the configuration matches exactly.
    #[test]
    fn relay_for_matches_configured_gateway_ignoring_case() {
        let networks = example_networks();
        for (host, relay) in [
            (MAINNET_GATEWAY, MAINNET_RELAY),
            ("OHTTP-GATEWAY.example", MAINNET_RELAY),
            ("Ohttp-Gateway.Example", MAINNET_RELAY),
            (TESTNET_GATEWAY, TESTNET_RELAY),
            ("OHTTP-GATEWAY-TESTNET.EXAMPLE", TESTNET_RELAY),
        ] {
            assert_eq!(relay_for(&networks, host), Some(relay), "{host}");
        }
        for host in [
            "prefix.ohttp-gateway.example",
            "ohttp-gateway.example.attacker.invalid",
            "ohttp-gateway",
            "zec.rocks",
            "",
        ] {
            assert_eq!(relay_for(&networks, host), None, "{host}");
        }
    }

    /// Without a configuration OHTTP is off: no host has a relay or a network, the example
    /// gateways included.
    #[test]
    fn configuration_key_debug_shows_no_configured_value() {
        let key = ConfigurationKey::of(&example_networks(), MAINNET_GATEWAY).expect("key");
        let shown = format!("{key:?} {:?}", Some(&key));
        assert!(shown.contains("mainnet"), "{shown}");
        for value in [
            MAINNET_GATEWAY,
            MAINNET_RELAY,
            MAINNET_KEYS_DNS_NAME,
            MAINNET_SIGNING_KEY,
            "example",
            "d75a9801",
        ] {
            assert!(!shown.contains(value), "{shown}");
        }
        // Nor does a cache key that contains it.
        let id = format!(
            "{:?}",
            SharedKeyId {
                gateway_host: String::new(),
                relay: String::new(),
                configuration: Some(key),
            }
        );
        assert!(!id.contains("example") && !id.contains("d75a9801"), "{id}");
    }

    #[test]
    fn live_input_names_are_the_documented_ones() {
        let names = live_inputs();
        let expected = [
            "OHTTP_E2E_GATEWAY_HOST_MAINNET",
            "OHTTP_E2E_RELAY_URL_MAINNET",
            "OHTTP_E2E_KEYS_DNS_NAME_MAINNET",
            "OHTTP_E2E_SIGNING_PUBKEY_MAINNET",
            "OHTTP_E2E_GATEWAY_HOST_TESTNET",
            "OHTTP_E2E_RELAY_URL_TESTNET",
            "OHTTP_E2E_KEYS_DNS_NAME_TESTNET",
            "OHTTP_E2E_SIGNING_PUBKEY_TESTNET",
        ];
        let mut got = names.clone();
        got.sort();
        let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn relay_for_is_none_without_configuration() {
        let networks = OhttpNetworks::default();
        for host in [
            MAINNET_GATEWAY,
            TESTNET_GATEWAY,
            "OHTTP-GATEWAY.example",
            "zec.rocks",
        ] {
            assert_eq!(relay_for(&networks, host), None, "{host}");
            assert!(gateway_network(&networks, host).is_err(), "{host}");
        }
    }

    /// Every constructor of a connector builds one for the gateway of a configured network
    /// only, in any letter case, and takes its relay from that network's configuration. The
    /// error for any other host does not repeat it.
    #[tokio::test]
    async fn connector_refuses_unconfigured_gateway() {
        let tor = || {
            Dialer::Tor(
                arti_client::TorClient::builder()
                    .create_unbootstrapped()
                    .expect("unbootstrapped tor client"),
            )
        };
        let configured = example_networks();
        let off = OhttpNetworks::default();
        for (networks, host) in [
            (&off, MAINNET_GATEWAY),
            (&off, TESTNET_GATEWAY),
            (&configured, "zec.rocks"),
            (&configured, "prefix.ohttp-gateway.example"),
        ] {
            for refused in [
                OhttpConnector::new(networks, host).err(),
                OhttpConnector::dedicated(networks, host).err(),
                OhttpConnector::with_dialer(networks, host, Dialer::Direct, None).err(),
                OhttpConnector::with_dialer(networks, host, tor(), None).err(),
            ] {
                let error = refused.expect("a host outside the configuration is refused");
                assert!(!error.contains(host), "the error names the host: {error}");
            }
        }
        for (host, relay) in [
            ("OHTTP-GATEWAY.example", MAINNET_RELAY),
            (TESTNET_GATEWAY, TESTNET_RELAY),
        ] {
            for connector in [
                OhttpConnector::new(&configured, host),
                OhttpConnector::dedicated(&configured, host),
                OhttpConnector::with_dialer(&configured, host, tor(), None),
            ] {
                let route = connector.expect("a configured gateway").health_route();
                assert_eq!(route.gateway_host, host);
                assert_eq!(route.relay_url, relay);
            }
        }
    }

    /// Clients and verified keys are cached under the whole configuration of the gateway's
    /// network: two configurations with the same gateway and relay but different signing keys
    /// share neither a client nor a key verified under the other's signer.
    #[tokio::test]
    async fn client_cache_key_covers_whole_configuration() {
        let relay = "https://relay-cache-configuration.invalid/relay";
        let first = example_networks();
        let second = example_testnet_with_another_signer();
        let key = |networks: &OhttpNetworks| {
            ClientCacheKey::new(
                networks,
                TESTNET_GATEWAY,
                relay,
                None,
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .expect("a cache key")
        };
        assert_ne!(key(&first), key(&second));
        assert_eq!(key(&first), key(&example_networks()));

        let client = |networks: &OhttpNetworks| {
            cached_or_new_client(
                networks,
                TESTNET_GATEWAY,
                relay,
                Dialer::Direct,
                None,
                ClientProfile::SLIPSTREAM_HTTP,
            )
            .expect("client")
        };
        let (a, b) = (client(&first), client(&second));
        assert!(
            !Arc::ptr_eq(&a, &b),
            "another configuration gets its own client"
        );
        assert!(
            Arc::ptr_eq(&a, &client(&example_networks())),
            "the same configuration shares one"
        );

        // A key verified under the first configuration's signer serves the first only.
        assert_ne!(a.shared_key(), b.shared_key());
        shared_keys().insert(
            a.shared_key(),
            CachedKey {
                config: test_key(),
                not_after: unix_now().expect("time") + 3600,
            },
        );
        let fetches = Arc::new(AtomicUsize::new(0));
        serve_in_process_relay(&b, {
            let fetches = fetches.clone();
            move |_| {
                fetches.fetch_add(1, Ordering::SeqCst);
                async {
                    let mut answer = Response::new(Full::new(Bytes::new()).boxed());
                    *answer.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                    answer
                }
            }
        })
        .await;
        let dns_queries = refuse_dns_queries(&b).await;
        assert!(
            b.key_config(false).await.is_err(),
            "the second configuration fetches a key of its own"
        );
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert_eq!(dns_queries.load(Ordering::SeqCst), DOH_RESOLVERS.len());
        assert_eq!(
            a.key_config(false).await.expect("the shared key").key_id(),
            test_key().key_id()
        );
    }

    /// Info lines show a configured gateway host only as `ohttp-gateway`, in any letter case;
    /// a host the configuration does not name, the example gateways without a configuration
    /// included, is shown as it is.
    #[test]
    fn log_host_redacts_only_configured_gateways() {
        let networks = example_networks();
        assert_eq!(log_host(&networks, MAINNET_GATEWAY), "ohttp-gateway");
        assert_eq!(
            log_host(&networks, "OHTTP-GATEWAY-TESTNET.example"),
            "ohttp-gateway"
        );
        assert_eq!(log_host(&networks, "zec.rocks"), "zec.rocks");
        assert_eq!(
            gateway_label(&networks, "OHTTP-GATEWAY.example"),
            "mainnet ohttp-gateway"
        );
        assert_eq!(
            gateway_label(&networks, TESTNET_GATEWAY),
            "testnet ohttp-gateway"
        );
        let off = OhttpNetworks::default();
        assert_eq!(log_host(&off, MAINNET_GATEWAY), MAINNET_GATEWAY);
        assert_eq!(log_host(&off, TESTNET_GATEWAY), TESTNET_GATEWAY);
    }

    /// Without a configuration of the gateway's network, a plain HTTP round trip fails before
    /// anything is sent, and its error does not name the host.
    #[tokio::test]
    async fn http_round_trip_without_configuration_fails_before_sending() {
        let off = OhttpNetworks::default();
        let mainnet_only =
            OhttpNetworks::new(example_networks().get(Network::Mainnet).cloned(), None)
                .expect("one network");
        for (networks, host, network) in [
            (&off, MAINNET_GATEWAY, NetworkType::Main),
            (&off, TESTNET_GATEWAY, NetworkType::Test),
            (&mainnet_only, TESTNET_GATEWAY, NetworkType::Test),
        ] {
            let dispatched = AtomicBool::new(false);
            let err = http_round_trip_with_dispatch(
                networks,
                host,
                network,
                Dialer::Direct,
                "POST",
                "https://vote.example/api",
                &[],
                b"{}",
                256 * 1024,
                || dispatched.store(true, Ordering::SeqCst),
            )
            .await
            .expect_err("OHTTP is off for the gateway's network");
            assert!(
                matches!(&err, HttpRoundTripError::Failed(m) if !m.contains(host)),
                "{err:?}"
            );
            assert!(!dispatched.load(Ordering::SeqCst), "nothing was sent");
            let err = http_round_trip(
                networks,
                host,
                network,
                Dialer::Direct,
                "GET",
                "https://vote.example/api",
                &[],
                b"",
            )
            .await
            .expect_err("OHTTP is off for the gateway's network");
            assert!(!err.contains(host), "{err}");
        }
    }
}
