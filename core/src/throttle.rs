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

//! [v0.7 P0] The weather machine: a local TCP proxy with a token-bucket
//! bandwidth cap, so "sick server" is a deterministic test fixture instead
//! of a wait for real weather (the v0.6.0 ship day measured a 10× same-
//! morning provider swing — 1.5 → 14.7 MB/s — with zero hard failures;
//! that shape is what this reproduces on demand).
//!
//! Scope: plain TCP pass-through. Darkside lightwalletd runs
//! `--no-tls-very-insecure`, so the P4 ship gates run entirely behind this
//! proxy. Real-server TLS is deliberately OUT of scope: the client's SNI +
//! certificate pin to the true hostname, and this proxy does not (and must
//! not) terminate TLS.
//!
//! The cap models server egress, matching the observed failure mode: ONE
//! bucket shared by every connection (the engine's 4 streams share the sick
//! pipe), applied to the server→client direction only (requests are tiny).
//! [`ThrottleProxy::set_cap`] retunes it mid-stream — the P4 "mid-pass
//! collapse" gate flips a healthy pipe sick at T+15 s and watches the
//! failover fire.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Uncapped sentinel for [`ThrottleProxy::set_cap`].
pub const UNCAPPED: u64 = u64::MAX;

/// Shared token bucket: `cap` bytes/second with a one-second burst ceiling.
/// The cap is re-read on every refill, so a runtime [`ThrottleProxy::set_cap`]
/// takes effect within one pump read (≤ [`READ_BUF`] bytes).
struct TokenBucket {
    cap: AtomicU64,
    state: Mutex<BucketState>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

/// Pump read size. Small enough that a cap change bites quickly, big enough
/// that the throttle overhead is invisible at healthy rates.
const READ_BUF: usize = 16 * 1024;

impl TokenBucket {
    fn new(cap_bytes_per_sec: u64) -> Self {
        Self {
            cap: AtomicU64::new(cap_bytes_per_sec),
            state: Mutex::new(BucketState {
                tokens: 0.0,
                last: Instant::now(),
            }),
        }
    }

    /// Debit `n` bytes, sleeping until the bucket can afford them. Sleeps in
    /// short slices so a mid-wait cap change is honored promptly.
    async fn consume(&self, n: usize) {
        loop {
            let cap = self.cap.load(Ordering::Relaxed);
            if cap == UNCAPPED {
                return;
            }
            let cap = cap.max(1) as f64;
            let wait = {
                let mut s = self.state.lock().await;
                let now = Instant::now();
                s.tokens = (s.tokens + now.duration_since(s.last).as_secs_f64() * cap).min(cap);
                s.last = now;
                if s.tokens >= n as f64 {
                    s.tokens -= n as f64;
                    return;
                }
                (n as f64 - s.tokens) / cap
            };
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait.min(0.05))).await;
        }
    }
}

/// A running weather machine. Dropping it does NOT stop the proxy — call
/// [`ThrottleProxy::shutdown`] (tests) or let the process end (CLI).
pub struct ThrottleProxy {
    local_addr: SocketAddr,
    bucket: Arc<TokenBucket>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl ThrottleProxy {
    /// Bind 127.0.0.1:`listen_port` (0 = ephemeral, see [`Self::local_addr`])
    /// and forward every connection to `target`, capping the server→client
    /// direction at `cap_bytes_per_sec` (shared across connections).
    pub async fn start(
        listen_port: u16,
        target: SocketAddr,
        cap_bytes_per_sec: u64,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", listen_port)).await?;
        let local_addr = listener.local_addr()?;
        let bucket = Arc::new(TokenBucket::new(cap_bytes_per_sec));
        let accept_bucket = Arc::clone(&bucket);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    return; // listener closed (shutdown) or fatal accept error
                };
                let bucket = Arc::clone(&accept_bucket);
                tokio::spawn(async move {
                    // Per-connection failures (refused target, mid-stream
                    // reset) just drop the connection — exactly what a real
                    // sick server does; the client's own retry story is the
                    // thing under test.
                    let _ = proxy_connection(client, target, bucket).await;
                });
            }
        });
        Ok(Self {
            local_addr,
            bucket,
            accept_task,
        })
    }

    /// The bound address — point the engine's `Endpoint` here (tls = false).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Retune the cap (bytes/second; [`UNCAPPED`] lifts it). Takes effect
    /// within one in-flight read on every open connection.
    pub fn set_cap(&self, cap_bytes_per_sec: u64) {
        self.bucket.cap.store(cap_bytes_per_sec, Ordering::Relaxed);
    }

    /// Stop accepting and tear down. In-flight connections die with their
    /// tasks when both ends close.
    pub fn shutdown(self) {
        self.accept_task.abort();
    }
}

async fn proxy_connection(
    client: TcpStream,
    target: SocketAddr,
    bucket: Arc<TokenBucket>,
) -> io::Result<()> {
    let server = TcpStream::connect(target).await?;
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut server_rd, mut server_wr) = server.into_split();

    // Upstream (requests): tiny, never throttled.
    let up = tokio::spawn(async move {
        let mut buf = [0u8; READ_BUF];
        loop {
            match client_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if server_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = server_wr.shutdown().await;
    });

    // Downstream (block data): the throttled direction.
    let mut buf = [0u8; READ_BUF];
    loop {
        match server_rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                bucket.consume(n).await;
                if client_wr.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = client_wr.shutdown().await;
    up.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-shot blast server: accepts connections and writes `total` bytes
    /// at full speed — the healthiest possible upstream, so measured pacing
    /// is the proxy's doing alone.
    async fn blast_server(total: usize) -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let chunk = vec![0xABu8; 64 * 1024];
                    let mut sent = 0;
                    while sent < total {
                        let n = chunk.len().min(total - sent);
                        if sock.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        sent += n;
                    }
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    async fn read_all(addr: SocketAddr) -> usize {
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => return total,
                Ok(n) => total += n,
            }
        }
    }

    /// The cap paces the pipe: 1.5 MB through a 1 MB/s proxy takes ~1.5 s
    /// (and materially longer than uncapped).
    #[tokio::test]
    async fn cap_paces_downstream() {
        let total = 1_500_000usize;
        let target = blast_server(total).await;
        let proxy = ThrottleProxy::start(0, target, 1_000_000)
            .await
            .expect("proxy");

        let started = Instant::now();
        let got = read_all(proxy.local_addr()).await;
        let elapsed = started.elapsed().as_secs_f64();

        assert_eq!(got, total, "byte-transparent");
        // ~1.5 s expected minus the 1 s burst allowance; generous CI bounds.
        assert!(elapsed > 0.35, "cap did not pace: {elapsed:.2}s");
        assert!(elapsed < 4.0, "cap overshot: {elapsed:.2}s");
        proxy.shutdown();
    }

    /// Mid-stream retune: the cap change must bite live connections. Tested
    /// in the buffer-proof direction — start CAPPED (the client can never be
    /// ahead of the bucket, so no kernel-buffer race) and lift the cap
    /// mid-stream; the tail must then arrive far faster than the capped
    /// head. Same mechanism the P4 "mid-pass collapse" gate drives the other
    /// way at engine scale, where transfers dwarf socket buffering.
    #[tokio::test]
    async fn set_cap_bites_mid_stream() {
        let total = 2_000_000usize;
        let target = blast_server(total).await;
        let proxy = ThrottleProxy::start(0, target, 400_000)
            .await
            .expect("proxy");
        let addr = proxy.local_addr();

        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0;
        // Capped head: 800 KB at 400 KB/s must take ~2 s (tokens start empty).
        let started = Instant::now();
        while got < 800_000 {
            let n = sock.read(&mut buf).await.expect("read");
            assert!(n > 0, "early eof");
            got += n;
        }
        let head = started.elapsed().as_secs_f64();
        // Lift the cap; the remaining ~1.2 MB must now pour.
        proxy.set_cap(UNCAPPED);
        let started = Instant::now();
        while got < total {
            match sock.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => break,
            }
        }
        let tail = started.elapsed().as_secs_f64();
        assert_eq!(got, total, "byte-transparent across retune");
        assert!(head > 1.0, "cap did not pace the head: {head:.2}s");
        assert!(
            tail < head / 2.0,
            "lifting the cap did not bite: head {head:.2}s tail {tail:.2}s"
        );
        proxy.shutdown();
    }

    /// Byte transparency at uncapped speed (the proxy must never corrupt or
    /// truncate — a broken weather machine would invalidate every P4 gate).
    #[tokio::test]
    async fn uncapped_is_transparent() {
        let total = 3_000_000usize;
        let target = blast_server(total).await;
        let proxy = ThrottleProxy::start(0, target, UNCAPPED)
            .await
            .expect("proxy");
        let got = read_all(proxy.local_addr()).await;
        assert_eq!(got, total);
        proxy.shutdown();
    }
}
