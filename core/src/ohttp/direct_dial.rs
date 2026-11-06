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

//! Direct-only address racing. The dial owns every connection future, so cancellation,
//! timeout and the first success drop all losing attempts without background tasks.

use std::{collections::VecDeque, future::Future, io, net::SocketAddr, time::Duration};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::time::{Instant, sleep_until, timeout_at};

use super::DIRECT_DIAL_TIMEOUT;

const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const MAX_ACTIVE_ATTEMPTS: usize = 2;

pub(super) async fn connect<R, I, C, F, T>(
    resolve: R,
    connector: C,
) -> Result<io::Result<T>, tokio::time::error::Elapsed>
where
    R: Future<Output = io::Result<I>>,
    I: IntoIterator<Item = SocketAddr>,
    C: FnMut(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    // DNS and all candidates consume one budget; a slow resolver cannot restart it.
    let deadline = Instant::now() + DIRECT_DIAL_TIMEOUT;
    timeout_at(deadline, async {
        // Resolver diagnostics can contain hostnames or IPs. Preserve the kind and a fixed
        // category without retaining the original error or its source chain.
        let addresses = resolve
            .await
            .map_err(|error| io::Error::new(error.kind(), "address resolution failed"))?;
        race_addresses(addresses, connector).await
    })
    .await
}

async fn race_addresses<I, C, F, T>(addresses: I, mut connector: C) -> io::Result<T>
where
    I: IntoIterator<Item = SocketAddr>,
    C: FnMut(SocketAddr) -> F,
    F: Future<Output = io::Result<T>>,
{
    let mut addresses = addresses.into_iter().peekable();
    let first_is_ipv6 = addresses.peek().is_some_and(SocketAddr::is_ipv6);
    let (mut preferred, mut alternate): (VecDeque<_>, VecDeque<_>) =
        addresses.partition(|address| address.is_ipv6() == first_is_ipv6);
    // Respect DNS's preferred family and each family's order, but try the other family
    // second even if DNS returned several preferred-family addresses first.
    let mut addresses = std::iter::from_fn(move || {
        let next = preferred.pop_front().or_else(|| alternate.pop_front());
        std::mem::swap(&mut preferred, &mut alternate);
        next
    })
    .peekable();
    let mut active = FuturesUnordered::new();
    let mut last_error = io::Error::new(
        io::ErrorKind::InvalidInput,
        "could not resolve to any address",
    );
    let mut next_start = Instant::now();
    loop {
        if active.is_empty() {
            let Some(address) = addresses.next() else {
                return Err(last_error);
            };
            active.push(connector(address));
            next_start = Instant::now() + ATTEMPT_DELAY;
        }
        tokio::select! {
            result = active.next() => {
                match result.expect("at least one active connection") {
                    Ok(stream) => return Ok(stream),
                    // Connector errors may contain resolved addresses. Keep this category
                    // distinct from resolver failures and an empty DNS answer.
                    Err(error) => {
                        last_error = io::Error::new(
                            error.kind(),
                            format!("connection failed: {}", error.kind()),
                        );
                    }
                }
                // A failed attempt frees its slot immediately; do not delay recovery.
                if let Some(address) = addresses.next() {
                    active.push(connector(address));
                    next_start = Instant::now() + ATTEMPT_DELAY;
                }
            }
            _ = sleep_until(next_start),
                if active.len() < MAX_ACTIVE_ATTEMPTS && addresses.peek().is_some() =>
            {
                active.push(connector(addresses.next().expect("another candidate")));
                next_start = Instant::now() + ATTEMPT_DELAY;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc, time::Duration};
    use tokio::time::Instant;

    #[derive(Default)]
    struct Attempts {
        active: usize,
        max_active: usize,
        started: Vec<(SocketAddr, Instant)>,
    }

    struct Active(Rc<RefCell<Attempts>>);

    impl Active {
        fn new(state: &Rc<RefCell<Attempts>>, address: SocketAddr) -> Self {
            let mut attempts = state.borrow_mut();
            attempts.active += 1;
            attempts.max_active = attempts.max_active.max(attempts.active);
            attempts.started.push((address, Instant::now()));
            Self(Rc::clone(state))
        }
    }

    impl Drop for Active {
        fn drop(&mut self) {
            self.0.borrow_mut().active -= 1;
        }
    }

    fn addresses() -> Vec<SocketAddr> {
        [
            "[::1]:4001",
            "[::1]:4002",
            "127.0.0.1:4003",
            "127.0.0.1:4004",
        ]
        .map(|address| address.parse().unwrap())
        .to_vec()
    }

    // A stalled preferred IPv6 address must not consume the IPv4 candidate's budget.
    #[tokio::test(start_paused = true)]
    async fn blackholed_ipv6_does_not_block_ipv4() {
        let addresses = addresses();
        let reachable_ipv4 = addresses[2];
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let started = Instant::now();
        let winner = connect(std::future::ready(Ok(addresses)), |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                if address.is_ipv6() {
                    std::future::pending::<()>().await;
                }
                Ok(address)
            }
        })
        .await
        .expect("IPv4 should connect before the deadline")
        .unwrap();
        assert_eq!(winner, reachable_ipv4);
        assert_eq!(started.elapsed(), Duration::from_millis(250));
        assert!(started.elapsed() < DIRECT_DIAL_TIMEOUT);
        let attempts = attempts.borrow();
        assert_eq!(attempts.active, 0, "the losing IPv6 future must be dropped");
        assert_eq!(attempts.max_active, 2);
        assert_eq!(attempts.started.len(), 2);
    }

    // Serial four-second failures exhaust the budget before reaching every candidate.
    #[tokio::test(start_paused = true)]
    async fn all_addresses_fail_within_dial_budget() {
        let addresses = addresses();
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let started = Instant::now();
        let result = connect(std::future::ready(Ok(addresses.clone())), |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                tokio::time::sleep(Duration::from_secs(4)).await;
                Err::<SocketAddr, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
            }
        })
        .await
        .expect("all candidates should be attempted within one budget");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);
        assert!(started.elapsed() < DIRECT_DIAL_TIMEOUT);
        let attempts = attempts.borrow();
        assert_eq!(attempts.active, 0);
        assert_eq!(attempts.max_active, 2);
        assert_eq!(
            attempts.started.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            vec![addresses[0], addresses[2], addresses[1], addresses[3]]
        );
    }

    // Dropping a dial owns and drops both pending connections without background tasks.
    #[tokio::test(start_paused = true)]
    async fn cancellation_drops_losing_attempts() {
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let mut dial = Box::pin(connect(std::future::ready(Ok(addresses())), |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                std::future::pending::<io::Result<SocketAddr>>().await
            }
        }));
        assert!(futures_util::poll!(&mut dial).is_pending());
        tokio::time::advance(Duration::from_millis(250)).await;
        assert!(futures_util::poll!(&mut dial).is_pending());
        assert_eq!(attempts.borrow().active, 2);
        drop(dial);
        assert_eq!(attempts.borrow().active, 0);
    }

    // DNS must consume the same deadline as connections, even with a slow resolver.
    #[tokio::test(start_paused = true)]
    async fn dns_time_counts_toward_dial_budget() {
        let started = Instant::now();
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let resolve = async {
            tokio::time::sleep(Duration::from_secs(14)).await;
            Ok(addresses())
        };
        let result = connect(resolve, |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(address)
            }
        })
        .await;
        assert!(result.is_err(), "DNS must not reset the connect budget");
        assert_eq!(started.elapsed(), Duration::from_secs(15));
        assert_eq!(attempts.borrow().active, 0);
    }

    // Resolver, empty-answer and connection failures must remain distinguishable without
    // retaining endpoint-bearing diagnostics, even when all three have the same kind.
    #[tokio::test]
    async fn dns_failures_keep_safe_distinct_categories() {
        let sensitive = "secret-relay.example at 192.0.2.42 and [2001:db8::42]";
        let mut messages = Vec::new();
        for resolved in [
            Err(io::Error::new(io::ErrorKind::InvalidInput, sensitive)),
            Ok(Vec::new()),
            Ok(addresses()),
        ] {
            let error = connect(std::future::ready(resolved), |_| async {
                Err::<SocketAddr, _>(io::Error::new(io::ErrorKind::InvalidInput, sensitive))
            })
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let diagnostic = format!("{error} {error:?}");
            for endpoint in ["secret-relay.example", "192.0.2.42", "2001:db8::42"] {
                assert!(
                    !diagnostic.contains(endpoint),
                    "leaked {endpoint}: {diagnostic}"
                );
            }
            messages.push(error.to_string());
        }
        for (index, message) in messages.iter().enumerate() {
            for other in &messages[index + 1..] {
                assert_ne!(message, other, "failure categories must stay distinct");
            }
        }
    }

    // Endpoint-bearing DNS and connect diagnostics must never escape in dial errors.
    #[tokio::test]
    async fn connect_errors_omit_resolved_addresses() {
        let sensitive = "secret-relay.example at 192.0.2.42 and [2001:db8::42]";
        for dns_failure in [false, true] {
            let resolved = if dns_failure {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, sensitive))
            } else {
                Ok(addresses())
            };
            let error = connect(std::future::ready(resolved), |_| async {
                Err::<SocketAddr, _>(io::Error::new(io::ErrorKind::ConnectionRefused, sensitive))
            })
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
            for endpoint in ["secret-relay.example", "192.0.2.42", "2001:db8::42"] {
                assert!(
                    !error.to_string().contains(endpoint),
                    "leaked {endpoint}: {error}"
                );
            }
        }
    }

    // Direct connection failures name their kind but never the host or address they dialed.
    #[tokio::test]
    async fn connect_failure_message_names_the_error_kind() {
        for (kind, expected) in [
            (
                io::ErrorKind::ConnectionRefused,
                "connection failed: connection refused",
            ),
            (io::ErrorKind::TimedOut, "connection failed: timed out"),
        ] {
            let error = connect(std::future::ready(Ok(addresses())), |_| async move {
                Err::<SocketAddr, _>(io::Error::new(
                    kind,
                    "secret-relay.example 192.0.2.42 [2001:db8::42]:443",
                ))
            })
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), expected);
            for endpoint in ["secret-relay.example", "192.0.2.42", "2001:db8::42"] {
                assert!(
                    !error.to_string().contains(endpoint),
                    "leaked {endpoint}: {error}"
                );
            }
        }
    }

    // A refused connection must make room immediately, even while its competitor hangs.
    #[tokio::test(start_paused = true)]
    async fn failed_attempt_immediately_frees_slot() {
        let candidates = addresses();
        let reachable = candidates[1];
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let started = Instant::now();
        let winner = connect(std::future::ready(Ok(candidates.clone())), |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                if address == reachable {
                    return Ok(address);
                }
                if address.is_ipv4() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                }
                std::future::pending().await
            }
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(winner, reachable);
        assert_eq!(started.elapsed(), Duration::from_millis(260));
        let attempts = attempts.borrow();
        assert_eq!(attempts.active, 0);
        assert_eq!(attempts.max_active, 2);
        assert_eq!(
            attempts.started.iter().map(|(a, _)| *a).collect::<Vec<_>>(),
            vec![candidates[0], candidates[2], candidates[1]]
        );
    }

    // The dial deadline drops both hanging sockets and never exceeds the concurrency cap.
    #[tokio::test(start_paused = true)]
    async fn timeout_drops_all_attempts() {
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let started = Instant::now();
        let result = connect(std::future::ready(Ok(addresses())), |address| {
            let guard = Active::new(&attempts, address);
            async move {
                let _guard = guard;
                std::future::pending::<io::Result<SocketAddr>>().await
            }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(15));
        let attempts = attempts.borrow();
        assert_eq!(attempts.active, 0);
        assert_eq!(attempts.max_active, 2);
        assert_eq!(attempts.started.len(), 2);
    }

    // Both family preference directions and single-family answers must remain usable.
    #[tokio::test(start_paused = true)]
    async fn preserves_first_family_and_per_family_order() {
        let addresses = addresses();
        for candidates in [
            vec![addresses[2], addresses[3], addresses[0], addresses[1]],
            vec![addresses[0], addresses[1]],
            vec![addresses[2], addresses[3]],
        ] {
            let expected = if candidates.len() == 4 {
                vec![addresses[2], addresses[0], addresses[3], addresses[1]]
            } else {
                candidates.clone()
            };
            let attempts = Rc::new(RefCell::new(Attempts::default()));
            let result = connect(std::future::ready(Ok(candidates)), |address| {
                let guard = Active::new(&attempts, address);
                async move {
                    let _guard = guard;
                    Err::<SocketAddr, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
                }
            })
            .await
            .unwrap();
            assert!(result.is_err());
            assert_eq!(
                attempts
                    .borrow()
                    .started
                    .iter()
                    .map(|(a, _)| *a)
                    .collect::<Vec<_>>(),
                expected
            );
            assert_eq!(attempts.borrow().active, 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn empty_resolution_never_connects() {
        let result = connect(std::future::ready(Ok(Vec::new())), |_| {
            std::future::ready(Err::<(), _>(io::Error::other("unexpected connection")))
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    // A real TCP stream must be returned and remain usable after dropping its loser.
    #[tokio::test]
    async fn real_loopback_succeeds_while_ipv6_is_pending() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let blackhole = "[::1]:4001".parse().unwrap();
        let attempts = Rc::new(RefCell::new(Attempts::default()));
        let mut tcp = connect(
            std::future::ready(Ok(vec![blackhole, reachable])),
            |address| {
                let guard = Active::new(&attempts, address);
                async move {
                    let _guard = guard;
                    if address.is_ipv6() {
                        std::future::pending::<()>().await;
                    }
                    tokio::net::TcpStream::connect(address).await
                }
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(tcp.peer_addr().unwrap(), reachable);
        assert_eq!(attempts.borrow().active, 0);
        let (mut peer, _) = listener.accept().await.unwrap();
        tcp.write_all(b"alive").await.unwrap();
        let mut received = [0; 5];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"alive");
    }

    // Exercise the production DNS/TCP adapters and the unchanged boxed Dialer interface.
    #[tokio::test]
    async fn direct_dialer_connects_to_loopback() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut tcp = super::super::Dialer::Direct
            .dial("localhost", port, "relay")
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        peer.write_all(b"reply").await.unwrap();
        let mut received = [0; 5];
        tcp.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"reply");
    }
}
