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

//! [API v2.1 E-6] `restore_anchor` — engine-owned wallet-provisioning anchor.
//!
//! Hosts creating or restoring a wallet need two chain facts before the first sync pass:
//!   - RESTORE: the `recover_until` height (the current tip), so the [birthday..tip]
//!     backfill is tracked as recovery (`is_recovering`) — with the OFFLINE fallback
//!     policy inside: a NULL recover_until would make a restore look like a new wallet
//!     (no "Restoring" UI, no recovery gate — field failure syncLogsMac9), so an
//!     unreachable server falls back to `max(bundled-checkpoint height, birthday + 1)`.
//!   - NEW: a reorg-safe recent tree state (`tip − MAX_REORG` floored at Sapling
//!     activation), so funds sent to the brand-new wallet can't be missed if the tip
//!     reorganizes; offline ⇒ no anchor (the host keeps its bundled checkpoint).
//!
//! A server whose tip or tree-state height is above `i32::MAX` counts as unreachable for
//! both: no real chain gets there, and a host bounding server heights there could not
//! store the answer.
//!
//! This POLICY used to live per host (the Swift SDK's `Initializer.initialize` +
//! `importAccount`); moving it here gives every host the same provisioning semantics
//! through one primitive. Keys never cross this boundary — the host keeps its
//! `createAccount`/`importAccount` calls and passes only heights.
//!
//! Privacy: the tree-state/height fetches are identifying (they reveal wallet-birthday
//! interest), so when the host runs Tor they ride an isolated circuit (`MetadataUnique`)
//! exactly like the sync pass's metadata calls. A requested-but-failed Tor bootstrap is
//! treated as OFFLINE (fallback policy) — never a silent de-anonymising direct retry.

use tracing::{info, warn};
use zcash_client_backend::proto::service::TreeState;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use crate::{
    config::Endpoint,
    connector::{ConnPurpose, TorConn, connect_via},
    grpc,
};

/// Reorg-safety margin for a NEW wallet's anchor: the tree state is fetched this many
/// blocks below the advertised tip. Mirrors the Swift SDK's `ZcashSDK.maxReorgSize`.
pub const ANCHOR_MAX_REORG_BLOCKS: u64 = 100;

/// What the host is provisioning.
#[derive(Debug, Clone, Copy)]
pub enum AnchorIntent {
    /// Restoring from seed (or importing a UFVK) with `birthday`; `fallback_checkpoint`
    /// is the host's latest BUNDLED checkpoint height — the offline recover_until input.
    Restore {
        birthday: u64,
        fallback_checkpoint: u64,
    },
    /// Creating a brand-new wallet (no history).
    New,
}

/// The provisioning anchor. For `Restore`: `height` = recover_until (always present by
/// policy — online tip or the offline fallback), `treestate` = None (the host keeps its
/// birthday checkpoint). For `New`: `height`+`treestate` = the reorg-safe server tree
/// state, or `None`/0 when offline (the host keeps its bundled checkpoint defaults).
#[derive(Debug)]
pub struct Anchor {
    pub height: u64,
    pub treestate: Option<TreeState>,
}

/// Resolve the provisioning anchor for `intent`. NEVER errors — the offline policy is the
/// whole point: a restore always gets a valid recover_until, a new wallet degrades to the
/// host's bundled checkpoint. `tor`: `Some` ⇒ identifying calls ride an isolated circuit.
pub async fn restore_anchor(
    endpoint: &Endpoint,
    network: crate::network::SlipstreamNetwork,
    intent: AnchorIntent,
    tor: Option<&TorConn>,
) -> Anchor {
    match intent {
        AnchorIntent::Restore { .. } => match tip_via(endpoint, tor).await {
            Some(tip) => {
                info!(tip, "restore anchor: recover_until = live tip");
                Anchor {
                    height: tip,
                    treestate: None,
                }
            }
            None => offline_anchor(intent),
        },
        AnchorIntent::New => {
            let sapling_activation: u64 = network
                .activation_height(NetworkUpgrade::Sapling)
                .map(|h| u64::from(u32::from(h)))
                .unwrap_or(0);
            let fetched = async {
                let mut client = client_via(endpoint, tor).await?;
                let tip = usable_height(grpc::get_latest_block_height(&mut client).await.ok()?)?;
                let anchor_height = tip
                    .saturating_sub(ANCHOR_MAX_REORG_BLOCKS)
                    .max(sapling_activation);
                let ts = grpc::get_tree_state(&mut client, anchor_height)
                    .await
                    .ok()?;
                if usable_height(ts.height)? != anchor_height {
                    return None;
                }
                Some(Anchor {
                    height: ts.height,
                    treestate: Some(ts),
                })
            }
            .await;
            match fetched {
                Some(anchor) => {
                    info!(
                        height = anchor.height,
                        "new-wallet anchor: reorg-safe server tree state"
                    );
                    anchor
                }
                None => offline_anchor(intent),
            }
        }
    }
}

/// The pure OFFLINE resolution — no network attempted. Also used directly when a
/// REQUESTED Tor bootstrap fails: the result must be identical to an unreachable server
/// (never a silent de-anonymising direct retry).
pub fn offline_anchor(intent: AnchorIntent) -> Anchor {
    match intent {
        AnchorIntent::Restore {
            birthday,
            fallback_checkpoint,
        } => {
            // The syncLogsMac9 rule, verbatim: the best offline estimate of "now";
            // max(.., birthday+1) guarantees a non-empty recovery segment even when the
            // wallet's birthday is newer than the bundled checkpoints.
            let height = fallback_checkpoint.max(birthday.saturating_add(1));
            warn!(
                height,
                fallback_checkpoint,
                birthday,
                "restore anchor: server unreachable — offline recover_until fallback"
            );
            Anchor {
                height,
                treestate: None,
            }
        }
        AnchorIntent::New => {
            warn!("new-wallet anchor: server unreachable — host keeps its bundled checkpoint");
            Anchor {
                height: 0,
                treestate: None,
            }
        }
    }
}

/// Fetch the advertised tip over the given transport; `None` on any failure, an unusable
/// tip included.
async fn tip_via(endpoint: &Endpoint, tor: Option<&TorConn>) -> Option<u64> {
    let mut client = client_via(endpoint, tor).await?;
    usable_height(grpc::get_latest_block_height(&mut client).await.ok()?)
}

/// `height` if a host can use it; `None`, the unreachable-server answer, above `i32::MAX`.
/// That is the Swift SDK's bound for server-reported heights, and about 1,700 years of
/// 25-second blocks away, so only a broken or hostile server reports more. Passed on, such
/// a height would cost a restore its recover_until in a host that rejects it.
fn usable_height(height: u64) -> Option<u64> {
    if height <= i32::MAX as u64 {
        Some(height)
    } else {
        warn!(
            height,
            "anchor: server height above i32::MAX — treated as unreachable"
        );
        None
    }
}

/// Anchor connect policy: Tor rides the connector's bounded fresh-circuit retries (never
/// falls back to direct); DIRECT is a SINGLE attempt — old-SDK parity (`try?` + offline
/// fallback IS the retry policy here, and a user is waiting on the restore spinner, so
/// the multi-attempt backoff window the sync pass uses would be pure added latency).
async fn client_via(endpoint: &Endpoint, tor: Option<&TorConn>) -> Option<crate::grpc::LwdClient> {
    match tor {
        Some(_) => connect_via(endpoint, tor, ConnPurpose::MetadataUnique)
            .await
            .ok(),
        None => grpc::connect(endpoint).await.ok(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        task::{Context, Poll},
    };

    use tonic::{
        body::Body,
        codegen::{BoxFuture, Service, http},
        server::{Grpc, NamedService, UnaryService},
        transport::{Server, server::TcpIncoming},
    };
    use tonic_prost::ProstCodec;
    use zcash_client_backend::proto::service::{BlockId, ChainSpec};

    use super::*;

    /// Server heights no host can use: just above `i32::MAX`, `u32::MAX` and `u64::MAX`.
    const UNUSABLE_HEIGHTS: [u64; 3] = [i32::MAX as u64 + 1, u32::MAX as u64, u64::MAX];

    /// A stand-in lightwalletd: `GetLatestBlock` reports `tip`, and `GetTreeState` a tree
    /// state at `tree_state_height` (the height asked for when `None`). Other RPCs are
    /// unimplemented.
    #[derive(Clone, Copy)]
    struct FakeLightwalletd {
        tip: u64,
        tree_state_height: Option<u64>,
    }

    impl NamedService for FakeLightwalletd {
        const NAME: &'static str = "cash.z.wallet.sdk.rpc.CompactTxStreamer";
    }

    impl Service<http::Request<Body>> for FakeLightwalletd {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<Body>) -> Self::Future {
            let Self {
                tip,
                tree_state_height,
            } = *self;
            Box::pin(async move {
                Ok(match request.uri().path() {
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock" => {
                        unary(request, move |_: ChainSpec| BlockId {
                            height: tip,
                            hash: vec![],
                        })
                        .await
                    }
                    "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState" => {
                        unary(request, move |at: BlockId| TreeState {
                            height: tree_state_height.unwrap_or(at.height),
                            ..TreeState::default()
                        })
                        .await
                    }
                    _ => tonic::Status::unimplemented("not faked").into_http(),
                })
            })
        }
    }

    /// Answer the unary RPC `request` with `reply` to its message.
    async fn unary<Req, Resp>(
        request: http::Request<Body>,
        reply: impl Fn(Req) -> Resp,
    ) -> http::Response<Body>
    where
        Req: prost::Message + Default + Send + 'static,
        Resp: prost::Message + Send + 'static,
    {
        struct Reply<F>(F);

        impl<Req, Resp, F: Fn(Req) -> Resp> UnaryService<Req> for Reply<F> {
            type Response = Resp;
            type Future = std::future::Ready<Result<tonic::Response<Resp>, tonic::Status>>;

            fn call(&mut self, request: tonic::Request<Req>) -> Self::Future {
                std::future::ready(Ok(tonic::Response::new((self.0)(request.into_inner()))))
            }
        }

        Grpc::new(ProstCodec::<Resp, Req>::default())
            .unary(Reply(reply), request)
            .await
    }

    /// `restore_anchor` for `intent` against `server`, served on a free loopback port.
    async fn anchor_from(server: FakeLightwalletd, intent: AnchorIntent) -> Anchor {
        let incoming = TcpIncoming::bind(([127, 0, 0, 1], 0).into()).expect("bind loopback");
        let port = incoming.local_addr().expect("bound address").port();
        tokio::spawn(
            Server::builder()
                .add_service(server)
                .serve_with_incoming(incoming),
        );
        let endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port,
            tls: false,
        };
        restore_anchor(
            &endpoint,
            crate::network::SlipstreamNetwork::MAIN,
            intent,
            None,
        )
        .await
    }

    /// A tip above `i32::MAX` is an unusable server answer: the restore takes the offline
    /// recover_until fallback, exactly as for an unreachable server, so a host that bounds
    /// server heights at `i32::MAX` still provisions a recovery.
    #[tokio::test]
    async fn restore_with_tip_above_i32_max_falls_back_offline() {
        for tip in UNUSABLE_HEIGHTS {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip,
                    tree_state_height: None,
                },
                AnchorIntent::Restore {
                    birthday: 2_000_000,
                    fallback_checkpoint: 2_500_000,
                },
            )
            .await;
            assert_eq!(
                anchor.height, 2_500_000,
                "tip {tip}: max(checkpoint, birthday+1), not the tip"
            );
            assert!(anchor.treestate.is_none());
        }
    }

    /// Control: a usable tip, up to and including `i32::MAX`, is the restore's
    /// recover_until.
    #[tokio::test]
    async fn restore_takes_a_usable_tip() {
        for tip in [3_100_000, i32::MAX as u64] {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip,
                    tree_state_height: None,
                },
                AnchorIntent::Restore {
                    birthday: 2_000_000,
                    fallback_checkpoint: 2_500_000,
                },
            )
            .await;
            assert_eq!(anchor.height, tip);
            assert!(anchor.treestate.is_none());
        }
    }

    /// A new wallet facing a tip above `i32::MAX` gets no anchor (the host keeps its
    /// bundled checkpoint), as when the server is unreachable.
    #[tokio::test]
    async fn new_wallet_with_tip_above_i32_max_yields_no_anchor() {
        for tip in UNUSABLE_HEIGHTS {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip,
                    tree_state_height: None,
                },
                AnchorIntent::New,
            )
            .await;
            assert_eq!(anchor.height, 0, "tip {tip}");
            assert!(anchor.treestate.is_none(), "tip {tip}");
        }
    }

    /// A tree state above `i32::MAX` is as unusable as such a tip: no anchor.
    #[tokio::test]
    async fn new_wallet_with_tree_state_above_i32_max_yields_no_anchor() {
        for height in UNUSABLE_HEIGHTS {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip: 3_100_000,
                    tree_state_height: Some(height),
                },
                AnchorIntent::New,
            )
            .await;
            assert_eq!(anchor.height, 0, "tree state {height}");
            assert!(anchor.treestate.is_none(), "tree state {height}");
        }
    }

    /// Control: below a usable tip, up to and including `i32::MAX`, a new wallet anchors
    /// at the reorg-safe tree state.
    #[tokio::test]
    async fn new_wallet_takes_a_usable_tree_state() {
        for tip in [3_100_000, i32::MAX as u64] {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip,
                    tree_state_height: None,
                },
                AnchorIntent::New,
            )
            .await;
            let expected = tip - ANCHOR_MAX_REORG_BLOCKS;
            assert_eq!(anchor.height, expected);
            assert_eq!(anchor.treestate.map(|ts| ts.height), Some(expected));
        }
    }

    /// A new wallet must reject a tree state returned at any height other than the
    /// requested reorg-safe height, even when the server reports a usable height.
    #[tokio::test]
    async fn new_wallet_rejects_a_mismatched_tree_state() {
        for height in [3_099_899, 3_099_901, 3_100_000] {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip: 3_100_000,
                    tree_state_height: Some(height),
                },
                AnchorIntent::New,
            )
            .await;
            assert_eq!(anchor.height, 0, "tree state {height}");
            assert!(anchor.treestate.is_none(), "tree state {height}");
        }
    }

    /// The Sapling activation floor is itself the requested anchor; only an exact-height
    /// tree state is usable there too.
    #[tokio::test]
    async fn new_wallet_accepts_the_requested_sapling_floor() {
        let network = crate::network::SlipstreamNetwork::MAIN;
        let sapling_activation = u64::from(u32::from(
            network
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activates on mainnet"),
        ));
        let tip = sapling_activation + 50;

        for height in [
            sapling_activation - 1,
            sapling_activation,
            sapling_activation + 1,
        ] {
            let anchor = anchor_from(
                FakeLightwalletd {
                    tip,
                    tree_state_height: Some(height),
                },
                AnchorIntent::New,
            )
            .await;
            if height == sapling_activation {
                assert_eq!(anchor.height, sapling_activation);
                assert_eq!(
                    anchor.treestate.map(|treestate| treestate.height),
                    Some(sapling_activation)
                );
            } else {
                assert_eq!(anchor.height, 0, "tree state {height}");
                assert!(anchor.treestate.is_none(), "tree state {height}");
            }
        }
    }

    /// Offline restore: the recover_until fallback is max(checkpoint, birthday+1) — a
    /// restore NEVER provisions recover_until = NULL (the syncLogsMac9 class).
    #[tokio::test]
    async fn offline_restore_falls_back_to_checkpoint_floor() {
        // Unroutable endpoint (TEST-NET-1 address, port closed) — connect fails fast enough
        // for the direct retry budget only on refused connections; use an invalid host to
        // fail at URI/DNS level instead.
        let endpoint = Endpoint {
            host: "invalid.host.invalid".into(),
            port: 1,
            tls: false,
        };
        let anchor = restore_anchor(
            &endpoint,
            crate::network::SlipstreamNetwork::MAIN,
            AnchorIntent::Restore {
                birthday: 2_000_000,
                fallback_checkpoint: 1_500_000,
            },
            None,
        )
        .await;
        assert_eq!(
            anchor.height, 2_000_001,
            "birthday newer than the bundled checkpoints ⇒ birthday+1 floor"
        );
        assert!(
            anchor.treestate.is_none(),
            "restore intent never carries a treestate"
        );

        let anchor = restore_anchor(
            &endpoint,
            crate::network::SlipstreamNetwork::MAIN,
            AnchorIntent::Restore {
                birthday: 1_000_000,
                fallback_checkpoint: 1_500_000,
            },
            None,
        )
        .await;
        assert_eq!(
            anchor.height, 1_500_000,
            "old birthday ⇒ the checkpoint estimate of now"
        );
    }

    /// Offline new-wallet: no anchor — the host keeps its bundled checkpoint (height 0
    /// + no treestate is the documented "keep your defaults" signal).
    #[tokio::test]
    async fn offline_new_wallet_yields_no_anchor() {
        let endpoint = Endpoint {
            host: "invalid.host.invalid".into(),
            port: 1,
            tls: false,
        };
        let anchor = restore_anchor(
            &endpoint,
            crate::network::SlipstreamNetwork::MAIN,
            AnchorIntent::New,
            None,
        )
        .await;
        assert_eq!(anchor.height, 0);
        assert!(anchor.treestate.is_none());
    }
}
