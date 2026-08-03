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

//! [IW-0.5] The engine's network parameters: stock main/test, or a CUSTOM chain —
//! a chosen [`NetworkType`]'s constants (HRPs, coin type) paired with explicit
//! per-upgrade activation heights.
//!
//! Why this exists (empirical, 2026-07-09): the valargroup Ironwood testnet runs
//! MAINNET constants (coin type 133, `uview`/`u1` encodings — proven byte-for-byte
//! by re-deriving a faucet wallet's UFVK) on a ~10k-block chain with regtest-style
//! activation heights (Ironwood/"NU6.3" @ 5000). Stock [`Network::MainNetwork`]
//! parameters put the Sapling floor at 419,200 — above that chain's tip — so
//! upstream produces zero scannable ranges (a graceful but total no-op). No stock
//! parameter set can describe such a chain; this type can.
//!
//! The engine is purely observational (it never spends and holds no spending
//! keys), so consensus parameters are the ONLY place activation heights touch it:
//! they bound scan ranges, select trial-decryption domains per height, and pick
//! key/address encodings.

use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, NetworkUpgrade, Parameters};

/// Per-upgrade activation heights for a custom chain. `None` = never activates.
///
/// Invariant expected by consensus code (not enforced here): heights are
/// monotonically non-decreasing in upgrade order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CustomActivations {
    pub overwinter: Option<u32>,
    pub sapling: Option<u32>,
    pub blossom: Option<u32>,
    pub heartwood: Option<u32>,
    pub canopy: Option<u32>,
    pub nu5: Option<u32>,
    pub nu6: Option<u32>,
    pub nu6_1: Option<u32>,
    /// The highest upgrade this crate's zcash_protocol knows un-gated (Nu7 sits
    /// behind `zcash_unstable`); on the valargroup Ironwood testnet this is the
    /// stand-in for the chain's "NU6.3"/Ironwood activation (5000).
    pub nu6_2: Option<u32>,
}

impl CustomActivations {
    /// Regtest-style default: every upgrade this crate knows active from height 1.
    /// Matches the common shape of hosted test chains (only the upgrade under test
    /// gets a distinctive height, via the corresponding field).
    pub fn all_from_genesis() -> Self {
        Self {
            overwinter: Some(1),
            sapling: Some(1),
            blossom: Some(1),
            heartwood: Some(1),
            canopy: Some(1),
            nu5: Some(1),
            nu6: Some(1),
            nu6_1: Some(1),
            nu6_2: Some(1),
        }
    }
}

/// The engine's network selector: stock chains by enum, custom chains by
/// constants + explicit heights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlipstreamNetwork {
    /// Stock Zcash mainnet or testnet parameters.
    Standard(Network),
    /// A custom chain: `constants` selects encodings (HRPs, coin type — e.g.
    /// [`NetworkType::Main`] for the valargroup Ironwood testnet) and `heights`
    /// the activation schedule.
    Custom {
        constants: NetworkType,
        heights: CustomActivations,
    },
}

impl SlipstreamNetwork {
    pub const MAIN: Self = Self::Standard(Network::MainNetwork);
    pub const TEST: Self = Self::Standard(Network::TestNetwork);
}

impl From<Network> for SlipstreamNetwork {
    fn from(n: Network) -> Self {
        Self::Standard(n)
    }
}

impl Parameters for SlipstreamNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            Self::Standard(n) => n.network_type(),
            Self::Custom { constants, .. } => *constants,
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Self::Standard(n) => n.activation_height(nu),
            Self::Custom { heights, .. } => {
                let h = match nu {
                    NetworkUpgrade::Overwinter => heights.overwinter,
                    NetworkUpgrade::Sapling => heights.sapling,
                    NetworkUpgrade::Blossom => heights.blossom,
                    NetworkUpgrade::Heartwood => heights.heartwood,
                    NetworkUpgrade::Canopy => heights.canopy,
                    NetworkUpgrade::Nu5 => heights.nu5,
                    NetworkUpgrade::Nu6 => heights.nu6,
                    NetworkUpgrade::Nu6_1 => heights.nu6_1,
                    NetworkUpgrade::Nu6_2 => heights.nu6_2,
                    // Unstable/future upgrades (Nu7, ZFuture — cfg-gated in
                    // zcash_protocol): never active on a custom chain until this
                    // crate learns a field for them.
                    #[allow(unreachable_patterns)]
                    _ => None,
                };
                h.map(BlockHeight::from_u32)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wallet #36 from the valargroup Ironwood testnet faucet — a disposable
    /// testnet fixture (the chain resets at unannounced times). Encoded with
    /// MAINNET constants; the whole point of `Custom { constants: Main, … }`.
    const IRONWOOD_TESTNET_FIXTURE_UFVK: &str = "uview1fc4n4zlrfrvuh80g6nwulcv9wlq77jyt04un9mqh63dcm33u0vag6v0r9jnyuvfwm8akcp5kjf4fzf7kl0gz0a8qg3q7zhqz7nufkjuhas6meege00a4l9vjq8apfq5ufnsesr6en2zh02gutf8eu7px3zv32se5stk25w44hctlju745dn64pdk36q6ey0ler4cey0rwxfc6px7zeq7f2tppnux3h2kkjdrczjy2nk278yg3klv8m0jywze5nldf84awnqdqzhve78k2zffla2mze352xprnccv8tf2axvy9svf9jgj6dh0qzch56u27knnu589cdvf9tepnpvudc8rr008jkaxlw4uehwhsehmr8np2mnwg9uceaq7lv8cl5yz0ezc02eht8gqyw7sp9z28acdeexumnk0s8c9l88uc3u3r0j448mf73fn93xf05024zhm4whu2ez238yt3zfyyjc3nlvx9c7tkqgm3dlk8gkw2uqp7mrg";

    #[test]
    fn standard_delegates_to_stock_parameters() {
        let main = SlipstreamNetwork::MAIN;
        assert_eq!(main.network_type(), NetworkType::Main);
        assert_eq!(
            main.activation_height(NetworkUpgrade::Sapling),
            Network::MainNetwork.activation_height(NetworkUpgrade::Sapling)
        );
    }

    #[test]
    fn custom_reports_configured_heights_and_constants() {
        let net = SlipstreamNetwork::Custom {
            constants: NetworkType::Main,
            heights: CustomActivations {
                nu6_2: Some(5000),
                ..CustomActivations::all_from_genesis()
            },
        };
        assert_eq!(net.network_type(), NetworkType::Main);
        assert_eq!(
            net.activation_height(NetworkUpgrade::Sapling),
            Some(BlockHeight::from_u32(1))
        );
        assert_eq!(
            net.activation_height(NetworkUpgrade::Nu6_2),
            Some(BlockHeight::from_u32(5000))
        );

        let sparse = SlipstreamNetwork::Custom {
            constants: NetworkType::Main,
            heights: CustomActivations::default(),
        };
        assert_eq!(sparse.activation_height(NetworkUpgrade::Sapling), None);
    }

    /// The load-bearing regression: main-constants custom params must decode the
    /// mainnet-encoded fixture UFVK (stock TestNetwork parameters reject it).
    #[test]
    fn custom_main_constants_decode_the_ironwood_fixture_ufvk() {
        let net = SlipstreamNetwork::Custom {
            constants: NetworkType::Main,
            heights: CustomActivations::all_from_genesis(),
        };
        zcash_keys::keys::UnifiedFullViewingKey::decode(&net, IRONWOOD_TESTNET_FIXTURE_UFVK)
            .expect("main-constants custom params decode the fixture UFVK");

        zcash_keys::keys::UnifiedFullViewingKey::decode(
            &SlipstreamNetwork::TEST,
            IRONWOOD_TESTNET_FIXTURE_UFVK,
        )
        .expect_err("stock testnet params must reject the mainnet-encoded UFVK");
    }
}
