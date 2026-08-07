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

//! T-Tor.0 runtime-boundary spike.
//!
//! Question: can a tokio runtime that mimics the Slipstream engine's
//! (`new_multi_thread().enable_all()`) build and drive an arti Tor lightwalletd
//! connection **directly** — no `block_on`, no dedicated `PreferredRuntime::create()` —
//! the way the engine would? If yes, the engine can own Tor on its own runtime.
//!
//! Source analysis already says GO: `zcash_client_backend::tor::Client::create` binds to
//! `PreferredRuntime::current()` (the ambient runtime), so the old FFI's `block_on` is only a
//! sync-FFI workaround the async engine doesn't need. This is the empirical confirmation.
//!
//! `#[ignore]`: live — needs network + a Tor bootstrap. Run for the gate:
//!   cargo test -p zodl-slipstream --test tor_runtime_spike -- --ignored --nocapture

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live: needs network + Tor bootstrap; run manually for the T-Tor.0 gate"]
async fn engine_runtime_can_drive_arti_tor_lwd() {
    use zcash_client_backend::{proto::service, tor::Client};

    let dir = tempfile::tempdir().expect("tempdir");

    // Mirror rust/src/tor.rs's Client::create, but await it on THIS tokio runtime
    // (no PreferredRuntime::create()) — Client::create grabs PreferredRuntime::current().
    let client = Client::create(dir.path(), |permissions| {
        permissions.dangerously_trust_everyone();
    })
    .await
    .expect("arti Client::create on the engine-style tokio runtime");

    // isolated_client() = the `.uniqueTor` isolation the old SDK uses.
    let isolated = client.isolated_client();

    let mut conn = isolated
        .connect_to_lightwalletd("https://zec.rocks:443".parse().expect("uri"), false)
        .await
        .expect("connect_to_lightwalletd over Tor from the engine runtime");

    // One real RPC over the Tor-backed CompactTxStreamerClient<Channel>.
    let info = conn
        .get_lightd_info(service::Empty {})
        .await
        .expect("get_lightd_info over Tor")
        .into_inner();

    assert!(
        info.block_height > 0,
        "expected a real tip height over Tor, got {}",
        info.block_height
    );
    println!(
        "T-Tor.0 GO: drove arti Tor from the engine runtime; lightd block_height={}",
        info.block_height
    );
}
