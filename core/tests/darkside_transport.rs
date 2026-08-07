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

//! Hermetic transport tests against a local darkside lightwalletd.
//! Start it first (from repo root):
//!   Tests/lightwalletd/lightwalletd --no-tls-very-insecure --data-dir /tmp \
//!     --darkside-very-insecure --log-file /dev/stdout
//! Then: cargo test -p zodl-slipstream --features darkside -- --ignored
#![cfg(feature = "darkside")]

use zodl_slipstream::{config::Endpoint, darkside::DarksideCtl, grpc};

fn darkside_endpoint() -> Endpoint {
    Endpoint {
        host: "127.0.0.1".into(),
        port: 9067,
        tls: false,
    }
}

#[tokio::test]
#[ignore = "requires local darkside lightwalletd"]
async fn stage_apply_and_read_tip_roundtrip() {
    let ep = darkside_endpoint();
    let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
    ctl.reset().await.expect("reset");
    // Stage from sapling activation (663150) — darkside requires no gap from 0.
    // 663150..=663350 inclusive = 201 blocks.
    ctl.stage_blocks_create(663_150, 201).await.expect("stage");
    ctl.apply_staged(663_350).await.expect("apply");
    // Darkside propagates staged state asynchronously after returning from ApplyStaged.
    // A brief yield ensures the tip is visible before we query it (mirrors Swift DarksideTests sleep(2)).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut client = grpc::connect(&ep).await.expect("lwd connect");
    let tip = grpc::get_latest_block_height(&mut client)
        .await
        .expect("tip");
    assert_eq!(tip, 663_350);
}

#[tokio::test]
#[ignore = "requires local darkside lightwalletd"]
async fn parallel_fetch_5000_blocks_in_order() {
    use zodl_slipstream::{
        chunk::chunk_queue,
        fetch::{FetchPlan, run_fetch},
    };

    let ep = darkside_endpoint();
    let mut ctl = DarksideCtl::connect(&ep).await.expect("darkside connect");
    ctl.reset().await.expect("reset");
    // T1.2-correction (a): staging must start at sapling activation 663_150 (not 663_151).
    ctl.stage_blocks_create(663_150, 5_000)
        .await
        .expect("stage");
    ctl.apply_staged(663_150 + 4_999).await.expect("apply");
    // T1.2-correction (b): darkside propagates staged state asynchronously; sleep 2s before fetching.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let (tx, mut rx) = chunk_queue(64 * 1024 * 1024);
    let plan = FetchPlan::new(663_150, 663_150 + 4_999, 512, 3);
    let consumer = tokio::spawn(async move {
        let mut total = 0u64;
        let mut last_height = None::<u64>;
        while let Some((chunk, permit, _treestate)) = rx.recv().await {
            if let (Some(prev), Some(start)) = (last_height, chunk.start_height()) {
                assert_eq!(start, prev + 1, "chunks must arrive in order");
            }
            last_height = chunk.end_height();
            total += chunk.blocks.len() as u64;
            drop(permit);
        }
        total
    });

    let stats = run_fetch(&ep, plan, tx, None).await.expect("fetch");
    assert_eq!(stats.blocks, 5_000);
    assert_eq!(consumer.await.expect("consumer"), 5_000);
}
