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

//! Regenerates the darkside-control gRPC client into zodl-slipstream.
//! Shared walletrpc types are extern-mapped to zcash_client_backend's
//! generated module so no duplicate prost types exist.

fn main() -> anyhow::Result<()> {
    let out = std::path::Path::new("slipstream/core/src/grpc_generated");
    std::fs::create_dir_all(out)?;
    tonic_prost_build::configure()
        .build_server(false)
        .out_dir(out)
        .extern_path(
            ".cash.z.wallet.sdk.rpc.Empty",
            "::zcash_client_backend::proto::service::Empty",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.RawTransaction",
            "::zcash_client_backend::proto::service::RawTransaction",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.TreeState",
            "::zcash_client_backend::proto::service::TreeState",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.BlockID",
            "::zcash_client_backend::proto::service::BlockId",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.GetAddressUtxosReply",
            "::zcash_client_backend::proto::service::GetAddressUtxosReply",
        )
        .compile_protos(
            &["Tests/TestUtils/proto/darkside.proto"],
            &[
                "Tests/TestUtils/proto",
                "Sources/ZcashLightClientKit/Modules/Service/GRPC/ProtoBuf/proto",
            ],
        )?;
    Ok(())
}
