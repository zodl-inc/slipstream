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

//! GPU-OFFLOAD Orchard subtree build (feature `gpu`, Phase B0 — PARKED, default-off;
//! device matrix 2026-06-15: ~1.1× A14/iPhone, −25% M4, A10 pathological).
//! Since Task 13 the shared lookup-map machinery lives in `lookup_build.rs`; this is
//! the thin wrapper binding it to the wgpu kernel in `slipstream-gpuhash`.

use std::collections::BTreeMap;

use incrementalmerkletree::{Position, Retention};
use orchard::tree::MerkleHashOrchard;
use shardtree::LocatedPrunableTree;
use zcash_protocol::consensus::BlockHeight;

/// GPU equivalent of `persist::build_subtrees` for Orchard (byte-identical output;
/// gated by `gpu_subtree_build_matches_cpu` + the engine oracle).
pub(crate) fn build_subtrees_gpu<const SHARD_HEIGHT: u8>(
    start_position: Position,
    commitments: &mut [Option<(MerkleHashOrchard, Retention<BlockHeight>)>],
) -> Vec<(
    LocatedPrunableTree<MerkleHashOrchard>,
    BTreeMap<BlockHeight, Position>,
)> {
    crate::lookup_build::build_subtrees_lookup::<SHARD_HEIGHT>(
        slipstream_gpuhash::orchard_combine_batch,
        start_position,
        commitments,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

    #[test]
    fn gpu_subtree_build_matches_cpu() {
        for n in [1usize, 7, 1000, 1024, 2000, 5000] {
            let start = Position::from(0);
            let mut a = crate::lookup_build::tests::synth(n);
            let mut b = crate::lookup_build::tests::synth(n);
            let cpu = crate::persist::build_subtrees::<MerkleHashOrchard, ORCHARD_SHARD_HEIGHT>(
                start,
                &mut a,
                crate::persist::BUILD_CHUNK_SIZE,
            );
            let gpu = build_subtrees_gpu::<ORCHARD_SHARD_HEIGHT>(start, &mut b);
            assert_eq!(cpu, gpu, "GPU subtree build diverged from CPU at n={n}");
        }
    }
}
