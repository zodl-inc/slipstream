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

//! In-memory BlockSource adapter: serves exactly one transport Chunk to
//! upstream `scan_cached_blocks`. One chunk per scan call keeps the upstream
//! commit (one txn per call) and our memory bounded (decision D2 + plan facts).

use zcash_client_backend::{
    data_api::chain::{BlockSource, error::Error as ChainError},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

use crate::chunk::Chunk;

pub struct MemBlockSource<'a> {
    chunk: &'a Chunk,
    /// v0.6 P6: wall spent inside each `with_blocks` walk, in call order.
    /// Upstream `scan_cached_blocks` walks the source EXACTLY twice per
    /// call — pass 1 feeds the batch runners (walk wall = feed + task
    /// spawning), pass 2 re-walks doing the wallet-side processing (walk
    /// wall = extract recv + nullifier checks + ScannedBlock assembly) —
    /// so after the scan call, \[0\] = pass 1 and \[1\] = pass 2. The A18 P5
    /// readout showed the wall lives in ONE of these; this names which.
    /// RefCell: `with_blocks` takes `&self` and the producer is
    /// single-threaded.
    walk_wall: std::cell::RefCell<Vec<std::time::Duration>>,
}

impl<'a> MemBlockSource<'a> {
    pub fn new(chunk: &'a Chunk) -> Self {
        Self {
            chunk,
            walk_wall: std::cell::RefCell::new(Vec::with_capacity(2)),
        }
    }

    /// `(pass1, pass2)` walk walls recorded so far (zero if a walk didn't
    /// happen — e.g. an error exit). Walks beyond the second are ignored;
    /// the two-walk shape is upstream `scan_cached_blocks`' structure.
    pub fn walk_walls(&self) -> (std::time::Duration, std::time::Duration) {
        let w = self.walk_wall.borrow();
        (
            w.first().copied().unwrap_or_default(),
            w.get(1).copied().unwrap_or_default(),
        )
    }
}

impl BlockSource for MemBlockSource<'_> {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let started = std::time::Instant::now();
        let from = from_height.map(u64::from).unwrap_or(0);
        let mut served = 0usize;
        let mut serve = || {
            for b in &self.chunk.blocks {
                if b.height < from {
                    continue;
                }
                if let Some(l) = limit
                    && served >= l
                {
                    break;
                }
                with_block(b.clone())?;
                served += 1;
            }
            Ok(())
        };
        let result = serve();
        self.walk_wall.borrow_mut().push(started.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Chunk;

    fn block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            hash: vec![height as u8; 32],
            ..Default::default()
        }
    }

    fn collect(src: &MemBlockSource<'_>, from: Option<u64>, limit: Option<usize>) -> Vec<u64> {
        let mut out = Vec::new();
        src.with_blocks::<_, std::convert::Infallible>(
            from.map(|h| BlockHeight::from(h as u32)),
            limit,
            |b| {
                out.push(b.height);
                Ok(())
            },
        )
        .expect("infallible");
        out
    }

    #[test]
    fn serves_all_blocks_in_order() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, None, None), (100..=109).collect::<Vec<_>>());
    }

    #[test]
    fn respects_from_height_and_limit() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, Some(105), Some(3)), vec![105, 106, 107]);
    }

    #[test]
    fn from_height_past_end_serves_nothing() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert!(collect(&src, Some(200), None).is_empty());
    }
}
