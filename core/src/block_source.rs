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
//! The session scan can also hand it the session's [`Progress`]
//! ([`MemBlockSource::with_stop`]), so that a host's stop right before a wallet
//! change ends the walk at the next block instead of after the whole chunk.

use zcash_client_backend::{
    data_api::chain::{BlockSource, error::Error as ChainError},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

use crate::{chunk::Chunk, events::Progress};

/// Why a [`MemBlockSource`] walk ended early: the host asked the running session to stop
/// because it is about to change the wallet (see [`Progress::request_stop_for_wallet_change`]).
///
/// This is the source's `BlockSource::Error`, so `scan_cached_blocks` hands it back as
/// `ChainError::BlockSource(StoppedForWalletChange)`. It is a request being honoured, not a
/// fault: no block was malformed, and the wallet is untouched because upstream writes only in
/// its final `put_blocks` (see [`MemBlockSource::with_blocks`]). It is a type of its own so that
/// nothing else can be mistaken for it; before the stop existed this error type was
/// `Infallible`, since a walk over blocks already in memory had no way to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("scan stopped for a wallet change")]
pub struct StoppedForWalletChange;

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
    /// The session's progress, polled before each block for a wallet-change stop (see
    /// [`MemBlockSource::with_stop`]). `None` for every source that is not a session's scan:
    /// the CLI, the oracles and the tests never stop early.
    stop: Option<&'a Progress>,
}

impl<'a> MemBlockSource<'a> {
    pub fn new(chunk: &'a Chunk) -> Self {
        Self {
            chunk,
            walk_wall: std::cell::RefCell::new(Vec::with_capacity(2)),
            stop: None,
        }
    }

    /// Make this source refuse its next block once the host has asked the running session to
    /// stop for a wallet change ([`Progress::request_stop_for_wallet_change`], read back with
    /// [`Progress::stop_requested`]).
    ///
    /// The session scan passes its progress, so that a stop requested right before a wallet
    /// change ends the scan at the next block instead of after the whole chunk. The CLI, the
    /// oracles and the tests pass nothing: `None` is also what [`Self::new`] starts with, and
    /// then every walk behaves exactly as it always has. What a stopped walk returns, and why
    /// that is safe, is on [`MemBlockSource::with_blocks`].
    pub fn with_stop(mut self, progress: Option<&'a Progress>) -> Self {
        self.stop = progress;
        self
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
    type Error = StoppedForWalletChange;

    /// Hands the chunk's blocks to `with_block` in order, from `from_height` on, at most `limit`
    /// of them.
    ///
    /// Before each block it checks the stop given to [`MemBlockSource::with_stop`]. If the host
    /// has asked for a stop for a wallet change, the walk returns
    /// `Err(ChainError::BlockSource(StoppedForWalletChange))` instead of handing the block out.
    /// Three things make that safe:
    ///
    /// * The check runs in BOTH of upstream `scan_cached_blocks`' walks (pass 1 feeds the batch
    ///   runners, pass 2 does the wallet-side processing), so the scan stops within a block
    ///   whichever walk it is in.
    /// * It costs two Relaxed loads per block ([`Progress::stop_requested`]), and nothing but an
    ///   `Option` test when no stop was given.
    /// * An early exit writes nothing. While it walks, upstream `scan_cached_blocks` only reads
    ///   the wallet, and it writes in one final `put_blocks` that an error from either walk
    ///   never reaches (`zcash_client_backend-0.25.0/src/data_api/chain.rs`: the walks at
    ///   lines 644 and 672, `put_blocks` at 713).
    ///
    /// The walk wall is recorded on every exit, a stopped walk included.
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
                // The host asked for a stop for a wallet change: refuse this block (see above).
                if self.stop.is_some_and(|p| p.stop_requested()) {
                    return Err(ChainError::BlockSource(StoppedForWalletChange));
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

    // ── stop for a wallet change ─────────────────────────────────────────────

    /// Walks `src` once and returns the heights the callback saw together with how the walk
    /// ended.
    fn walk(
        src: &MemBlockSource<'_>,
    ) -> (
        Vec<u64>,
        Result<(), ChainError<std::convert::Infallible, StoppedForWalletChange>>,
    ) {
        let mut out = Vec::new();
        let result = src.with_blocks::<_, std::convert::Infallible>(None, None, |b| {
            out.push(b.height);
            Ok(())
        });
        (out, result)
    }

    /// Whether a walk ended because a wallet-change stop was requested. (`ChainError` has no
    /// `PartialEq`, so a test cannot `assert_eq!` on the result.)
    fn ended_in_a_wallet_change_stop(
        result: &Result<(), ChainError<std::convert::Infallible, StoppedForWalletChange>>,
    ) -> bool {
        matches!(result, Err(ChainError::BlockSource(StoppedForWalletChange)))
    }

    #[test]
    fn with_a_progress_but_no_request_all_blocks_are_served() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let progress = Progress::default();
        let src = MemBlockSource::new(&chunk).with_stop(Some(&progress));
        assert_eq!(collect(&src, None, None), (100..=109).collect::<Vec<_>>());
    }

    #[test]
    fn a_stop_requested_before_the_walk_serves_no_block() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let progress = Progress::default();
        progress.request_stop_for_wallet_change();
        let src = MemBlockSource::new(&chunk).with_stop(Some(&progress));

        let (served, result) = walk(&src);
        assert!(
            served.is_empty(),
            "no block may be handed out after the request"
        );
        assert!(
            ended_in_a_wallet_change_stop(&result),
            "the walk must end with the wallet-change stop, got {result:?}"
        );
        assert_eq!(
            src.walk_wall.borrow().len(),
            1,
            "a stopped walk still records its wall"
        );
    }

    /// The host asks for the stop while the scan is running (here: from inside the callback,
    /// after the second block). The block being handled finishes; the next one is refused.
    #[test]
    fn a_stop_raised_inside_the_walk_ends_it_at_the_next_block() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let progress = Progress::default();
        let src = MemBlockSource::new(&chunk).with_stop(Some(&progress));

        let mut served = Vec::new();
        let result = src.with_blocks::<_, std::convert::Infallible>(None, None, |b| {
            served.push(b.height);
            if served.len() == 2 {
                progress.request_stop_for_wallet_change();
            }
            Ok(())
        });

        assert_eq!(
            served,
            vec![100, 101],
            "exactly the two blocks handed out before the request"
        );
        assert!(
            ended_in_a_wallet_change_stop(&result),
            "the walk must end with the wallet-change stop, got {result:?}"
        );
    }

    /// Upstream `scan_cached_blocks` walks the source twice. A stop requested once pass 1 is
    /// over must end pass 2 just as surely.
    #[test]
    fn the_second_walk_stops_too() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let progress = Progress::default();
        let src = MemBlockSource::new(&chunk).with_stop(Some(&progress));

        let (served, result) = walk(&src);
        assert_eq!(
            served,
            (100..=109).collect::<Vec<_>>(),
            "pass 1 runs to the end"
        );
        assert!(result.is_ok(), "no request yet: pass 1 completes");

        progress.request_stop_for_wallet_change();
        let (served, result) = walk(&src);
        assert!(served.is_empty(), "pass 2 must hand out no block");
        assert!(
            ended_in_a_wallet_change_stop(&result),
            "pass 2 must end with the wallet-change stop, got {result:?}"
        );
        assert_eq!(
            src.walk_wall.borrow().len(),
            2,
            "both walks recorded their wall, the stopped one included"
        );
    }

    #[test]
    fn a_new_session_re_arms_the_source() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let progress = Progress::default();
        let src = MemBlockSource::new(&chunk).with_stop(Some(&progress));

        progress.request_stop_for_wallet_change();
        let (served, result) = walk(&src);
        assert!(served.is_empty());
        assert!(ended_in_a_wallet_change_stop(&result));

        // `run_session` does this right after it takes the pass lock.
        progress.begin_session();
        assert_eq!(
            collect(&src, None, None),
            (100..=109).collect::<Vec<_>>(),
            "the request was aimed at the previous session"
        );
    }
}
