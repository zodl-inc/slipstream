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

//! Crate-wide error type. One variant per subsystem; transport/wallet details
//! become structured payloads as those subsystems land (P1/P2).

/// Crate-wide error returned by every Slipstream subsystem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SlipstreamError {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("chain discontinuity at height {at}: {detail}")]
    Discontinuity { at: u32, detail: String },

    #[error("wallet db: {0}")]
    Wallet(String),

    #[error("misbehaving server (invalid or out-of-range data in response)")]
    MisbehavingServer,

    /// A channel inside the engine closed under a sender: the fetch side's chunk queue lost its
    /// scanner (`chunk.rs`), typically because the scan already ended with an error of its own,
    /// which takes precedence (`scheduler.rs`). Engine lifecycle, not a request from the host:
    /// NOT the stop a host asks for before changing the wallet, which is
    /// [`Self::StoppedForWalletChange`] and the only one the session ends quietly on.
    #[error("engine is stopped")]
    Stopped,

    /// The host asked the running session to stop because it is about to change the wallet
    /// (adding or removing an account, a rewind, a wipe; see
    /// [`crate::events::Progress::request_stop_for_wallet_change`]), and the scan stopped at its
    /// next block. Raised from the session's block source
    /// ([`crate::block_source::StoppedForWalletChange`]).
    ///
    /// It is not a failure. The session ends quietly: `run_session` sets `SyncState::Idle` and
    /// returns, with no `Error` state, no tag-4 event, no revival and no retry
    /// ([`Self::is_stop_for_wallet_change`] is what the session checks). The scan call it
    /// interrupted wrote nothing, because upstream `scan_cached_blocks` writes only in its final
    /// `put_blocks` (earlier sub-batches of a chunk stay committed), so the next pass scans those
    /// blocks again.
    ///
    /// Not to be confused with [`Self::Stopped`], an engine channel that closed.
    #[error("sync stopped for a wallet change")]
    StoppedForWalletChange,

    /// Scan detected a chain continuity break (reorg) at the given height.
    /// The scheduler's recovery arm truncates the wallet DB and re-suggests ranges.
    /// Mirrors upstream sync.rs:404 `Err(ChainError::Scan(err)) if err.is_continuity_error()`
    /// (zcash_client_backend-0.22.0/src/sync.rs:404).
    #[error("scan continuity break at height {at}")]
    ScanContinuity { at: u32 },

    /// [v0.7 P2] The wire-collapse detector fired: the CURRENT endpoint's
    /// throughput fell below the failover floor for a sustained window (or
    /// the reorder stage starved with zero arrivals) while the scan side was
    /// keeping up — i.e. the server's doing, not backpressure. The engine's
    /// failover loop catches this (only ever raised when alternates are
    /// configured), cools the endpoint down, re-probes, and resumes from the
    /// wallet DB. `measured_mbps` is the offending window's rate (0.0 for a
    /// full stall).
    #[error("wire collapse: {measured_mbps:.2} MB/s sustained (floor {floor_mbps:.2})")]
    WireCollapse { measured_mbps: f64, floor_mbps: f64 },
}

impl SlipstreamError {
    /// Returns `true` for errors that reflect a transient transport-layer failure
    /// (timeout, connect failure, stream stall) where retrying — ideally with a
    /// fresh connection — may succeed.
    ///
    /// Classification table (T6.8-H2):
    /// - `Transport`       → **true**  (timeout / connect / stream stall — retry after reconnect)
    /// - `Config`          → false     (bad config; no amount of retrying fixes this)
    /// - `Wallet`          → false     (DB / scan logic error; retry would hit the same error)
    /// - `ScanContinuity`  → false     (internally handled by the reorg recovery arm)
    /// - `Discontinuity`   → false     (fetch continuity bug; retry would loop)
    /// - `MisbehavingServer` → false   (bad proto / decode error; not a transport transient)
    /// - `Stopped`         → false     (engine lifecycle; not retryable)
    /// - `StoppedForWalletChange` → false (the host asked for it; a retry would scan the wallet
    ///   the host is about to change — the session ends quietly instead, see
    ///   [`Self::is_stop_for_wallet_change`])
    /// - `WireCollapse`    → false     (handled by the v0.7 failover loop — the generic
    ///   transient-reconnect path would dial the SAME collapsed server again)
    pub fn is_transient(&self) -> bool {
        matches!(self, SlipstreamError::Transport(_))
    }

    /// Returns `true` only for [`SlipstreamError::StoppedForWalletChange`]: the host asked the
    /// running session to stop because it is about to change the wallet.
    ///
    /// The session checks this before anything else it does with a failed pass. The retry loop
    /// returns the stop at once (no retry, and not counted as a failed attempt), and the initial
    /// pass and every follow catch-up pass end the session quietly on it, ahead of the transient
    /// and non-transient handling that would otherwise back off, surface `Error` or revive.
    ///
    /// [`SlipstreamError::Stopped`], a closed engine channel, is a different thing: `false` here,
    /// like every other variant, so it keeps its existing handling.
    pub fn is_stop_for_wallet_change(&self) -> bool {
        matches!(self, SlipstreamError::StoppedForWalletChange)
    }
}

#[cfg(test)]
mod tests {
    use super::SlipstreamError;

    #[test]
    fn discontinuity_displays_height_and_detail() {
        let e = SlipstreamError::Discontinuity {
            at: 1_650_000,
            detail: "prev-hash mismatch".into(),
        };
        assert_eq!(
            e.to_string(),
            "chain discontinuity at height 1650000: prev-hash mismatch"
        );
    }

    #[test]
    fn scan_continuity_displays_height() {
        let e = SlipstreamError::ScanContinuity { at: 663_195 };
        assert_eq!(e.to_string(), "scan continuity break at height 663195");
    }

    // ── T6.8-H2: is_transient exhaustive classification ──────────────────────────

    #[test]
    fn transport_is_transient() {
        assert!(SlipstreamError::Transport("timeout".into()).is_transient());
        assert!(SlipstreamError::Transport("connect refused".into()).is_transient());
        assert!(
            SlipstreamError::Transport("stream idle timeout (30s without a message)".into())
                .is_transient()
        );
    }

    #[test]
    fn config_is_not_transient() {
        assert!(!SlipstreamError::Config("bad birthday".into()).is_transient());
    }

    #[test]
    fn wallet_is_not_transient() {
        assert!(!SlipstreamError::Wallet("scan_cached_blocks: ...".into()).is_transient());
    }

    #[test]
    fn scan_continuity_is_not_transient() {
        assert!(!SlipstreamError::ScanContinuity { at: 663_195 }.is_transient());
    }

    #[test]
    fn discontinuity_is_not_transient() {
        assert!(
            !SlipstreamError::Discontinuity {
                at: 1_000_000,
                detail: "prev-hash mismatch".into()
            }
            .is_transient()
        );
    }

    #[test]
    fn misbehaving_server_is_not_transient() {
        assert!(!SlipstreamError::MisbehavingServer.is_transient());
    }

    #[test]
    fn stopped_is_not_transient() {
        assert!(!SlipstreamError::Stopped.is_transient());
    }

    // ── stop for a wallet change ─────────────────────────────────────────────

    #[test]
    fn stopped_for_wallet_change_displays_its_cause() {
        assert_eq!(
            SlipstreamError::StoppedForWalletChange.to_string(),
            "sync stopped for a wallet change"
        );
    }

    /// A retry would scan the wallet the host is about to change: the stop is never transient.
    #[test]
    fn stopped_for_wallet_change_is_not_transient() {
        assert!(!SlipstreamError::StoppedForWalletChange.is_transient());
    }

    /// Only the host's wallet-change stop ends a session quietly. Every other error keeps its own
    /// handling, and the closed-channel `Stopped` in particular is a different thing.
    #[test]
    fn only_the_wallet_change_stop_is_a_stop_for_wallet_change() {
        assert!(SlipstreamError::StoppedForWalletChange.is_stop_for_wallet_change());
        assert!(
            !SlipstreamError::Stopped.is_stop_for_wallet_change(),
            "a closed chunk channel is not a stop the host asked for"
        );
        for other in [
            SlipstreamError::Config("bad birthday".into()),
            SlipstreamError::Transport("timeout".into()),
            SlipstreamError::Discontinuity {
                at: 1_000_000,
                detail: "prev-hash mismatch".into(),
            },
            SlipstreamError::Wallet("scan_cached_blocks: ...".into()),
            SlipstreamError::MisbehavingServer,
            SlipstreamError::ScanContinuity { at: 663_195 },
            SlipstreamError::WireCollapse {
                measured_mbps: 0.0,
                floor_mbps: 1.0,
            },
        ] {
            assert!(!other.is_stop_for_wallet_change(), "{other}");
        }
    }
}
