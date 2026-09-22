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

//! Slipstream sync engine core (platform-neutral).
//! See HOSTING.md for the integration contract and REVIEWING.md for the
//! module map.

// Storage-independent transport/planning layer — compiled unconditionally.
pub mod anchor;
pub(crate) mod batch_sinsemilla;
pub mod block_source;
pub mod census;
pub mod chunk;
pub mod config;
pub mod connector;
pub mod error;
pub mod events;
pub mod fetch;
pub mod grpc;
pub mod network;
pub mod probe;
pub mod throttle;
pub mod treestate;
pub mod verify;

// Issue #4: the zcash_client_sqlite wallet-storage backend and — today — the
// engine loop that is hard-wired to it. A future non-sqlite backend would slot
// in beside this gate, with the engine loop generalized over the storage
// capability traits.
#[cfg(feature = "zcash_client_sqlite")]
pub mod engine;
#[cfg(feature = "zcash_client_sqlite")]
pub mod enhance;
#[cfg(feature = "zcash_client_sqlite")]
pub mod ffi_handle;
#[cfg(feature = "gpu")]
mod gpu_subtree;
#[cfg(feature = "zcash_client_sqlite")]
pub(crate) mod graft;
#[cfg(feature = "zcash_client_sqlite")]
pub(crate) mod graft_accumulator;
#[cfg(feature = "zcash_client_sqlite")]
pub(crate) mod lookup_build;
#[cfg(feature = "zcash_client_sqlite")]
pub mod mempool;
#[cfg(feature = "zcash_client_sqlite")]
pub mod migrations;
#[cfg(feature = "zcash_client_sqlite")]
pub mod oracle;
#[cfg(feature = "zcash_client_sqlite")]
pub mod persist;
#[cfg(feature = "zcash_client_sqlite")]
pub mod reconcile;
#[cfg(feature = "zcash_client_sqlite")]
pub mod report;
#[cfg(feature = "zcash_client_sqlite")]
pub mod scan;
#[cfg(feature = "zcash_client_sqlite")]
pub mod scan_queue;
#[cfg(feature = "zcash_client_sqlite")]
pub mod scheduler;
#[cfg(feature = "zcash_client_sqlite")]
pub mod session;
#[cfg(feature = "zcash_client_sqlite")]
pub mod transparent;
#[cfg(feature = "zcash_client_sqlite")]
pub mod wallet_session;

#[cfg(feature = "darkside")]
pub mod darkside;
#[cfg(feature = "darkside")]
#[allow(clippy::all, missing_docs)]
#[path = "grpc_generated/darkside.rs"]
pub mod darkside_generated;

pub use config::{Endpoint, EngineConfig};
pub use error::SlipstreamError;
pub use events::{Bound, Event, Progress, ProgressArc, Snapshot, SyncMode};
pub use network::{CustomActivations, SlipstreamNetwork};
#[cfg(feature = "zcash_client_sqlite")]
pub use session::{SessionConfig, SessionReporter, TorSessionConfig, run_session};
/// Re-exported so hosts configure the anchor-retention policy from the same types
/// the wallet itself is configured with — the grid must match or a migration
/// transfer anchored to a boundary this engine did not retain becomes unprovable.
pub use zcash_client_backend::data_api::anchor_retention::{
    AnchorRetention, AnchorRetentionInterval,
};
pub use zcash_protocol::consensus::Network;
// Re-exported because they appear in the public engine surface (`engine::sync_once`,
// `SessionConfig::accounts`): callers name the account key/birthday as typed values.
pub use zcash_keys::keys::UnifiedFullViewingKey;
pub use zcash_protocol::consensus::BlockHeight;

/// Crate smoke marker used by the workspace smoke test. Derived from the
/// package name so it cannot drift from the published crate.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "zodl-slipstream");
    }
}
