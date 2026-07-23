//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

pub mod anchor;
// v0.5 Plan C (C1 home; today only the C0 probe — test-gated, no prod code).
#[cfg(test)]
mod batch_ecdh;
pub(crate) mod batch_sinsemilla;
pub mod block_source;
pub mod census;
pub mod chunk;
pub mod config;
pub mod connector;
pub mod engine;
pub mod enhance;
pub mod error;
pub mod events;
pub mod fetch;
pub mod ffi_handle;
// dead_code: consumed by the sparse build path in v0.4 plan Task 7 — this allow
// is deleted in that diff (buffer CRUD lands first so Task 6/7 build on green).
#[cfg(feature = "gpu")]
mod gpu_subtree;
#[allow(dead_code)]
pub(crate) mod graft;
#[allow(dead_code)]
pub(crate) mod graft_accumulator;
pub mod grpc;
pub(crate) mod lookup_build;
pub mod mempool;
pub mod network;
pub mod oracle;
pub mod persist;
pub mod probe;
pub mod reconcile;
pub mod report;
pub mod scan;
pub mod scan_queue;
pub mod scheduler;
pub mod session;
pub mod throttle;
pub mod transparent;
pub mod treestate;
pub mod verify;
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
pub use session::{SessionConfig, SessionReporter, TorSessionConfig, run_session};
pub use zcash_protocol::consensus::Network;
// Re-exported because they appear in the public engine surface (`engine::sync_once`,
// `SessionConfig::accounts`): callers name the account key/birthday as typed values.
pub use zcash_keys::keys::UnifiedFullViewingKey;
pub use zcash_protocol::consensus::BlockHeight;

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
