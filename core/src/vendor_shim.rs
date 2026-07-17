//! [IW-1 SPIKE] No-op shims for the vendored-orchard fork APIs (endo +
//! batch-DH toggles and fire-stats counters, v0.5–v0.6 perf work).
//!
//! While the workspace rides the 0.15-pre orchard line for the valargroup
//! ironwood graph, the 0.14-based vendor forks are un-patched, so the fork's
//! process-global toggle/stats surface does not exist. These shims keep the
//! engine's plumbing compiling with honest zeros (`enabled=false` semantics —
//! the per-item upstream paths run, exactly like the toggles being off).
//!
//! Restore the real implementations by re-vendoring the fork onto the
//! ironwood-era orchard, or retire this module when the upstream seam PRs land.

/// v0.5 C1 toggle — no-op (kernel absent; upstream per-item path runs).
pub fn set_batch_dh_enabled(_enabled: bool) {}

/// v0.5 C2 toggle — no-op (endo ladder absent; upstream mul runs).
pub fn set_endo_enabled(_enabled: bool) {}

/// v0.5 C2 fire counter — always 0 without the fork.
pub fn endo_calls() -> u64 {
    0
}

/// v0.6 P5/P6 fire stats `(calls, lanes, kernel_lanes, dh_nanos,
/// dh_wall_nanos, epk_nanos)` — all 0 without the fork's brackets.
pub fn batch_dh_stats() -> (u64, u64, u64, u64, u64, u64) {
    (0, 0, 0, 0, 0, 0)
}
