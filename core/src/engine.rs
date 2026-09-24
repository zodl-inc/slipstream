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

//! Engine v0: one full sync pass (preflight → chain state → scheduler → enhancement).
//! P3 adds enhancement/transparent/events; P4 wraps this behind FFI.

use std::{sync::Arc, time::Instant};

use tracing::{info, warn};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    config::{Endpoint, EngineConfig},
    connector::{ConnPurpose, TorConn, connect_via},
    enhance::{EnhanceStats, run_enhancement},
    error::SlipstreamError,
    events::Progress,
    grpc,
    scheduler::{SyncReport, run_to_completion},
    transparent::{TransparentStats, refresh_utxos},
    wallet_session::WalletSession,
};

/// Engine build tag, logged at every sync start and in the stage-split line.
/// BUMP THIS on every performance-relevant engine change (anything that warrants a
/// framework rebuild) — it is the definitive freshness check for device logs: if the
/// tag in the log doesn't match HEAD's value, the device is running a stale
/// XCFramework (the three-layer gotcha, consuming side). Probe a built slice with:
/// `strings <slice>/libzcashlc.framework/libzcashlc | grep <tag>`.
///
/// IT WENT STALE, and cost real diagnostic time (2026-08-02). A device log reading
/// `engine_build="2026-07-08.v07-wire-p2"` was taken as evidence that the phone was
/// running a month-old engine — the single most likely explanation for a migration
/// that would not prove — when in fact the binary was current and only this constant
/// was a month behind. Two minutes were spent chasing a stale-slice hypothesis that
/// the binary itself refuted (`strings` showed BOTH this tag and the current
/// `zcashlc_build`, which is how the mistake was caught).
///
/// A freshness marker that can silently go stale is worse than no marker: it does not
/// merely fail to inform, it actively misinforms, and it does so precisely when
/// someone is under pressure and reaching for it. Every ironwood/migration change
/// since 07-08 shipped without touching this line. If the discipline of bumping it by
/// hand cannot be relied on — and this is the evidence that it cannot — it should be
/// derived from something that moves on its own (git describe at build time) rather
/// than maintained.
pub const ENGINE_BUILD: &str = "2026-08-02.v0.8-ironwood-migration";

/// [v0.7 P2] Mid-pass endpoint switches allowed per pass before the
/// detector disarms and the pass grinds to completion (the all-sick
/// guarantee). Each switch costs a drain + ~1.2 s re-probe, resuming from
/// the wallet DB.
const MAX_WIRE_SWITCHES: u32 = 2;

/// Current wall-clock time as a `YYYY-MM-DD HH:MM:SSZ` UTC string.
///
/// Logged at pass start, in the stage-split line, and on runner failure so a
/// long-running device/simulator sync can be timed from the log alone — no need
/// to remember when it was started. No external date dependency: civil-from-days
/// per Howard Hinnant's algorithm, unit-tested against known epochs.
pub fn wall_clock_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

/// Format a unix timestamp (seconds) as `YYYY-MM-DD HH:MM:SSZ` (UTC).
fn format_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    // Civil-from-days (Hinnant): days since 1970-01-01 → (y, m, d) in the
    // proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(month <= 2);
    format!("{y:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

#[derive(Debug)]
pub struct SyncOutcome {
    pub report: SyncReport,
    pub enhance: EnhanceStats,
    pub transparent: TransparentStats,
    /// Total wall-clock time for the `run_enhancement` call.
    pub enhance_elapsed: std::time::Duration,
    pub elapsed: std::time::Duration,
    pub chain_tip: u64,
    /// Wire-probe cost (ms) for this pass; 0 when no alternates were probed.
    /// Reporting input (see `crate::report`), not consumed by the sync itself.
    pub wire_probe_ms: f64,
    /// Mid-pass wire failovers that occurred this pass. Reporting input.
    pub wire_switches: u32,
    /// This pass's persist-lane telemetry (delta over the pass). Reporting input.
    pub persist_lane: crate::persist::lane_stats::Totals,
}

impl SyncOutcome {
    /// Returns the name of the stage that consumed the most wall-clock time:
    /// `"fetch"`, `"scan"`, `"enhance"`, or `"idle"` if all stages are < 1 s.
    ///
    /// Used for honest G5 "bound" reporting (Decision-Log requirement, 2026-06-10).
    /// F3: `enhance_elapsed` is now the SUM of all per-range runs + the final post-loop run.
    pub fn bound(&self) -> &'static str {
        let fetch_s = self.report.fetch_elapsed.as_secs_f64();
        let scan_s = self.report.scan_elapsed.as_secs_f64();
        let enhance_s = self.enhance_elapsed.as_secs_f64();

        // Threshold: stages < 1 s on a real sync are noise.
        if fetch_s < 1.0 && scan_s < 1.0 && enhance_s < 1.0 {
            return "idle";
        }

        if fetch_s >= scan_s && fetch_s >= enhance_s {
            "fetch"
        } else if scan_s >= enhance_s {
            "scan"
        } else {
            "enhance"
        }
    }
}

/// True when an observed server tip justifies a new follow pass (T8.1).
///
/// A server replying with a LOWER tip than the last synced one (load-balanced
/// cluster lag) must NOT trigger a pass — the pass would no-op at best and
/// fight reorg logic at worst; the next probe of a caught-up backend recovers.
pub fn should_resync(last_synced_tip: u64, observed_tip: u64) -> bool {
    observed_tip > last_synced_tip
}

/// One cheap tip probe (T8.1 fast path): connect + GetLatestBlock ONLY —
/// none of the preflight work of a full pass (subtree roots, UTXO refresh).
///
/// Fresh connection per probe (TLS ~100-300 ms every FOLLOW_POLL; a held
/// connection would need its own keepalive/staleness handling). All awaits
/// carry the hardening1 deadlines (connect 10 s, unary 30 s).
pub async fn probe_tip(
    config: &EngineConfig,
    tor: Option<&TorConn>,
) -> Result<u64, SlipstreamError> {
    let mut client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;
    grpc::get_latest_block_height(&mut client).await
}

/// One sync pass. `accounts` bootstraps the wallet: each `(ufvk, birthday)` is imported
/// as a view-only account when the wallet does not already track that key (its treestate
/// is fetched from the server at `birthday - 1`). Pass an empty slice for a keyless pass —
/// every follow pass, and any host that provisions its own accounts into the wallet DB.
///
/// `progress` — optional shared progress state for poll-based consumers (decision D8).
/// Pass `Some(Arc::new(Progress::default()))` to receive live counter updates;
/// `None` for no-op (default in all tests and the darkside suite).
/// The `chain_tip` and `current_range_end` fields are set by the engine;
/// `fetched_blocks` / `scanned_blocks` / `enhanced_txs` are bumped during the pipeline.
///
/// Every birthday must be `>= 1`: the birthday-1 treestate fetch would underflow at
/// height 0, which is never a valid mainnet/testnet wallet birthday. All birthdays are
/// validated up front — a clean Config error — before any network or wallet I/O.
///
/// Endpoint selection is a property of the config: with `alternate_endpoints`
/// configured (and Tor off), the pass opens by racing them and committing the
/// winner ([`EngineConfig::with_selected_endpoint`]); with none, `config.endpoint`
/// is used as-is at zero cost.
pub async fn sync_once(
    config: &EngineConfig,
    accounts: &[(UnifiedFullViewingKey, BlockHeight)],
    progress: Option<Arc<Progress>>,
    tor: Option<&TorConn>,
) -> Result<SyncOutcome, SlipstreamError> {
    config.validate()?;

    // Early guard: a birthday of 0 would underflow the `birthday - 1` treestate fetch
    // below, and is never valid for mainnet/testnet. Validate EVERY provided account here,
    // before any I/O, so a bad birthday is a clean Config failure regardless of network
    // availability. (u32 subtraction wraps in release builds without overflow checks —
    // the guard is required.)
    if accounts
        .iter()
        .any(|(_, birthday)| u32::from(*birthday) == 0)
    {
        return Err(SlipstreamError::Config(
            "birthday must be >= 1 (height 0 is not a valid wallet birthday)".into(),
        ));
    }

    let started = Instant::now();

    // Reset per-pass ratio counters (scanned/fetched/pass_total/range_end/spendable).
    // The FFI handle — and therefore this Progress — outlives individual passes
    // (Swift opens it once in prepare(); stop()/start() reuse it across app
    // background/foreground cycles), so stale pass-1 counters would corrupt pass-2's
    // scanned/pass_total ratio. Monotonic delta counters (enhanced_txs,
    // ranges_completed, reorgs_recovered) are deliberately left untouched.
    if let Some(ref p) = progress {
        p.begin_pass();
    }

    // Definitive device-log freshness marker (see ENGINE_BUILD doc).
    info!(
        engine_build = ENGINE_BUILD,
        sparse = config.sparse_persistence,
        write_behind = config.write_behind,
        gpu_subtree = config.gpu_subtree,
        graft_subtree = config.graft_subtree,
        batch_combine = config.batch_combine,
        local_treestate = config.local_treestate,
        started_at_utc = %wall_clock_utc(),
        "engine pass starting"
    );
    // v0.6 P2: persist-lane totals are process-cumulative atomics — snapshot
    // here so the pass-end log reports THIS pass's delta.
    let persist_lane_start = crate::persist::lane_stats::totals();

    // [v0.7 P1] Probe-then-commit (`EngineConfig::with_selected_endpoint`):
    // with alternates configured, race every endpoint and commit the winner
    // for THIS pass; the rest of the pass reads the winner through the
    // returned config. Skipped — config unchanged, zero cost — with no
    // alternates, and on Tor passes (the probe dials direct, which would
    // bypass the circuit).
    let (config, probe_elapsed) = config.clone().with_selected_endpoint(tor.is_some()).await;
    let wire_probe_ms = probe_elapsed.as_secs_f64() * 1e3;

    let mut session = WalletSession::open(config.network, &config.wallet_db_path)?;
    let mut client = connect_via(&config.endpoint, tor, ConnPurpose::MetadataUnique).await?;

    // Per-account bootstrap (for hosts without their own account manager — the CLI and
    // tests; production hosts import directly into the wallet DB). Each key is imported
    // only if the wallet does not already track it, so a re-run neither re-imports nor
    // spends a GetTreeState RPC on an account already present. An empty slice (every
    // follow pass) skips this loop entirely.
    for (ufvk, birthday) in accounts {
        if session.has_account_for_ufvk(ufvk)? {
            continue;
        }
        let birthday_ts =
            grpc::get_tree_state(&mut client, u64::from(u32::from(*birthday)) - 1).await?;
        if let Some(ref p) = progress {
            p.touch(); // liveness: a server response is forward progress
        }
        session.import_account(ufvk, birthday_ts)?;
    }

    let roots = grpc::get_subtree_roots(&mut client).await?;
    if let Some(ref p) = progress {
        p.touch(); // liveness: a server response is forward progress
    }
    session.put_subtree_roots(&roots)?;

    let tip = grpc::get_latest_block_height(&mut client).await?;
    if let Some(ref p) = progress {
        p.touch(); // liveness: a server response is forward progress
    }
    session.update_chain_tip(tip)?;
    info!(tip, "chain tip updated");

    // Advertise the chain tip to poll-based consumers, and record the refresh FACT —
    // [E-2] `update_chain_tip` just succeeded, so this run has proven the wallet-DB tip
    // (the FFI `tip_fresh` latch keys on this counter, not on the tip value changing).
    if let Some(ref p) = progress {
        p.set_chain_tip(tip);
        p.note_tip_refreshed();
    }

    // Transparent UTXO refresh — runs BEFORE the shielded scan loop, mirroring upstream
    // sync.rs:108-121 ("We do this before we perform any shielded scanning, to ensure
    // that we discover any UTXOs between the old fully-scanned height and the current
    // chain tip.").
    let transparent = refresh_utxos(&mut session, &mut client).await?;
    if let Some(ref p) = progress {
        p.touch(); // liveness: a server response is forward progress
    }

    // T6.1: per-pass dedupe set for TransactionsInvolvingAddress skip keys.
    // Scope = one sync pass (all interleaved/per-range/final runs share it).
    let mut skipped_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    // [v0.7 P2] Failover loop: WireCollapse (raised by the fetch detector,
    // and ONLY when armed — alternates present + wire_failover on) cools the
    // offending endpoint, re-probes the remainder, and re-runs; the
    // scheduler resumes from the wallet DB, so a switch costs the drain +
    // probe (~2–3 s), never progress. After MAX_WIRE_SWITCHES the detector
    // is DISARMED and the pass grinds to completion on the best-known
    // endpoint — the all-sick guarantee: completion beats speed. Tor passes
    // never arm (the re-probe dials direct, which would bypass the circuit).
    let mut attempt_config = config.clone();
    if tor.is_some() {
        attempt_config.wire_failover = false;
    }
    let mut wire_switches: u32 = 0;
    let mut cooled: Vec<Endpoint> = Vec::new();
    let report = loop {
        let attempt = run_to_completion(
            &attempt_config,
            &mut session,
            progress.clone(),
            &mut skipped_keys,
            tor,
        )
        .await;
        match attempt {
            Err(SlipstreamError::WireCollapse {
                measured_mbps,
                floor_mbps,
            }) => {
                wire_switches += 1;
                warn!(
                    measured_mbps = format!("{measured_mbps:.2}").as_str(),
                    floor_mbps = format!("{floor_mbps:.2}").as_str(),
                    from = attempt_config.endpoint.host.as_str(),
                    switch = wire_switches,
                    "wire collapse — failing over"
                );
                cooled.push(attempt_config.endpoint.clone());
                let mut candidates: Vec<Endpoint> = std::iter::once(config.endpoint.clone())
                    .chain(config.alternate_endpoints.iter().cloned())
                    .filter(|e| !cooled.contains(e))
                    .collect();
                if candidates.is_empty() {
                    // Everything configured has collapsed at least once this
                    // pass — clear the cooldown and pick among the others.
                    cooled.clear();
                    candidates = std::iter::once(config.endpoint.clone())
                        .chain(config.alternate_endpoints.iter().cloned())
                        .filter(|e| *e != attempt_config.endpoint)
                        .collect();
                }
                let next = if candidates.len() == 1 {
                    candidates.remove(0)
                } else {
                    let outcome = crate::probe::probe_endpoints(
                        &candidates,
                        crate::probe::DEFAULT_PROBE_BUDGET,
                    )
                    .await;
                    candidates.swap_remove(outcome.chosen)
                };
                info!(
                    to = next.host.as_str(),
                    port = next.port,
                    "wire failover committed"
                );
                attempt_config.endpoint = next;
                if wire_switches >= MAX_WIRE_SWITCHES {
                    attempt_config.wire_failover = false;
                    info!(
                        switches = wire_switches,
                        "wire failover budget spent — detector disarmed for the remainder"
                    );
                }
            }
            other => break other?,
        }
    };

    // Final enhancement: fetch full tx data for any remaining TransactionDataRequests
    // that were not caught by the per-range enhancement (F3 cleanup run). This is cheap
    // on a wallet with few remaining requests (typically zero after per-range runs).
    // Stats are merged into the report's `enhance` field so the stage-split log
    // reports total enhancement time (per-range runs + this final run) correctly.
    let enhance_started = Instant::now();
    let final_enhance = run_enhancement(
        &mut session,
        &mut client,
        config.network,
        progress.clone(),
        &mut skipped_keys,
    )
    .await?;
    let final_enhance_elapsed = enhance_started.elapsed();

    // F3: merge final enhancement stats into report so the total is correct.
    let mut report = report;
    report.enhance.requests += final_enhance.requests;
    report.enhance.txs_stored += final_enhance.txs_stored;
    report.enhance.statuses_set += final_enhance.statuses_set;
    report.enhance.skipped += final_enhance.skipped;
    report.enhance.fetch_wait += final_enhance.fetch_wait;
    report.enhance.store += final_enhance.store;
    report.enhance.address += final_enhance.address;
    // Total enhance_elapsed = per-range elapsed (in report) + final run elapsed.
    let total_enhance_elapsed = report.enhance_elapsed + final_enhance_elapsed;

    // Expose the merged enhance stats and total elapsed via SyncOutcome.
    let enhance = report.enhance.clone();
    let enhance_elapsed = total_enhance_elapsed;

    // v0.6 P2: this pass's persist-lane delta over the pass-start snapshot
    // (process-cumulative atomics; see the snapshot at pass start).
    let persist_lane = crate::persist::lane_stats::totals().delta_since(&persist_lane_start);

    let outcome = SyncOutcome {
        report,
        enhance,
        transparent,
        enhance_elapsed,
        elapsed: started.elapsed(),
        chain_tip: tip,
        wire_probe_ms,
        wire_switches,
        persist_lane,
    };

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// format_utc against known epochs (no clock dependency).
    #[test]
    fn format_utc_known_values() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14 22:13:20Z");
        // Leap-year day: 2024-02-29 12:00:00 UTC.
        assert_eq!(format_utc(1_709_208_000), "2024-02-29 12:00:00Z");
        // End-of-year boundary: 2025-12-31 23:59:59 UTC.
        assert_eq!(format_utc(1_767_225_599), "2025-12-31 23:59:59Z");
    }

    /// wall_clock_utc returns a sane, well-formed current timestamp.
    #[test]
    fn wall_clock_utc_is_well_formed() {
        let s = wall_clock_utc();
        assert_eq!(s.len(), "2026-06-13 00:00:00Z".len());
        assert!(s.ends_with('Z'));
        assert!(s.starts_with("20"), "expected a 21st-century year, got {s}");
    }

    /// Helper to construct a minimal SyncOutcome with specified stage durations.
    fn make_outcome(fetch_s: f64, scan_s: f64, enhance_s: f64) -> SyncOutcome {
        use std::time::Duration;
        let report = crate::scheduler::SyncReport {
            fetch_elapsed: Duration::from_secs_f64(fetch_s),
            scan_elapsed: Duration::from_secs_f64(scan_s),
            ..Default::default()
        };
        SyncOutcome {
            report,
            enhance: crate::enhance::EnhanceStats::default(),
            transparent: crate::transparent::TransparentStats::default(),
            enhance_elapsed: Duration::from_secs_f64(enhance_s),
            elapsed: Duration::from_secs_f64(fetch_s + scan_s + enhance_s),
            chain_tip: 0,
            wire_probe_ms: 0.0,
            wire_switches: 0,
            persist_lane: crate::persist::lane_stats::Totals::default(),
        }
    }

    #[test]
    fn bound_picks_max_stage() {
        assert_eq!(make_outcome(5.0, 2.0, 1.0).bound(), "fetch");
        assert_eq!(make_outcome(2.0, 5.0, 1.0).bound(), "scan");
        assert_eq!(make_outcome(2.0, 1.0, 5.0).bound(), "enhance");
    }

    #[test]
    fn bound_returns_idle_when_all_tiny() {
        // All < 1 s → idle.
        assert_eq!(make_outcome(0.5, 0.3, 0.1).bound(), "idle");
    }

    #[test]
    fn bound_ties_prefer_fetch_then_scan() {
        // Equal fetch=scan=5s, enhance=0 → fetch wins (fetch >= scan in the branch).
        assert_eq!(make_outcome(5.0, 5.0, 0.0).bound(), "fetch");
        // Equal scan=enhance=5s, fetch=0 → scan wins.
        assert_eq!(make_outcome(0.0, 5.0, 5.0).bound(), "scan");
    }

    /// T8.1 — the follow loop's pure re-sync decision.
    #[test]
    fn follow_should_resync_only_when_tip_advances() {
        assert!(!should_resync(3_375_000, 3_374_999)); // tip behind (server lag) → no
        assert!(!should_resync(3_375_000, 3_375_000)); // tip equal → no
        assert!(should_resync(3_375_000, 3_375_001)); // tip advanced → yes
        assert!(!should_resync(0, 0));
    }

    #[test]
    fn birthday_height_zero_is_rejected() {
        // Hermetic: the birthday guard runs before any network or wallet I/O. The engine
        // now receives an already-decoded key, so the guard inspects the BlockHeight
        // directly (decoding is the caller's concern). A birthday of 0 is a Config error.
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime for test");
        let cfg = EngineConfig::new(
            zcash_protocol::consensus::Network::MainNetwork,
            std::path::PathBuf::from("/tmp/slipstream-engine-test-nonexistent/data.db"),
            crate::config::Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                tls: false,
            },
        );
        let ufvk = UnifiedFullViewingKey::decode(
            &zcash_protocol::consensus::Network::MainNetwork,
            crate::wallet_session::TEST_UFVK,
        )
        .expect("decode TEST_UFVK");
        // birthday=0 must fail before any network call.
        let result = rt.block_on(async {
            sync_once(&cfg, &[(ufvk, BlockHeight::from_u32(0))], None, None).await
        });
        assert!(
            matches!(result, Err(SlipstreamError::Config(_))),
            "expected Config error for birthday=0, got: {result:?}"
        );
    }
}
