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

//! [v0.7 P1] Endpoint probe — the "pit crew" half of approach A: at pass
//! start, race every configured endpoint with a tip query + a timed
//! ~100-block sample, then COMMIT to one winner for the whole pass (the
//! pass itself stays single-server, every pre-v0.7 invariant intact).
//! The probe never blocks a pass: every stage runs against a shared
//! deadline, and a budget overrun simply falls back to the configured
//! preferred endpoint. Evidence this exists for: the 2026-07-08 ship day
//! measured a 10× same-morning provider swing (1.5 → 14.7 MB/s) — a ~1 s
//! probe converts "unlucky server pick" from a 3× restore into a ~1 s tax.

use std::time::{Duration, Instant};

use tokio::time::timeout;
use tracing::{info, warn};
use zcash_client_backend::proto::service::{BlockId, BlockRange};

use crate::{
    config::Endpoint,
    grpc::{self, LwdClient},
};

/// Default shared wall-clock budget for one [`probe_endpoints`] race (tip
/// query + timed sample across all candidates).
pub const DEFAULT_PROBE_BUDGET: Duration = Duration::from_millis(1200);

/// Blocks in the timed throughput sample (ending at the endpoint's tip —
/// tip-region blocks are small, but ranking is RELATIVE so only fairness
/// across endpoints matters, not absolute MB/s).
const PROBE_SAMPLE_BLOCKS: u64 = 100;

/// An endpoint whose tip is within this many blocks of the best observed
/// tip still qualifies (servers lag their backends by a block or two; a
/// pass plans against the CHOSEN server's own tip, so a small lag is fine).
const TIP_FRESHNESS_SLACK: u64 = 10;

/// One endpoint's probe readout. `tip: None` = unreachable (or too slow to
/// answer inside the budget); `sample_mbps: None` = tip answered but no
/// sample bytes arrived. A PARTIAL sample still yields a rate — a crawling
/// server ranks low instead of unknown, which is exactly the signal.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub endpoint: Endpoint,
    pub tip: Option<u64>,
    pub sample_mbps: Option<f64>,
}

/// The probe's verdict: per-endpoint readouts (same order as the input),
/// the winner's index, and how long the whole probe took.
#[derive(Debug)]
pub struct ProbeOutcome {
    pub results: Vec<ProbeResult>,
    pub chosen: usize,
    pub elapsed: Duration,
}

/// Pure ranking, TDD'd: endpoints with a tip within `TIP_FRESHNESS_SLACK`
/// of the best observed tip qualify; among qualified, the highest sampled
/// rate wins (a missing sample ranks below any measured one); ties keep
/// configured order (index 0 = the host's preferred endpoint). Nothing
/// qualified ⇒ index 0 — the probe must never leave the engine worse off
/// than the pre-v0.7 behavior.
pub fn rank(results: &[ProbeResult]) -> usize {
    let Some(best_tip) = results.iter().filter_map(|r| r.tip).max() else {
        return 0;
    };
    let mut chosen: Option<(usize, f64)> = None;
    for (i, r) in results.iter().enumerate() {
        let Some(tip) = r.tip else { continue };
        if tip + TIP_FRESHNESS_SLACK < best_tip {
            continue;
        }
        let rate = r.sample_mbps.unwrap_or(-1.0); // sampleless ranks below any rate
        match chosen {
            Some((_, best_rate)) if rate <= best_rate => {}
            _ => chosen = Some((i, rate)),
        }
    }
    chosen.map_or(0, |(i, _)| i)
}

/// Probe all `endpoints` in parallel within `budget` and pick the winner.
/// `endpoints[0]` is the host's preferred server; the returned `chosen`
/// indexes into the input slice.
pub async fn probe_endpoints(endpoints: &[Endpoint], budget: Duration) -> ProbeOutcome {
    let started = Instant::now();
    let deadline = started + budget;

    let mut handles = Vec::with_capacity(endpoints.len());
    for ep in endpoints {
        let ep = ep.clone();
        handles.push(tokio::spawn(probe_one(ep, deadline)));
    }
    let mut results = Vec::with_capacity(handles.len());
    for (i, h) in handles.into_iter().enumerate() {
        match h.await {
            Ok(r) => results.push(r),
            Err(e) => {
                warn!(index = i, error = %e, "endpoint probe task panicked");
                results.push(ProbeResult {
                    endpoint: endpoints[i].clone(),
                    tip: None,
                    sample_mbps: None,
                });
            }
        }
    }
    let chosen = rank(&results);
    for (i, r) in results.iter().enumerate() {
        info!(
            index = i,
            host = r.endpoint.host.as_str(),
            port = r.endpoint.port,
            tip = r.tip,
            sample_mbps = r.sample_mbps.map(|m| format!("{m:.2}")),
            winner = (i == chosen),
            "wire probe"
        );
    }
    ProbeOutcome {
        results,
        chosen,
        elapsed: started.elapsed(),
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn probe_one(endpoint: Endpoint, deadline: Instant) -> ProbeResult {
    let mut result = ProbeResult {
        endpoint: endpoint.clone(),
        tip: None,
        sample_mbps: None,
    };

    let Ok(Ok(mut client)) = timeout(remaining(deadline), grpc::connect(&endpoint)).await else {
        return result;
    };
    let Ok(Ok(tip)) = timeout(
        remaining(deadline),
        grpc::get_latest_block_height(&mut client),
    )
    .await
    else {
        return result;
    };
    result.tip = Some(tip);

    // Timed sample: read up to PROBE_SAMPLE_BLOCKS tip-region blocks until
    // the stream ends or the deadline hits — partial bytes still rate.
    let start = tip.saturating_sub(PROBE_SAMPLE_BLOCKS - 1);
    let sampled = Instant::now();
    let bytes = sample_range_bytes(&mut client, start, tip, deadline).await;
    let secs = sampled.elapsed().as_secs_f64();
    if bytes > 0 && secs > 0.0 {
        result.sample_mbps = Some(bytes as f64 / (1024.0 * 1024.0) / secs);
    }
    result
}

/// Stream `start..=end`, returning bytes received by stream end OR the
/// deadline, whichever first (errors just cut the sample short).
async fn sample_range_bytes(
    client: &mut LwdClient,
    start: u64,
    end: u64,
    deadline: Instant,
) -> u64 {
    let req = BlockRange {
        start: Some(BlockId {
            height: start,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: end,
            hash: vec![],
        }),
        ..Default::default()
    };
    let Ok(Ok(resp)) = timeout(remaining(deadline), client.get_block_range(req)).await else {
        return 0;
    };
    let mut stream = resp.into_inner();
    let mut bytes = 0u64;
    loop {
        match timeout(remaining(deadline), stream.message()).await {
            Ok(Ok(Some(block))) => {
                bytes += prost::Message::encoded_len(&block) as u64;
            }
            _ => return bytes, // stream end, error, or deadline — sample closes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str) -> Endpoint {
        Endpoint {
            host: host.into(),
            port: 443,
            tls: true,
        }
    }

    fn r(host: &str, tip: Option<u64>, mbps: Option<f64>) -> ProbeResult {
        ProbeResult {
            endpoint: ep(host),
            tip,
            sample_mbps: mbps,
        }
    }

    #[test]
    fn fastest_fresh_endpoint_wins() {
        let results = [
            r("preferred", Some(1000), Some(2.2)),
            r("alt-1", Some(1000), Some(14.7)),
            r("alt-2", Some(999), Some(8.0)),
        ];
        assert_eq!(rank(&results), 1);
    }

    #[test]
    fn stale_tip_disqualifies_even_the_fastest() {
        let results = [
            r("preferred", Some(1000), Some(2.0)),
            r(
                "alt-stale",
                Some(1000 - TIP_FRESHNESS_SLACK - 1),
                Some(50.0),
            ),
        ];
        assert_eq!(rank(&results), 0);
    }

    #[test]
    fn slack_tip_still_qualifies() {
        let results = [
            r("preferred", Some(1000), Some(2.0)),
            r("alt-lagging", Some(1000 - TIP_FRESHNESS_SLACK), Some(9.0)),
        ];
        assert_eq!(rank(&results), 1);
    }

    #[test]
    fn sampleless_ranks_below_any_measured_rate() {
        let results = [
            r("preferred", Some(1000), None),
            r("alt", Some(1000), Some(0.1)),
        ];
        assert_eq!(rank(&results), 1);
    }

    #[test]
    fn all_unreachable_falls_back_to_preferred() {
        let results = [r("preferred", None, None), r("alt", None, None)];
        assert_eq!(rank(&results), 0);
    }

    #[test]
    fn tie_keeps_configured_order() {
        let results = [
            r("preferred", Some(1000), Some(10.0)),
            r("alt", Some(1000), Some(10.0)),
        ];
        assert_eq!(rank(&results), 0);
    }

    #[test]
    fn only_reachable_endpoint_wins_even_sampleless() {
        let results = [r("preferred", None, None), r("alt", Some(1000), None)];
        assert_eq!(rank(&results), 1);
    }
}
