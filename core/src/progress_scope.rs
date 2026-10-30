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

//! Lifetime scope evidence used only by scheduler bookkeeping.

use crate::work::WorkEstimator;
use std::ops::Range;

#[derive(Debug)]
struct Observation {
    span: Range<u64>,
    pending: Vec<Range<u64>>,
}

#[derive(Debug, Default)]
pub(crate) struct WorkScope {
    previous: Option<Observation>,
    rewinds: Vec<Range<u64>>,
    charged: Vec<Range<u64>>,
}

fn union(mut ranges: Vec<Range<u64>>) -> Vec<Range<u64>> {
    ranges.retain(|r| r.start < r.end);
    ranges.sort_unstable_by_key(|r| r.start);
    let mut result: Vec<Range<u64>> = Vec::new();
    for range in ranges {
        if let Some(last) = result.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
        } else {
            result.push(range);
        }
    }
    result
}

fn subtract(ranges: &[Range<u64>], removed: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut result = Vec::new();
    for range in ranges {
        let mut start = range.start;
        for cut in removed {
            if cut.end <= start || cut.start >= range.end {
                continue;
            }
            if cut.start > start {
                result.push(start..cut.start);
            }
            start = start.max(cut.end);
            if start >= range.end {
                break;
            }
        }
        if start < range.end {
            result.push(start..range.end);
        }
    }
    result
}

impl WorkScope {
    pub(crate) fn completed(&mut self, range: Range<u64>) {
        if let Some(old) = &mut self.previous {
            old.pending = subtract(&old.pending, std::slice::from_ref(&range));
        }
        self.charged = subtract(&self.charged, std::slice::from_ref(&range));
    }

    pub(crate) fn rewound(&mut self, range: Range<u64>) {
        let reopened = if let Some(old) = &self.previous {
            subtract(std::slice::from_ref(&range), &old.pending)
        } else {
            vec![range]
        };
        self.rewinds.extend(reopened);
        self.rewinds = union(std::mem::take(&mut self.rewinds));
    }

    /// Missing/invalid metadata is rejected before entering this method. Both spans are
    /// priced with this observation's estimator, never with stored estimated totals.
    pub(crate) fn observe(
        &mut self,
        span: Range<u64>,
        pending: &[Range<u64>],
        estimator: &WorkEstimator,
        floor: u64,
    ) -> u64 {
        let pending = union(pending.to_vec());
        let Some(old) = &self.previous else {
            self.previous = Some(Observation { span, pending });
            // A first observation proves no growth relative to a retained WORK floor.
            self.rewinds.clear();
            return floor;
        };
        // Keep the known global envelope: temporary tip/birthday contraction does not
        // make its later restoration into newly added work a second time.
        let span = old.span.start.min(span.start)..old.span.end.max(span.end);
        let old_work = u128::from(estimator.range(old.span.start, old.span.end - 1));
        let new_work = u128::from(estimator.range(span.start, span.end - 1)).max(old_work);
        if old_work == 0 || new_work == 0 {
            return floor;
        }
        let mut reopened = subtract(&pending, &old.pending);
        reopened.extend(self.rewinds.iter().cloned());
        let reopened = union(
            reopened
                .into_iter()
                .filter_map(|r| {
                    let start = r.start.max(old.span.start);
                    let end = r.end.min(old.span.end);
                    (start < end).then_some(start..end)
                })
                .collect(),
        );
        let reopened = subtract(&reopened, &self.charged);
        let reopened_work: u128 = reopened
            .iter()
            .map(|r| u128::from(estimator.range(r.start, r.end - 1)))
            .sum();
        // One division loses at most one permille. Queue additions outside the old
        // span are already paid for by scaling, so only its interior is subtracted.
        let lower = (u128::from(floor.min(1000)) * old_work).saturating_sub(reopened_work * 1000)
            / new_work;
        self.charged.extend(reopened);
        self.charged = union(std::mem::take(&mut self.charged));
        self.rewinds.clear();
        self.previous = Some(Observation { span, pending });
        lower as u64
    }
}
