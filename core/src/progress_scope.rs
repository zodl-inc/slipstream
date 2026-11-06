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

// Upward-rounded fractional permille avoids spending a fresh integer rounding
// loss on every held observation. The final integer candidate loses less than one.
const SHARE_SCALE: u128 = 1 << 32;

#[derive(Debug)]
struct Correction {
    earned_share: u128,
    observed_floor: u64,
    reopened: Vec<Range<u64>>,
    refunded: Vec<Range<u64>>,
}

#[derive(Debug, Default)]
pub(crate) struct WorkScope {
    previous: Option<Observation>,
    rewinds: Vec<Range<u64>>,
    charged: Vec<Range<u64>>,
    // Geometry may advance while the epsilon holds the display. This entitlement
    // survives those observations until the scheduler applies or settles it.
    correction: Option<Correction>,
    // Consumed proposals may publish an integer floor just below their precise
    // earned share. Carry that fraction into the next proposal, not a new loss.
    rounding_credit: u128,
    rounding_credit_floor: u64,
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
        self.rewinds = subtract(&self.rewinds, std::slice::from_ref(&range));
        if let Some(correction) = &mut self.correction {
            let remaining = subtract(&correction.reopened, std::slice::from_ref(&range));
            correction
                .refunded
                .extend(subtract(&correction.reopened, &remaining));
            correction.refunded = union(std::mem::take(&mut correction.refunded));
            correction.reopened = remaining;
        }
    }

    /// The scheduler calls this only after applying a proposal, or when its raw
    /// seed independently supports the displayed floor. Deduplication stays live.
    pub(crate) fn acknowledge(&mut self, floor: u64) {
        if let Some(correction) = self.correction.take() {
            self.rounding_credit = correction
                .earned_share
                .saturating_sub(u128::from(floor.min(1000)) * SHARE_SCALE)
                .min(SHARE_SCALE - 1);
        } else if floor > self.rounding_credit_floor {
            // An unchanged seed acknowledgment consumes no proposal or precision.
            // A genuinely higher raw floor independently settles the old fraction.
            self.rounding_credit = 0;
        }
        self.rounding_credit_floor = floor;
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
        let has_growth = new_work > old_work || reopened_work > 0;
        let lower = if has_growth || self.correction.is_some() {
            let share_ceiling = (u128::from(floor.min(1000)) * SHARE_SCALE + self.rounding_credit)
                .min(1000 * SHARE_SCALE);
            let correction = self.correction.get_or_insert_with(|| Correction {
                earned_share: share_ceiling,
                observed_floor: floor,
                reopened: Vec::new(),
                refunded: Vec::new(),
            });
            // A newly displayed earned share belongs to the previous observation's
            // span. Add it before scaling for this observation's new scope.
            let gained = u128::from(floor.saturating_sub(correction.observed_floor)) * SHARE_SCALE;
            let refunded_work: u128 = correction
                .refunded
                .iter()
                .map(|r| u128::from(estimator.range(r.start, r.end - 1)))
                .sum();
            let earned = correction.earned_share.saturating_add(gained);
            let numerator = earned
                .saturating_mul(old_work)
                .saturating_add(refunded_work * 1000 * SHARE_SCALE)
                .saturating_sub(reopened_work * 1000 * SHARE_SCALE);
            // All products fit u128: a share is <=1000*2^32, work is u64.
            // Round UP here so repeated held proposals cannot accumulate extra
            // downward rounding. Only the final integer conversion rounds down.
            correction.earned_share = numerator.div_ceil(new_work).min(share_ceiling);
            correction.observed_floor = floor;
            correction.reopened.extend(reopened.iter().cloned());
            correction.reopened = union(std::mem::take(&mut correction.reopened));
            correction.refunded.clear();
            (correction.earned_share / SHARE_SCALE) as u64
        } else {
            floor
        };
        self.charged.extend(reopened);
        self.charged = union(std::mem::take(&mut self.charged));
        self.rewinds.clear();
        self.previous = Some(Observation { span, pending });
        lower
    }
}
