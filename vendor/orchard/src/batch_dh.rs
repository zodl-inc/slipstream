//! [slipstream fork] Batched same-scalar Diffie–Hellman for trial decryption.
//!
//! Trial decryption multiplies MANY ephemeral keys by the SAME incoming
//! viewing key, so every lane of a batch takes IDENTICAL double-and-add
//! ladder steps. This module advances all lanes one step at a time, sharing
//! ONE Montgomery batch inversion per step with cheap affine formulas.
//! Honest edge over upstream's prepared path (which is already wNAF-4
//! tabled): ~1.6× per multiplication at the production batch size (N=100,
//! Apple Silicon, batch-normalized output) — the shared inversions beat the
//! table lookups, but only modestly. Degenerate lanes (identity inputs,
//! `k = 0`, `acc == ±T` collisions, `y = 0` doublings) are poison-marked;
//! the caller falls back to the per-item path for those lanes, so
//! correctness never depends on the batch.
//!
//! The kernel is OFF by default: [`set_enabled`] is the runtime toggle the
//! embedding engine flips from its config (slipstream `batch_decrypt`).
//! Byte-identical output is KAT-gated in this module's tests.
//!
//! [v0.6 P8] Second kernel: [`batch_mul_same_scalar_glv`] — the same
//! lockstep-affine machinery rebuilt on the P7 shared window (prebuilt
//! tables), a GLV half-length digit schedule, and once-per-call scratch.
//! The dispatch in note_encryption.rs routes window-prepared epks there
//! and Wnaf-prepared epks through the original full-width kernel.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use group::ff::{Field, PrimeField};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

static ENABLED: AtomicBool = AtomicBool::new(false);
// Did-it-fire counters (the graft lever's lesson: a lever without a fire
// signal is unverifiable in production — build-then-prune looked identical).
// CALLS/LANES tick on every `batch_ka_agree_dec` entry (either path);
// KERNEL_LANES ticks only when the lockstep kernel actually multiplies.
static CALLS: AtomicU64 = AtomicU64::new(0);
static LANES: AtomicU64 = AtomicU64::new(0);
static KERNEL_LANES: AtomicU64 = AtomicU64::new(0);
static NANOS: AtomicU64 = AtomicU64::new(0);
static WALL_NANOS: AtomicU64 = AtomicU64::new(0);
// v0.6 P6: CPU inside `batch_epk` (epk decompression + table build — since
// P7 the shared φ-endo window, pre-P7 the wNAF table the levers never read) —
// task work OUTSIDE the DH bracket; joins the same union wall (task-core wall).
static EPK_NANOS: AtomicU64 = AtomicU64::new(0);

/// [slipstream v0.6 P5] Union-of-intervals wall clock for the DH seam: the
/// time during which ≥1 `batch_ka_agree_dec` call is in flight on ANY
/// thread. Against `NANOS` (CPU-sum across threads) it yields the average
/// busy-thread count DURING DH; against the scanner's call wall it isolates
/// the serial non-DH share. Guard-based so every exit path (including
/// panics) closes its interval; the interval only ends when the LAST
/// in-flight call drops. Poisoned-lock tolerant — an instrument must not
/// become a crash.
#[cfg(feature = "std")]
mod wall {
    use core::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::Instant;

    struct Active {
        count: u32,
        since: Option<Instant>,
    }

    static ACTIVE: Mutex<Active> = Mutex::new(Active { count: 0, since: None });

    fn lock() -> std::sync::MutexGuard<'static, Active> {
        ACTIVE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) struct Guard(());

    pub(crate) fn enter() -> Guard {
        let mut a = lock();
        if a.count == 0 {
            a.since = Some(Instant::now());
        }
        a.count += 1;
        Guard(())
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let mut a = lock();
            a.count = a.count.saturating_sub(1);
            if a.count == 0 {
                if let Some(since) = a.since.take() {
                    super::WALL_NANOS
                        .fetch_add(since.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

/// RAII guard opening (or joining) a DH-wall interval — hold across the
/// whole `batch_ka_agree_dec` body. See [`wall`].
#[cfg(feature = "std")]
pub(crate) fn wall_enter() -> wall::Guard {
    wall::enter()
}

/// Runtime toggle for the batched DH kernel (default OFF = the per-item
/// path, byte-for-byte). Flipped by the embedding engine from its config;
/// resets the fire counters so each pass reads its own totals.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    LANES.store(0, Ordering::Relaxed);
    KERNEL_LANES.store(0, Ordering::Relaxed);
    NANOS.store(0, Ordering::Relaxed);
    WALL_NANOS.store(0, Ordering::Relaxed);
    EPK_NANOS.store(0, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn note_call(lanes: usize) {
    CALLS.fetch_add(1, Ordering::Relaxed);
    LANES.fetch_add(lanes as u64, Ordering::Relaxed);
}

pub(crate) fn note_kernel_lanes(lanes: usize) {
    KERNEL_LANES.fetch_add(lanes as u64, Ordering::Relaxed);
}

#[cfg(feature = "std")]
pub(crate) fn note_nanos(n: u64) {
    NANOS.fetch_add(n, Ordering::Relaxed);
}

#[cfg(feature = "std")]
pub(crate) fn note_epk_nanos(n: u64) {
    EPK_NANOS.fetch_add(n, Ordering::Relaxed);
}

/// `(calls, lanes, kernel_lanes, nanos, wall_nanos)` since the last
/// [`set_enabled`]. `calls > 0` proves the batched seam is reached at all;
/// `kernel_lanes > 0` proves the lockstep kernel engaged (vs. the per-item
/// fallback). `nanos` is CPU-side wall accumulated inside
/// `batch_ka_agree_dec` across all threads and BOTH paths (std builds only;
/// 0 without std) — the true production DH cost, so an ON/OFF pair measures
/// the kernel's real ratio and DH's share of scan without microbenchmark
/// assumptions. `wall_nanos` is the union-of-intervals wall (time ≥1
/// bracketed call in flight, any thread — the DH bracket AND `batch_epk`
/// join the same interval): `(nanos + epk_nanos) / wall_nanos` = average
/// busy threads inside the bracketed task core. `epk_nanos` is CPU inside
/// `batch_epk` (decompression + per-epk table build — the task work the
/// DH-only readout was blind to; since P7 the table is the shared φ-endo
/// window instead of the unread wNAF table).
pub fn stats() -> (u64, u64, u64, u64, u64, u64) {
    (
        CALLS.load(Ordering::Relaxed),
        LANES.load(Ordering::Relaxed),
        KERNEL_LANES.load(Ordering::Relaxed),
        NANOS.load(Ordering::Relaxed),
        WALL_NANOS.load(Ordering::Relaxed),
        EPK_NANOS.load(Ordering::Relaxed),
    )
}

/// Montgomery batch inversion in place. `xs` MUST contain no zeros (the
/// caller poison-replaces zeros with ONE and marks those lanes fallback).
fn batch_invert(xs: &mut [pallas::Base]) {
    let n = xs.len();
    if n == 0 {
        return;
    }
    let mut prefix = Vec::with_capacity(n);
    let mut acc = pallas::Base::ONE;
    for x in xs.iter() {
        prefix.push(acc);
        acc *= x;
    }
    let mut inv_all = acc.invert().expect("no zeros by contract");
    for i in (0..n).rev() {
        let inv_i = inv_all * prefix[i];
        inv_all *= xs[i];
        xs[i] = inv_i;
    }
}

/// Width-4 wNAF recode: signed odd digits, nonzero density ~1/5. Runs once
/// per (ivk, batch) — the scalar is fixed across the batch.
pub(crate) fn wnaf4(repr: &[u8; 32]) -> Vec<i8> {
    let mut k = [0u64; 5]; // one spare limb: k + 7 must not overflow
    for (i, limb) in k.iter_mut().take(4).enumerate() {
        *limb = u64::from_le_bytes(repr[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
    }
    fn is_zero(k: &[u64; 5]) -> bool {
        k.iter().all(|&x| x == 0)
    }
    fn add_small(k: &mut [u64; 5], v: u64) {
        let mut carry = v;
        for limb in k.iter_mut() {
            let (s, c) = limb.overflowing_add(carry);
            *limb = s;
            carry = u64::from(c);
            if carry == 0 {
                break;
            }
        }
    }
    fn sub_small(k: &mut [u64; 5], v: u64) {
        let mut borrow = v;
        for limb in k.iter_mut() {
            let (s, b) = limb.overflowing_sub(borrow);
            *limb = s;
            borrow = u64::from(b);
            if borrow == 0 {
                break;
            }
        }
    }
    fn shr1(k: &mut [u64; 5]) {
        for i in 0..4 {
            k[i] = (k[i] >> 1) | (k[i + 1] << 63);
        }
        k[4] >>= 1;
    }
    let mut digits = Vec::with_capacity(260);
    while !is_zero(&k) {
        if k[0] & 1 == 1 {
            let low = (k[0] & 0xF) as i8;
            let d = if low >= 8 { low - 16 } else { low };
            digits.push(d);
            if d >= 0 {
                sub_small(&mut k, d as u64);
            } else {
                add_small(&mut k, (-d) as u64);
            }
        } else {
            digits.push(0);
        }
        shr1(&mut k);
    }
    digits
}

/// `[k]·P` for every `P` in `points` — the lockstep-affine wNAF-4 ladder.
/// `None` = degenerate lane (caller falls back per-item).
pub(crate) fn batch_mul_same_scalar(
    k: &pallas::Scalar,
    points: &[pallas::Affine],
) -> Vec<Option<pallas::Affine>> {
    let n = points.len();
    if n == 0 {
        return vec![];
    }
    let repr = k.to_repr();
    let repr_bytes: &[u8] = repr.as_ref();
    let repr_arr: &[u8; 32] = repr_bytes.try_into().expect("32 bytes");
    let digits = wnaf4(repr_arr);
    if digits.is_empty() {
        return vec![None; n]; // k == 0 → identity everywhere
    }

    // Odd-multiple tables {P, 3P, 5P, 7P} per lane, built with 4 batched ops.
    let mut dead = vec![false; n];
    let mut tx = vec![vec![pallas::Base::ZERO; n]; 4];
    let mut ty = vec![vec![pallas::Base::ZERO; n]; 4];
    for (i, p) in points.iter().enumerate() {
        let coords: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
            p.coordinates().into();
        match coords {
            Some(c) => {
                tx[0][i] = *c.x();
                ty[0][i] = *c.y();
            }
            None => dead[i] = true,
        }
    }
    let two = pallas::Base::from(2);
    let three = pallas::Base::from(3);
    let mut denom = vec![pallas::Base::ONE; n];

    let mut dx = vec![pallas::Base::ZERO; n];
    let mut dy = vec![pallas::Base::ZERO; n];
    for i in 0..n {
        denom[i] = if dead[i] {
            pallas::Base::ONE
        } else {
            let d = two * ty[0][i];
            if bool::from(d.is_zero()) {
                dead[i] = true;
                pallas::Base::ONE
            } else {
                d
            }
        };
    }
    batch_invert(&mut denom);
    for i in 0..n {
        if dead[i] {
            continue;
        }
        let lambda = three * tx[0][i].square() * denom[i];
        dx[i] = lambda.square() - two * tx[0][i];
        dy[i] = lambda * (tx[0][i] - dx[i]) - ty[0][i];
    }
    for j in 1..4 {
        for i in 0..n {
            denom[i] = if dead[i] {
                pallas::Base::ONE
            } else {
                let d = dx[i] - tx[j - 1][i];
                if bool::from(d.is_zero()) {
                    dead[i] = true;
                    pallas::Base::ONE
                } else {
                    d
                }
            };
        }
        batch_invert(&mut denom);
        for i in 0..n {
            if dead[i] {
                continue;
            }
            let lambda = (dy[i] - ty[j - 1][i]) * denom[i];
            let x3 = lambda.square() - tx[j - 1][i] - dx[i];
            let y3 = lambda * (tx[j - 1][i] - x3) - ty[j - 1][i];
            tx[j][i] = x3;
            ty[j][i] = y3;
        }
    }

    // Seed at the top digit (always nonzero), then the lockstep ladder.
    let top = digits.len() - 1;
    let seed = digits[top];
    let jt = ((seed.unsigned_abs() as usize) - 1) / 2;
    let mut x: Vec<pallas::Base> = (0..n).map(|i| tx[jt][i]).collect();
    let mut y: Vec<pallas::Base> = (0..n)
        .map(|i| if seed < 0 { -ty[jt][i] } else { ty[jt][i] })
        .collect();

    for pos in (0..top).rev() {
        for i in 0..n {
            denom[i] = if dead[i] {
                pallas::Base::ONE
            } else {
                let d = two * y[i];
                if bool::from(d.is_zero()) {
                    dead[i] = true;
                    pallas::Base::ONE
                } else {
                    d
                }
            };
        }
        batch_invert(&mut denom);
        for i in 0..n {
            if dead[i] {
                continue;
            }
            let lambda = three * x[i].square() * denom[i];
            let x3 = lambda.square() - two * x[i];
            let y3 = lambda * (x[i] - x3) - y[i];
            x[i] = x3;
            y[i] = y3;
        }
        let d = digits[pos];
        if d != 0 {
            let j = ((d.unsigned_abs() as usize) - 1) / 2;
            let neg = d < 0;
            for i in 0..n {
                denom[i] = if dead[i] {
                    pallas::Base::ONE
                } else {
                    let dd = tx[j][i] - x[i];
                    if bool::from(dd.is_zero()) {
                        dead[i] = true;
                        pallas::Base::ONE
                    } else {
                        dd
                    }
                };
            }
            batch_invert(&mut denom);
            for i in 0..n {
                if dead[i] {
                    continue;
                }
                let py = if neg { -ty[j][i] } else { ty[j][i] };
                let lambda = (py - y[i]) * denom[i];
                let x3 = lambda.square() - x[i] - tx[j][i];
                let y3 = lambda * (x[i] - x3) - y[i];
                x[i] = x3;
                y[i] = y3;
            }
        }
    }

    (0..n)
        .map(|i| {
            if dead[i] {
                None
            } else {
                Option::from(pallas::Affine::from_xy(x[i], y[i]))
            }
        })
        .collect()
}

/// Montgomery batch inversion in place with caller-provided scratch — the
/// GLV kernel runs ~180 batched steps per call, and C1's fresh prefix Vec
/// inside every step (~5M allocations per restore) is one of the three
/// named production killers this kernel exists to fix. Same zero contract
/// as [`batch_invert`].
fn batch_invert_scratch(xs: &mut [pallas::Base], prefix: &mut Vec<pallas::Base>) {
    let n = xs.len();
    if n == 0 {
        return;
    }
    prefix.clear();
    let mut acc = pallas::Base::ONE;
    for x in xs.iter() {
        prefix.push(acc);
        acc *= x;
    }
    let mut inv_all = acc.invert().expect("no zeros by contract");
    for i in (0..n).rev() {
        let inv_i = inv_all * prefix[i];
        inv_all *= xs[i];
        xs[i] = inv_i;
    }
}

/// [v0.6 P8] Per-lane accumulator state for the GLV-lockstep ladder: every
/// buffer allocated once per call, reused across all steps. Dead lanes are
/// poison-marked exactly like the full-width kernel (the caller falls back
/// per-item, so correctness never depends on the batch).
struct GlvLanes {
    x: Vec<pallas::Base>,
    y: Vec<pallas::Base>,
    dead: Vec<bool>,
    denom: Vec<pallas::Base>,
    prefix: Vec<pallas::Base>,
}

impl GlvLanes {
    /// One batched affine doubling across all live lanes (shared inversion).
    fn double_step(&mut self) {
        let n = self.x.len();
        let two = pallas::Base::from(2);
        let three = pallas::Base::from(3);
        for i in 0..n {
            self.denom[i] = if self.dead[i] {
                pallas::Base::ONE
            } else {
                let d = two * self.y[i];
                if bool::from(d.is_zero()) {
                    self.dead[i] = true;
                    pallas::Base::ONE
                } else {
                    d
                }
            };
        }
        batch_invert_scratch(&mut self.denom, &mut self.prefix);
        for i in 0..n {
            if self.dead[i] {
                continue;
            }
            let lambda = three * self.x[i].square() * self.denom[i];
            let x3 = lambda.square() - two * self.x[i];
            let y3 = lambda * (self.x[i] - x3) - self.y[i];
            self.x[i] = x3;
            self.y[i] = y3;
        }
    }

    /// One batched affine addition of table entry `j` (negated when `neg`)
    /// across all live lanes. `tx`/`ty` are the flat [j·n + i] table planes.
    fn add_entry(&mut self, tx: &[pallas::Base], ty: &[pallas::Base], j: usize, neg: bool) {
        let n = self.x.len();
        for i in 0..n {
            self.denom[i] = if self.dead[i] {
                pallas::Base::ONE
            } else {
                let dd = tx[j * n + i] - self.x[i];
                if bool::from(dd.is_zero()) {
                    self.dead[i] = true;
                    pallas::Base::ONE
                } else {
                    dd
                }
            };
        }
        batch_invert_scratch(&mut self.denom, &mut self.prefix);
        for i in 0..n {
            if self.dead[i] {
                continue;
            }
            let py = if neg { -ty[j * n + i] } else { ty[j * n + i] };
            let lambda = (py - self.y[i]) * self.denom[i];
            let x3 = lambda.square() - self.x[i] - tx[j * n + i];
            let y3 = lambda * (self.x[i] - x3) - self.y[i];
            self.x[i] = x3;
            self.y[i] = y3;
        }
    }
}

/// [v0.6 P8] `[k]·P` for every prepared window — the GLV-lockstep kernel.
/// C1's batch-affine ladder (graveyard: 1.4–2× slower per lane under real
/// scan concurrency despite a 1.6× microbench) rebuilt on the three fixes
/// the P6/P7 instruments named: the odd-multiple tables come PREBUILT from
/// the P7 shared window (no per-call build, no per-call input normalize),
/// the GLV split halves the doubling schedule (~128 shared doublings vs
/// ~255 — doublings dominate a same-scalar ladder), and every buffer is
/// allocated once per call and reused across all ~180 batched steps.
/// Digit schedule: width-4 wNAF over both signed halves, table planes
/// j∈0..4 = {1,3,5,7}·P and j∈4..8 = {1,3,5,7}·φ(P). `None` = degenerate
/// lane (identity table point, mid-ladder collision, or k ≡ 0) — the
/// caller falls back per-item, so output is byte-identical either way
/// (KAT-gated below).
pub(crate) fn batch_mul_same_scalar_glv(
    k: &pallas::Scalar,
    tables: &[&crate::endo::EndoTable],
) -> Vec<Option<pallas::Affine>> {
    use pasta_curves::arithmetic::Coordinates;

    let n = tables.len();
    if n == 0 {
        return vec![];
    }
    let ((s1, a1), (s2, a2)) = crate::endo::decompose(k);
    if a1 == 0 && a2 == 0 {
        return vec![None; n]; // k ≡ 0 → identity everywhere → per-item path
    }
    let (d1, l1) = crate::endo::wnaf_digits(a1);
    let (d2, l2) = crate::endo::wnaf_digits(a2);
    let top = l1.max(l2) - 1;

    // Bulk-extract the 8 table planes into flat [j·n + i] SoA once per
    // call: the ladder's inner loops then run on contiguous lanes, C1's
    // proven access pattern, without C1's build cost.
    let mut lanes = GlvLanes {
        x: vec![pallas::Base::ZERO; n],
        y: vec![pallas::Base::ZERO; n],
        dead: vec![false; n],
        denom: vec![pallas::Base::ONE; n],
        prefix: Vec::with_capacity(n),
    };
    let mut tx = vec![pallas::Base::ZERO; 8 * n];
    let mut ty = vec![pallas::Base::ZERO; 8 * n];
    for (i, t) in tables.iter().enumerate() {
        for (j, p) in t.t1().iter().chain(t.t2().iter()).enumerate() {
            let coords: Option<Coordinates<pallas::Affine>> = p.coordinates().into();
            match coords {
                Some(c) => {
                    tx[j * n + i] = *c.x();
                    ty[j * n + i] = *c.y();
                }
                // Unreachable for prepared epks (non-identity invariant);
                // poison, don't panic — an instrumented lever must not crash.
                None => lanes.dead[i] = true,
            }
        }
    }

    // Digit → (plane index, effective sign). Planes 0..4 walk stream 1
    // (·P, sign s1), planes 4..8 walk stream 2 (·φ(P), sign s2).
    let plane1 = |d: i8| ((d.unsigned_abs() / 2) as usize, (d < 0) ^ s1);
    let plane2 = |d: i8| (4 + (d.unsigned_abs() / 2) as usize, (d < 0) ^ s2);

    // Seed at the top position: the longer stream's top wNAF digit is
    // nonzero by construction; if both streams top out here, seed from
    // stream 1 and add stream 2's entry.
    let g1 = if top < l1 { d1[top] } else { 0 };
    let g2 = if top < l2 { d2[top] } else { 0 };
    let (seed_j, seed_neg) = if g1 != 0 { plane1(g1) } else { plane2(g2) };
    for i in 0..n {
        if lanes.dead[i] {
            continue;
        }
        lanes.x[i] = tx[seed_j * n + i];
        lanes.y[i] = if seed_neg {
            -ty[seed_j * n + i]
        } else {
            ty[seed_j * n + i]
        };
    }
    if g1 != 0 && g2 != 0 {
        let (j, neg) = plane2(g2);
        lanes.add_entry(&tx, &ty, j, neg);
    }

    // The shared-doubling ladder: ~half the schedule of the full-width
    // kernel, up to two adds per position.
    for pos in (0..top).rev() {
        lanes.double_step();
        let d = if pos < l1 { d1[pos] } else { 0 };
        if d != 0 {
            let (j, neg) = plane1(d);
            lanes.add_entry(&tx, &ty, j, neg);
        }
        let d = if pos < l2 { d2[pos] } else { 0 };
        if d != 0 {
            let (j, neg) = plane2(d);
            lanes.add_entry(&tx, &ty, j, neg);
        }
    }

    (0..n)
        .map(|i| {
            if lanes.dead[i] {
                None
            } else {
                Option::from(pallas::Affine::from_xy(lanes.x[i], lanes.y[i]))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group};

    /// KAT: the kernel must be byte-identical to the curve's own scalar mult.
    #[test]
    fn kernel_matches_group_mul() {
        let base = pallas::Point::generator();
        let points: Vec<pallas::Affine> =
            (0..500u64).map(|i| (base * pallas::Scalar::from(31 + i)).to_affine()).collect();
        let k = pallas::Scalar::from(0xDEAD_BEEF_0BAD_F00Du64).square()
            + pallas::Scalar::from(17);
        let ours = batch_mul_same_scalar(&k, &points);
        for (p, o) in points.iter().zip(&ours) {
            let expected = (pallas::Point::from(*p) * k).to_affine();
            assert_eq!(o.expect("no degenerates on random points"), expected);
        }
    }

    /// [v0.6 P8] KAT: the GLV-lockstep kernel is byte-identical to the
    /// curve's own scalar multiplication on prebuilt tables — edge scalars
    /// (±1, 2, λ — each exercising a distinct seed/stream branch) plus a
    /// full-width sweep for digit-pattern diversity.
    #[test]
    fn glv_kernel_matches_group_mul() {
        use ff::WithSmallOrderMulGroup;

        let base = pallas::Point::generator();
        let points: Vec<pallas::Point> = (0..200u64)
            .map(|i| base * pallas::Scalar::from(31 + i))
            .collect();
        let tables = crate::endo::endo_tables(&points);
        let refs: Vec<&crate::endo::EndoTable> = tables.iter().collect();

        let edges = [
            pallas::Scalar::from(0xDEAD_BEEF_0BAD_F00Du64).square() + pallas::Scalar::from(17),
            pallas::Scalar::ONE,
            -pallas::Scalar::ONE,
            pallas::Scalar::ZETA,
            pallas::Scalar::from(2),
            pallas::Scalar::from(u64::MAX),
        ];
        for k in edges {
            let ours = batch_mul_same_scalar_glv(&k, &refs);
            for (i, (p, o)) in points.iter().zip(&ours).enumerate() {
                let expected = (p * k).to_affine();
                assert_eq!(
                    o.expect("no degenerates on random points"),
                    expected,
                    "lane {i}"
                );
            }
        }

        // Full-width sweep on a smaller batch (the fork's KAT scalar pattern).
        let small: Vec<&crate::endo::EndoTable> = tables.iter().take(8).collect();
        let n = if cfg!(debug_assertions) { 100u64 } else { 500 };
        for (si, k) in (0..n)
            .map(|i| {
                (pallas::Scalar::from(0x9E37_79B9_7F4A_7C15u64 + i).square()
                    + pallas::Scalar::from(0x0123_4567_89AB_CDEFu64))
                .square()
                    + pallas::Scalar::from(i)
            })
            .enumerate()
        {
            let ours = batch_mul_same_scalar_glv(&k, &small);
            for (p, o) in points.iter().take(8).zip(&ours) {
                assert_eq!(o.expect("live"), (p * k).to_affine(), "sweep {si}");
            }
        }

        // k ≡ 0: every lane degenerate (mirrors the full-width kernel).
        let zeros = batch_mul_same_scalar_glv(&pallas::Scalar::ZERO, &refs);
        assert!(zeros.iter().all(Option::is_none));
    }

    /// [v0.6 P8] End-to-end through the REAL types: the GLV kernel must
    /// equal the per-item tabled path byte-for-byte, for BOTH scope ivks
    /// (the shared window's two consumers).
    #[test]
    fn glv_kernel_matches_per_item_tabled() {
        use crate::keys::{
            FullViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, Scope,
            SpendingKey,
        };

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let base = pallas::Point::generator();
        let epks: Vec<PreparedEphemeralPublicKey> = (0..150u64)
            .map(|i| {
                PreparedEphemeralPublicKey::testing_from_point_tabled(
                    base * pallas::Scalar::from(1_000 + i),
                )
            })
            .collect();
        let tables: Vec<&crate::endo::EndoTable> = epks
            .iter()
            .map(|e| e.endo_table().expect("tabled"))
            .collect();

        for scope in [Scope::External, Scope::Internal] {
            let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(scope));
            let batched = batch_mul_same_scalar_glv(&ivk.raw_scalar(), &tables);
            for (i, (epk, b)) in epks.iter().zip(batched).enumerate() {
                let per_item = epk.agree(&ivk);
                let kernel = crate::keys::SharedSecret::from_kernel_point(pallas::Point::from(
                    b.expect("live"),
                ));
                assert_eq!(
                    per_item.to_bytes(),
                    kernel.to_bytes(),
                    "scope {scope:?}, lane {i}"
                );
            }
        }
    }

    /// End-to-end KAT through the REAL types: the batched override must equal
    /// the per-item `agree` byte-for-byte (SharedSecret comparison).
    #[test]
    fn shared_secrets_match_per_item_agree() {
        use crate::keys::{FullViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, Scope, SpendingKey};

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

        let base = pallas::Point::generator();
        let epks: Vec<PreparedEphemeralPublicKey> = (0..200u64)
            .map(|i| {
                let p = base * pallas::Scalar::from(1_000 + i);
                PreparedEphemeralPublicKey::testing_from_point(p)
            })
            .collect();

        let k = ivk.raw_scalar();
        let bases: Vec<pallas::Affine> =
            epks.iter().map(|e| e.raw_point().to_affine()).collect();
        let batched = batch_mul_same_scalar(&k, &bases);
        for (epk, b) in epks.iter().zip(batched) {
            let per_item = epk.agree(&ivk);
            let kernel = crate::keys::SharedSecret::from_kernel_point(pallas::Point::from(
                b.expect("live"),
            ));
            assert_eq!(per_item.to_bytes(), kernel.to_bytes());
        }
    }
}
