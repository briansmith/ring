// Copyright 2023 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{CommonOps, Elem, Point, Scalar, MAX_BITS};
use crate::{arithmetic::montgomery::R, c, limb::Limb};

pub(super) fn points_mul_vartime(
    ops: &'static CommonOps,
    g_scalar: &Scalar,
    g: &(Elem<R>, Elem<R>),
    p_scalar: &Scalar,
    p: &(Elem<R>, Elem<R>),
) -> Point {
    let mut g_wnaf: [i8; WNAF_MAX_LEN] = [0; WNAF_MAX_LEN];
    let (g_wnaf, g_precomp) = prepare(ops, g_scalar, g, &mut g_wnaf);

    let mut p_wnaf: [i8; WNAF_MAX_LEN] = [0; WNAF_MAX_LEN];
    let (p_wnaf, p_precomp) = prepare(ops, p_scalar, p, &mut p_wnaf);

    let mut acc = PointVartime::new_at_infinity(ops);
    // Iterate from the highest-order digit to the lowest-order digit.
    g_wnaf
        .iter()
        .zip(p_wnaf)
        .enumerate()
        .rev()
        .for_each(|(i, (&g_digit, &p_digit))| {
            process_digit(ops, &mut acc, g_digit, &g_precomp);
            process_digit(ops, &mut acc, p_digit, &p_precomp);
            if i > 0 {
                acc.double_assign();
            }
        });
    acc.value.unwrap_or_else(Point::new_at_infinity)
}

const WINDOW_BITS: u32 = 4;
const WNAF_MAX_LEN: usize = MAX_BITS.as_usize_bits() + 1;
const PRECOMP_LEN: usize = 1 << (WINDOW_BITS - 1);

fn prepare<'a>(
    ops: &'static CommonOps,
    a: &Scalar,
    (x, y): &(Elem<R>, Elem<R>),
    wnaf: &'a mut [i8; WNAF_MAX_LEN],
) -> (&'a [i8], [Point; PRECOMP_LEN]) {
    let order_bits = ops.order_bits().as_usize_bits();
    let wnaf = &mut wnaf[..(order_bits + 1)];
    prefixed_extern! {
        fn ec_compute_wNAF(out: *mut i8, scalar: *const Limb, scalar_limbs: c::size_t,
                           order_bits: c::size_t, w: c::int);
    }
    unsafe {
        ec_compute_wNAF(
            wnaf.as_mut_ptr(),
            a.limbs.as_ptr(),
            a.limbs.len(),
            order_bits,
            WINDOW_BITS as c::int,
        );
    }

    let mut precomp = [Point::new_at_infinity(); PRECOMP_LEN];
    // Fill `precomp` with `p` and all odd multiples (1 * p, 3 * p, 5 * p, etc.).
    precomp[0] = ops.point_new_affine(x, y);
    let mut p2 = precomp[0];
    ops.point_double_assign(&mut p2);
    for i in 1..precomp.len() {
        precomp[i] = ops.point_sum(&p2, &precomp[i - 1]);
    }
    (wnaf, precomp)
}

fn process_digit(
    ops: &CommonOps,
    acc: &mut PointVartime,
    digit: i8,
    precomp: &[Point; PRECOMP_LEN],
) {
    if digit != 0 {
        debug_assert_eq!(digit & 1, 1);
        let neg = digit < 0;
        let idx = usize::try_from(if neg { -digit } else { digit }).unwrap() >> 1;
        let entry = &precomp[idx];
        let entry_neg;
        let entry = if neg {
            entry_neg = ops.point_neg_vartime(entry);
            &entry_neg
        } else {
            entry
        };
        acc.add_assign(entry);
    }
}

/// A `Point` with operations optimized for the case where it is the point at
/// infinity.
struct PointVartime {
    ops: &'static CommonOps,

    /// `None` means "definitely the point at infinity." `Some(p)` may or may
    /// not be the point at infinity. Will be `None` until a nonzero bit of
    /// the scalar is encountered.
    value: Option<Point>,
}

impl PointVartime {
    pub fn new_at_infinity(ops: &'static CommonOps) -> Self {
        Self { ops, value: None }
    }

    pub fn double_assign(&mut self) {
        if let Some(p) = &mut self.value {
            self.ops.point_double_assign(p);
        }
    }

    pub fn add_assign(&mut self, a: &Point) {
        if let Some(value) = &mut self.value {
            self.ops.point_add_assign(value, a);
        } else {
            self.value = Some(*a);
        }
    }
}
