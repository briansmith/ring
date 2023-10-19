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

use super::{CommonOps, Elem, Point, Scalar};
use crate::{
    arithmetic::montgomery::R,
    limb::{Limb, LIMB_BITS},
};

pub(super) fn points_mul_vartime(
    ops: &'static CommonOps,
    g_scalar: &Scalar,
    (gx, gy): &(Elem<R>, Elem<R>),
    p_scalar: &Scalar,
    (px, py): &(Elem<R>, Elem<R>),
) -> Point {
    let g = ops.point_new_affine(gx, gy);
    let p = ops.point_new_affine(px, py);

    let mut acc = PointVartime::new_at_infinity(ops);

    // Iterate from the highest bit to the lowest bit.
    (0..ops.order_bits().as_usize_bits()).rev().for_each(|i| {
        if is_bit_set(&g_scalar.limbs, i) {
            acc.add_assign(&g);
        }
        if is_bit_set(&p_scalar.limbs, i) {
            acc.add_assign(&p);
        }
        if i > 0 {
            acc.double_assign();
        }
    });
    acc.value.unwrap_or_else(Point::new_at_infinity)
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

fn is_bit_set(limbs: &[Limb], bit: usize) -> bool {
    let limb = limbs[bit / LIMB_BITS];
    let shift = bit % LIMB_BITS;
    let bit = (limb >> shift) & 1;
    bit != 0
}
