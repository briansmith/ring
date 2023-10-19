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

use super::{
    fallback::{point_add_assign_vartime, point_double_assign},
    CommonOps, Elem, Point, Scalar,
};
use crate::{
    arithmetic::montgomery::R,
    limb::{Limb, LIMB_BITS},
};

pub(super) fn points_mul_vartime(
    ops: &'static CommonOps,
    g_scalar: &Scalar,
    g: &(Elem<R>, Elem<R>),
    p_scalar: &Scalar,
    p: &(Elem<R>, Elem<R>),
) -> Point {
    let mut acc = point_mul_vartime(ops, g_scalar, g);
    let b_scaled = point_mul_vartime(ops, p_scalar, p);
    point_add_assign_vartime(ops, &mut acc, &b_scaled);
    acc
}

fn point_mul_vartime(ops: &'static CommonOps, a: &Scalar, (x, y): &(Elem<R>, Elem<R>)) -> Point {
    let z = {
        let mut acc = Elem::zero();
        acc.limbs[0] = 1;
        let mut rr = Elem::zero();
        rr.limbs[..ops.num_limbs].copy_from_slice(&ops.q.rr[..ops.num_limbs]);

        ops.elem_mul(&mut acc, &rr);
        acc
    };
    let p = ops.new_point(&x, &y, &z);

    // Set `i` to the highest bit of the scalar.
    // TODO: Remove this `unwrap()`.
    let mut i = (ops.num_limbs * LIMB_BITS).checked_sub(1).unwrap();
    let mut acc = PointVartime::new_at_infinity(ops);
    loop {
        if is_bit_set(&a.limbs, i) {
            acc.add_assign(&p);
        }
        if i == 0 {
            break;
        }
        i -= 1;
        acc.double_assign();
    }
    acc.value.unwrap_or_else(Point::new_at_infinity)
}

struct PointVartime {
    ops: &'static CommonOps,
    value: Option<Point>, // None is the point at infinity.
}

impl PointVartime {
    pub fn new_at_infinity(ops: &'static CommonOps) -> Self {
        Self { ops, value: None }
    }
    pub fn double_assign(&mut self) {
        if let Some(p) = &mut self.value {
            point_double_assign(self.ops, p);
        }
    }

    pub fn add_assign(&mut self, a: &Point) {
        if let Some(value) = &mut self.value {
            point_add_assign_vartime(self.ops, value, a);
        } else {
            self.value = Some(a.clone());
        }
    }
}

fn is_bit_set(limbs: &[Limb], bit: usize) -> bool {
    let limb = limbs[bit / LIMB_BITS];
    let shift = bit % LIMB_BITS;
    let bit = (limb >> shift) & 1;
    bit != 0
}

#[cfg(test)]
mod tests {
    use super::{
        super::{p384, tests::point_mul_tests},
        *,
    };
    #[test]
    fn p384_point_mul_test() {
        point_mul_tests(
            &p384::PRIVATE_KEY_OPS,
            test_file!("p384_point_mul_tests.txt"),
            |s, p| point_mul_vartime(&p384::COMMON_OPS, s, p),
        );
    }
}
