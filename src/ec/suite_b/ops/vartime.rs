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
    fallback::{point_double, points_add_vartime, InOut},
    CommonOps, Elem, Point, Scalar, MAX_BITS,
};
use crate::{arithmetic::montgomery::R, c, limb::Limb};

pub(super) fn points_mul_vartime(
    ops: &'static CommonOps,
    g_scalar: &Scalar,
    g: &(Elem<R>, Elem<R>),
    p_scalar: &Scalar,
    p: &(Elem<R>, Elem<R>),
) -> Point {
    let mut g_wnaf: [i8; WNAF_MAX_LEN] = [0; WNAF_MAX_LEN];
    let mut g_precomp = [[Elem::zero(); 3]; PRECOMP_SIZE];
    let (g_wnaf, g_precomp) = prepare(ops, g_scalar, g, &mut g_wnaf, &mut g_precomp);

    let mut p_wnaf: [i8; WNAF_MAX_LEN] = [0; WNAF_MAX_LEN];
    let mut p_precomp = [[Elem::zero(); 3]; PRECOMP_SIZE];
    let (p_wnaf, p_precomp) = prepare(ops, p_scalar, p, &mut p_wnaf, &mut p_precomp);

    let r = point_mul_vartime(ops, g_wnaf, g_precomp, p_wnaf, p_precomp);
    ops.new_point(&r[0], &r[1], &r[2])
}

const WINDOW_BITS: u32 = 4;
const WNAF_MAX_LEN: usize = MAX_BITS.as_usize_bits() + 1;
const PRECOMP_SIZE: usize = 1 << (WINDOW_BITS - 1);

fn prepare<'a>(
    ops: &'static CommonOps,
    a: &Scalar,
    (x, y): &(Elem<R>, Elem<R>),
    wnaf: &'a mut [i8; WNAF_MAX_LEN],
    precomp: &'a mut [[Elem<R>; 3]; PRECOMP_SIZE],
) -> (&'a [i8], &'a [[Elem<R>; 3]; PRECOMP_SIZE]) {
    // Fill `precomp` with `p` and all odd multiples (1 * p, 3 * p, 5 * p, etc.).
    precomp[0][0] = *x;
    precomp[0][1] = *y;
    precomp[0][2] = {
        // Calculate 1 in the Montgomery domain.
        let mut acc = Elem::zero();
        acc.limbs[0] = 1;
        let mut rr = Elem::zero();
        rr.limbs[..ops.num_limbs].copy_from_slice(&ops.q.rr[..ops.num_limbs]);

        ops.elem_mul(&mut acc, &rr);
        acc
    };

    let mut p2: [Elem<R>; 3] = [Elem::zero(); 3];
    point_double(
        ops,
        InOut::OutOfPlace {
            output: &mut p2,
            input: &precomp[0],
        },
    );

    for i in 1..precomp.len() {
        let (written, to_write) = precomp.split_at_mut(i);

        points_add_vartime(
            ops,
            InOut::OutOfPlace {
                output: &mut to_write[0],
                input: &p2,
            },
            &written[i - 1][0],
            &written[i - 1][1],
            &written[i - 1][2],
        );
    }

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

    (wnaf, precomp)
}
fn point_mul_vartime(
    ops: &'static CommonOps,
    g_wnaf: &[i8],
    g_precomp: &[[Elem<R>; 3]; PRECOMP_SIZE],
    p_wnaf: &[i8],
    p_precomp: &[[Elem<R>; 3]; PRECOMP_SIZE],
) -> [Elem<R>; 3] {
    let mut acc = PointVartime::new_at_infinity(ops);

    fn process_bit(
        ops: &CommonOps,
        acc: &mut PointVartime,
        digit: i8,
        precomp: &[[Elem<R>; 3]; PRECOMP_SIZE],
    ) {
        if digit != 0 {
            debug_assert_eq!(digit & 1, 1);
            let neg = digit < 0;
            let idx = usize::try_from(if neg { -digit } else { digit }).unwrap() >> 1;
            let entry = &precomp[idx];
            let mut y_neg;
            let y = if neg {
                y_neg = entry[1];
                ops.elem_negate_vartime(&mut y_neg);
                &y_neg
            } else {
                &entry[1]
            };
            acc.add_assign(&entry[0], y, &entry[2]);
        }
    }

    g_wnaf
        .iter()
        .zip(p_wnaf)
        .enumerate()
        .rev()
        .for_each(|(i, (&g_digit, &p_digit))| {
            process_bit(ops, &mut acc, g_digit, g_precomp);
            process_bit(ops, &mut acc, p_digit, p_precomp);
            if i != 0 {
                acc.double_assign();
            }
        });
    acc.value.unwrap_or_else(|| [Elem::zero(); 3])
}

struct PointVartime {
    ops: &'static CommonOps,
    value: Option<[Elem<R>; 3]>, // None is the point at infinity.
}

impl PointVartime {
    pub fn new_at_infinity(ops: &'static CommonOps) -> Self {
        Self { ops, value: None }
    }
    pub fn double_assign(&mut self) {
        if let Some(p) = &mut self.value {
            point_double(self.ops, InOut::InPlace(p));
        }
    }

    pub fn add_assign(&mut self, x: &Elem<R>, y: &Elem<R>, z: &Elem<R>) {
        if let Some(value) = &mut self.value {
            points_add_vartime(self.ops, InOut::InPlace(value), x, y, z);
        } else {
            self.value = Some([*x, *y, *z]);
        }
    }
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
            |s, p| {
                let ops = &p384::COMMON_OPS;

                // Dummy `g_scalar`.
                let g_scalar = Scalar::zero();
                let mut g_wnaf = [0; WNAF_MAX_LEN];
                let mut g_precomp = [[Elem::zero(); 3]; PRECOMP_SIZE];
                let (g_wnaf, g_precomp) = prepare(
                    ops,
                    &g_scalar,
                    &p384::GENERATOR,
                    &mut g_wnaf,
                    &mut g_precomp,
                );

                let mut wnaf: [i8; WNAF_MAX_LEN] = [0; WNAF_MAX_LEN];
                let mut precomp = [[Elem::zero(); 3]; PRECOMP_SIZE];
                let (wnaf, precomp) = prepare(ops, s, p, &mut wnaf, &mut precomp);

                let [x, y, z] = point_mul_vartime(ops, g_wnaf, g_precomp, wnaf, precomp);
                ops.new_point(&x, &y, &z)
            },
        );
    }
}
