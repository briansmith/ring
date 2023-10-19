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

use super::CommonOps;
use crate::{arithmetic::montgomery::R, limb};

pub(super) type Elem = super::Elem<R>;

pub enum InOut<'a, 'b> {
    InPlace(&'a mut [Elem; 3]),
    OutOfPlace {
        output: &'a mut [Elem; 3],
        input: &'b [Elem; 3],
    },
}
pub(super) fn points_add_vartime(
    ops: &CommonOps,
    p1: InOut<'_, '_>,
    X2: &Elem,
    Y2: &Elem,
    Z2: &Elem,
) {
    let input = match &p1 {
        InOut::InPlace(a) => *a,
        InOut::OutOfPlace { input: a, .. } => *a,
    };
    let X1 = &input[0];
    let Y1 = &input[1];
    let Z1 = &input[2];

    if is_zero(Z1) {
        match p1 {
            InOut::InPlace(r) | InOut::OutOfPlace { output: r, .. } => {
                *r = [*X2, *Y2, *Z2];
            }
        };
        return;
    } else if is_zero(Z2) {
        match p1 {
            InOut::InPlace(_) => {} // It's already set.
            InOut::OutOfPlace { output, input } => {
                *output = *input;
            }
        }
        return;
    }

    let Z1Z1 = ops.elem_squared(Z1);
    let Z2Z2 = ops.elem_squared(Z2);
    let U1 = ops.elem_product(X1, &Z2Z2);
    let U2 = ops.elem_product(X2, &Z1Z1);
    let t0 = ops.elem_product(Z2, &Z2Z2);
    let S1 = ops.elem_product(Y1, &t0);
    let t1 = ops.elem_product(Z1, &Z1Z1);
    let S2 = ops.elem_product(Y2, &t1);
    let H = difference(ops, &U2, &U1);
    let t2 = times_2(ops, &H);
    let I = ops.elem_squared(&t2);
    let J = ops.elem_product(&H, &I);
    let t3 = difference(ops, &S2, &S1);
    let r = times_2(ops, &t3);

    if is_zero(&H) && is_zero(&r) {
        point_double(ops, p1);
        return;
    }

    let V = ops.elem_product(&U1, &I);
    let t4 = ops.elem_squared(&r);
    let t5 = times_2(ops, &V);
    let t6 = difference(ops, &t4, &J);
    let X3 = difference(ops, &t6, &t5);
    let t7 = difference(ops, &V, &X3);
    let t8 = ops.elem_product(&S1, &J);
    let t9 = times_2(ops, &t8);
    let t10 = ops.elem_product(&r, &t7);
    let Y3 = difference(ops, &t10, &t9);
    let t11 = sum(ops, Z1, Z2);
    let t12 = ops.elem_squared(&t11);
    let t13 = difference(ops, &t12, &Z1Z1);
    let t14 = difference(ops, &t13, &Z2Z2);
    let Z3 = ops.elem_product(&t14, &H);

    match p1 {
        InOut::InPlace(r) | InOut::OutOfPlace { output: r, .. } => {
            *r = [X3, Y3, Z3];
        }
    };
}

// From http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b,
// specifically http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/doubling/dbl-2001-b.op3
pub(super) fn point_double(ops: &CommonOps, p: InOut<'_, '_>) {
    let input = match &p {
        InOut::InPlace(a) => *a,
        InOut::OutOfPlace { input: a, .. } => *a,
    };
    let X1 = &input[0];
    let Y1 = &input[1];
    let Z1 = &input[2];

    let delta = ops.elem_squared(Z1);
    let gamma = ops.elem_squared(Y1);
    let beta = ops.elem_product(X1, &gamma);
    let t0 = difference(ops, X1, &delta);
    let t1 = sum(ops, X1, &delta);
    let t2 = ops.elem_product(&t0, &t1);
    let alpha = times_3(ops, &t2);
    let t3 = ops.elem_squared(&alpha);
    let t4 = times_8(ops, &beta);
    let X3 = difference(ops, &t3, &t4);
    let t5 = sum(ops, Y1, Z1);
    let t6 = ops.elem_squared(&t5);
    let t7 = difference(ops, &t6, &gamma);
    let Z3 = difference(ops, &t7, &delta);
    let t8 = times_4(ops, &beta);
    let t9 = difference(ops, &t8, &X3);
    let t10 = ops.elem_squared(&gamma);
    let t11 = times_8(ops, &t10);
    let t12 = ops.elem_product(&alpha, &t9);
    let Y3 = difference(ops, &t12, &t11);

    match p {
        InOut::InPlace(r) | InOut::OutOfPlace { output: r, .. } => {
            *r = [X3, Y3, Z3];
        }
    };
}

#[inline]
fn is_zero(a: &Elem) -> bool {
    a.limbs.iter().all(|x| *x == 0)
}

fn sum(ops: &CommonOps, a: &Elem, b: &Elem) -> Elem {
    let mut acc = *a;
    ops.elem_add(&mut acc, b);
    acc
}
fn difference(ops: &CommonOps, a: &Elem, b: &Elem) -> Elem {
    let mut acc = Elem::zero();
    limb::limbs_sub_mod(
        &mut acc.limbs[..ops.num_limbs],
        &a.limbs[..ops.num_limbs],
        &b.limbs[..ops.num_limbs],
        &ops.q.p[..ops.num_limbs],
    );
    acc
}
fn times_2(ops: &CommonOps, x: &Elem) -> Elem {
    sum(ops, x, x)
}
fn times_3(ops: &CommonOps, x: &Elem) -> Elem {
    let mut acc = times_2(ops, x);
    ops.elem_add(&mut acc, x);
    acc
}
fn times_4(ops: &CommonOps, x: &Elem) -> Elem {
    times_2(ops, &times_2(ops, x))
}

fn times_8(ops: &CommonOps, x: &Elem) -> Elem {
    times_2(ops, &times_4(ops, x))
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            p384,
            tests::{point_double_test, point_sum_test},
        },
        *,
    };

    #[test]
    fn p384_point_double_test() {
        point_double_test(
            &p384::PRIVATE_KEY_OPS,
            |p| {
                let ops = &p384::COMMON_OPS;
                let mut p = [ops.point_x(p), ops.point_y(p), ops.point_z(p)];
                point_double(ops, InOut::InPlace(&mut p));
                ops.new_point(&p[0], &p[1], &p[2])
            },
            test_file!("p384_point_double_tests.txt"),
        );
    }

    #[test]
    fn p384_points_add_vartime_test() {
        point_sum_test(
            &p384::PRIVATE_KEY_OPS,
            |a, b| {
                let ops = &p384::COMMON_OPS;
                let mut acc = [Elem::zero(); 3];
                let a = [ops.point_x(a), ops.point_y(a), ops.point_z(a)];
                let x2 = ops.point_x(b);
                let y2 = ops.point_y(b);
                let z2 = ops.point_z(b);
                points_add_vartime(
                    ops,
                    InOut::OutOfPlace {
                        output: &mut acc,
                        input: &a,
                    },
                    &x2,
                    &y2,
                    &z2,
                );
                ops.new_point(&acc[0], &acc[1], &acc[2])
            },
            test_file!("p384_point_sum_tests.txt"),
        );
    }
}
