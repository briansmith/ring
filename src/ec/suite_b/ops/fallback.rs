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

use super::{CommonOps, Elem, Point};
use crate::{arithmetic::montgomery::R, limb};

// From http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b,
// specifically http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/doubling/dbl-2001-b.op3
pub(super) fn point_double_assign(ops: &CommonOps, p: &mut Point) {
    let X1 = ops.point_x(&p);
    let Y1 = ops.point_y(&p);
    let Z1 = ops.point_z(&p);

    let delta = ops.elem_squared(&Z1);
    let gamma = ops.elem_squared(&Y1);
    let beta = ops.elem_product(&X1, &gamma);
    let t0 = difference(ops, &X1, &delta);
    let t1 = sum(ops, &X1, &delta);
    let t2 = ops.elem_product(&t0, &t1);
    let alpha = times_3(ops, &t2);
    let t3 = ops.elem_squared(&alpha);
    let t4 = times_8(ops, &beta);
    let X3 = difference(ops, &t3, &t4);
    let t5 = sum(ops, &Y1, &Z1);
    let t6 = ops.elem_squared(&t5);
    let t7 = difference(ops, &t6, &gamma);
    let Z3 = difference(ops, &t7, &delta);
    let t8 = times_4(ops, &beta);
    let t9 = difference(ops, &t8, &X3);
    let t10 = ops.elem_squared(&gamma);
    let t11 = times_8(ops, &t10);
    let t12 = ops.elem_product(&alpha, &t9);
    let Y3 = difference(ops, &t12, &t11);

    *p = ops.new_point(&X3, &Y3, &Z3);
}

fn sum(ops: &CommonOps, a: &Elem<R>, b: &Elem<R>) -> Elem<R> {
    let mut acc = a.clone();
    ops.elem_add(&mut acc, b);
    acc
}
fn difference(ops: &CommonOps, a: &Elem<R>, b: &Elem<R>) -> Elem<R> {
    let mut acc = Elem::zero();
    limb::limbs_sub_mod(
        &mut acc.limbs[..ops.num_limbs],
        &a.limbs[..ops.num_limbs],
        &b.limbs[..ops.num_limbs],
        &ops.q.p[..ops.num_limbs],
    );
    acc
}
fn times_2(ops: &CommonOps, x: &Elem<R>) -> Elem<R> {
    sum(ops, x, x)
}
fn times_3(ops: &CommonOps, x: &Elem<R>) -> Elem<R> {
    let mut acc = times_2(ops, x);
    ops.elem_add(&mut acc, x);
    acc
}
fn times_4(ops: &CommonOps, x: &Elem<R>) -> Elem<R> {
    times_2(ops, &times_2(ops, x))
}

fn times_8(ops: &CommonOps, x: &Elem<R>) -> Elem<R> {
    times_2(ops, &times_4(ops, x))
}

#[cfg(test)]
mod tests {
    use super::{
        super::{p384, tests::point_double_test},
        *,
    };

    #[test]
    fn p384_point_double_test() {
        point_double_test(
            &p384::PRIVATE_KEY_OPS,
            |p| {
                let mut p = p.clone();
                point_double_assign(&p384::COMMON_OPS, &mut p);
                p
            },
            test_file!("p384_point_double_tests.txt"),
        );
    }
}
