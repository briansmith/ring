// Copyright 2016 Brian Smith.
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

//! Elliptic curve operations on P-256 & P-384.


use self::ops::*;


// NIST SP 800-56A Step 3: "If q is an odd prime p, verify that
// yQ**2 = xQ**3 + axQ + b in GF(p), where the arithmetic is performed modulo
// p."
//
// That is, verify that (x, y) is on the curve, which is true iif:
//
//     y**2 == x**3 + a*x + b (mod q)
//
// Or, equivalently, but more efficiently:
//
//     y**2 == (x**2 + a)*x + b  (mod q)
//
fn verify_affine_point_is_on_the_curve(ops: &CommonOps, (x, y): (&Elem, &Elem))
                                       -> Result<(), ()> {
    let lhs = ops.elem_sqr(&y);

    let mut rhs = ops.elem_sqr(&x);
    ops.elem_add(&mut rhs, &ops.a);
    let mut rhs = ops.elem_mul(&rhs, &x);
    ops.elem_add(&mut rhs, &ops.b);

    if !ops.elems_are_equal(&lhs, &rhs) {
        return Err(());
    }

    Ok(())
}


pub mod ecdsa;
pub mod ecdh;

#[macro_use]
#[path = "ops/ops.rs"]
mod ops;

mod private_key;
mod public_key;
