// Copyright 2015-2017 Brian Smith.
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

//! Elliptic curve operations on the birationally equivalent curves Curve25519
//! and Edwards25519.

use {bssl, c, error};

// Keep this in sync with `fe` in curve25519/internal.h.
pub type Elem = [i32; ELEM_LIMBS];
const ELEM_LIMBS: usize = 10;

// An encoding of a curve point. If on Curve25519, it should be encoded as
// described in Section 5 of [RFC 7748]. If on Edwards25519, it should be
// encoded as described in section 5.1.2 of [RFC 8032].
//
// [RFC 7748] https://tools.ietf.org/html/rfc7748#section-5
// [RFC 8032] https://tools.ietf.org/html/rfc8032#section-5.1.2
pub type EncodedPoint = [u8; ELEM_LEN];
pub const ELEM_LEN: usize = 32;

pub type Scalar = [u8; SCALAR_LEN];
pub const SCALAR_LEN: usize = 32;

pub type UnreducedScalar = [u8; UNREDUCED_SCALAR_LEN];
const UNREDUCED_SCALAR_LEN: usize = SCALAR_LEN * 2;

// Keep this in sync with `ge_p3` in curve25519/internal.h.
#[repr(C)]
pub struct ExtPoint {
    x: Elem,
    y: Elem,
    z: Elem,
    t: Elem,
}

impl ExtPoint {
    pub fn new_at_infinity() -> Self {
        ExtPoint {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
            t: [0; ELEM_LIMBS],
        }
    }

    pub fn from_encoded_point_vartime(encoded: &EncodedPoint)
                          -> Result<Self, error::Unspecified> {
        let mut point = Self::new_at_infinity();

        bssl::map_result(unsafe {
            GFp_x25519_ge_frombytes_vartime(&mut point, encoded)
        })?;

        Ok(point)
    }

    pub fn into_encoded_point(self) -> EncodedPoint {
        encode_point(self.x, self.y, self.z)
    }

    pub fn invert_vartime(&mut self) {
        for i in 0..ELEM_LIMBS {
            self.x[i] = -self.x[i];
            self.t[i] = -self.t[i];
        }
    }
}

// Keep this in sync with `ge_p2` in curve25519/internal.h.
#[repr(C)]
pub struct Point {
    x: Elem,
    y: Elem,
    z: Elem,
}

impl Point {
    pub fn new_at_infinity() -> Self {
        Point {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
        }
    }

    pub fn into_encoded_point(self) -> EncodedPoint {
        encode_point(self.x, self.y, self.z)
    }
}

fn encode_point(x: Elem, y: Elem, z: Elem) -> EncodedPoint {
    let mut recip = [0; ELEM_LIMBS];
    let mut x_over_z = [0; ELEM_LIMBS];
    let mut y_over_z = [0; ELEM_LIMBS];
    let mut bytes = [0; ELEM_LEN];

    let sign_bit: u8 = unsafe {
        GFp_fe_invert(&mut recip, &z);
        GFp_fe_mul(&mut x_over_z, &x, &recip);
        GFp_fe_mul(&mut y_over_z, &y, &recip);
        GFp_fe_tobytes(&mut bytes, &y_over_z);
        GFp_fe_isnegative(&x_over_z)
    };

    // The preceding computations must execute in constant time, but this
    // doesn't need to.
    bytes[ELEM_LEN - 1] ^= sign_bit << 7;

    bytes
}

extern {
    fn GFp_fe_invert(out: &mut Elem, z: &Elem);
    fn GFp_fe_isnegative(elem: &Elem) -> u8;
    fn GFp_fe_mul(h: &mut Elem, f: &Elem, g: &Elem);
    fn GFp_fe_tobytes(bytes: &mut EncodedPoint, elem: &Elem);
    fn GFp_x25519_ge_frombytes_vartime(h: &mut ExtPoint, s: &EncodedPoint)
                                       -> c::int;
}
