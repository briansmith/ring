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

        try!(bssl::map_result(unsafe {
            GFp_x25519_ge_frombytes_vartime(&mut point, encoded)
        }));

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

// If the target architecture is non-Windows x86-64, then it is faster to
// compute base point scalar multiplication using the target-optimized general
// scalar multiplication.
#[cfg(all(target_arch = "x86_64", not(windows)))]
pub fn scalar_mult_with_base_point(scalar: &Scalar) -> EncodedPoint {
    let mut point = [0u8; ELEM_LEN];
    unsafe { GFp_x25519_scalar_mult(&mut point, scalar, &BASE_POINT); }
    point
}

// If the target architecture is NEON-capable ARM, then it is faster to compute
// base point scalar multiplication using the target-optimized general scalar
// multiplication. Otherwise, if NEON is not available, we fall back on the
// architecture-generic base point multiplication.
#[cfg(target_arch = "arm")]
pub fn scalar_mult_with_base_point(scalar: &Scalar) -> EncodedPoint {
    if is_neon_capable() {
        let mut point = [0u8; ELEM_LEN];

        // We could use `GFp_x25519_scalar_mult()` here, instead. When compiled
        // for ARM, that function performs the same NEON capability check we
        // just did, then calls the following function when it succeeds. Since
        // we already know we're in a branch where it is appropriate, we can
        // skip the extra check and call the NEON-optimized implementation.
        unsafe { GFp_x25519_NEON(&mut point, scalar, &BASE_POINT); }

        return point;
    }

    scalar_mult_with_base_point_generic(scalar)
}

#[cfg(any(all(target_arch = "x86_64", not(windows)), target_arch = "arm"))]
static BASE_POINT: EncodedPoint = [
    9, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];

#[cfg(not(any(all(target_arch = "x86_64", not(windows)), target_arch = "arm")))]
pub fn scalar_mult_with_base_point(scalar: &Scalar) -> EncodedPoint {
    scalar_mult_with_base_point_generic(scalar)
}

#[cfg(not(all(target_arch = "x86_64", not(windows))))]
fn scalar_mult_with_base_point_generic(scalar: &Scalar) -> EncodedPoint {
    let mut point = ExtPoint::new_at_infinity();

    unsafe { GFp_x25519_ge_scalarmult_base(&mut point, scalar); }

    let mut z_plus_y = [0i32; ELEM_LIMBS];
    let mut z_minus_y = [0i32; ELEM_LIMBS];
    let mut z_minus_y_inv = [0i32; ELEM_LIMBS];
    let mut u_coord = [0i32; ELEM_LIMBS];
    unsafe {
        GFp_fe_add(&mut z_plus_y, &point.z, &point.y);
        GFp_fe_sub(&mut z_minus_y, &point.z, &point.y);
        GFp_fe_invert(&mut z_minus_y_inv, &z_minus_y);
        GFp_fe_mul(&mut u_coord, &z_plus_y, &z_minus_y_inv);
    }

    let mut encoded_point = [0u8; ELEM_LEN];
    unsafe { GFp_fe_tobytes(&mut encoded_point, &u_coord); }

    encoded_point
}

#[cfg(target_arch = "arm")]
fn is_neon_capable() -> bool {
    unsafe { GFp_is_NEON_capable_at_runtime() == 1 }
}

extern {
    fn GFp_fe_invert(out: &mut Elem, z: &Elem);
    fn GFp_fe_isnegative(elem: &Elem) -> u8;
    fn GFp_fe_mul(h: &mut Elem, f: &Elem, g: &Elem);
    fn GFp_fe_tobytes(bytes: &mut EncodedPoint, elem: &Elem);
    fn GFp_x25519_ge_frombytes_vartime(h: &mut ExtPoint, s: &EncodedPoint)
                                       -> c::int;
}

// Externs needed for the generic base point multiplication impl.
#[cfg(not(all(target_arch = "x86_64", not(windows))))]
extern {
    fn GFp_fe_add(out: &mut Elem, f: &Elem, g: &Elem);
    fn GFp_fe_sub(out: &mut Elem, f: &Elem, g: &Elem);
    fn GFp_x25519_ge_scalarmult_base(point: &mut ExtPoint, scalar: &Scalar);
}

#[cfg(target_arch = "arm")]
extern {
    fn GFp_is_NEON_capable_at_runtime() -> u8;
    fn GFp_x25519_NEON(out: &mut EncodedPoint, scalar: &Scalar,
                       point: &EncodedPoint);
}

#[cfg(all(target_arch = "x86_64", not(windows)))]
extern {
    fn GFp_x25519_scalar_mult(out: &mut EncodedPoint, scalar: &Scalar,
                              point: &EncodedPoint);
}
