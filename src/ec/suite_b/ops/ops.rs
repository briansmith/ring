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

#![allow(unsafe_code)]

use {bssl, c, der};
use core;
use untrusted;

/// Field elements. Field elements are always Montgomery-encoded and always
/// fully reduced mod q; i.e. their range is [0, q).
pub struct Elem {
    limbs: [Limb; MAX_LIMBS],
}

impl Elem {
    #[inline(always)]
    fn zero() -> Elem {
        Elem { limbs: [0; MAX_LIMBS] }
    }
}

/// Field elements that are *not* Montgomery-encoded. TODO: document range.
pub struct ElemDecoded {
    pub limbs: [Limb; MAX_LIMBS],
}



/// Scalars. Scalars are *not* Montgomery-encoded. They are always
/// fully reduced mod n; i.e. their range is [0, n]. In most contexts,
/// zero-valued scalars are forbidden.
pub struct Scalar {
    pub limbs: [Limb; MAX_LIMBS],
}

impl Scalar {
    #[inline(always)]
    pub fn from_limbs_unchecked(limbs: &[Limb; MAX_LIMBS]) -> Scalar {
        Scalar { limbs: *limbs }
    }
}

/// A `Scalar`, except Montgomery-encoded.
pub struct ScalarMont {
    limbs: [Limb; MAX_LIMBS],
}


pub struct Point {
    // The coordinates are stored in a contiguous array, where the first
    // `ops.num_limbs` elements are the X coordinate, the next
    // `ops.num_limbs` elements are the Y coordinate, and the next
    // `ops.num_limbs` elements are the Z coordinate. This layout is dictated
    // by the requirements of the ecp_nistz256 code.
    xyz: [Limb; 3 * MAX_LIMBS],
}

impl Point {
    pub fn new_at_infinity() -> Point {
        Point { xyz: [0; 3 * MAX_LIMBS] }
    }
}

// Cannot be derived because `xyz` is too large on 32-bit platforms to have a
// built-in implementation of `Clone`.
impl Clone for Point {
    fn clone(&self) -> Self {
        Point { xyz: self.xyz }
    }
}

impl Copy for Point {
}

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")] pub type Limb = u64;
#[cfg(target_pointer_width = "32")] pub type Limb = u32;
#[cfg(target_pointer_width = "64")] pub const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")] pub const LIMB_BITS: usize = 32;

#[cfg(all(target_pointer_width = "32", target_endian = "little"))]
macro_rules! limbs {
    ( $limb_b:expr, $limb_a:expr, $limb_9:expr, $limb_8:expr,
      $limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
      $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr ) => {
        [$limb_0, $limb_1, $limb_2, $limb_3,
         $limb_4, $limb_5, $limb_6, $limb_7,
         $limb_8, $limb_9, $limb_a, $limb_b]
    }
}

#[cfg(all(target_pointer_width = "64", target_endian = "little"))]
macro_rules! limbs {
    ( $limb_b:expr, $limb_a:expr, $limb_9:expr, $limb_8:expr,
      $limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
      $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr ) => {
        [(($limb_1 | 0u64) << 32) | $limb_0,
         (($limb_3 | 0u64) << 32) | $limb_2,
         (($limb_5 | 0u64) << 32) | $limb_4,
         (($limb_7 | 0u64) << 32) | $limb_6,
         (($limb_9 | 0u64) << 32) | $limb_8,
         (($limb_b | 0u64) << 32) | $limb_a]
    }
}

pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;
pub const MAX_LIMBS: usize = (384 + (LIMB_BITS - 1)) / LIMB_BITS;

static ONE: ElemDecoded = ElemDecoded {
    limbs: limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
};


/// Operations and values needed by all curve operations.
pub struct CommonOps {
    pub num_limbs: usize,
    q: Mont,
    pub n: ElemDecoded,

    pub a: Elem, // Must be -3 mod q
    pub b: Elem,

    // In all cases, `r`, `a`, and `b` may all alias each other.
    elem_add_impl: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                    b: *const Limb),
    elem_mul_mont: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                    b: *const Limb),
    elem_sqr_mont: unsafe extern fn(r: *mut Limb, a: *const Limb),

    pub ec_group: &'static EC_GROUP,
}

impl CommonOps {
    #[inline]
    pub fn elem_add(&self, a: &mut Elem, b: &Elem) {
        ab_assign(self.elem_add_impl, &mut a.limbs, &b.limbs)
    }

    pub fn elems_are_equal(&self, a: &Elem, b: &Elem) -> bool {
        for i in 0..self.num_limbs {
            if a.limbs[i] != b.limbs[i] {
                return false;
            }
        }
        return true;
    }

    #[inline]
    pub fn elem_decoded(&self, a: &Elem) -> ElemDecoded {
        self.elem_mul_mixed(a, &ONE)
    }

    #[inline]
    pub fn elem_mul(&self, a: &mut Elem, b: &Elem) {
        ab_assign(self.elem_mul_mont, &mut a.limbs, &b.limbs)
    }

    #[inline]
    pub fn elem_mul_mixed(&self, a: &Elem, b: &ElemDecoded)
                           -> ElemDecoded {
        ElemDecoded { limbs: rab(self.elem_mul_mont, &a.limbs, &b.limbs) }
    }

    #[inline]
    pub fn elem_product(&self, a: &Elem, b: &Elem) -> Elem {
        Elem { limbs: rab(self.elem_mul_mont, &a.limbs, &b.limbs) }
    }

    #[inline]
    pub fn elem_square(&self, a: &mut Elem) {
        a_assign(self.elem_sqr_mont, &mut a.limbs);
    }

    #[inline]
    pub fn elem_squared(&self, a: &Elem) -> Elem {
        Elem { limbs: ra(self.elem_sqr_mont, &a.limbs) }
    }

    pub fn elem_verify_is_not_zero(&self, a: &Elem) -> Result<(), ()> {
        match unsafe {
            GFp_constant_time_limbs_are_zero(a.limbs.as_ptr(), self.num_limbs)
        } {
            0 => Ok(()),
            _ => Err(()),
        }
    }

    pub fn point_x(&self, p: &Point) -> Elem {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[0..self.num_limbs]);
        r
    }

    pub fn point_y(&self, p: &Point) -> Elem {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[self.num_limbs..
                                                         (2 * self.num_limbs)]);
        r
    }

    pub fn point_z(&self, p: &Point) -> Elem {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[(2 * self.num_limbs)..
                                                         (3 * self.num_limbs)]);
        r
    }
}

struct Mont {
    p: [Limb; MAX_LIMBS],
    rr: [Limb; MAX_LIMBS],
}

#[allow(non_camel_case_types)]
pub enum EC_GROUP { }


/// Operations on private keys, for ECDH and ECDSA signing.
pub struct PrivateKeyOps {
    pub common: &'static CommonOps,
    elem_inv: fn(a: &Elem) -> Elem,
    point_mul_base_impl: fn(a: &Scalar) -> Result<Point, ()>,
    point_mul_impl: fn(s: &Scalar, point_x_y: &(Elem, Elem))
                       -> Result<Point, ()>,
}

impl PrivateKeyOps {
    #[inline(always)]
    pub fn point_mul_base(&self, a: &Scalar) -> Result<Point, ()> {
        (self.point_mul_base_impl)(a)
    }

    #[inline(always)]
    pub fn point_mul(&self, s: &Scalar, point_x_y: &(Elem, Elem))
                     -> Result<Point, ()> {
        (self.point_mul_impl)(s, point_x_y)
    }

    #[inline]
    pub fn elem_inverse(&self, a: &Elem) -> Elem {
        (self.elem_inv)(&a)
    }
}


/// Operations and values needed by all operations on public keys (ECDH
/// agreement and ECDSA verification).
pub struct PublicKeyOps {
    pub common: &'static CommonOps,
}

impl PublicKeyOps {
    // The serialized bytes are in big-endian order, zero-padded. The limbs
    // of `Elem` are in the native endianness, least significant limb to
    // most significant limb. Besides the parsing, conversion, this also
    // implements NIST SP 800-56A Step 2: "Verify that xQ and yQ are integers
    // in the interval [0, p-1] in the case that q is an odd prime p[.]"
    pub fn elem_parse(&self, input: &mut untrusted::Reader)
                      -> Result<Elem, ()> {
        let encoded_value =
            try!(input.skip_and_get_input(self.common.num_limbs * LIMB_BYTES));
        let mut elem_limbs =
            try!(parse_big_endian_value_in_range(
                    encoded_value, 0,
                    &self.common.q.p[..self.common.num_limbs]));
        // Montgomery encode (elem_to_mont).
        unsafe {
            (self.common.elem_mul_mont)(elem_limbs.as_mut_ptr(),
                                        elem_limbs.as_ptr(),
                                        self.common.q.rr.as_ptr())
        }
        Ok(Elem { limbs: elem_limbs })
    }
}


/// Operations on public scalars needed by ECDSA signature verification.
pub struct PublicScalarOps {
    pub public_key_ops: &'static PublicKeyOps,
    pub q_minus_n: ElemDecoded,

    scalar_inv_to_mont_impl: unsafe extern fn(r: *mut Limb, a: *const Limb),
    scalar_mul_mont: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                      b: *const Limb),
}

impl PublicScalarOps {
    pub fn scalar_parse(&self, input: &mut untrusted::Reader)
                        -> Result<Scalar, ()> {
        let encoded_value = try!(der::positive_integer(input));
        let limbs = try!(parse_big_endian_value_in_range(
                            encoded_value, 1,
                            &self.public_key_ops.common.n.limbs[
                                ..self.public_key_ops.common.num_limbs]));
        Ok(Scalar { limbs: limbs })
    }

    /// Returns the modular inverse of `a` (mod `n`). `a` must not be zero.
    pub fn scalar_inv_to_mont(&self, a: &Scalar) -> ScalarMont {
        let num_limbs = self.public_key_ops.common.num_limbs;

        // `a` must not be zero.
        assert!(a.limbs[..num_limbs].iter().any(|x| *x != 0));

        let mut r = ScalarMont { limbs: [0; MAX_LIMBS] };
        unsafe {
            (self.scalar_inv_to_mont_impl)(r.limbs.as_mut_ptr(),
                                           a.limbs.as_ptr());
        }
        r
    }

    #[inline]
    pub fn scalar_mul_mixed(&self, a: &Scalar, b: &ScalarMont) -> Scalar {
        Scalar { limbs: rab(self.scalar_mul_mont, &a.limbs, &b.limbs) }
    }

    #[inline]
    pub fn scalar_as_elem_decoded(&self, a: &Scalar) -> ElemDecoded {
        ElemDecoded { limbs: a.limbs }
    }

    pub fn elem_decoded_equals(&self, a: &ElemDecoded, b: &ElemDecoded)
                               -> bool {
        for i in 0..self.public_key_ops.common.num_limbs {
            if a.limbs[i] != b.limbs[i] {
                return false;
            }
        }
        return true;
    }

    pub fn elem_decoded_less_than(&self, a: &ElemDecoded, b: &ElemDecoded)
                                  -> bool {
        let num_limbs = self.public_key_ops.common.num_limbs;
        limbs_less_than_limbs(&a.limbs[..num_limbs], &b.limbs[..num_limbs])
    }

    #[inline]
    pub fn elem_decoded_sum(&self, a: &ElemDecoded, b: &ElemDecoded)
                            -> ElemDecoded {
        ElemDecoded {
            limbs: rab(self.public_key_ops.common.elem_add_impl, &a.limbs,
                       &b.limbs)
        }
    }

    #[inline]
    pub fn elem_mul_mixed(&self, a: &Elem, b: &ElemDecoded) -> ElemDecoded {
        ElemDecoded {
            limbs: rab(self.public_key_ops.common.elem_mul_mont, &a.limbs,
                       &b.limbs)
        }
    }

    pub fn twin_mult(&self, g_scalar: &Scalar, p_scalar: &Scalar,
                     &(ref peer_x, ref peer_y): &(Elem, Elem))
                     -> Result<Point, ()> {
        let mut p = Point::new_at_infinity();
        try!(bssl::map_result(unsafe {
            GFp_suite_b_public_twin_mult(
                self.public_key_ops.common.ec_group, p.xyz.as_mut_ptr(),
                g_scalar.limbs.as_ptr(), p_scalar.limbs.as_ptr(),
                peer_x.limbs.as_ptr(), peer_y.limbs.as_ptr())
        }));
        Ok(p)
    }
}


// Public Keys consist of two fixed-width, big-endian-encoded integers in the
// range [0, q). ECDSA signatures consist of two variable-width,
// big-endian-encoded integers in the range [1, n).
// `parse_big_endian_value_in_range` is the common logic for converting the
// big-endian encoding of bytes into an least-significant-limb-first array of
// native-endian limbs, padded with zeros, and for validating that the value is
// in the given range.
fn parse_big_endian_value_in_range(input: untrusted::Input, min_inclusive: Limb,
                                   max_exclusive: &[Limb])
                                   -> Result<[Limb; MAX_LIMBS], ()> {
    let num_limbs = max_exclusive.len();
    let result = try!(parse_big_endian_value(input, num_limbs));
    if !limbs_less_than_limbs(&result[..num_limbs], max_exclusive) {
        return Err(());
    }
    if result[0] < min_inclusive &&
       result[1..num_limbs].iter().all(|limb| *limb == 0) {
        return Err(());
    }
    Ok(result)
}


// Returns (`a` squared `squarings` times) * `b`.
fn elem_sqr_mul(ops: &CommonOps, a: &Elem, squarings: usize, b: &Elem)
                -> Elem {
    debug_assert!(squarings >= 1);
    let mut tmp = ops.elem_squared(a);
    for _ in 1..squarings {
        ops.elem_square(&mut tmp);
    }
    ops.elem_product(&tmp, &b)
}

// Sets `acc` = (`acc` squared `squarings` times) * `b`.
fn elem_sqr_mul_acc(ops: &CommonOps, acc: &mut Elem, squarings: usize,
                    b: &Elem) {
    debug_assert!(squarings >= 1);
    for _ in 0..squarings {
        ops.elem_square(acc);
    }
    ops.elem_mul(acc, &b)
}


// let r = f(a, b); return r;
#[inline]
fn rab(f: unsafe extern fn(r: *mut Limb, a: *const Limb, b: *const Limb),
       a: &[Limb; MAX_LIMBS], b: &[Limb; MAX_LIMBS]) -> [Limb; MAX_LIMBS] {
    let mut r = [0; MAX_LIMBS];
    unsafe {
        f(r.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
    r
}


// a = f(a, b);
#[inline]
fn a_assign(f: unsafe extern fn(r: *mut Limb, a: *const Limb),
            a: &mut [Limb; MAX_LIMBS]) {
    unsafe {
        f(a.as_mut_ptr(), a.as_ptr())
    }
}

// a = f(a, b);
#[inline]
fn ab_assign(f: unsafe extern fn(r: *mut Limb, a: *const Limb, b: *const Limb),
             a: &mut [Limb; MAX_LIMBS], b: &[Limb; MAX_LIMBS]) {
    unsafe {
        f(a.as_mut_ptr(), a.as_ptr(), b.as_ptr())
    }
}

// let r = f(a); return r;
#[inline]
fn ra(f: unsafe extern fn(r: *mut Limb, a: *const Limb),
      a: &[Limb; MAX_LIMBS]) -> [Limb; MAX_LIMBS] {
    let mut r = [0; MAX_LIMBS];
    unsafe {
        f(r.as_mut_ptr(), a.as_ptr())
    }
    r
}


// `parse_big_endian_value` is the common logic for converting the big-endian
// encoding of bytes into an least-significant-limb-first array of
// native-endian limbs, padded with zeros.
pub fn parse_big_endian_value(input: untrusted::Input, num_limbs: usize)
                              -> Result<[Limb; MAX_LIMBS], ()> {
    if input.len() == 0 {
        return Err(());
    }

    // `bytes_in_current_limb` is the number of bytes in the current limb.
    // It will be `LIMB_BYTES` for all limbs except maybe the highest-order
    // limb.
    let mut bytes_in_current_limb = input.len() % LIMB_BYTES;
    if bytes_in_current_limb == 0 {
        bytes_in_current_limb = LIMB_BYTES;
    }

    let num_encoded_limbs =
        (input.len() / LIMB_BYTES) +
        (if bytes_in_current_limb == LIMB_BYTES { 0 } else { 1 });
    if num_encoded_limbs > num_limbs {
        return Err(());
    }

    input.read_all((), |input| {
        let mut result = [0; MAX_LIMBS];
        for i in 0..num_encoded_limbs {
            let mut limb: Limb = 0;
            for _ in 0..bytes_in_current_limb {
                let b = try!(input.read_byte());
                limb = (limb << 8) | (b as Limb);
            }
            result[num_encoded_limbs - i - 1] = limb;
            bytes_in_current_limb = LIMB_BYTES;
        }
        Ok(result)
    })
}

pub fn limbs_less_than_limbs(a: &[Limb], b: &[Limb]) -> bool {
    assert_eq!(a.len(), b.len());
    let num_limbs = a.len();

    // Verify `min_inclusive <= value < max_exclusive`.
    for i in 0..num_limbs {
        match a[num_limbs - 1 - i].cmp(&b[num_limbs - 1 - i]) {
            core::cmp::Ordering::Less => {
                return true;
            },
            core::cmp::Ordering::Equal => { }, // keep going
            core::cmp::Ordering::Greater => { break; }
        }
    }
    false
}


extern {
    fn GFp_constant_time_limbs_are_zero(a: *const Limb, num_limbs: c::size_t)
                                        -> Limb;

    fn GFp_suite_b_public_twin_mult(group: &EC_GROUP, xyz_out: *mut Limb,
                                    g_scalar: *const Limb,
                                    p_scalar: *const Limb, p_x: *const Limb,
                                    p_y: *const Limb) -> c::int;
}


#[cfg(test)]
mod tests {
    use super::*;
    use untrusted;

    const ZERO_SCALAR: Scalar = Scalar { limbs: [0; MAX_LIMBS] };

    #[test]
    #[should_panic(expected = "a.limbs[..num_limbs].iter().any(|x| *x != 0)")]
    fn p256_scalar_inv_to_mont_zero_panic_test() {
        let _ = p256::PUBLIC_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[cfg(feature = "use_heap")]
    #[test]
    #[should_panic(expected = "a.limbs[..num_limbs].iter().any(|x| *x != 0)")]
    fn p384_scalar_inv_to_mont_zero_panic_test() {
        let _ = p384::PUBLIC_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[test]
    fn parse_big_endian_value_test() {
        // Empty input.
        let inp = untrusted::Input::from(&[]);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS), Err(()));

        // Less than a full limb.
        let inp = [0xfe];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe]));

        // A whole limb for 32-bit, half a limb for 64-bit.
        let inp = [0xbe, 0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0xbeeff00d]));

        // A whole number of limbs (2 for 32-bit, 1 for 64-bit).
        let inp = [0xfe, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0xfeeddead, 0xbeeff00d]));

        // One limb - 1 for 32-bit.
        let inp = [0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0xeff00d]));

        // Two limbs - 1 for 64-bit, four limbs - 1 for 32-bit.
        let inp = [     0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
                   0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0,
                             0x000e0d0c, 0x0b0a0908, 0x07060504, 0x03020100]));

        // One limb + 1 for for 32-bit, half a limb + 1 for 64-bit.
        let inp = [0x4, 0x3, 0x2, 0x1, 0x0];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x03020100]));

        // A whole number of limbs + 1.
        let inp = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00];
        let inp = untrusted::Input::from(&inp);
        let out = limbs![0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0x88, 0x77665544, 0x33221100];
        assert_eq!(parse_big_endian_value(inp, 3), Ok(out));

        // The input is longer than will fit in the given number of limbs.
        assert_eq!(parse_big_endian_value(inp, 2),
                   if cfg!(target_pointer_width = "64") {
                        Ok(out)
                   } else {
                        Err(())
                   });
        assert_eq!(parse_big_endian_value(inp, 1), Err(()));
    }
}


#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::{Limb, MAX_LIMBS};

    pub const LIMBS_1: [Limb; MAX_LIMBS] =
        limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    pub const LIMBS_ALTERNATING_10: [Limb; MAX_LIMBS] =
        limbs![0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010,
               0b10101010_10101010_10101010_10101010];
}

#[cfg(feature = "internal_benches")]
macro_rules! bench_curve {
    ( $vectors:expr ) => {
        use super::super::{Elem, Scalar};
        use bench;

        #[bench]
        fn elem_inverse_bench(bench: &mut bench::Bencher) {
            // This benchmark assumes that the `elem_inverse()` is
            // constant-time so inverting 1 mod q is as good of a choice as
            // anything.
            let mut a = Elem::zero();
            a.limbs[0] = 1;
            bench.iter(|| {
                let _ = PRIVATE_KEY_OPS.elem_inverse(&a);
            });
        }

        #[bench]
        fn elem_product_bench(bench: &mut bench::Bencher) {
            // This benchmark assumes that the multiplication is constant-time
            // so 0 * 0 is as good of a choice as anything.
            let a = Elem::zero();
            let b = Elem::zero();
            bench.iter(|| {
                let _ = COMMON_OPS.elem_product(&a, &b);
            });
        }

        #[bench]
        fn elem_squared_bench(bench: &mut bench::Bencher) {
            // This benchmark assumes that the squaring is constant-time so
            // 0**2 * 0 is as good of a choice as anything.
            let a = Elem::zero();
            bench.iter(|| {
                let _ = COMMON_OPS.elem_squared(&a);
            });
        }

        #[bench]
        fn scalar_inv_to_mont_bench(bench: &mut bench::Bencher) {
            const VECTORS: &'static [Scalar] = $vectors;
            let vectors_len = VECTORS.len();
            let mut i = 0;
            bench.iter(|| {
                let _ = PUBLIC_SCALAR_OPS.scalar_inv_to_mont(&VECTORS[i]);

                i += 1;
                if i == vectors_len {
                    i = 0;
                }
            });
        }
    }
}


pub mod p256;

#[cfg(feature = "use_heap")]
pub mod p384;
