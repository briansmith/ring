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

use arithmetic::montgomery::*;
use core::marker::PhantomData;
use {der, error, limb};
use untrusted;

pub use limb::*; // XXX
pub use self::elem::*; // XXX

/// A field element, i.e. an element of ℤ/qℤ for the curve's field modulus
/// *q*.
pub type Elem<E> = elem::Elem<Q, E>;

/// Represents the (prime) order *q* of the curve's prime field.
#[derive(Clone, Copy)]
pub enum Q {}

/// A scalar that is not Montgomery-encoded. Its value is in [0, n). Zero-valued
/// scalars are forbidden in most contexts.
pub type Scalar = elem::Elem<N, Unencoded>;

/// Represents the prime order *n* of the curve's group.
pub enum N {}

impl Scalar {
    #[inline(always)]
    pub fn from_limbs_unchecked(limbs: &[Limb; MAX_LIMBS]) -> Scalar {
        Scalar {
            limbs: *limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }
}

/// A Scalar that is Montgomery-encoded and not reduced. Its value is in
/// [0, 2**`LIMB_BITS`).
#[derive(Clone, Copy)]
pub struct ScalarMont {
    limbs: [Limb; MAX_LIMBS],
}


pub struct Point {
    // The coordinates are stored in a contiguous array, where the first
    // `ops.num_limbs` elements are the X coordinate, the next
    // `ops.num_limbs` elements are the Y coordinate, and the next
    // `ops.num_limbs` elements are the Z coordinate. This layout is dictated
    // by the requirements of the GFp_nistz256 code.
    xyz: [Limb; 3 * MAX_LIMBS],
}

impl Point {
    pub fn new_at_infinity() -> Point { Point { xyz: [0; 3 * MAX_LIMBS] } }
}

// Cannot be derived because `xyz` is too large on 32-bit platforms to have a
// built-in implementation of `Clone`.
impl Clone for Point {
    fn clone(&self) -> Self { Point { xyz: self.xyz } }
}

impl Copy for Point {}

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

static ONE: Elem<Unencoded> = Elem {
    limbs: limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    m: PhantomData,
    encoding: PhantomData,
};


/// Operations and values needed by all curve operations.
pub struct CommonOps {
    pub num_limbs: usize,
    q: Mont,
    pub n: Elem<Unencoded>,

    pub a: Elem<R>, // Must be -3 mod q
    pub b: Elem<R>,

    // In all cases, `r`, `a`, and `b` may all alias each other.
    elem_add_impl: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                    b: *const Limb),
    elem_mul_mont: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                    b: *const Limb),
    elem_sqr_mont: unsafe extern fn(r: *mut Limb, a: *const Limb),

    #[cfg_attr(not(test), allow(dead_code))]
    point_add_jacobian_impl: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                              b: *const Limb),
}

impl CommonOps {
    #[inline]
    pub fn elem_add(&self, a: &mut Elem<R>, b: &Elem<R>) {
        ab_assign(self.elem_add_impl, &mut a.limbs, &b.limbs)
    }

    pub fn elems_are_equal(&self, a: &Elem<R>, b: &Elem<R>) -> bool {
        for i in 0..self.num_limbs {
            if a.limbs[i] != b.limbs[i] {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn elem_decoded(&self, a: &Elem<R>) -> Elem<Unencoded> {
        self.elem_mul_mixed(a, &ONE)
    }

    #[inline]
    pub fn elem_mul(&self, a: &mut Elem<R>, b: &Elem<R>) {
        ab_assign(self.elem_mul_mont, &mut a.limbs, &b.limbs)
    }

    #[inline]
    pub fn elem_mul_mixed(&self, a: &Elem<R>, b: &Elem<Unencoded>)
                          -> Elem<Unencoded> {
        let unreduced = rab(self.elem_mul_mont, &a.limbs, &b.limbs);
        Elem {
            limbs: self.reduced_limbs(&unreduced, &self.q.p),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    #[inline]
    pub fn elem_product(&self, a: &Elem<R>, b: &Elem<R>) -> Elem<R> {
        Elem {
            limbs: rab(self.elem_mul_mont, &a.limbs, &b.limbs),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    #[inline]
    pub fn elem_reduced(&self, a: &Elem<R>) -> Elem<R> {
        Elem {
            limbs: self.reduced_limbs(&a.limbs, &self.q.p),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    #[inline]
    pub fn elem_square(&self, a: &mut Elem<R>) {
        a_assign(self.elem_sqr_mont, &mut a.limbs);
    }

    #[inline]
    pub fn elem_squared(&self, a: &Elem<R>) -> Elem<R> {
        Elem {
            limbs: ra(self.elem_sqr_mont, &a.limbs),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn elem_verify_is_not_zero(&self, a: &Elem<R>)
                                   -> Result<(), error::Unspecified> {
        match limbs_are_zero_constant_time(&a.limbs[..self.num_limbs]) {
            LimbMask::False => Ok(()),
            _ => Err(error::Unspecified),
        }
    }

    pub fn point_sum(&self, a: &Point, b: &Point) -> Point {
        let mut r = Point::new_at_infinity();
        unsafe {
            (self.point_add_jacobian_impl)(r.xyz.as_mut_ptr(), a.xyz.as_ptr(),
                                           b.xyz.as_ptr())
        }
        r
    }

    pub fn point_x(&self, p: &Point) -> Elem<R> {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[0..self.num_limbs]);
        r
    }

    pub fn point_y(&self, p: &Point) -> Elem<R> {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[self.num_limbs..
                                                         (2 * self.num_limbs)]);
        r
    }

    pub fn point_z(&self, p: &Point) -> Elem<R> {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[(2 * self.num_limbs)..
                                                         (3 * self.num_limbs)]);
        r
    }

    // This assumes
    // 2**((self.num_limbs * LIMB_BITS) - 1) < p and
    // p < 2**(self.num_limbs * LIMB_BITS) and `p` is prime. See
    // "Efficient Software Implementations of Modular Exponentiation" by Shay
    // Gueron for the details. This is the case for both the field order and
    // group order for both P-256 and P-384, but it is not the case for all
    // curves. For example, it is not true for P-521.
    fn reduced_limbs(&self, a: &[Limb; MAX_LIMBS], p: &[Limb; MAX_LIMBS])
                     -> [Limb; MAX_LIMBS] {
        let mut r = *a;
        limbs_reduce_once_constant_time(&mut r, p);
        r
    }
}

struct Mont {
    p: [Limb; MAX_LIMBS],
    rr: [Limb; MAX_LIMBS],
}


/// Operations on private keys, for ECDH and ECDSA signing.
pub struct PrivateKeyOps {
    pub common: &'static CommonOps,
    elem_inv: fn(a: &Elem<R>) -> Elem<R>,
    point_mul_base_impl: fn(a: &Scalar) -> Point,
    point_mul_impl: unsafe extern fn(r: *mut Limb/*[3][num_limbs]*/,
                                     p_scalar: *const Limb/*[num_limbs]*/,
                                     p_x: *const Limb/*[num_limbs]*/,
                                     p_y: *const Limb/*[num_limbs]*/),
}

impl PrivateKeyOps {
    #[inline(always)]
    pub fn point_mul_base(&self, a: &Scalar) -> Point {
        (self.point_mul_base_impl)(a)
    }

    #[inline(always)]
    pub fn point_mul(&self, p_scalar: &Scalar,
                     &(ref p_x, ref p_y): &(Elem<R>, Elem<R>)) -> Point {
        let mut r = Point::new_at_infinity();
        unsafe {
            (self.point_mul_impl)(r.xyz.as_mut_ptr(), p_scalar.limbs.as_ptr(),
                                  p_x.limbs.as_ptr(), p_y.limbs.as_ptr());
        }
        r
    }

    #[inline]
    pub fn elem_inverse(&self, a: &Elem<R>) -> Elem<R> {
        (self.elem_inv)(a)
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
                      -> Result<Elem<R>, error::Unspecified> {
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
        Ok(Elem {
            limbs: elem_limbs,
            m: PhantomData,
            encoding: PhantomData
        })
    }
}


/// Operations on public scalars needed by ECDSA signature verification.
pub struct PublicScalarOps {
    pub public_key_ops: &'static PublicKeyOps,

    // XXX: `PublicScalarOps` shouldn't depend on `PrivateKeyOps`, but it does
    // temporarily until `twin_mul` is rewritten.
    pub private_key_ops: &'static PrivateKeyOps,

    pub q_minus_n: Elem<Unencoded>,

    scalar_inv_to_mont_impl: fn(a: &Scalar) -> ScalarMont,
    scalar_mul_mont: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                      b: *const Limb),
}

impl PublicScalarOps {
    pub fn scalar_parse(&self, input: &mut untrusted::Reader)
                        -> Result<Scalar, error::Unspecified> {
        let encoded_value = try!(der::positive_integer(input));
        let limbs = try!(parse_big_endian_value_in_range(
                            encoded_value, 1,
                            &self.public_key_ops.common.n.limbs[
                                ..self.public_key_ops.common.num_limbs]));
        Ok(Scalar {
            limbs: limbs,
            m: PhantomData,
            encoding: PhantomData,
        })
    }

    // See the documentation for `reduced_limbs()` for the limitations of this
    // function.
    pub fn scalar_from_unreduced_limbs(&self, unreduced: &[Limb; MAX_LIMBS])
                                       -> Scalar {
        let cops = self.public_key_ops.common;
        Scalar {
            limbs: cops.reduced_limbs(unreduced, &cops.n.limbs),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    /// Returns the modular inverse of `a` (mod `n`). `a` must not be zero.
    pub fn scalar_inv_to_mont(&self, a: &Scalar) -> ScalarMont {
        let num_limbs = self.public_key_ops.common.num_limbs;

        // `a` must not be zero.
        assert!(a.limbs[..num_limbs].iter().any(|x| *x != 0));

        (self.scalar_inv_to_mont_impl)(a)
    }

    #[inline]
    pub fn scalar_mul_mixed(&self, a: &Scalar, b: &ScalarMont) -> Scalar {
        let unreduced = rab(self.scalar_mul_mont, &a.limbs, &b.limbs);
        self.scalar_from_unreduced_limbs(&unreduced)
    }

    #[inline]
    pub fn scalar_as_elem_decoded(&self, a: &Scalar) -> Elem<Unencoded> {
        Elem {
            limbs: a.limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn elem_decoded_equals(&self, a: &Elem<Unencoded>, b: &Elem<Unencoded>)
                               -> bool {
        for i in 0..self.public_key_ops.common.num_limbs {
            if a.limbs[i] != b.limbs[i] {
                return false;
            }
        }
        true
    }

    pub fn elem_decoded_less_than(&self, a: &Elem<Unencoded>, b: &Elem<Unencoded>)
                                  -> bool {
        let num_limbs = self.public_key_ops.common.num_limbs;
        limb::limbs_less_than_limbs_vartime(&a.limbs[..num_limbs],
                                            &b.limbs[..num_limbs])
    }

    #[inline]
    pub fn elem_decoded_sum(&self, a: &Elem<Unencoded>, b: &Elem<Unencoded>)
                            -> Elem<Unencoded> {
        Elem {
            limbs: rab(self.public_key_ops.common.elem_add_impl, &a.limbs,
                       &b.limbs),
            m: PhantomData,
            encoding: PhantomData,
        }
    }
}


// Public Keys consist of two fixed-width, big-endian-encoded integers in the
// range [0, q). ECDSA signatures consist of two variable-width,
// big-endian-encoded integers in the range [1, n).
// `parse_big_endian_value_in_range` is the common logic for converting the
// big-endian encoding of bytes into an least-significant-limb-first array of
// native-endian limbs, padded with zeros, and for validating that the value is
// in the given range.
fn parse_big_endian_value_in_range(
        input: untrusted::Input, min_inclusive: Limb, max_exclusive: &[Limb])
        -> Result<[Limb; MAX_LIMBS], error::Unspecified> {
    let mut result = [0; MAX_LIMBS];
    try!(limb::parse_big_endian_in_range_and_pad(
            input, min_inclusive, max_exclusive,
            &mut result[..max_exclusive.len()]));
    Ok(result)
}


// Returns (`a` squared `squarings` times) * `b`.
fn elem_sqr_mul(ops: &CommonOps, a: &Elem<R>, squarings: usize, b: &Elem<R>)
                -> Elem<R> {
    debug_assert!(squarings >= 1);
    let mut tmp = ops.elem_squared(a);
    for _ in 1..squarings {
        ops.elem_square(&mut tmp);
    }
    ops.elem_product(&tmp, b)
}

// Sets `acc` = (`acc` squared `squarings` times) * `b`.
fn elem_sqr_mul_acc(ops: &CommonOps, acc: &mut Elem<R>, squarings: usize,
                    b: &Elem<R>) {
    debug_assert!(squarings >= 1);
    for _ in 0..squarings {
        ops.elem_square(acc);
    }
    ops.elem_mul(acc, b)
}


// let r = f(a, b); return r;
#[inline]
fn rab(f: unsafe extern fn(r: *mut Limb, a: *const Limb, b: *const Limb),
       a: &[Limb; MAX_LIMBS], b: &[Limb; MAX_LIMBS]) -> [Limb; MAX_LIMBS] {
    let mut r = [0; MAX_LIMBS];
    unsafe { f(r.as_mut_ptr(), a.as_ptr(), b.as_ptr()) }
    r
}


// a = f(a, b);
#[inline]
fn a_assign(f: unsafe extern fn(r: *mut Limb, a: *const Limb),
            a: &mut [Limb; MAX_LIMBS]) {
    unsafe { f(a.as_mut_ptr(), a.as_ptr()) }
}

// a = f(a, b);
#[inline]
fn ab_assign(f: unsafe extern fn(r: *mut Limb, a: *const Limb, b: *const Limb),
             a: &mut [Limb; MAX_LIMBS], b: &[Limb; MAX_LIMBS]) {
    unsafe { f(a.as_mut_ptr(), a.as_ptr(), b.as_ptr()) }
}

// let r = f(a); return r;
#[inline]
fn ra(f: unsafe extern fn(r: *mut Limb, a: *const Limb), a: &[Limb; MAX_LIMBS])
      -> [Limb; MAX_LIMBS] {
    let mut r = [0; MAX_LIMBS];
    unsafe { f(r.as_mut_ptr(), a.as_ptr()) }
    r
}


// `parse_big_endian_value` is the common logic for converting the big-endian
// encoding of bytes into an least-significant-limb-first array of
// native-endian limbs, padded with zeros.
pub fn parse_big_endian_value(input: untrusted::Input, num_limbs: usize)
                              -> Result<[Limb; MAX_LIMBS], error::Unspecified> {
    let mut result = [0; MAX_LIMBS];
    try!(limb::parse_big_endian_and_pad(input, &mut result[..num_limbs]));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use {error, test};
    use std;
    use super::*;
    use super::parse_big_endian_value_in_range;
    use untrusted;

    #[test]
    fn p256_elem_reduced_test() { test_elem_reduced(&p256::COMMON_OPS); }

    #[test]
    fn p384_elem_reduced_test() { test_elem_reduced(&p384::COMMON_OPS); }

    fn test_elem_reduced(ops: &CommonOps) {
        let zero = Elem::zero();

        let reduced = ops.elem_reduced(&zero);
        assert_eq!(reduced.limbs, zero.limbs);

        let mut one = Elem::zero();
        one.limbs[0] = 1;

        let reduced = ops.elem_reduced(&one);
        assert_eq!(reduced.limbs, one.limbs);

        let q = Elem {
            limbs: ops.q.p,
            m: PhantomData,
            encoding: PhantomData,
        };
        let reduced = ops.elem_reduced(&q);
        assert_eq!(reduced.limbs, zero.limbs);

        let mut q_minus_1 = Elem {
            limbs: ops.q.p,
            m: PhantomData,
            encoding: PhantomData,
        };
        q_minus_1.limbs[0] -= 1;
        let reduced = ops.elem_reduced(&q_minus_1);
        assert_eq!(reduced.limbs, q_minus_1.limbs);

        let mut q_plus_1 = Elem {
            limbs: ops.q.p,
            m: PhantomData,
            encoding: PhantomData,
        };
        // Add one to it, dealing with the fact that the lower limb(s) are
        // 0xfff...ff. We can't use `elem_add` because at least the P-384
        // implementation would do the reduction itself.
        for i in 0..ops.num_limbs {
            q_plus_1.limbs[i] = q_plus_1.limbs[i].wrapping_add(1);
            if q_plus_1.limbs[i] != 0 {
                break;
            }
        }
        assert!(reduced.limbs != q.limbs); // Sanity check the math we did.
        assert!(reduced.limbs != one.limbs); // Sanity check the math we did.
        let reduced = ops.elem_reduced(&q_plus_1);
        assert_eq!(reduced.limbs, one.limbs);
    }

    const ZERO_SCALAR: Scalar = Scalar {
        limbs: [0; MAX_LIMBS],
        m: PhantomData,
        encoding: PhantomData,
    };

    #[test]
    fn p256_elem_add_test() {
        elem_add_test(&p256::PUBLIC_SCALAR_OPS,
                      "src/ec/suite_b/ops/p256_elem_sum_tests.txt");
    }

    #[test]
    fn p384_elem_add_test() {
        elem_add_test(&p384::PUBLIC_SCALAR_OPS,
                      "src/ec/suite_b/ops/p384_elem_sum_tests.txt");
    }

    fn elem_add_test(ops: &PublicScalarOps, file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");

            let cops = ops.public_key_ops.common;
            let a = consume_elem(cops, test_case, "a");
            let b = consume_elem(cops, test_case, "b");
            let expected_sum = consume_elem(cops, test_case, "r");

            let mut actual_sum = a.clone();
            ops.public_key_ops.common.elem_add(&mut actual_sum, &b);
            assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

            let mut actual_sum = b.clone();
            ops.public_key_ops.common.elem_add(&mut actual_sum, &a);
            assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

            Ok(())
        })
    }

    // XXX: There's no `GFp_nistz256_sub` in *ring*; it's logic is inlined into
    // the point arithmetic functions. Thus, we can't test it.

    #[test]
    fn p384_elem_sub_test() {
        extern {
            fn GFp_p384_elem_sub(r: *mut Limb, a: *const Limb, b: *const Limb);
        }
        elem_sub_test(&p384::COMMON_OPS, GFp_p384_elem_sub,
                      "src/ec/suite_b/ops/p384_elem_sum_tests.txt");
    }

    fn elem_sub_test(ops: &CommonOps,
                     elem_sub: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                                b: *const Limb),
                       file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let b = consume_elem(ops, test_case, "b");
            let r = consume_elem(ops, test_case, "r");

            let mut actual_difference = Elem::<R>::zero();
            unsafe {
                elem_sub(actual_difference.limbs.as_mut_ptr(),
                         r.limbs.as_ptr(), b.limbs.as_ptr());
            }
            assert_limbs_are_equal(ops, &actual_difference.limbs, &a.limbs);

            let mut actual_difference = Elem::<R>::zero();
            unsafe {
                elem_sub(actual_difference.limbs.as_mut_ptr(),
                         r.limbs.as_ptr(), a.limbs.as_ptr());
            }
            assert_limbs_are_equal(ops, &actual_difference.limbs, &b.limbs);

            Ok(())
        })
    }

    // XXX: There's no `GFp_nistz256_div_by_2` in *ring*; it's logic is inlined
    // into the point arithmetic functions. Thus, we can't test it.

    #[test]
    fn p384_elem_div_by_2_test() {
        extern {
            fn GFp_p384_elem_div_by_2(r: *mut Limb, a: *const Limb);
        }
        elem_div_by_2_test(&p384::COMMON_OPS, GFp_p384_elem_div_by_2,
                           "src/ec/suite_b/ops/p384_elem_div_by_2_tests.txt");
    }

    fn elem_div_by_2_test(ops: &CommonOps,
                          elem_div_by_2: unsafe extern fn(r: *mut Limb,
                                                          a: *const Limb),
                     file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let r = consume_elem(ops, test_case, "r");

            let mut actual_result = Elem::<R>::zero();
            unsafe {
                elem_div_by_2(actual_result.limbs.as_mut_ptr(),
                              a.limbs.as_ptr());
            }
            assert_limbs_are_equal(ops, &actual_result.limbs, &r.limbs);

            Ok(())
        })
    }

    // TODO: Add test vectors that test the range of values above `q`.
    #[test]
    fn p256_elem_neg_test() {
        extern {
            fn GFp_nistz256_neg(r: *mut Limb, a: *const Limb);
        }
        elem_neg_test(&p256::COMMON_OPS, GFp_nistz256_neg,
                      "src/ec/suite_b/ops/p256_elem_neg_tests.txt");
    }

    #[test]
    fn p384_elem_neg_test() {
        extern {
            fn GFp_p384_elem_neg(r: *mut Limb, a: *const Limb);
        }
        elem_neg_test(&p384::COMMON_OPS, GFp_p384_elem_neg,
                      "src/ec/suite_b/ops/p384_elem_neg_tests.txt");
    }

    fn elem_neg_test(ops: &CommonOps,
                     elem_neg: unsafe extern fn(r: *mut Limb, a: *const Limb),
                     file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let r = consume_elem(ops, test_case, "r");

            let mut actual_result = Elem::<R>::zero();
            unsafe {
                elem_neg(actual_result.limbs.as_mut_ptr(), a.limbs.as_ptr());
            }
            assert_limbs_are_equal(ops, &actual_result.limbs, &r.limbs);

            // We would test that the -r == a here, but because the P-256 uses
            // almost-Montgomery reduction, and because -0 == 0. we can't.
            // Instead, unlike the other input files, the input files for this
            // test contain the inverse test vectors explicitly.

            Ok(())
        })
    }

    #[test]
    #[should_panic(expected = "a.limbs[..num_limbs].iter().any(|x| *x != 0)")]
    fn p256_scalar_inv_to_mont_zero_panic_test() {
        let _ = p256::PUBLIC_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[test]
    #[should_panic(expected = "a.limbs[..num_limbs].iter().any(|x| *x != 0)")]
    fn p384_scalar_inv_to_mont_zero_panic_test() {
        let _ = p384::PUBLIC_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[test]
    fn parse_big_endian_value_test() {
        // Empty input.
        let inp = untrusted::Input::from(&[]);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Err(error::Unspecified));

        // Less than a full limb.
        let inp = [0xfe];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe]));

        // A whole limb for 32-bit, half a limb for 64-bit.
        let inp = [0xbe, 0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbeeff00d]));

        // A whole number of limbs (2 for 32-bit, 1 for 64-bit).
        let inp = [0xfe, 0xed, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfeeddead,
                             0xbeeff00d]));

        // One limb - 1 for 32-bit.
        let inp = [0xef, 0xf0, 0x0d];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xeff00d]));

        // Two limbs - 1 for 64-bit, four limbs - 1 for 32-bit.
        let inp = [     0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8,
                   0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0x000e0d0c, 0x0b0a0908,
                             0x07060504, 0x03020100]));

        // One limb + 1 for for 32-bit, half a limb + 1 for 64-bit.
        let inp = [0x4, 0x3, 0x2, 0x1, 0x0];
        let inp = untrusted::Input::from(&inp);
        assert_eq!(parse_big_endian_value(inp, MAX_LIMBS),
                   Ok(limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x03020100]));

        // A whole number of limbs + 1.
        let inp = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00];
        let inp = untrusted::Input::from(&inp);
        let out = limbs![0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x77665544,
                         0x33221100];
        assert_eq!(parse_big_endian_value(inp, 3), Ok(out));

        // The input is longer than will fit in the given number of limbs.
        assert_eq!(parse_big_endian_value(inp, 2),
                   if cfg!(target_pointer_width = "64") {
                       Ok(out)
                   } else {
                       Err(error::Unspecified)
                   });
        assert_eq!(parse_big_endian_value(inp, 1), Err(error::Unspecified));
    }

    #[test]
    fn p256_point_sum_test() {
        point_sum_test(&p256::PRIVATE_KEY_OPS,
                       "src/ec/suite_b/ops/p256_point_sum_tests.txt");
    }

    #[test]
    fn p384_point_sum_test() {
        point_sum_test(&p384::PRIVATE_KEY_OPS,
                       "src/ec/suite_b/ops/p384_point_sum_tests.txt");
    }

    fn point_sum_test(ops: &PrivateKeyOps, file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_jacobian_point(ops, test_case, "a");
            let b = consume_jacobian_point(ops, test_case, "b");
            let r_expected = consume_point(ops, test_case, "r");

            let r_actual = ops.common.point_sum(&a, &b);
            assert_point_actual_equals_expected(ops, &r_actual, &r_expected);

            Ok(())
        });
    }

    #[test]
    fn p256_point_mul_test() {
        point_mul_tests(&p256::PRIVATE_KEY_OPS,
                        "src/ec/suite_b/ops/p256_point_mul_tests.txt");
    }

    #[test]
    fn p384_point_mul_test() {
        point_mul_tests(&p384::PRIVATE_KEY_OPS,
                        "src/ec/suite_b/ops/p384_point_mul_tests.txt");
    }

    fn point_mul_tests(ops: &PrivateKeyOps, file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");
            let p_scalar = consume_scalar(ops.common, test_case, "p_scalar");
            let (x, y) = match consume_point(ops, test_case, "p") {
                TestPoint::Infinity => {
                    panic!("can't be inf.");
                },
                TestPoint::Affine(x, y) => (x, y),
            };
            let expected_result = consume_point(ops, test_case, "r");
            let actual_result = ops.point_mul(&p_scalar, &(x, y));
            assert_point_actual_equals_expected(ops, &actual_result,
                                                &expected_result);
            Ok(())
        })
    }

    #[test]
    fn p256_point_mul_base_test() {
        point_mul_base_tests(&p256::PRIVATE_KEY_OPS,
                             "src/ec/suite_b/ops/p256_point_mul_base_tests.txt");
    }

    #[test]
    fn p384_point_mul_base_test() {
        point_mul_base_tests(&p384::PRIVATE_KEY_OPS,
                             "src/ec/suite_b/ops/p384_point_mul_base_tests.txt");
    }

    fn point_mul_base_tests(ops: &PrivateKeyOps, file_path: &str) {
        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");
            let g_scalar = consume_scalar(ops.common, test_case, "g_scalar");
            let expected_result = consume_point(ops, test_case, "r");
            let actual_result = ops.point_mul_base(&g_scalar);
            assert_point_actual_equals_expected(ops, &actual_result,
                                                &expected_result);
            Ok(())
        })
    }

    fn assert_point_actual_equals_expected(ops: &PrivateKeyOps,
                                           actual_point: &Point,
                                           expected_point: &TestPoint) {
        let cops = ops.common;
        let actual_x = &cops.point_x(&actual_point);
        let actual_y = &cops.point_y(&actual_point);
        let actual_z = &cops.point_z(&actual_point);
        match expected_point {
            &TestPoint::Infinity => {
                let zero = Elem::zero();
                assert!(cops.elems_are_equal(&cops.elem_reduced(&actual_x),
                                             &zero));
                assert!(cops.elems_are_equal(&cops.elem_reduced(&actual_y),
                                             &zero));
                assert!(cops.elems_are_equal(&cops.elem_reduced(&actual_z),
                                             &zero));
            },
            &TestPoint::Affine(ref expected_x, ref expected_y) => {
                let z_inv = ops.elem_inverse(&actual_z);
                let zz_inv = cops.elem_squared(&z_inv);
                let x_aff =
                    cops.elem_reduced(&cops.elem_product(&actual_x, &zz_inv));
                let zzz_inv = cops.elem_product(&z_inv, &zz_inv);
                let y_aff =
                    cops.elem_reduced(&cops.elem_product(&actual_y, &zzz_inv));
                assert!(cops.elems_are_equal(&x_aff, &expected_x));
                assert!(cops.elems_are_equal(&y_aff, &expected_y));
            },
        }
    }

    fn consume_jacobian_point(ops: &PrivateKeyOps,
                              test_case: &mut test::TestCase, name: &str)
                              -> Point {
        fn consume_point_elem(ops: &CommonOps, p: &mut Point,
                              elems: &std::vec::Vec<&str>, i: usize) {
            let bytes = test::from_hex(elems[i]).unwrap();
            let bytes = untrusted::Input::from(&bytes);
            let limbs =
                parse_big_endian_value_in_range(
                    bytes, 0, &ops.q.p[..ops.num_limbs]).unwrap();
            p.xyz[(i * ops.num_limbs)..((i + 1) * ops.num_limbs)]
                .copy_from_slice(&limbs[..ops.num_limbs]);
        }

        let input = test_case.consume_string(name);
        let elems = input.split(", ").collect::<std::vec::Vec<&str>>();
        assert_eq!(elems.len(), 3);
        let mut p = Point::new_at_infinity();
        consume_point_elem(ops.common, &mut p, &elems, 0);
        consume_point_elem(ops.common, &mut p, &elems, 1);
        consume_point_elem(ops.common, &mut p, &elems, 2);
        p
    }

    enum TestPoint {
        Infinity,
        Affine(Elem<R>, Elem<R>),
    }

    fn consume_point(ops: &PrivateKeyOps, test_case: &mut test::TestCase,
                     name: &str) -> TestPoint {
        fn consume_point_elem(ops: &CommonOps, elems: &std::vec::Vec<&str>,
                              i: usize) -> Elem<R> {
            let bytes = test::from_hex(elems[i]).unwrap();
            let bytes = untrusted::Input::from(&bytes);
            Elem {
                limbs:
                    parse_big_endian_value_in_range(
                        bytes, 0, &ops.q.p[..ops.num_limbs]).unwrap(),
                m: PhantomData,
                encoding: PhantomData,
            }
        }

        let input = test_case.consume_string(name);
        if input == "inf" {
            return TestPoint::Infinity;
        }
        let elems = input.split(", ").collect::<std::vec::Vec<&str>>();
        assert_eq!(elems.len(), 2);
        let x = consume_point_elem(ops.common, &elems, 0);
        let y = consume_point_elem(ops.common, &elems, 1);
        TestPoint::Affine(x, y)
    }

    fn assert_limbs_are_equal(ops: &CommonOps, actual: &[Limb; MAX_LIMBS],
                              expected: &[Limb; MAX_LIMBS]) {
        for i in 0..ops.num_limbs {
            if actual[i] != expected[i] {
                let mut s = std::string::String::new();
                for j in 0..ops.num_limbs {
                    let formatted = format!("{:016x}",
                                            actual[ops.num_limbs - j - 1]);
                    s.push_str(&formatted);
                }
                print!("\n");
                panic!("Actual != Expected,\nActual = {}", s);
            }
        }
    }

    fn consume_elem(ops: &CommonOps, test_case: &mut test::TestCase,
                    name: &str) -> Elem<R> {
        let bytes = test_case.consume_bytes(name);
        let bytes = untrusted::Input::from(&bytes);
        Elem {
            limbs: parse_big_endian_value(bytes, ops.num_limbs).unwrap(),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    fn consume_scalar(ops: &CommonOps, test_case: &mut test::TestCase,
                      name: &str) -> Scalar {
        let bytes = test_case.consume_bytes(name);
        let bytes = untrusted::Input::from(&bytes);
        Scalar {
            limbs: parse_big_endian_value_in_range(
                    bytes, 0, &ops.n.limbs[..ops.num_limbs]).unwrap(),
            m: PhantomData,
            encoding: PhantomData,
        }
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
pub mod p384;
mod elem;
