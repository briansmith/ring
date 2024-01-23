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

use crate::{arithmetic::limbs_from_hex, arithmetic::montgomery::*, error, limb::*};
use core::marker::PhantomData;

pub use self::elem::*;

/// A field element, i.e. an element of ℤ/qℤ for the curve's field modulus
/// *q*.
pub type Elem<E> = elem::Elem<Q, E>;

/// Represents the (prime) order *q* of the curve's prime field.
#[derive(Clone, Copy)]
pub enum Q {}

/// A scalar. Its value is in [0, n). Zero-valued scalars are forbidden in most
/// contexts.
pub type Scalar<E = Unencoded> = elem::Elem<N, E>;

/// Represents the prime order *n* of the curve's group.
#[derive(Clone, Copy)]
pub enum N {}

pub struct Point {
    // The coordinates are stored in a contiguous array, where the first
    // `ops.num_limbs` elements are the X coordinate, the next
    // `ops.num_limbs` elements are the Y coordinate, and the next
    // `ops.num_limbs` elements are the Z coordinate. This layout is dictated
    // by the requirements of the nistz256 code.
    xyz: [Limb; 3 * MAX_LIMBS],
}

impl Point {
    pub fn new_at_infinity() -> Self {
        Self {
            xyz: [0; 3 * MAX_LIMBS],
        }
    }
}

/// Operations and values needed by all curve operations.
pub struct CommonOps {
    num_limbs: usize,
    q: Modulus,
    n: Elem<Unencoded>,

    pub a: Elem<R>, // Must be -3 mod q
    pub b: Elem<R>,

    // In all cases, `r`, `a`, and `b` may all alias each other.
    elem_mul_mont: unsafe extern "C" fn(r: *mut Limb, a: *const Limb, b: *const Limb),
    elem_sqr_mont: unsafe extern "C" fn(r: *mut Limb, a: *const Limb),

    point_add_jacobian_impl: unsafe extern "C" fn(r: *mut Limb, a: *const Limb, b: *const Limb),
}

impl CommonOps {
    // The length of a field element, which is the same as the length of a
    // scalar, in bytes.
    pub fn len(&self) -> usize {
        self.num_limbs * LIMB_BYTES
    }

    #[cfg(test)]
    pub(super) fn n_limbs(&self) -> &[Limb] {
        &self.n.limbs[..self.num_limbs]
    }

    #[inline]
    pub fn elem_add<E: Encoding>(&self, a: &mut Elem<E>, b: &Elem<E>) {
        let num_limbs = self.num_limbs;
        limbs_add_assign_mod(
            &mut a.limbs[..num_limbs],
            &b.limbs[..num_limbs],
            &self.q.p[..num_limbs],
        );
    }

    #[inline]
    pub fn elems_are_equal(&self, a: &Elem<R>, b: &Elem<R>) -> LimbMask {
        limbs_equal_limbs_consttime(&a.limbs[..self.num_limbs], &b.limbs[..self.num_limbs])
    }

    #[inline]
    pub fn elem_unencoded(&self, a: &Elem<R>) -> Elem<Unencoded> {
        const ONE: Elem<Unencoded> = Elem::from_hex("1");
        self.elem_product(a, &ONE)
    }

    #[inline]
    pub fn elem_mul(&self, a: &mut Elem<R>, b: &Elem<R>) {
        binary_op_assign(self.elem_mul_mont, a, b)
    }

    #[inline]
    pub fn elem_product<EA: Encoding, EB: Encoding>(
        &self,
        a: &Elem<EA>,
        b: &Elem<EB>,
    ) -> Elem<<(EA, EB) as ProductEncoding>::Output>
    where
        (EA, EB): ProductEncoding,
    {
        mul_mont(self.elem_mul_mont, a, b)
    }

    #[inline]
    pub fn elem_square(&self, a: &mut Elem<R>) {
        unary_op_assign(self.elem_sqr_mont, a);
    }

    #[inline]
    pub fn elem_squared(&self, a: &Elem<R>) -> Elem<R> {
        unary_op(self.elem_sqr_mont, a)
    }

    #[inline]
    pub fn is_zero<M, E: Encoding>(&self, a: &elem::Elem<M, E>) -> bool {
        limbs_are_zero_constant_time(&a.limbs[..self.num_limbs]) == LimbMask::True
    }

    pub fn elem_verify_is_not_zero(&self, a: &Elem<R>) -> Result<(), error::Unspecified> {
        if self.is_zero(a) {
            Err(error::Unspecified)
        } else {
            Ok(())
        }
    }

    pub fn point_sum(&self, a: &Point, b: &Point) -> Point {
        let mut r = Point::new_at_infinity();
        unsafe {
            (self.point_add_jacobian_impl)(r.xyz.as_mut_ptr(), a.xyz.as_ptr(), b.xyz.as_ptr())
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
        r.limbs[..self.num_limbs].copy_from_slice(&p.xyz[self.num_limbs..(2 * self.num_limbs)]);
        r
    }

    pub fn point_z(&self, p: &Point) -> Elem<R> {
        let mut r = Elem::zero();
        r.limbs[..self.num_limbs]
            .copy_from_slice(&p.xyz[(2 * self.num_limbs)..(3 * self.num_limbs)]);
        r
    }
}

struct Modulus {
    p: [Limb; MAX_LIMBS],
    rr: [Limb; MAX_LIMBS],
}

/// Operations on private keys, for ECDH and ECDSA signing.
pub struct PrivateKeyOps {
    pub common: &'static CommonOps,
    elem_inv_squared: fn(a: &Elem<R>) -> Elem<R>,
    point_mul_base_impl: fn(a: &Scalar) -> Point,
    point_mul_impl: unsafe extern "C" fn(
        r: *mut Limb,          // [3][num_limbs]
        p_scalar: *const Limb, // [num_limbs]
        p_x: *const Limb,      // [num_limbs]
        p_y: *const Limb,      // [num_limbs]
    ),
}

impl PrivateKeyOps {
    pub fn leak_limbs<'a>(&self, a: &'a Elem<Unencoded>) -> &'a [Limb] {
        &a.limbs[..self.common.num_limbs]
    }

    #[inline(always)]
    pub fn point_mul_base(&self, a: &Scalar) -> Point {
        (self.point_mul_base_impl)(a)
    }

    #[inline(always)]
    pub fn point_mul(&self, p_scalar: &Scalar, (p_x, p_y): &(Elem<R>, Elem<R>)) -> Point {
        let mut r = Point::new_at_infinity();
        unsafe {
            (self.point_mul_impl)(
                r.xyz.as_mut_ptr(),
                p_scalar.limbs.as_ptr(),
                p_x.limbs.as_ptr(),
                p_y.limbs.as_ptr(),
            );
        }
        r
    }

    #[inline]
    pub fn elem_inverse_squared(&self, a: &Elem<R>) -> Elem<R> {
        (self.elem_inv_squared)(a)
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
    pub fn elem_parse(&self, input: &mut untrusted::Reader) -> Result<Elem<R>, error::Unspecified> {
        let encoded_value = input.read_bytes(self.common.len())?;
        let parsed = elem_parse_big_endian_fixed_consttime(self.common, encoded_value)?;
        let mut r = Elem::zero();
        // Montgomery encode (elem_to_mont).
        // TODO: do something about this.
        unsafe {
            (self.common.elem_mul_mont)(
                r.limbs.as_mut_ptr(),
                parsed.limbs.as_ptr(),
                self.common.q.rr.as_ptr(),
            )
        }
        Ok(r)
    }
}

// Operations used by both ECDSA signing and ECDSA verification. In general
// these must be side-channel resistant.
pub struct ScalarOps {
    pub common: &'static CommonOps,

    scalar_mul_mont: unsafe extern "C" fn(r: *mut Limb, a: *const Limb, b: *const Limb),
}

impl ScalarOps {
    // The (maximum) length of a scalar, not including any padding.
    pub fn scalar_bytes_len(&self) -> usize {
        self.common.len()
    }

    pub fn leak_limbs<'s>(&self, s: &'s Scalar) -> &'s [Limb] {
        &s.limbs[..self.common.num_limbs]
    }

    #[inline]
    pub fn scalar_product<EA: Encoding, EB: Encoding>(
        &self,
        a: &Scalar<EA>,
        b: &Scalar<EB>,
    ) -> Scalar<<(EA, EB) as ProductEncoding>::Output>
    where
        (EA, EB): ProductEncoding,
    {
        mul_mont(self.scalar_mul_mont, a, b)
    }
}

/// Operations on public scalars needed by ECDSA signature verification.
pub struct PublicScalarOps {
    pub scalar_ops: &'static ScalarOps,
    pub public_key_ops: &'static PublicKeyOps,

    pub twin_mul: fn(g_scalar: &Scalar, p_scalar: &Scalar, p_xy: &(Elem<R>, Elem<R>)) -> Point,
    pub scalar_inv_to_mont_vartime: fn(s: &Scalar<Unencoded>) -> Scalar<R>,
    pub q_minus_n: Elem<Unencoded>,
}

impl PublicScalarOps {
    pub fn n(&self) -> &Elem<Unencoded> {
        &self.scalar_ops.common.n
    }

    #[inline]
    pub fn scalar_as_elem(&self, a: &Scalar) -> Elem<Unencoded> {
        Elem {
            limbs: a.limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn elem_equals_vartime(&self, a: &Elem<Unencoded>, b: &Elem<Unencoded>) -> bool {
        a.limbs[..self.public_key_ops.common.num_limbs]
            == b.limbs[..self.public_key_ops.common.num_limbs]
    }

    pub fn elem_less_than(&self, a: &Elem<Unencoded>, b: &Elem<Unencoded>) -> bool {
        let num_limbs = self.public_key_ops.common.num_limbs;
        limbs_less_than_limbs_vartime(&a.limbs[..num_limbs], &b.limbs[..num_limbs])
    }

    pub fn scalar_inv_to_mont_vartime(&self, s: &Scalar<Unencoded>) -> Scalar<R> {
        (self.scalar_inv_to_mont_vartime)(s)
    }
}

#[allow(non_snake_case)]
pub struct PrivateScalarOps {
    pub scalar_ops: &'static ScalarOps,

    oneRR_mod_n: Scalar<RR>, // 1 * R**2 (mod n). TOOD: Use One<RR>.
    scalar_inv_to_mont: fn(a: Scalar<R>) -> Scalar<R>,
}

impl PrivateScalarOps {
    pub fn to_mont(&self, s: &Scalar<Unencoded>) -> Scalar<R> {
        self.scalar_ops.scalar_product(s, &self.oneRR_mod_n)
    }

    /// Returns the modular inverse of `a` (mod `n`). Panics if `a` is zero.
    pub fn scalar_inv_to_mont(&self, a: &Scalar) -> Scalar<R> {
        assert!(!self.scalar_ops.common.is_zero(a));
        let a = self.to_mont(a);
        (self.scalar_inv_to_mont)(a)
    }
}

// XXX: Inefficient and unnecessarily depends on `PrivateKeyOps`. TODO: implement interleaved wNAF
// multiplication.
fn twin_mul_inefficient(
    ops: &PrivateKeyOps,
    g_scalar: &Scalar,
    p_scalar: &Scalar,
    p_xy: &(Elem<R>, Elem<R>),
) -> Point {
    let scaled_g = ops.point_mul_base(g_scalar);
    let scaled_p = ops.point_mul(p_scalar, p_xy);
    ops.common.point_sum(&scaled_g, &scaled_p)
}

// This assumes n < q < 2*n.
pub fn elem_reduced_to_scalar(ops: &CommonOps, elem: &Elem<Unencoded>) -> Scalar<Unencoded> {
    let num_limbs = ops.num_limbs;
    let mut r_limbs = elem.limbs;
    limbs_reduce_once_constant_time(&mut r_limbs[..num_limbs], &ops.n.limbs[..num_limbs]);
    Scalar {
        limbs: r_limbs,
        m: PhantomData,
        encoding: PhantomData,
    }
}

pub fn scalar_sum(ops: &CommonOps, a: &Scalar, mut b: Scalar) -> Scalar {
    limbs_add_assign_mod(
        &mut b.limbs[..ops.num_limbs],
        &a.limbs[..ops.num_limbs],
        &ops.n.limbs[..ops.num_limbs],
    );
    b
}

// Returns (`a` squared `squarings` times) * `b`.
fn elem_sqr_mul(ops: &CommonOps, a: &Elem<R>, squarings: usize, b: &Elem<R>) -> Elem<R> {
    debug_assert!(squarings >= 1);
    let mut tmp = ops.elem_squared(a);
    for _ in 1..squarings {
        ops.elem_square(&mut tmp);
    }
    ops.elem_product(&tmp, b)
}

// Sets `acc` = (`acc` squared `squarings` times) * `b`.
fn elem_sqr_mul_acc(ops: &CommonOps, acc: &mut Elem<R>, squarings: usize, b: &Elem<R>) {
    debug_assert!(squarings >= 1);
    for _ in 0..squarings {
        ops.elem_square(acc);
    }
    ops.elem_mul(acc, b)
}

#[inline]
pub fn elem_parse_big_endian_fixed_consttime(
    ops: &CommonOps,
    bytes: untrusted::Input,
) -> Result<Elem<Unencoded>, error::Unspecified> {
    parse_big_endian_fixed_consttime(ops, bytes, AllowZero::Yes, &ops.q.p[..ops.num_limbs])
}

#[inline]
pub fn scalar_parse_big_endian_fixed_consttime(
    ops: &CommonOps,
    bytes: untrusted::Input,
) -> Result<Scalar, error::Unspecified> {
    parse_big_endian_fixed_consttime(ops, bytes, AllowZero::No, &ops.n.limbs[..ops.num_limbs])
}

#[inline]
pub fn scalar_parse_big_endian_variable(
    ops: &CommonOps,
    allow_zero: AllowZero,
    bytes: untrusted::Input,
) -> Result<Scalar, error::Unspecified> {
    let mut r = Scalar::zero();
    parse_big_endian_in_range_and_pad_consttime(
        bytes,
        allow_zero,
        &ops.n.limbs[..ops.num_limbs],
        &mut r.limbs[..ops.num_limbs],
    )?;
    Ok(r)
}

pub fn scalar_parse_big_endian_partially_reduced_variable_consttime(
    ops: &CommonOps,
    bytes: untrusted::Input,
) -> Result<Scalar, error::Unspecified> {
    let mut r = Scalar::zero();

    {
        let r = &mut r.limbs[..ops.num_limbs];
        parse_big_endian_and_pad_consttime(bytes, r)?;
        limbs_reduce_once_constant_time(r, &ops.n.limbs[..ops.num_limbs]);
    }

    Ok(r)
}

fn parse_big_endian_fixed_consttime<M>(
    ops: &CommonOps,
    bytes: untrusted::Input,
    allow_zero: AllowZero,
    max_exclusive: &[Limb],
) -> Result<elem::Elem<M, Unencoded>, error::Unspecified> {
    if bytes.len() != ops.len() {
        return Err(error::Unspecified);
    }
    let mut r = elem::Elem::zero();
    parse_big_endian_in_range_and_pad_consttime(
        bytes,
        allow_zero,
        max_exclusive,
        &mut r.limbs[..ops.num_limbs],
    )?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::test;
    use alloc::{format, vec, vec::Vec};

    const ZERO_SCALAR: Scalar = Scalar {
        limbs: [0; MAX_LIMBS],
        m: PhantomData,
        encoding: PhantomData,
    };

    trait Convert<E: Encoding> {
        fn convert(self, cops: &CommonOps) -> Elem<E>;
    }

    impl Convert<R> for Elem<R> {
        fn convert(self, _cops: &CommonOps) -> Elem<R> {
            self
        }
    }

    impl Convert<Unencoded> for Elem<R> {
        fn convert(self, cops: &CommonOps) -> Elem<Unencoded> {
            cops.elem_unencoded(&self)
        }
    }

    fn q_minus_n_plus_n_equals_0_test(ops: &PublicScalarOps) {
        let cops = ops.scalar_ops.common;
        let mut x = ops.q_minus_n;
        cops.elem_add(&mut x, &cops.n);
        assert!(cops.is_zero(&x));
    }

    #[test]
    fn p256_q_minus_n_plus_n_equals_0_test() {
        q_minus_n_plus_n_equals_0_test(&p256::PUBLIC_SCALAR_OPS);
    }

    #[test]
    fn p384_q_minus_n_plus_n_equals_0_test() {
        q_minus_n_plus_n_equals_0_test(&p384::PUBLIC_SCALAR_OPS);
    }

    #[test]
    fn p256_elem_add_test() {
        elem_add_test(
            &p256::PUBLIC_SCALAR_OPS,
            test_file!("ops/p256_elem_sum_tests.txt"),
        );
    }

    #[test]
    fn p384_elem_add_test() {
        elem_add_test(
            &p384::PUBLIC_SCALAR_OPS,
            test_file!("ops/p384_elem_sum_tests.txt"),
        );
    }

    fn elem_add_test(ops: &PublicScalarOps, test_file: test::File) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let cops = ops.public_key_ops.common;
            let a = consume_elem(cops, test_case, "a");
            let b = consume_elem(cops, test_case, "b");
            let expected_sum = consume_elem(cops, test_case, "r");

            let mut actual_sum = a;
            ops.public_key_ops.common.elem_add(&mut actual_sum, &b);
            assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

            let mut actual_sum = b;
            ops.public_key_ops.common.elem_add(&mut actual_sum, &a);
            assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

            Ok(())
        })
    }

    // XXX: There's no `p256_sub` in *ring*; it's logic is inlined into
    // the point arithmetic functions. Thus, we can't test it.

    #[test]
    fn p384_elem_sub_test() {
        prefixed_extern! {
            fn p384_elem_sub(r: *mut Limb, a: *const Limb, b: *const Limb);
        }
        elem_sub_test(
            &p384::COMMON_OPS,
            p384_elem_sub,
            test_file!("ops/p384_elem_sum_tests.txt"),
        );
    }

    fn elem_sub_test(
        ops: &CommonOps,
        elem_sub: unsafe extern "C" fn(r: *mut Limb, a: *const Limb, b: *const Limb),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let b = consume_elem(ops, test_case, "b");
            let r = consume_elem(ops, test_case, "r");

            let mut actual_difference = Elem::<R>::zero();
            unsafe {
                elem_sub(
                    actual_difference.limbs.as_mut_ptr(),
                    r.limbs.as_ptr(),
                    b.limbs.as_ptr(),
                );
            }
            assert_limbs_are_equal(ops, &actual_difference.limbs, &a.limbs);

            let mut actual_difference = Elem::<R>::zero();
            unsafe {
                elem_sub(
                    actual_difference.limbs.as_mut_ptr(),
                    r.limbs.as_ptr(),
                    a.limbs.as_ptr(),
                );
            }
            assert_limbs_are_equal(ops, &actual_difference.limbs, &b.limbs);

            Ok(())
        })
    }

    // XXX: There's no `p256_div_by_2` in *ring*; it's logic is inlined
    // into the point arithmetic functions. Thus, we can't test it.

    #[test]
    fn p384_elem_div_by_2_test() {
        prefixed_extern! {
            fn p384_elem_div_by_2(r: *mut Limb, a: *const Limb);
        }
        elem_div_by_2_test(
            &p384::COMMON_OPS,
            p384_elem_div_by_2,
            test_file!("ops/p384_elem_div_by_2_tests.txt"),
        );
    }

    fn elem_div_by_2_test(
        ops: &CommonOps,
        elem_div_by_2: unsafe extern "C" fn(r: *mut Limb, a: *const Limb),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let r = consume_elem(ops, test_case, "r");

            let mut actual_result = Elem::<R>::zero();
            unsafe {
                elem_div_by_2(actual_result.limbs.as_mut_ptr(), a.limbs.as_ptr());
            }
            assert_limbs_are_equal(ops, &actual_result.limbs, &r.limbs);

            Ok(())
        })
    }

    // There is no `ecp_nistz256_neg` on other targets.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn p256_elem_neg_test() {
        prefixed_extern! {
            fn ecp_nistz256_neg(r: *mut Limb, a: *const Limb);
        }
        elem_neg_test(
            &p256::COMMON_OPS,
            ecp_nistz256_neg,
            test_file!("ops/p256_elem_neg_tests.txt"),
        );
    }

    #[test]
    fn p384_elem_neg_test() {
        prefixed_extern! {
            fn p384_elem_neg(r: *mut Limb, a: *const Limb);
        }
        elem_neg_test(
            &p384::COMMON_OPS,
            p384_elem_neg,
            test_file!("ops/p384_elem_neg_tests.txt"),
        );
    }

    fn elem_neg_test(
        ops: &CommonOps,
        elem_neg: unsafe extern "C" fn(r: *mut Limb, a: *const Limb),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_elem(ops, test_case, "a");
            let b = consume_elem(ops, test_case, "b");

            // Verify -a == b.
            {
                let mut actual_result = Elem::<R>::zero();
                unsafe {
                    elem_neg(actual_result.limbs.as_mut_ptr(), a.limbs.as_ptr());
                }
                assert_limbs_are_equal(ops, &actual_result.limbs, &b.limbs);
            }

            // Verify -b == a.
            {
                let mut actual_result = Elem::<R>::zero();
                unsafe {
                    elem_neg(actual_result.limbs.as_mut_ptr(), b.limbs.as_ptr());
                }
                assert_limbs_are_equal(ops, &actual_result.limbs, &a.limbs);
            }

            Ok(())
        })
    }

    #[test]
    fn p256_elem_mul_test() {
        elem_mul_test(&p256::COMMON_OPS, test_file!("ops/p256_elem_mul_tests.txt"));
    }

    #[test]
    fn p384_elem_mul_test() {
        elem_mul_test(&p384::COMMON_OPS, test_file!("ops/p384_elem_mul_tests.txt"));
    }

    fn elem_mul_test(ops: &CommonOps, test_file: test::File) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let mut a = consume_elem(ops, test_case, "a");
            let b = consume_elem(ops, test_case, "b");
            let r = consume_elem(ops, test_case, "r");
            ops.elem_mul(&mut a, &b);
            assert_limbs_are_equal(ops, &a.limbs, &r.limbs);

            Ok(())
        })
    }

    #[test]
    fn p256_scalar_mul_test() {
        scalar_mul_test(
            &p256::SCALAR_OPS,
            test_file!("ops/p256_scalar_mul_tests.txt"),
        );
    }

    #[test]
    fn p384_scalar_mul_test() {
        scalar_mul_test(
            &p384::SCALAR_OPS,
            test_file!("ops/p384_scalar_mul_tests.txt"),
        );
    }

    fn scalar_mul_test(ops: &ScalarOps, test_file: test::File) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");
            let cops = ops.common;
            let a = consume_scalar(cops, test_case, "a");
            let b = consume_scalar_mont(cops, test_case, "b");
            let expected_result = consume_scalar(cops, test_case, "r");
            let actual_result = ops.scalar_product(&a, &b);
            assert_limbs_are_equal(cops, &actual_result.limbs, &expected_result.limbs);

            Ok(())
        })
    }

    #[test]
    fn p256_scalar_square_test() {
        prefixed_extern! {
            fn p256_scalar_sqr_rep_mont(r: *mut Limb, a: *const Limb, rep: Limb);
        }
        scalar_square_test(
            &p256::SCALAR_OPS,
            p256_scalar_sqr_rep_mont,
            test_file!("ops/p256_scalar_square_tests.txt"),
        );
    }

    // XXX: There's no `p384_scalar_square_test()` because there's no dedicated
    // `p384_scalar_sqr_rep_mont()`.

    fn scalar_square_test(
        ops: &ScalarOps,
        sqr_rep: unsafe extern "C" fn(r: *mut Limb, a: *const Limb, rep: Limb),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");
            let cops = &ops.common;
            let a = consume_scalar(cops, test_case, "a");
            let expected_result = consume_scalar(cops, test_case, "r");

            {
                let mut actual_result: Scalar<R> = Scalar {
                    limbs: [0; MAX_LIMBS],
                    m: PhantomData,
                    encoding: PhantomData,
                };
                unsafe {
                    sqr_rep(actual_result.limbs.as_mut_ptr(), a.limbs.as_ptr(), 1);
                }
                assert_limbs_are_equal(cops, &actual_result.limbs, &expected_result.limbs);
            }

            {
                let actual_result = ops.scalar_product(&a, &a);
                assert_limbs_are_equal(cops, &actual_result.limbs, &expected_result.limbs);
            }

            Ok(())
        })
    }

    #[test]
    #[should_panic(expected = "!self.scalar_ops.common.is_zero(a)")]
    fn p256_scalar_inv_to_mont_zero_panic_test() {
        let _ = p256::PRIVATE_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[test]
    #[should_panic(expected = "!self.scalar_ops.common.is_zero(a)")]
    fn p384_scalar_inv_to_mont_zero_panic_test() {
        let _ = p384::PRIVATE_SCALAR_OPS.scalar_inv_to_mont(&ZERO_SCALAR);
    }

    #[test]
    fn p256_point_sum_test() {
        point_sum_test(
            &p256::PRIVATE_KEY_OPS,
            test_file!("ops/p256_point_sum_tests.txt"),
        );
    }

    #[test]
    fn p384_point_sum_test() {
        point_sum_test(
            &p384::PRIVATE_KEY_OPS,
            test_file!("ops/p384_point_sum_tests.txt"),
        );
    }

    fn point_sum_test(ops: &PrivateKeyOps, test_file: test::File) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_jacobian_point(ops, test_case, "a");
            let b = consume_jacobian_point(ops, test_case, "b");
            let r_expected: TestPoint<R> = consume_point(ops, test_case, "r");

            let r_actual = ops.common.point_sum(&a, &b);
            assert_point_actual_equals_expected(ops, &r_actual, &r_expected);

            Ok(())
        });
    }

    #[test]
    fn p256_point_sum_mixed_test() {
        prefixed_extern! {
            fn p256_point_add_affine(
                r: *mut Limb,   // [p256::COMMON_OPS.num_limbs*3]
                a: *const Limb, // [p256::COMMON_OPS.num_limbs*3]
                b: *const Limb, // [p256::COMMON_OPS.num_limbs*2]
            );
        }
        point_sum_mixed_test(
            &p256::PRIVATE_KEY_OPS,
            p256_point_add_affine,
            test_file!("ops/p256_point_sum_mixed_tests.txt"),
        );
    }

    // XXX: There is no `nistz384_point_add_affine()`.

    fn point_sum_mixed_test(
        ops: &PrivateKeyOps,
        point_add_affine: unsafe extern "C" fn(
            r: *mut Limb,   // [ops.num_limbs*3]
            a: *const Limb, // [ops.num_limbs*3]
            b: *const Limb, // [ops.num_limbs*2]
        ),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_jacobian_point(ops, test_case, "a");
            let b = consume_affine_point(ops, test_case, "b");
            let r_expected: TestPoint<R> = consume_point(ops, test_case, "r");

            let mut r_actual = Point::new_at_infinity();
            unsafe {
                point_add_affine(r_actual.xyz.as_mut_ptr(), a.xyz.as_ptr(), b.xy.as_ptr());
            }

            assert_point_actual_equals_expected(ops, &r_actual, &r_expected);

            Ok(())
        });
    }

    #[test]
    fn p256_point_double_test() {
        prefixed_extern! {
            fn p256_point_double(
                r: *mut Limb,   // [p256::COMMON_OPS.num_limbs*3]
                a: *const Limb, // [p256::COMMON_OPS.num_limbs*3]
            );
        }
        point_double_test(
            &p256::PRIVATE_KEY_OPS,
            p256_point_double,
            test_file!("ops/p256_point_double_tests.txt"),
        );
    }

    #[test]
    fn p384_point_double_test() {
        prefixed_extern! {
            fn p384_point_double(
                r: *mut Limb,   // [p384::COMMON_OPS.num_limbs*3]
                a: *const Limb, // [p384::COMMON_OPS.num_limbs*3]
            );
        }
        point_double_test(
            &p384::PRIVATE_KEY_OPS,
            p384_point_double,
            test_file!("ops/p384_point_double_tests.txt"),
        );
    }

    fn point_double_test(
        ops: &PrivateKeyOps,
        point_double: unsafe extern "C" fn(
            r: *mut Limb,   // [ops.num_limbs*3]
            a: *const Limb, // [ops.num_limbs*3]
        ),
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");

            let a = consume_jacobian_point(ops, test_case, "a");
            let r_expected: TestPoint<R> = consume_point(ops, test_case, "r");

            let mut r_actual = Point::new_at_infinity();
            unsafe {
                point_double(r_actual.xyz.as_mut_ptr(), a.xyz.as_ptr());
            }

            assert_point_actual_equals_expected(ops, &r_actual, &r_expected);

            Ok(())
        });
    }

    /// TODO: We should be testing `point_mul` with points other than the generator.
    #[test]
    fn p256_point_mul_test() {
        point_mul_base_tests(
            &p256::PRIVATE_KEY_OPS,
            |s| p256::PRIVATE_KEY_OPS.point_mul(s, &p256::GENERATOR),
            test_file!("ops/p256_point_mul_base_tests.txt"),
        );
    }

    /// TODO: We should be testing `point_mul` with points other than the generator.
    #[test]
    fn p384_point_mul_test() {
        point_mul_base_tests(
            &p384::PRIVATE_KEY_OPS,
            |s| p384::PRIVATE_KEY_OPS.point_mul(s, &p384::GENERATOR),
            test_file!("ops/p384_point_mul_base_tests.txt"),
        );
    }

    #[test]
    fn p256_point_mul_serialized_test() {
        point_mul_serialized_test(
            &p256::PRIVATE_KEY_OPS,
            &p256::PUBLIC_KEY_OPS,
            test_file!("ops/p256_point_mul_serialized_tests.txt"),
        );
    }

    fn point_mul_serialized_test(
        priv_ops: &PrivateKeyOps,
        pub_ops: &PublicKeyOps,
        test_file: test::File,
    ) {
        let cops = pub_ops.common;

        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");
            let p_scalar = consume_scalar(cops, test_case, "p_scalar");

            let p = test_case.consume_bytes("p");
            let p = super::super::public_key::parse_uncompressed_point(
                pub_ops,
                untrusted::Input::from(&p),
            )
            .expect("valid point");

            let expected_result = test_case.consume_bytes("r");

            let product = priv_ops.point_mul(&p_scalar, &p);

            let mut actual_result = vec![4u8; 1 + (2 * cops.len())];
            {
                let (x, y) = actual_result[1..].split_at_mut(cops.len());
                super::super::private_key::big_endian_affine_from_jacobian(
                    priv_ops,
                    Some(x),
                    Some(y),
                    &product,
                )
                .expect("successful encoding");
            }

            assert_eq!(expected_result, actual_result);

            Ok(())
        })
    }

    #[test]
    fn p256_point_mul_base_test() {
        point_mul_base_tests(
            &p256::PRIVATE_KEY_OPS,
            |s| p256::PRIVATE_KEY_OPS.point_mul_base(s),
            test_file!("ops/p256_point_mul_base_tests.txt"),
        );
    }

    #[test]
    fn p384_point_mul_base_test() {
        point_mul_base_tests(
            &p384::PRIVATE_KEY_OPS,
            |s| p384::PRIVATE_KEY_OPS.point_mul_base(s),
            test_file!("ops/p384_point_mul_base_tests.txt"),
        );
    }

    pub(super) fn point_mul_base_tests(
        ops: &PrivateKeyOps,
        f: impl Fn(&Scalar) -> Point,
        test_file: test::File,
    ) {
        test::run(test_file, |section, test_case| {
            assert_eq!(section, "");
            let g_scalar = consume_scalar(ops.common, test_case, "g_scalar");
            let expected_result: TestPoint<Unencoded> = consume_point(ops, test_case, "r");
            let actual_result = f(&g_scalar);
            assert_point_actual_equals_expected(ops, &actual_result, &expected_result);
            Ok(())
        })
    }

    fn assert_point_actual_equals_expected<E: Encoding>(
        ops: &PrivateKeyOps,
        actual_point: &Point,
        expected_point: &TestPoint<E>,
    ) where
        Elem<R>: Convert<E>,
    {
        let cops = ops.common;
        let actual_x = &cops.point_x(actual_point);
        let actual_y = &cops.point_y(actual_point);
        let actual_z = &cops.point_z(actual_point);
        match expected_point {
            TestPoint::Infinity => {
                let zero = Elem::zero();
                assert_elems_are_equal(cops, actual_z, &zero);
            }
            TestPoint::Affine(expected_x, expected_y) => {
                let zz_inv = ops.elem_inverse_squared(actual_z);
                let x_aff = cops.elem_product(actual_x, &zz_inv);
                let y_aff = {
                    let zzzz_inv = cops.elem_squared(&zz_inv);
                    let zzz_inv = cops.elem_product(actual_z, &zzzz_inv);
                    cops.elem_product(actual_y, &zzz_inv)
                };

                let x_aff = x_aff.convert(cops);
                let y_aff = y_aff.convert(cops);

                assert_elems_are_equal(cops, &x_aff, expected_x);
                assert_elems_are_equal(cops, &y_aff, expected_y);
            }
        }
    }

    fn consume_jacobian_point(
        ops: &PrivateKeyOps,
        test_case: &mut test::TestCase,
        name: &str,
    ) -> Point {
        let input = test_case.consume_string(name);
        let elems = input.split(", ").collect::<Vec<&str>>();
        assert_eq!(elems.len(), 3);
        let mut p = Point::new_at_infinity();
        consume_point_elem(ops.common, &mut p.xyz, &elems, 0);
        consume_point_elem(ops.common, &mut p.xyz, &elems, 1);
        consume_point_elem(ops.common, &mut p.xyz, &elems, 2);
        p
    }

    struct AffinePoint {
        xy: [Limb; 2 * MAX_LIMBS],
    }

    fn consume_affine_point(
        ops: &PrivateKeyOps,
        test_case: &mut test::TestCase,
        name: &str,
    ) -> AffinePoint {
        let input = test_case.consume_string(name);
        let elems = input.split(", ").collect::<Vec<&str>>();
        assert_eq!(elems.len(), 2);
        let mut p = AffinePoint {
            xy: [0; 2 * MAX_LIMBS],
        };
        consume_point_elem(ops.common, &mut p.xy, &elems, 0);
        consume_point_elem(ops.common, &mut p.xy, &elems, 1);
        p
    }

    fn consume_point_elem(ops: &CommonOps, limbs_out: &mut [Limb], elems: &[&str], i: usize) {
        let bytes = test::from_hex(elems[i]).unwrap();
        let bytes = untrusted::Input::from(&bytes);
        let r: Elem<Unencoded> = elem_parse_big_endian_fixed_consttime(ops, bytes).unwrap();
        // XXX: “Transmute” this to `Elem<R>` limbs.
        limbs_out[(i * ops.num_limbs)..((i + 1) * ops.num_limbs)]
            .copy_from_slice(&r.limbs[..ops.num_limbs]);
    }

    enum TestPoint<E: Encoding> {
        Infinity,
        Affine(Elem<E>, Elem<E>),
    }

    fn consume_point<E: Encoding>(
        ops: &PrivateKeyOps,
        test_case: &mut test::TestCase,
        name: &str,
    ) -> TestPoint<E> {
        fn consume_point_elem<E: Encoding>(ops: &CommonOps, elems: &[&str], i: usize) -> Elem<E> {
            let bytes = test::from_hex(elems[i]).unwrap();
            let bytes = untrusted::Input::from(&bytes);
            let unencoded: Elem<Unencoded> =
                elem_parse_big_endian_fixed_consttime(ops, bytes).unwrap();
            // XXX: “Transmute” this to `Elem<R>` limbs.
            Elem {
                limbs: unencoded.limbs,
                m: PhantomData,
                encoding: PhantomData,
            }
        }

        let input = test_case.consume_string(name);
        if input == "inf" {
            return TestPoint::Infinity;
        }
        let elems = input.split(", ").collect::<Vec<&str>>();
        assert_eq!(elems.len(), 2);
        let x = consume_point_elem(ops.common, &elems, 0);
        let y = consume_point_elem(ops.common, &elems, 1);
        TestPoint::Affine(x, y)
    }

    fn assert_elems_are_equal<E: Encoding>(ops: &CommonOps, a: &Elem<E>, b: &Elem<E>) {
        assert_limbs_are_equal(ops, &a.limbs, &b.limbs)
    }

    fn assert_limbs_are_equal(
        ops: &CommonOps,
        actual: &[Limb; MAX_LIMBS],
        expected: &[Limb; MAX_LIMBS],
    ) {
        if actual[..ops.num_limbs] != expected[..ops.num_limbs] {
            let mut actual_s = alloc::string::String::new();
            let mut expected_s = alloc::string::String::new();
            for j in 0..ops.num_limbs {
                let width = LIMB_BITS / 4;
                let formatted = format!("{:0width$x}", actual[ops.num_limbs - j - 1]);
                actual_s.push_str(&formatted);
                let formatted = format!("{:0width$x}", expected[ops.num_limbs - j - 1]);
                expected_s.push_str(&formatted);
            }
            panic!(
                "Actual != Expected,\nActual = {}, Expected = {}",
                actual_s, expected_s
            );
        }
    }

    fn consume_elem(ops: &CommonOps, test_case: &mut test::TestCase, name: &str) -> Elem<R> {
        let bytes = consume_padded_bytes(ops, test_case, name);
        let bytes = untrusted::Input::from(&bytes);
        let r: Elem<Unencoded> = elem_parse_big_endian_fixed_consttime(ops, bytes).unwrap();
        // XXX: “Transmute” this to an `Elem<R>`.
        Elem {
            limbs: r.limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    fn consume_scalar(ops: &CommonOps, test_case: &mut test::TestCase, name: &str) -> Scalar {
        let bytes = test_case.consume_bytes(name);
        let bytes = untrusted::Input::from(&bytes);
        scalar_parse_big_endian_variable(ops, AllowZero::Yes, bytes).unwrap()
    }

    fn consume_scalar_mont(
        ops: &CommonOps,
        test_case: &mut test::TestCase,
        name: &str,
    ) -> Scalar<R> {
        let bytes = test_case.consume_bytes(name);
        let bytes = untrusted::Input::from(&bytes);
        let s = scalar_parse_big_endian_variable(ops, AllowZero::Yes, bytes).unwrap();
        // “Transmute” it to a `Scalar<R>`.
        Scalar {
            limbs: s.limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    fn consume_padded_bytes(
        ops: &CommonOps,
        test_case: &mut test::TestCase,
        name: &str,
    ) -> Vec<u8> {
        let unpadded_bytes = test_case.consume_bytes(name);
        let mut bytes = vec![0; ops.len() - unpadded_bytes.len()];
        bytes.extend(&unpadded_bytes);
        bytes
    }
}

mod elem;
pub mod p256;
pub mod p384;
