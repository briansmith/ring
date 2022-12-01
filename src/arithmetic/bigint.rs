// Copyright 2015-2012 Brian Smith.
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

//! Multi-precision integers.
//!
//! # Modular Arithmetic.
//!
//! Modular arithmetic is done in finite commutative rings ℤ/mℤ for some
//! modulus *m*. We work in finite commutative rings instead of finite fields
//! because the RSA public modulus *n* is not prime, which means ℤ/nℤ contains
//! nonzero elements that have no multiplicative inverse, so ℤ/nℤ is not a
//! finite field.
//!
//! In some calculations we need to deal with multiple rings at once. For
//! example, RSA private key operations operate in the rings ℤ/nℤ, ℤ/pℤ, and
//! ℤ/qℤ. Types and functions dealing with such rings are all parameterized
//! over a type `M` to ensure that we don't wrongly mix up the math, e.g. by
//! multiplying an element of ℤ/pℤ by an element of ℤ/qℤ modulo q. This follows
//! the "unit" pattern described in [Static checking of units in Servo].
//!
//! `Elem` also uses the static unit checking pattern to statically track the
//! Montgomery factors that need to be canceled out in each value using it's
//! `E` parameter.
//!
//! [Static checking of units in Servo]:
//!     https://blog.mozilla.org/research/2014/06/23/static-checking-of-units-in-servo/

use self::{boxed_limbs::BoxedLimbs, n0::N0};
pub(crate) use self::{
    elem::Elem,
    modulus::{Modulus, PartialModulus, MODULUS_MAX_LIMBS},
    private_exponent::{elem_exp_consttime, PrivateExponent},
};
pub(crate) use super::nonnegative::Nonnegative;
use crate::{
    arithmetic::montgomery::*,
    bssl, c, cpu, error,
    limb::{self, Limb, LimbMask},
};
use core::{marker::PhantomData, num::NonZeroU64};

mod bn_mul_mont_fallback;
mod boxed_limbs;
mod elem;
mod modulus;
mod n0;
mod one;
mod private_exponent;

/// A prime modulus.
///
/// # Safety
///
/// Some logic may assume a `Prime` number is non-zero, and thus a non-empty
/// array of limbs, or make similar assumptions. TODO: Any such logic should
/// be encapsulated here, or this trait should be made non-`unsafe`. TODO:
/// non-zero-ness and non-empty-ness should be factored out into a separate
/// trait. (In retrospect, this shouldn't have been made an `unsafe` trait
/// preemptively.)
pub unsafe trait Prime {}

struct Width<M> {
    num_limbs: usize,

    /// The modulus *m* that the width originated from.
    m: PhantomData<M>,
}

/// A modulus *s* that is smaller than another modulus *l* so every element of
/// ℤ/sℤ is also an element of ℤ/lℤ.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value, e.g. by assuming the larger modulus has at least as many limbs.
/// TODO: Any such logic should be encapsulated here, or this trait should be
/// made non-`unsafe`. (In retrospect, this shouldn't have been made an `unsafe`
/// trait preemptively.)
pub unsafe trait SmallerModulus<L> {}

/// A modulus *s* where s < l < 2*s for the given larger modulus *l*. This is
/// the precondition for reduction by conditional subtraction,
/// `elem_reduce_once()`.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value, e.g. by assuming that the smaller modulus is at most one limb
/// smaller than the larger modulus. TODO: Any such logic should be
/// encapsulated here, or this trait should be made non-`unsafe`. (In retrospect,
/// this shouldn't have been made an `unsafe` trait preemptively.)
pub unsafe trait SlightlySmallerModulus<L>: SmallerModulus<L> {}

/// A modulus *s* where √l <= s < l for the given larger modulus *l*. This is
/// the precondition for the more general Montgomery reduction from ℤ/lℤ to
/// ℤ/sℤ.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value. TODO: Any such logic should be encapsulated here, or this trait
/// should be made non-`unsafe`. (In retrospect, this shouldn't have been made
/// an `unsafe` trait preemptively.)
pub unsafe trait NotMuchSmallerModulus<L>: SmallerModulus<L> {}

pub trait PublicModulus {}

pub(crate) fn elem_mul<M, AF, BF>(
    a: &Elem<M, AF>,
    b: Elem<M, BF>,
    m: &Modulus<M>,
) -> Elem<M, <(AF, BF) as ProductEncoding>::Output>
where
    (AF, BF): ProductEncoding,
{
    elem_mul_(a, b, &m.as_partial())
}

fn elem_mul_<M, AF, BF>(
    a: &Elem<M, AF>,
    mut b: Elem<M, BF>,
    m: &PartialModulus<M>,
) -> Elem<M, <(AF, BF) as ProductEncoding>::Output>
where
    (AF, BF): ProductEncoding,
{
    limbs_mont_mul(
        b.limbs_mut(),
        a.limbs(),
        m.limbs(),
        m.n0(),
        m.cpu_features(),
    );
    Elem::new_unchecked(b.into_limbs())
}

fn elem_mul_by_2<M, AF>(a: &mut Elem<M, AF>, m: &PartialModulus<M>) {
    prefixed_extern! {
        fn LIMBS_shl_mod(r: *mut Limb, a: *const Limb, m: *const Limb, num_limbs: c::size_t);
    }
    unsafe {
        LIMBS_shl_mod(
            a.limbs_mut().as_mut_ptr(),
            a.limbs().as_ptr(),
            m.limbs().as_ptr(),
            m.limbs().len(),
        );
    }
}

pub(crate) fn elem_reduced_once<Larger, Smaller: SlightlySmallerModulus<Larger>>(
    a: &Elem<Larger, Unencoded>,
    m: &Modulus<Smaller>,
) -> Elem<Smaller, Unencoded> {
    let mut r = a.limbs().clone();
    assert!(r.len() <= m.limbs().len());
    limb::limbs_reduce_once_constant_time(&mut r, m.limbs());
    Elem::new_unchecked(BoxedLimbs::new_unchecked(r.into_limbs()))
}

#[inline]
pub(crate) fn elem_reduced<Larger, Smaller: NotMuchSmallerModulus<Larger>>(
    a: &Elem<Larger, Unencoded>,
    m: &Modulus<Smaller>,
) -> Elem<Smaller, RInverse> {
    let mut tmp = [0; MODULUS_MAX_LIMBS];
    let tmp = &mut tmp[..a.limbs().len()];
    tmp.copy_from_slice(a.limbs());

    let mut r = m.zero();
    limbs_from_mont_in_place(r.limbs_mut(), tmp, m.limbs(), m.n0());
    r
}

fn elem_squared<M, E>(
    mut a: Elem<M, E>,
    m: &PartialModulus<M>,
) -> Elem<M, <(E, E) as ProductEncoding>::Output>
where
    (E, E): ProductEncoding,
{
    limbs_mont_square(a.limbs_mut(), m.limbs(), m.n0(), m.cpu_features());
    Elem::new_unchecked(a.into_limbs())
}

pub(crate) fn elem_widen<Larger, Smaller: SmallerModulus<Larger>>(
    a: Elem<Smaller, Unencoded>,
    m: &Modulus<Larger>,
) -> Elem<Larger, Unencoded> {
    let mut r = m.zero();
    r.limbs_mut()[..a.limbs().len()].copy_from_slice(a.limbs());
    r
}

// TODO: Document why this works for all Montgomery factors.
pub(crate) fn elem_add<M, E>(mut a: Elem<M, E>, b: Elem<M, E>, m: &Modulus<M>) -> Elem<M, E> {
    limb::limbs_add_assign_mod(a.limbs_mut(), b.limbs(), m.limbs());
    a
}

// TODO: Document why this works for all Montgomery factors.
pub(crate) fn elem_sub<M, E>(mut a: Elem<M, E>, b: &Elem<M, E>, m: &Modulus<M>) -> Elem<M, E> {
    prefixed_extern! {
        // `r` and `a` may alias.
        fn LIMBS_sub_mod(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            m: *const Limb,
            num_limbs: c::size_t,
        );
    }
    unsafe {
        LIMBS_sub_mod(
            a.limbs_mut().as_mut_ptr(),
            a.limbs().as_ptr(),
            b.limbs().as_ptr(),
            m.limbs().as_ptr(),
            m.limbs().len(),
        );
    }
    a
}

/// Calculates base**exponent (mod m).
///
/// The run time  is a function of the number of limbs in `m` and the bit
/// length and Hamming Weight of `exponent`. The bounds on `m` are pretty
/// obvious but the bounds on `exponent` are less obvious. Callers should
/// document the bounds they place on the maximum value and maximum Hamming
/// weight of `exponent`.
// TODO: The test coverage needs to be expanded, e.g. test with the largest
// accepted exponent and with the most common values of 65537 and 3.
pub(crate) fn elem_exp_vartime<M>(
    base: Elem<M, R>,
    exponent: NonZeroU64,
    m: &PartialModulus<M>,
) -> Elem<M, R> {
    // Use what [Knuth] calls the "S-and-X binary method", i.e. variable-time
    // square-and-multiply that scans the exponent from the most significant
    // bit to the least significant bit (left-to-right). Left-to-right requires
    // less storage compared to right-to-left scanning, at the cost of needing
    // to compute `exponent.leading_zeros()`, which we assume to be cheap.
    //
    // As explained in [Knuth], exponentiation by squaring is the most
    // efficient algorithm when the Hamming weight is 2 or less. It isn't the
    // most efficient for all other, uncommon, exponent values but any
    // suboptimality is bounded at least by the small bit length of `exponent`
    // as enforced by its type.
    //
    // This implementation is slightly simplified by taking advantage of the
    // fact that we require the exponent to be a positive integer.
    //
    // [Knuth]: The Art of Computer Programming, Volume 2: Seminumerical
    //          Algorithms (3rd Edition), Section 4.6.3.
    let exponent = exponent.get();
    let mut acc = base.clone();
    let mut bit = 1 << (64 - 1 - exponent.leading_zeros());
    debug_assert!((exponent & bit) != 0);
    while bit > 1 {
        bit >>= 1;
        acc = elem_squared(acc, m);
        if (exponent & bit) != 0 {
            acc = elem_mul_(&base, acc, m);
        }
    }
    acc
}

/// Uses Fermat's Little Theorem to calculate modular inverse in constant time.
pub(crate) fn elem_inverse_consttime<M: Prime>(
    a: Elem<M, R>,
    m: &Modulus<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    elem_exp_consttime(a, &PrivateExponent::for_flt(m), m)
}

/// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
pub(crate) fn verify_inverses_consttime<M>(
    a: &Elem<M, R>,
    b: Elem<M, Unencoded>,
    m: &Modulus<M>,
) -> Result<(), error::Unspecified> {
    if elem_mul(a, b, m).is_one() {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

#[inline]
pub(crate) fn elem_verify_equal_consttime<M, E>(
    a: &Elem<M, E>,
    b: &Elem<M, E>,
) -> Result<(), error::Unspecified> {
    if limb::limbs_equal_limbs_consttime(a.limbs(), b.limbs()) == LimbMask::True {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

impl Nonnegative {
    pub fn to_elem<M>(&self, m: &Modulus<M>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.verify_less_than_modulus(m)?;
        let mut r = m.zero();
        r.limbs_mut()[0..self.limbs().len()].copy_from_slice(self.limbs());
        Ok(r)
    }

    pub fn verify_less_than_modulus<M>(&self, m: &Modulus<M>) -> Result<(), error::Unspecified> {
        if self.limbs().len() > m.limbs().len() {
            return Err(error::Unspecified);
        }
        if self.limbs().len() == m.limbs().len() {
            if limb::limbs_less_than_limbs_consttime(self.limbs(), m.limbs()) != LimbMask::True {
                return Err(error::Unspecified);
            }
        }
        Ok(())
    }
}

/// r *= a
fn limbs_mont_mul(r: &mut [Limb], a: &[Limb], m: &[Limb], n0: &N0, _cpu_features: cpu::Features) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            a.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

fn limbs_from_mont_in_place(r: &mut [Limb], tmp: &mut [Limb], m: &[Limb], n0: &N0) {
    prefixed_extern! {
        fn bn_from_montgomery_in_place(
            r: *mut Limb,
            num_r: c::size_t,
            a: *mut Limb,
            num_a: c::size_t,
            n: *const Limb,
            num_n: c::size_t,
            n0: &N0,
        ) -> bssl::Result;
    }
    Result::from(unsafe {
        bn_from_montgomery_in_place(
            r.as_mut_ptr(),
            r.len(),
            tmp.as_mut_ptr(),
            tmp.len(),
            m.as_ptr(),
            m.len(),
            n0,
        )
    })
    .unwrap()
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
fn limbs_mul(r: &mut [Limb], a: &[Limb], b: &[Limb]) {
    debug_assert_eq!(r.len(), 2 * a.len());
    debug_assert_eq!(a.len(), b.len());
    let ab_len = a.len();

    r[..ab_len].fill(0);
    for (i, &b_limb) in b.iter().enumerate() {
        r[ab_len + i] = unsafe {
            limbs_mul_add_limb(
                (&mut r[i..][..ab_len]).as_mut_ptr(),
                a.as_ptr(),
                b_limb,
                ab_len,
            )
        };
    }
}

/// r = a * b
#[cfg(not(target_arch = "x86_64"))]
fn limbs_mont_product(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    m: &[Limb],
    n0: &N0,
    _cpu_features: cpu::Features,
) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    debug_assert_eq!(b.len(), m.len());

    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

/// r = r**2
fn limbs_mont_square(r: &mut [Limb], m: &[Limb], n0: &N0, _cpu_features: cpu::Features) {
    debug_assert_eq!(r.len(), m.len());
    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            r.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

prefixed_extern! {
    // `r` and/or 'a' and/or 'b' may alias.
    fn bn_mul_mont(
        r: *mut Limb,
        a: *const Limb,
        b: *const Limb,
        n: *const Limb,
        n0: &N0,
        num_limbs: c::size_t,
    );
}

#[cfg(any(
    test,
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))
))]
prefixed_extern! {
    // `r` must not alias `a`
    #[must_use]
    fn limbs_mul_add_limb(r: *mut Limb, a: *const Limb, b: Limb, num_limbs: c::size_t) -> Limb;
}

#[cfg(test)]
mod tests {
    use super::{modulus::MODULUS_MIN_LIMBS, *};
    use crate::{limb::LIMB_BYTES, test};
    use alloc::format;

    // Type-level representation of an arbitrary modulus.
    struct M {}

    impl PublicModulus for M {}

    // TODO: fn test_elem_exp_vartime() using
    // "src/rsa/bigint_elem_exp_vartime_tests.txt". See that file for details.
    // In the meantime, the function is tested indirectly via the RSA
    // verification and signing tests.
    #[test]
    fn test_elem_mul() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_mul_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m = consume_modulus::<M>(test_case, "M", cpu_features);
                let expected_result = consume_elem(test_case, "ModMul", &m);
                let a = consume_elem(test_case, "A", &m);
                let b = consume_elem(test_case, "B", &m);

                let b = into_encoded(b, &m);
                let a = into_encoded(a, &m);
                let actual_result = elem_mul(&a, b, &m);
                let actual_result = actual_result.into_unencoded(&m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_squared() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_squared_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m = consume_modulus::<M>(test_case, "M", cpu_features);
                let expected_result = consume_elem(test_case, "ModSquare", &m);
                let a = consume_elem(test_case, "A", &m);

                let a = into_encoded(a, &m);
                let actual_result = elem_squared(a, &m.as_partial());
                let actual_result = actual_result.into_unencoded(&m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_reduced_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct MM {}
                unsafe impl SmallerModulus<MM> for M {}
                unsafe impl NotMuchSmallerModulus<MM> for M {}

                let m = consume_modulus::<M>(test_case, "M", cpu_features);
                let expected_result = consume_elem(test_case, "R", &m);
                let a =
                    consume_elem_unchecked::<MM>(test_case, "A", expected_result.limbs().len() * 2);

                let actual_result = elem_reduced(&a, &m);
                let oneRR = m.oneRR();
                let actual_result = elem_mul(oneRR.as_ref(), actual_result, &m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced_once() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_reduced_once_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct N {}
                struct QQ {}
                unsafe impl SmallerModulus<N> for QQ {}
                unsafe impl SlightlySmallerModulus<N> for QQ {}

                let qq = consume_modulus::<QQ>(test_case, "QQ", cpu_features);
                let expected_result = consume_elem::<QQ>(test_case, "R", &qq);
                let n = consume_modulus::<N>(test_case, "N", cpu_features);
                let a = consume_elem::<N>(test_case, "A", &n);

                let actual_result = elem_reduced_once(&a, &qq);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_modulus_debug() {
        let (modulus, _) = Modulus::<M>::from_be_bytes_with_bit_length(
            untrusted::Input::from(&[0xff; LIMB_BYTES * MODULUS_MIN_LIMBS]),
            cpu::features(),
        )
        .unwrap();
        assert_eq!("Modulus", format!("{:?}", modulus));
    }

    pub(super) fn consume_elem<M>(
        test_case: &mut test::TestCase,
        name: &str,
        m: &Modulus<M>,
    ) -> Elem<M, Unencoded> {
        let value = test_case.consume_bytes(name);
        Elem::from_be_bytes_padded(untrusted::Input::from(&value), m).unwrap()
    }

    fn consume_elem_unchecked<M>(
        test_case: &mut test::TestCase,
        name: &str,
        num_limbs: usize,
    ) -> Elem<M, Unencoded> {
        let value = consume_nonnegative(test_case, name);
        let mut r = Elem::zero(Width {
            num_limbs,
            m: PhantomData,
        });
        r.limbs_mut()[0..value.limbs().len()].copy_from_slice(value.limbs());
        r
    }

    pub(super) fn consume_modulus<M>(
        test_case: &mut test::TestCase,
        name: &str,
        cpu_features: cpu::Features,
    ) -> Modulus<M> {
        let value = test_case.consume_bytes(name);
        let (value, _) =
            Modulus::from_be_bytes_with_bit_length(untrusted::Input::from(&value), cpu_features)
                .unwrap();
        value
    }

    fn consume_nonnegative(test_case: &mut test::TestCase, name: &str) -> Nonnegative {
        let bytes = test_case.consume_bytes(name);
        let (r, _r_bits) =
            Nonnegative::from_be_bytes_with_bit_length(untrusted::Input::from(&bytes)).unwrap();
        r
    }

    pub(super) fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        if elem_verify_equal_consttime(a, b).is_err() {
            panic!("{:x?} != {:x?}", a.limbs().as_ref(), b.limbs().as_ref());
        }
    }

    pub(crate) fn into_encoded<M>(a: Elem<M, Unencoded>, m: &Modulus<M>) -> Elem<M, R> {
        elem_mul(m.oneRR().as_ref(), a, m)
    }

    #[test]
    // TODO: wasm
    fn test_mul_add_words() {
        const ZERO: Limb = 0;
        const MAX: Limb = ZERO.wrapping_sub(1);
        static TEST_CASES: &[(&[Limb], &[Limb], Limb, Limb, &[Limb])] = &[
            (&[0], &[0], 0, 0, &[0]),
            (&[MAX], &[0], MAX, 0, &[MAX]),
            (&[0], &[MAX], MAX, MAX - 1, &[1]),
            (&[MAX], &[MAX], MAX, MAX, &[0]),
            (&[0, 0], &[MAX, MAX], MAX, MAX - 1, &[1, MAX]),
            (&[1, 0], &[MAX, MAX], MAX, MAX - 1, &[2, MAX]),
            (&[MAX, 0], &[MAX, MAX], MAX, MAX, &[0, 0]),
            (&[0, 1], &[MAX, MAX], MAX, MAX, &[1, 0]),
            (&[MAX, MAX], &[MAX, MAX], MAX, MAX, &[0, MAX]),
        ];

        for (i, (r_input, a, w, expected_retval, expected_r)) in TEST_CASES.iter().enumerate() {
            extern crate std;
            let mut r = std::vec::Vec::from(*r_input);
            assert_eq!(r.len(), a.len()); // Sanity check
            let actual_retval =
                unsafe { limbs_mul_add_limb(r.as_mut_ptr(), a.as_ptr(), *w, a.len()) };
            assert_eq!(&r, expected_r, "{}: {:x?} != {:x?}", i, &r[..], expected_r);
            assert_eq!(
                actual_retval, *expected_retval,
                "{}: {:x?} != {:x?}",
                i, actual_retval, *expected_retval
            );
        }
    }
}
