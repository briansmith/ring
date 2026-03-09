// Copyright 2015-2023 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use self::boxed_limbs::BoxedLimbs;
use super::{LimbSliceError, MAX_LIMBS, montgomery::*};
use crate::{
    error::{self, LenMismatchError},
    limb::{self, Limb},
};
pub(crate) use {
    self::{
        boxed_limbs::Uninit,
        elem::{Elem, elem_verify_equal_consttime, verify_inverses_consttime},
        exp::elem_exp_consttime,
        modulus::{BoxedIntoMont, IntoMont, Mont, One},
        oversized_uninit::OversizedUninit,
        private_exponent::PrivateExponent,
    },
    super::exp_vartime::elem_exp_vartime,
};

mod boxed_limbs;
mod elem;
mod exp;
pub mod modulus;
mod oversized_uninit;
mod private_exponent;

pub trait PublicModulus {}

impl<M> Uninit<M> {
    pub fn into_elem_from_be_bytes_padded(
        self,
        input: untrusted::Input<'_>,
        m: &Mont<M>,
    ) -> Result<Elem<M>, error::Unspecified> {
        self.write_from_be_bytes_padded(input)
            .map_err(error::erase::<LenMismatchError>)
            .and_then(|out| Elem::from_limbs(out, m))
    }
}

impl<M> Elem<M, Unencoded> {
    fn from_limbs(
        out: BoxedLimbs<M>,
        m: &Mont<M>,
    ) -> Result<Elem<M, Unencoded>, error::Unspecified> {
        limb::verify_limbs_less_than_limbs_leak_bit(out.as_ref(), m.limbs())?;
        Ok(Elem::assume_in_range_and_encoded_less_safe(out))
    }
}

#[cold]
#[inline(never)]
fn unwrap_impossible_len_mismatch_error<T>(LenMismatchError { .. }: LenMismatchError) -> T {
    unreachable!()
}

#[cold]
#[inline(never)]
fn unwrap_impossible_limb_slice_error<T>(err: LimbSliceError) -> T {
    match err {
        LimbSliceError::LenMismatch(_) => unreachable!(),
        LimbSliceError::TooShort(_) => unreachable!(),
        LimbSliceError::TooLong(_) => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{elem::testutil::*, modulus::testutil::*};
    use crate::cpu;
    use crate::testutil as test;

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
            test_vector_file!("../../crypto/fipsmodule/bn/test/mod_mul_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m_owned = consume_modulus::<M>(test_case, "M");
                let m_owned = m_owned.reborrow();
                let m = m_owned.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModMul", &m);
                let a = consume_elem(test_case, "A", &m).encode_mont(&m_owned, cpu_features);
                let b = consume_elem(test_case, "B", &m).encode_mont(&m_owned, cpu_features);
                let actual_result = a.mul(&b, &m);
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
            test_vector_file!("bigint_elem_squared_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m_owned = consume_modulus::<M>(test_case, "M");
                let m_owned = m_owned.reborrow();
                let m = m_owned.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModSquare", &m);
                let a = consume_elem(test_case, "A", &m).encode_mont(&m_owned, cpu_features);
                let actual_result = a.square(&m);
                let actual_result = actual_result.into_unencoded(&m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced_mont() {
        let cpu_features = cpu::features();
        test::run(
            test_vector_file!("bigint_elem_reduced_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct M {}

                let m_ = consume_modulus::<M>(test_case, "M");
                let m_ = m_.reborrow();
                let m = m_.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "R", &m);
                let a =
                    consume_elem_unchecked::<M>(test_case, "A", expected_result.num_limbs() * 2);
                let other_modulus_len_bits = m_.len_bits();

                let actual_result = m
                    .alloc_uninit()
                    .elem_reduce_mont(&a, &m, other_modulus_len_bits)
                    .encode_mont(&m_, cpu_features);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced_once() {
        let cpu_features = cpu::features();
        test::run(
            test_vector_file!("bigint_elem_reduced_once_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct M {}
                struct O {}
                let m = consume_modulus::<M>(test_case, "m");
                let m = m.reborrow();
                let m = m.modulus(cpu_features);
                let a = consume_elem_unchecked::<O>(test_case, "a", m.limbs().len());
                let expected_result = consume_elem::<M>(test_case, "r", &m);
                let other_modulus_len_bits = m.len_bits();

                let actual_result =
                    m.alloc_uninit()
                        .elem_reduced_once(&a, &m, other_modulus_len_bits);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }
}
