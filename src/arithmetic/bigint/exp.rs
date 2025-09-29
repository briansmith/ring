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

use super::{
    super::{
        limbs512,
        montgomery::{RInverse, Unencoded, RRR},
        LimbSliceError,
    },
    elem_reduced, Elem, Modulus, One, PrivateExponent, Uninit,
};
use crate::{
    bits::BitLength,
    error::LenMismatchError,
    limb::{self, Limb, LIMB_BITS},
    polyfill::sliceutil::as_chunks_exact,
    window5::Window5,
};
use core::mem::MaybeUninit;

pub fn elem_exp_consttime<N, P>(
    out: Uninit<P>,
    base: &Elem<N>,
    oneRRR: &One<P, RRR>,
    exponent: &PrivateExponent,
    p: &Modulus<P>,
    other_prime_len_bits: BitLength,
) -> Result<Elem<P, Unencoded>, LimbSliceError> {
    // `elem_exp_consttime_inner` is parameterized on `STORAGE_LIMBS` only so
    // we can run tests with larger-than-supported-in-operation test vectors.
    elem_exp_consttime_inner::<N, P, { ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS * STORAGE_ENTRIES }>(
        out,
        base,
        oneRRR,
        exponent,
        p,
        other_prime_len_bits,
    )
}

// The maximum modulus size supported for `elem_exp_consttime` in normal
// operation.
const ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS: usize = 2048 / LIMB_BITS;
const _LIMBS_PER_CHUNK_DIVIDES_ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS: () =
    assert!(ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS % limbs512::LIMBS_PER_CHUNK == 0);
const WINDOW_BITS: u32 = 5;
const TABLE_ENTRIES: usize = 1 << WINDOW_BITS;
const STORAGE_ENTRIES: usize = TABLE_ENTRIES + if cfg!(target_arch = "x86_64") { 3 } else { 0 };

#[cfg(not(target_arch = "x86_64"))]
fn elem_exp_consttime_inner<N, M, const STORAGE_LIMBS: usize>(
    out: Uninit<M>,
    base_mod_n: &Elem<N>,
    oneRRR: &One<M, RRR>,
    exponent: &PrivateExponent,
    m: &Modulus<M>,
    other_prime_len_bits: BitLength,
) -> Result<Elem<M, Unencoded>, LimbSliceError> {
    use super::{
        super::montgomery::{limbs_mul_mont, limbs_square_mont, R},
        elem_mul, elem_squared,
    };
    use crate::{bssl, c, polyfill};

    let base_rinverse: Elem<M, RInverse> = elem_reduced(out, base_mod_n, m, other_prime_len_bits);

    let num_limbs = m.limbs().len();
    let m_chunked = as_chunks_exact::<_, { limbs512::LIMBS_PER_CHUNK }>(m.limbs())
        .ok_or_else(|| LenMismatchError::new(num_limbs))?;
    let cpe = m_chunked.len(); // 512-bit chunks per entry.

    // This code doesn't have the strict alignment requirements that the x86_64
    // version does, but uses the same aligned storage for convenience.
    assert!(STORAGE_LIMBS % (STORAGE_ENTRIES * limbs512::LIMBS_PER_CHUNK) == 0); // TODO: `const`
    let mut table = limbs512::AlignedStorage::<STORAGE_LIMBS>::uninit();
    let table = table.aligned_chunks_mut(TABLE_ENTRIES, cpe)?;

    // TODO: Rewrite the below in terms of `as_chunks`.
    let table = table.as_flattened_mut();

    fn gather<M>(table: &[Limb], acc: &mut Elem<M, R>, i: Window5) {
        prefixed_extern! {
            fn LIMBS_select_512_32(
                r: *mut Limb,
                table: *const Limb,
                num_limbs: c::size_t,
                i: Window5,
            ) -> bssl::Result;
        }
        let acc_len = acc.limbs.len();
        let acc = acc.limbs.as_mut().as_mut_ptr();
        Result::from(unsafe { LIMBS_select_512_32(acc, table.as_ptr(), acc_len, i) }).unwrap();
    }

    fn power<M>(
        table: &[Limb],
        mut acc: Elem<M, R>,
        m: &Modulus<M>,
        i: Window5,
        mut tmp: Elem<M, R>,
    ) -> (Elem<M, R>, Elem<M, R>) {
        for _ in 0..WINDOW_BITS {
            acc = elem_squared(acc, m);
        }
        gather(table, &mut tmp, i);
        let acc = elem_mul(&tmp, acc, m);
        (acc, tmp)
    }

    fn entry(table: &[Limb], i: usize, num_limbs: usize) -> &[Limb] {
        &table[(i * num_limbs)..][..num_limbs]
    }
    fn entry_uninit(
        table: &mut [MaybeUninit<Limb>],
        i: usize,
        num_limbs: usize,
    ) -> polyfill::slice::Uninit<'_, Limb> {
        polyfill::slice::Uninit::from(&mut table[(i * num_limbs)..][..num_limbs])
    }

    // table[0] = base**0 (i.e. 1).
    let _: &[Limb] = One::fillR(entry_uninit(table, 0, num_limbs), m)?;

    // table[1] = base*R == (base/R * RRR)/R
    let _: &[Limb] = limbs_mul_mont(
        (
            entry_uninit(table, 1, num_limbs),
            base_rinverse.limbs.as_ref(),
            oneRRR.as_ref().limbs.as_ref(),
        ),
        m.limbs(),
        m.n0(),
        m.cpu_features(),
    )?;
    for i in 2..TABLE_ENTRIES {
        let (square, src1, src2) = if i % 2 == 0 {
            (true, i / 2, i / 2)
        } else {
            (false, i - 1, 1)
        };
        let (previous, rest) = table.split_at_mut(num_limbs * i);
        let previous = polyfill::slice::Uninit::from(previous);
        let previous = unsafe { previous.assume_init() };
        let dst = entry_uninit(rest, 0, num_limbs);
        let src1 = entry(previous, src1, num_limbs);
        let _: &[Limb] = if square {
            limbs_square_mont((dst, src1), m.limbs(), m.n0(), m.cpu_features())?
        } else {
            let src2 = entry(previous, src2, num_limbs);
            limbs_mul_mont((dst, src1, src2), m.limbs(), m.n0(), m.cpu_features())?
        };
    }
    let table = polyfill::slice::Uninit::from(table);
    let table = unsafe { table.assume_init() };

    // Recycle the storage; the value will get overwritten.
    let mut acc = base_rinverse.transmute_encoding_less_safe::<R>();

    // TODO: We shouldn't need to write zeros here.
    let tmp = m.alloc_uninit().write_zeros();
    let tmp = Elem::<M, R>::assume_in_range_and_encoded_less_safe(tmp);

    let (acc, _) = limb::fold_5_bit_windows(
        exponent.limbs(),
        |initial_window| {
            gather(table, &mut acc, initial_window);
            (acc, tmp)
        },
        |(acc, tmp), window| power(table, acc, m, window, tmp),
    );

    Ok(acc.into_unencoded(m))
}

#[cfg(target_arch = "x86_64")]
fn elem_exp_consttime_inner<N, M, const STORAGE_LIMBS: usize>(
    out: Uninit<M>,
    base_mod_n: &Elem<N>,
    oneRRR: &One<M, RRR>,
    exponent: &PrivateExponent,
    m: &Modulus<M>,
    other_prime_len_bits: BitLength,
) -> Result<Elem<M, Unencoded>, LimbSliceError> {
    use super::{
        super::{
            limbs::x86_64::mont::{
                gather5, mul_mont5, mul_mont_gather5_amm, power5_amm, sqr_mont5,
            },
            limbs512::scatter5,
            montgomery::N0,
        },
        from_montgomery_amm, unwrap_impossible_limb_slice_error,
    };
    use crate::{
        cpu::{
            intel::{Adx, Bmi2},
            GetFeature as _,
        },
        polyfill,
        window5::LeakyWindow5,
    };

    let n0 = m.n0();

    let cpu2 = m.cpu_features().get_feature();
    let cpu3 = m.cpu_features().get_feature();

    if base_mod_n.limbs.len() != m.limbs().len() * 2 {
        Err(LenMismatchError::new(base_mod_n.limbs.len()))?;
    }

    let m_len = m.limbs().len();
    // 512-bit chunks per entry
    let cpe = as_chunks_exact::<_, { limbs512::LIMBS_PER_CHUNK }>(m.limbs())
        .ok_or_else(|| LenMismatchError::new(m_len))?
        .len();

    let oneRRR = oneRRR.as_ref().limbs.as_ref();

    // The x86_64 assembly was written under the assumption that the input data
    // is aligned to `MOD_EXP_CTIME_ALIGN` bytes, which was/is 64 in OpenSSL.
    // Subsequently, it was changed such that, according to BoringSSL, they
    // only require 16 byte alignment. We enforce the old, stronger, alignment
    // unless/until we can see a benefit to reducing it.
    //
    // Similarly, OpenSSL uses the x86_64 assembly functions by giving it only
    // inputs `tmp`, `am`, and `np` that immediately follow the table.
    // According to BoringSSL, in older versions of the OpenSSL code, this
    // extra space was required for memory safety because the assembly code
    // would over-read the table; according to BoringSSL, this is no longer the
    // case. Regardless, the upstream code also contained comments implying
    // that this was also important for performance. For now, we do as OpenSSL
    // did/does.
    const MOD_EXP_CTIME_ALIGN: usize = 64;
    // Required by
    const _TABLE_ENTRIES_IS_32: () = assert!(TABLE_ENTRIES == 32);
    const _STORAGE_ENTRIES_HAS_3_EXTRA: () = assert!(STORAGE_ENTRIES == TABLE_ENTRIES + 3);

    assert!(STORAGE_LIMBS % (STORAGE_ENTRIES * limbs512::LIMBS_PER_CHUNK) == 0); // TODO: `const`
    let mut table = limbs512::AlignedStorage::<STORAGE_LIMBS>::uninit();
    let table = table.aligned_chunks_mut(STORAGE_ENTRIES, cpe)?;
    let (table, state) = table.split_at_mut(TABLE_ENTRIES * cpe);
    assert_eq!((table.as_ptr() as usize) % MOD_EXP_CTIME_ALIGN, 0);

    // These are named `(tmp, am, np)` in BoringSSL.
    let state = state.as_flattened_mut();
    let (acc, rest) = state.split_at_mut(m_len);
    let (base_cached, m_cached) = rest.split_at_mut(m_len);

    // "To improve cache locality" according to upstream.
    let (m_cached, _) = polyfill::slice::Uninit::from(m_cached)
        .write_copy_of_slice_checked(m.limbs())?
        .as_chunks();

    let out: Elem<M, RInverse> = elem_reduced(out, base_mod_n, m, other_prime_len_bits);
    let base_rinverse = out.limbs.as_ref();

    // base_cached = base*R == (base/R * RRR)/R
    let base_cached: &[Limb] = mul_mont5(
        base_cached.into(),
        base_rinverse,
        oneRRR,
        m_cached,
        n0,
        cpu2,
    )?;
    let mut out = out.limbs; // recycle.

    // Fill in all the powers of 2 of `acc` into the table using only squaring and without any
    // gathering, storing the last calculated power into `acc`.
    fn scatter_powers_of_2(
        table: &mut [[MaybeUninit<Limb>; 8]],
        mut acc: &mut [Limb],
        m_cached: &[[Limb; 8]],
        n0: &N0,
        mut i: LeakyWindow5,
        cpu: Option<(Adx, Bmi2)>,
    ) -> Result<(), LimbSliceError> {
        loop {
            scatter5(acc, table, i)?;
            i = match i.checked_double() {
                Some(i) => i,
                None => break,
            };
            acc = sqr_mont5(acc, m_cached, n0, cpu)?;
        }
        Ok(())
    }

    // All entries in `table` will be Montgomery encoded.

    // t0 = table[0] = base**0 (i.e. 1).
    let t0 = One::fillR(acc.as_mut().into(), m)?;
    scatter5(t0, table, LeakyWindow5::_0)?;

    // acc = base**1 (i.e. base).
    let acc = polyfill::slice::Uninit::from(acc).write_copy_of_slice_checked(base_cached)?;

    // Fill in entries 1, 2, 4, 8, 16.
    scatter_powers_of_2(table, acc, m_cached, n0, LeakyWindow5::_1, cpu2)?;
    // Fill in entries 3, 6, 12, 24; 5, 10, 20, 30; 7, 14, 28; 9, 18; 11, 22; 13, 26; 15, 30;
    // 17; 19; 21; 23; 25; 27; 29; 31.
    for i in LeakyWindow5::range().skip(3).step_by(2) {
        let power = Window5::from(i.checked_pred().unwrap_or_else(|| {
            // Since i >= 3.
            unreachable!()
        }));
        // SAFETY: Entry `power` was previously written; see the comments above.
        unsafe { mul_mont_gather5_amm(acc, base_cached, table, m_cached, n0, power, cpu3) }?;
        scatter_powers_of_2(table, acc, m_cached, n0, i, cpu2)?;
    }
    let table = polyfill::slice::Uninit::from(table.as_flattened_mut());
    let table = unsafe { table.assume_init() };
    let (table, _) = table.as_chunks();

    let acc = limb::fold_5_bit_windows(
        exponent.limbs(),
        |initial_window| {
            gather5(acc, table, initial_window).unwrap_or_else(unwrap_impossible_limb_slice_error);
            acc
        },
        |acc, window| {
            power5_amm(acc, table, m_cached, n0, window, cpu3)
                .unwrap_or_else(unwrap_impossible_limb_slice_error);
            acc
        },
    );

    out.as_mut().copy_from_slice(acc);
    Ok(from_montgomery_amm(out, m))
}

#[cfg(test)]
mod tests {
    use super::super::PublicModulus;
    use super::{
        super::{testutil::*, *},
        *,
    };
    use crate::testutil as test;
    use crate::{cpu, error};

    // Type-level representation of an arbitrary modulus.
    struct M {}

    impl PublicModulus for M {}

    #[test]
    fn test_elem_exp_consttime() {
        let cpu_features = cpu::features();
        test::run(
            test_vector_file!("../../../crypto/fipsmodule/bn/test/mod_exp_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m = consume_modulus::<M>(test_case, "M");
                let m = m.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModExp", &m);
                let base = consume_elem(test_case, "A", &m);
                let e = {
                    let bytes = test_case.consume_bytes("E");
                    PrivateExponent::from_be_bytes_for_test_only(untrusted::Input::from(&bytes), &m)
                        .expect("valid exponent")
                };

                let oneRR = One::newRR(m.alloc_uninit(), &m)
                    .map_err(error::erase::<LenMismatchError>)
                    .unwrap();
                let oneRRR = One::newRRR(oneRR, &m);

                // `base` in the test vectors is reduced (mod M) already but
                // the API expects the bsae to be (mod N) where N = M * P for
                // some other prime of the same length. Fake that here.
                // Pretend there's another prime of equal length.
                struct N {}
                let other_modulus_len_bits = m.len_bits();
                let base: Elem<N> = {
                    let limbs = Uninit::new_less_safe(base.limbs.len() * 2)
                        .write_copy_of_slice_padded(base.limbs.as_ref())
                        .unwrap_or_else(unwrap_impossible_len_mismatch_error);
                    Elem::<N, Unencoded>::assume_in_range_and_encoded_less_safe(limbs)
                };

                let too_big = m.limbs().len() > ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS;
                let actual_result = if !too_big {
                    elem_exp_consttime(
                        m.alloc_uninit(),
                        &base,
                        &oneRRR,
                        &e,
                        &m,
                        other_modulus_len_bits,
                    )
                } else {
                    let actual_result = elem_exp_consttime(
                        m.alloc_uninit(),
                        &base,
                        &oneRRR,
                        &e,
                        &m,
                        other_modulus_len_bits,
                    );
                    // TODO: Be more specific with which error we expect?
                    assert!(actual_result.is_err());
                    // Try again with a larger-than-normally-supported limit
                    elem_exp_consttime_inner::<_, _, { (4096 / LIMB_BITS) * STORAGE_ENTRIES }>(
                        m.alloc_uninit(),
                        &base,
                        &oneRRR,
                        &e,
                        &m,
                        other_modulus_len_bits,
                    )
                };
                match actual_result {
                    Ok(r) => assert_elem_eq(&r, &expected_result),
                    Err(LimbSliceError::LenMismatch { .. }) => panic!(),
                    Err(LimbSliceError::TooLong { .. }) => panic!(),
                    Err(LimbSliceError::TooShort { .. }) => panic!(),
                };

                Ok(())
            },
        )
    }
}
