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
        LimbSliceError, limbs512,
        montgomery::{RRR, Unencoded},
    },
    IntoMont, Mont, One, OversizedUninit, PrivateExponent, elem,
};
use crate::{
    bits::BitLength,
    cpu,
    error::LenMismatchError,
    limb::{self, LIMB_BITS, Limb},
    window5::Window5,
};
use core::mem::MaybeUninit;

impl<N> elem::Ref<'_, N, Unencoded> {
    pub(crate) fn exp_consttime<'out, P>(
        self,
        out: &'out mut OversizedUninit<1>,
        exponent: &PrivateExponent,
        p: &IntoMont<P, RRR>,
        other_prime_len_bits: BitLength,
        tmp: &mut OversizedUninit<1>,
        cpu: cpu::Features,
    ) -> Result<elem::Mut<'out, P, Unencoded>, LimbSliceError> {
        let oneRRR = p.one();
        let p = &p.modulus(cpu);

        // `elem_exp_consttime_inner` is parameterized on `STORAGE_LIMBS` only so
        // we can run tests with larger-than-supported-in-operation test vectors.
        elem_exp_consttime_inner::<N, P, { ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS * STORAGE_ENTRIES }>(
            out,
            self,
            &oneRRR,
            exponent,
            p,
            other_prime_len_bits,
            tmp,
        )
    }
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
fn elem_exp_consttime_inner<'out, N, M, const STORAGE_LIMBS: usize>(
    out: &'out mut OversizedUninit<1>,
    base_mod_n: elem::Ref<'_, N, Unencoded>,
    oneRRR: &One<'_, M, RRR>,
    exponent: &PrivateExponent,
    m: &Mont<M>,
    other_prime_len_bits: BitLength,
    tmp: &mut OversizedUninit<1>,
) -> Result<elem::Mut<'out, M, Unencoded>, LimbSliceError> {
    use super::{
        super::montgomery::{R, limbs_mul_mont, limbs_square_mont},
        elem,
    };
    use crate::{
        bssl, c, error,
        polyfill::{self, StartMutPtr, dynarray},
    };

    let base_rinverse = base_mod_n.reduced_mont(out, m, other_prime_len_bits);

    let num_limbs = m.num_limbs();
    if num_limbs.get() % limbs512::LIMBS_PER_CHUNK != 0 {
        Err(LenMismatchError::new(num_limbs.get()))?
    }

    fn gather<'out, M>(
        mut out: polyfill::slice::Uninit<'out, Limb>,
        table: &[Limb],
        i: Window5,
    ) -> Result<elem::Mut<'out, M, R>, LenMismatchError> {
        prefixed_extern! {
            unsafe fn LIMBS_select_512_32(
                r: *mut Limb,
                table: *const Limb,
                num_limbs: c::size_t,
                i: Window5,
            ) -> bssl::Result;
        }
        if table.len() % 32 != 0 || out.len() != table.len() / 32 {
            return Err(LenMismatchError::new(out.len()));
        }
        Result::from(unsafe {
            LIMBS_select_512_32(out.start_mut_ptr(), table.as_ptr(), out.len(), i)
        })
        .map_err(|_: error::Unspecified| LenMismatchError::new(out.len()))?;
        let r = unsafe { out.assume_init() };
        Ok(elem::Mut::assume_in_range_and_encoded_less_safe(r))
    }

    fn power<'acc, M>(
        table: &[Limb],
        mut acc: elem::Mut<'acc, M, R>,
        m: &Mont<M>,
        i: Window5,
        tmp: polyfill::slice::Uninit<'_, Limb>,
    ) -> Result<elem::Mut<'acc, M, R>, LenMismatchError> {
        for _ in 0..WINDOW_BITS {
            acc = acc.square(m);
        }
        let tmp = gather(tmp, table, i)?;
        let acc = acc.mul(tmp.as_ref(), m);
        Ok(acc)
    }

    let mut storage: [MaybeUninit<Limb>; STORAGE_LIMBS] =
        [const { MaybeUninit::uninit() }; STORAGE_LIMBS];
    let table = dynarray::Uninit::new(&mut storage, STORAGE_ENTRIES, num_limbs)?.init_fold(
        |init, uninit| {
            let r: Result<&'_ mut [Limb], LimbSliceError> = match init.len() {
                // table[0] = base**0 (i.e. 1).
                0 => Ok(One::write_mont_identity(&mut uninit.into_cursor(), m)?),

                // table[1] = base*R == (base/R * RRR)/R
                1 => limbs_mul_mont(
                    (
                        uninit,
                        base_rinverse.leak_limbs_less_safe(),
                        oneRRR.leak_limbs_less_safe(),
                    ),
                    m.limbs(),
                    m.n0(),
                    m.cpu_features(),
                ),

                // table[2*i] = (n**i)**2/R
                i if i % 2 == 0 => {
                    let sqrt = init.mid().unwrap_or_else(|| unreachable!());
                    limbs_square_mont((uninit, sqrt), m.limbs(), m.n0(), m.cpu_features())
                }

                // table[i + 1] = n**1*n**i/R
                _ => {
                    let one = init.get(1).unwrap_or_else(|| unreachable!());
                    let previous = init.last().unwrap_or_else(|| unreachable!());
                    limbs_mul_mont((uninit, one, previous), m.limbs(), m.n0(), m.cpu_features())
                }
            };
            r.map_err(|e| match e {
                LimbSliceError::LenMismatch(e) => e, // Also unreachable.
                LimbSliceError::TooLong(_) => unreachable!(),
                LimbSliceError::TooShort(_) => unreachable!(),
            })
        },
    )?;
    let table: &[Limb] = table.as_flattened();

    let mut tmp = tmp
        .as_uninit(..num_limbs.get())
        .unwrap_or_else(|LenMismatchError { .. }| unreachable!()); // Because it's oversized.

    let acc = limb::fold_5_bit_windows(
        exponent.limbs(),
        |initial_window| {
            let out = out
                .as_uninit(..num_limbs.get())
                .unwrap_or_else(|LenMismatchError { .. }| unreachable!()); // Because it's oversized.
            gather(out, table, initial_window).unwrap_or_else(|_| unreachable!())
        },
        |acc, window| {
            power(table, acc, m, window, tmp.reborrow_mut()).unwrap_or_else(|_| unreachable!())
        },
    );

    Ok(acc.into_unencoded(m)?)
}

#[cfg(target_arch = "x86_64")]
fn elem_exp_consttime_inner<'out, N, M, const STORAGE_LIMBS: usize>(
    out: &'out mut OversizedUninit<1>,
    base_mod_n: elem::Ref<'_, N, Unencoded>,
    oneRRR: &One<M, RRR>,
    exponent: &PrivateExponent,
    m: &Mont<M>,
    other_prime_len_bits: BitLength,
    _tmp: &mut OversizedUninit<1>,
) -> Result<elem::Mut<'out, M, Unencoded>, LimbSliceError> {
    use super::{
        super::{
            limbs::x86_64::mont::{
                gather5, mul_mont_gather5_amm, mul_mont5, power5_amm, sqr_mont5,
            },
            limbs512::scatter::scatter5,
            montgomery::{N0, RInverse},
        },
        elem::MutAmm,
        unwrap_impossible_limb_slice_error,
    };
    use crate::{
        cpu::{
            GetFeature as _,
            intel::{Adx, Bmi2},
        },
        polyfill::{self, sliceutil::as_chunks_exact},
        window5::LeakyWindow5,
    };

    let n0 = m.n0();

    let cpu2 = m.cpu_features().get_feature();
    let cpu3 = m.cpu_features().get_feature();

    let m_len = m.num_limbs();
    if base_mod_n.num_limbs() != 2 * m_len.get() {
        Err(LenMismatchError::new(base_mod_n.num_limbs()))?;
    }

    let m_len = m.limbs().len();
    // 512-bit chunks per entry
    let cpe = as_chunks_exact::<_, { limbs512::LIMBS_PER_CHUNK }>(m.limbs())
        .ok_or_else(|| LenMismatchError::new(m_len))?
        .len();

    let oneRRR = oneRRR.leak_limbs_less_safe();

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
    let mut table = limbs512::storage::AlignedStorage::<STORAGE_LIMBS>::uninit();
    let table = table.aligned_chunks_mut(STORAGE_ENTRIES, cpe)?;
    let (table, state) = table.split_at_mut(TABLE_ENTRIES * cpe);
    assert_eq!((table.as_ptr() as usize) % MOD_EXP_CTIME_ALIGN, 0);

    // These are named `(tmp, am, np)` in BoringSSL.
    let state = state.as_flattened_mut();
    let (acc, rest) = state.split_at_mut(m_len);
    let (base_cached, m_cached) = rest.split_at_mut(m_len);

    let mut acc = polyfill::slice::Uninit::from(acc);

    // "To improve cache locality" according to upstream.
    let (m_cached, _) = polyfill::slice::Uninit::from(m_cached)
        .write_copy_of_slice(m.limbs())?
        .uninit_empty()?
        .into_written()
        .as_chunks();

    let base_mod_m: elem::Mut<'_, M, RInverse> =
        base_mod_n.reduced_mont(out, m, other_prime_len_bits);
    let base_rinverse = base_mod_m.leak_limbs_less_safe();

    // base_cached = base*R == (base/R * RRR)/R
    let base_cached: &[Limb] = mul_mont5(
        base_cached.into(),
        base_rinverse,
        oneRRR,
        m_cached,
        n0,
        cpu2,
    )?;

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
    let t0 = One::write_mont_identity(&mut acc.reborrow_mut().into_cursor(), m)?;
    scatter5(t0, table, LeakyWindow5::_0)?;

    // acc = base**1 (i.e. base).
    let acc = acc
        .write_copy_of_slice(base_cached)?
        .uninit_empty()?
        .into_written();

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

    let out: MutAmm<'out, M> = MutAmm::copy_from_limbs_assume_amm_and_encoded(out, acc)?;
    Ok(out.reduced_mont(m)?)
}

#[cfg(test)]
mod tests {
    use super::super::elem::testutil::*;
    use super::super::{
        Elem, PublicModulus, Uninit, modulus, unwrap_impossible_len_mismatch_error,
    };
    use super::*;
    use crate::cpu;
    use crate::testutil as test;

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

                let m_input = test_case.consume_bytes("M");
                let m_input =
                    modulus::ValidatedInput::try_from_be_bytes(untrusted::Input::from(&m_input))
                        .unwrap();
                let im = &m_input
                    .build_boxed_into_mont::<M>(cpu_features)
                    .intoRRR(cpu_features);
                let im = &im.reborrow();
                let m = im.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModExp", &m);
                let base = consume_elem(test_case, "A", &m);
                let e = {
                    let bytes = test_case.consume_bytes("E");
                    PrivateExponent::from_be_bytes_for_test_only(untrusted::Input::from(&bytes), &m)
                        .expect("valid exponent")
                };

                // `base` in the test vectors is reduced (mod M) already but
                // the API expects the bsae to be (mod N) where N = M * P for
                // some other prime of the same length. Fake that here.
                // Pretend there's another prime of equal length.
                struct N {}
                let other_modulus_len_bits = m.len_bits();
                let base: Elem<N> = {
                    let limbs = Uninit::new_less_safe(base.as_ref().num_limbs() * 2)
                        .write_copy_of_slice_padded(base.as_ref().leak_limbs_less_safe())
                        .unwrap_or_else(unwrap_impossible_len_mismatch_error);
                    Elem::<N, Unencoded>::assume_in_range_and_encoded_less_safe(limbs)
                };

                let too_big = m.limbs().len() > ELEM_EXP_CONSTTIME_MAX_MODULUS_LIMBS;
                let mut actual_result = OversizedUninit::new();
                let mut actual_result_2 = OversizedUninit::new();
                let mut tmp = OversizedUninit::new();
                let actual_result = if !too_big {
                    base.as_ref().exp_consttime(
                        &mut actual_result,
                        &e,
                        im,
                        other_modulus_len_bits,
                        &mut tmp,
                        cpu_features,
                    )
                } else {
                    let actual_result = base.as_ref().exp_consttime(
                        &mut actual_result,
                        &e,
                        im,
                        other_modulus_len_bits,
                        &mut tmp,
                        cpu_features,
                    );
                    // TODO: Be more specific with which error we expect?
                    assert!(actual_result.is_err());
                    // Try again with a larger-than-normally-supported limit
                    elem_exp_consttime_inner::<_, _, { (4096 / LIMB_BITS) * STORAGE_ENTRIES }>(
                        &mut actual_result_2,
                        base.as_ref(),
                        &im.one(),
                        &e,
                        &m,
                        other_modulus_len_bits,
                        &mut tmp,
                    )
                };
                match actual_result {
                    Ok(r) => assert_elem_eq(r.as_ref(), expected_result.as_ref()),
                    Err(LimbSliceError::LenMismatch { .. }) => panic!(),
                    Err(LimbSliceError::TooLong { .. }) => panic!(),
                    Err(LimbSliceError::TooShort { .. }) => panic!(),
                };

                Ok(())
            },
        )
    }
}
