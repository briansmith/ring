// Copyright 2015-2022 Brian Smith.
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

use super::{elem_exp_vartime, elem_mul_by_2, Elem, PartialModulus, PublicModulus};
use crate::{arithmetic::montgomery::*, bits, limb::LIMB_BITS, polyfill::u64_from_usize};
use core::num::NonZeroU64;

// The value 1, Montgomery-encoded some number of times.
pub(crate) struct One<M, E>(Elem<M, E>);

impl<M> One<M, RR> {
    // Returns RR = = R**2 (mod n) where R = 2**r is the smallest power of
    // 2**LIMB_BITS such that R > m.
    //
    // Even though the assembly on some 32-bit platforms works with 64-bit
    // values, using `LIMB_BITS` here, rather than `N0_LIMBS_USED * LIMB_BITS`,
    // is correct because R**2 will still be a multiple of the latter as
    // `N0_LIMBS_USED` is either one or two.
    pub(super) fn newRR(m: &PartialModulus<M>, m_bits: bits::BitLength) -> Self {
        let m_bits = m_bits.as_usize_bits();
        let r = (m_bits + (LIMB_BITS - 1)) / LIMB_BITS * LIMB_BITS;

        // base = 2**(lg m - 1).
        let bit = m_bits - 1;
        let mut base = m.zero();
        base.limbs_mut()[bit / LIMB_BITS] = 1 << (bit % LIMB_BITS);

        // Double `base` so that base == R == 2**r (mod m). For normal moduli
        // that have the high bit of the highest limb set, this requires one
        // doubling. Unusual moduli require more doublings but we are less
        // concerned about the performance of those.
        //
        // Then double `base` again so that base == 2*R (mod n), i.e. `2` in
        // Montgomery form (`elem_exp_vartime()` requires the base to be in
        // Montgomery form). Then compute
        // RR = R**2 == base**r == R**r == (2**r)**r (mod n).
        //
        // Take advantage of the fact that `elem_mul_by_2` is faster than
        // `elem_squared` by replacing some of the early squarings with shifts.
        // TODO: Benchmark shift vs. squaring performance to determine the
        // optimal value of `LG_BASE`.
        const LG_BASE: usize = 2; // Shifts vs. squaring trade-off.
        debug_assert_eq!(LG_BASE.count_ones(), 1); // Must be 2**n for n >= 0.
        let shifts = r - bit + LG_BASE;
        // `m_bits >= LG_BASE` (for the currently chosen value of `LG_BASE`)
        // since we require the modulus to have at least `MODULUS_MIN_LIMBS`
        // limbs. `r >= m_bits` as seen above. So `r >= LG_BASE` and thus
        // `r / LG_BASE` is non-zero.
        //
        // The maximum value of `r` is determined by
        // `MODULUS_MAX_LIMBS * LIMB_BITS`. Further `r` is a multiple of
        // `LIMB_BITS` so the maximum Hamming Weight is bounded by
        // `MODULUS_MAX_LIMBS`. For the common case of {2048, 4096, 8192}-bit
        // moduli the Hamming weight is 1. For the other common case of 3072
        // the Hamming weight is 2.
        let exponent = NonZeroU64::new(u64_from_usize(r / LG_BASE)).unwrap();
        for _ in 0..shifts {
            elem_mul_by_2(&mut base, m)
        }
        let RR = elem_exp_vartime(base, exponent, m);

        Self(Elem::new_unchecked(RR.into_limbs()))
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> {
        &self.0
    }
}

impl<M: PublicModulus, E> Clone for One<M, E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
