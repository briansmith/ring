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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::super::{
    super::montgomery::{R, RR},
    Limb, Mont, elem,
};
use crate::{
    bits::BitLength,
    error::LenMismatchError,
    limb::{self, LIMB_BITS},
    polyfill::slice::Cursor,
};
use core::{marker::PhantomData, mem::size_of};

// The value 1, Montgomery-encoded some number of times.
pub struct One<'a, M, E> {
    value: &'a [Limb],
    m: PhantomData<M>,
    encoding: PhantomData<E>,
}

impl<M, E> One<'_, M, E> {
    pub(super) fn from_limbs_unchecked_less_safe(value: &[Limb]) -> One<'_, M, E> {
        One {
            value,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub(in super::super) fn leak_limbs_less_safe(&self) -> &[Limb] {
        self.value
    }
}

impl<M> One<'_, M, R> {
    pub(in super::super) fn write_mont_identity_assuming_full_upper_limb<'r>(
        out: &mut Cursor<'r, Limb>,
        m: &Mont<'_, M>,
    ) -> Result<elem::Mut<'r, M, R>, LenMismatchError> {
        // out = 2**r - m where m = self.
        let r = limb::write_negative_assume_odd(out, m.limbs())?;
        Ok(elem::Mut::<'r, M, R>::assume_in_range_and_encoded_less_safe(r))
    }

    pub(in super::super) fn write_mont_identity<'r>(
        out: &mut Cursor<'r, Limb>,
        m: &Mont<'_, M>,
        m_bit_len: BitLength,
    ) -> Result<elem::Mut<'r, M, R>, LenMismatchError> {
        let mut out = Self::write_mont_identity_assuming_full_upper_limb(out, m)?;

        let r = m.limbs().len() * LIMB_BITS;
        let lg_m = m_bit_len.as_bits();
        let leading_zero_bits_in_m = r - lg_m;

        // When m's length is a multiple of LIMB_BITS, which is the case we
        // most want to optimize for, then we already have
        // out == 2**r - m == 2**r (mod m).
        if leading_zero_bits_in_m != 0 {
            debug_assert!(leading_zero_bits_in_m < LIMB_BITS);
            // Correct out to 2**(lg m) (mod m).
            // `write_mont_identity_assuming_full_upper_limb` flipped all the
            // leading zero bits to ones. Flip them back.
            *out.leak_limbs_mut_less_safe().last_mut().unwrap() &= (!0) >> leading_zero_bits_in_m;

            // Now we have out == 2**(lg m) (mod m). Keep doubling until we get
            // to 2**r (mod m).
            for _ in 0..leading_zero_bits_in_m {
                out = out.double(m);
            }
        }

        Ok(out)
    }
}

impl<'l, M> elem::Mut<'l, M, R> {
    // `self *= R (mod_m)`, where R is the Montgomery multiplication identity
    // element (a * R / R = a).
    //
    // Even though the assembly on some 32-bit platforms works with 64-bit
    // values, using `LIMB_BITS` here, rather than `N0::LIMBS_USED * LIMB_BITS`,
    // is correct because R**2 will still be a multiple of the latter as
    // `N0::LIMBS_USED` is either one or two.
    pub(crate) fn mul_r(
        mut self,
        m: &Mont<'_, M>,
    ) -> Result<elem::Mut<'l, M, RR>, LenMismatchError> {
        // The number of limbs in the numbers involved.
        let w = m.limbs().len();

        // The length of the numbers involved, in bits. R = 2**r.
        let r = w * LIMB_BITS;

        // 2**t * R can be calculated by t doublings starting with R.
        //
        // Choose a t that divides r and where t doublings are cheaper than 1 squaring.
        //
        // We could choose other values of t than w. But if t < d then the exponentiation that
        // follows would require multiplications. Normally d is 1 (i.e. the modulus length is a
        // power of two: RSA 1024, 2048, 4097, 8192) or 3 (RSA 1536, 3072).
        //
        // XXX(perf): Currently t = w / 2 is slightly faster. TODO(perf): Optimize `elem_double`
        // and re-run benchmarks to rebalance this.
        let t = w;
        let z = w.trailing_zeros();
        let d = w >> z;
        debug_assert_eq!(w, d * (1 << z));
        debug_assert!(d <= t);
        debug_assert!(t < r);
        for _ in 0..t {
            self = self.double(m);
        }

        // Because t | r:
        //
        //     MontExp(2**t * R, r / t)
        //   = (2**t)**(r / t)   * R (mod m) by definition of MontExp.
        //   = (2**t)**(1/t * r) * R (mod m)
        //   = (2**(t * 1/t))**r * R (mod m)
        //   = (2**1)**r         * R (mod m)
        //   = 2**r              * R (mod m)
        //   = R * R                 (mod m)
        //   = RR
        //
        // Like BoringSSL, use t = w (`m.limbs.len()`) which ensures that the exponent is a power
        // of two. Consequently, there will be no multiplications in the Montgomery exponentiation;
        // there will only be lg(r / t) squarings.
        //
        //     lg(r / t)
        //   = lg((w * 2**b) / t)
        //   = lg((t * 2**b) / t)
        //   = lg(2**b)
        //   = b
        // TODO(MSRV:1.67): const B: u32 = LIMB_BITS.ilog2();
        const B: u32 = match size_of::<Limb>() {
            8 => 6,
            4 => 5,
            _ => panic!("unsupported limb size"),
        };
        #[allow(clippy::assertions_on_constants)]
        const _LIMB_BITS_IS_2_POW_B: () = assert!(LIMB_BITS == 1 << B);
        debug_assert_eq!(r, t * (1 << B));
        for _ in 0..B {
            self = self.square(m);
        }

        Ok(
            elem::Mut::<'l, M, RR>::assume_in_range_and_encoded_less_safe(
                self.leak_limbs_into_mut_less_safe(),
            ),
        )
    }
}
