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

use super::{
    super::montgomery::{N0, R, RR, RRR},
    elem::{elem_double, elem_squared},
    modulus, Elem, Limb, Modulus, PublicModulus, Uninit,
};
use crate::{
    cpu,
    error::LenMismatchError,
    limb::{self, LIMB_BITS},
    polyfill,
};
use core::mem::size_of;

// The value 1, Montgomery-encoded some number of times.
pub struct One<M, E> {
    value: Elem<M, E>,
    n0: N0,
}

impl<M, E> One<M, E> {
    pub(super) fn n0(&self) -> &N0 {
        &self.n0
    }
}

impl<M> One<M, R> {
    pub(super) fn fillR<'r>(
        out: polyfill::slice::Uninit<'r, Limb>,
        m: &Modulus<'_, M>,
    ) -> Result<&'r mut [Limb], LenMismatchError> {
        let r = m.limbs().len() * LIMB_BITS;

        // out = 2**r - m where m = self.
        let out = limb::limbs_negative_odd(out, m.limbs())?;

        let lg_m = m.len_bits().as_bits();
        let leading_zero_bits_in_m = r - lg_m;

        // When m's length is a multiple of LIMB_BITS, which is the case we
        // most want to optimize for, then we already have
        // out == 2**r - m == 2**r (mod m).
        if leading_zero_bits_in_m != 0 {
            debug_assert!(leading_zero_bits_in_m < LIMB_BITS);
            // Correct out to 2**(lg m) (mod m). `limbs_negative_odd` flipped
            // all the leading zero bits to ones. Flip them back.
            *out.last_mut().unwrap() &= (!0) >> leading_zero_bits_in_m;

            // Now we have out == 2**(lg m) (mod m). Keep doubling until we get
            // to 2**r (mod m).
            for _ in 0..leading_zero_bits_in_m {
                limb::limbs_double_mod(out, m.limbs())?;
            }
        }

        // Now out == 2**r (mod m) == 1*R.
        Ok(out)
    }
}

impl<M> One<M, RR> {
    // Returns RR = = R**2 (mod n) where R = 2**r is the smallest power of
    // 2**LIMB_BITS such that R > m.
    //
    // Even though the assembly on some 32-bit platforms works with 64-bit
    // values, using `LIMB_BITS` here, rather than `N0::LIMBS_USED * LIMB_BITS`,
    // is correct because R**2 will still be a multiple of the latter as
    // `N0::LIMBS_USED` is either one or two.
    pub(crate) fn newRR(
        out: Uninit<M>,
        m: &modulus::OwnedModulusValue<M>,
        cpu: cpu::Features,
    ) -> Result<Self, LenMismatchError> {
        // The number of limbs in the numbers involved.
        let w = m.limbs().len();

        // The length of the numbers involved, in bits. R = 2**r.
        let r = w * LIMB_BITS;

        let n0 = N0::calculate_from(m);
        let m = &Modulus::from_parts(m, &n0, cpu);

        let mut acc = out
            .write_fully_with(|out| One::fillR(out, m))
            .map(Elem::<M, R>::assume_in_range_and_encoded_less_safe)?;

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
            elem_double(&mut acc, m);
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
            acc = elem_squared(acc, m);
        }

        Ok(Self {
            value: acc.transmute_encoding_less_safe::<RR>(),
            n0,
        })
    }
}

impl<M> One<M, RRR> {
    pub(crate) fn newRRR(
        One { value, n0 }: One<M, RR>,
        m: &modulus::OwnedModulusValue<M>,
        cpu: cpu::Features,
    ) -> Self {
        let m = &Modulus::from_parts(m, &n0, cpu);
        let value = elem_squared(value, m);
        Self { value, n0 }
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> {
        &self.value
    }
}

impl<M: PublicModulus, E> One<M, E> {
    pub fn clone_into(&self, out: Uninit<M>) -> Self {
        Self {
            value: self.value.clone_into(out),
            n0: self.n0,
        }
    }
}
