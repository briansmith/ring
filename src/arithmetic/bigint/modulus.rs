// Copyright 2015-2023 Brian Smith.
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

use super::{
    super::{
        montgomery::{Unencoded, R, RR},
        n0::N0,
    },
    BoxedLimbs, Elem, Nonnegative, One, PublicModulus, SlightlySmallerModulus, SmallerModulus,
    Width,
};
use crate::{
    bits, cpu, error,
    limb::{self, Limb, LimbMask, LIMB_BITS},
    polyfill::LeadingZerosStripped,
};
use core::marker::PhantomData;

/// The x86 implementation of `bn_mul_mont`, at least, requires at least 4
/// limbs. For a long time we have required 4 limbs for all targets, though
/// this may be unnecessary. TODO: Replace this with
/// `n.len() < 256 / LIMB_BITS` so that 32-bit and 64-bit platforms behave the
/// same.
pub const MODULUS_MIN_LIMBS: usize = 4;

pub const MODULUS_MAX_LIMBS: usize = super::super::BIGINT_MODULUS_MAX_LIMBS;

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct Modulus<M> {
    limbs: BoxedLimbs<M>, // Also `value >= 3`.

    // n0 * N == -1 (mod r).
    //
    // r == 2**(N0::LIMBS_USED * LIMB_BITS) and LG_LITTLE_R == lg(r). This
    // ensures that we can do integer division by |r| by simply ignoring
    // `N0::LIMBS_USED` limbs. Similarly, we can calculate values modulo `r` by
    // just looking at the lowest `N0::LIMBS_USED` limbs. This is what makes
    // Montgomery multiplication efficient.
    //
    // As shown in Algorithm 1 of "Fast Prime Field Elliptic Curve Cryptography
    // with 256 Bit Primes" by Shay Gueron and Vlad Krasnov, in the loop of a
    // multi-limb Montgomery multiplication of a * b (mod n), given the
    // unreduced product t == a * b, we repeatedly calculate:
    //
    //    t1 := t % r         |t1| is |t|'s lowest limb (see previous paragraph).
    //    t2 := t1*n0*n
    //    t3 := t + t2
    //    t := t3 / r         copy all limbs of |t3| except the lowest to |t|.
    //
    // In the last step, it would only make sense to ignore the lowest limb of
    // |t3| if it were zero. The middle steps ensure that this is the case:
    //
    //                            t3 ==  0 (mod r)
    //                        t + t2 ==  0 (mod r)
    //                   t + t1*n0*n ==  0 (mod r)
    //                       t1*n0*n == -t (mod r)
    //                        t*n0*n == -t (mod r)
    //                          n0*n == -1 (mod r)
    //                            n0 == -1/n (mod r)
    //
    // Thus, in each iteration of the loop, we multiply by the constant factor
    // n0, the negative inverse of n (mod r).
    //
    // TODO(perf): Not all 32-bit platforms actually make use of n0[1]. For the
    // ones that don't, we could use a shorter `R` value and use faster `Limb`
    // calculations instead of double-precision `u64` calculations.
    n0: N0,

    oneRR: One<M, RR>,

    cpu_features: cpu::Features,
}

impl<M: PublicModulus> Clone for Modulus<M> {
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            n0: self.n0.clone(),
            oneRR: self.oneRR.clone(),
            cpu_features: self.cpu_features,
        }
    }
}

impl<M: PublicModulus> core::fmt::Debug for Modulus<M> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        fmt.debug_struct("Modulus")
            // TODO: Print modulus value.
            .finish()
    }
}

impl<M> Modulus<M> {
    pub(crate) fn from_be_bytes_with_bit_length(
        input: untrusted::Input,
        cpu_features: cpu::Features,
    ) -> Result<(Self, bits::BitLength), error::KeyRejected> {
        let limbs = BoxedLimbs::positive_minimal_width_from_be_bytes(input)?;
        Self::from_boxed_limbs(limbs, cpu_features)
    }

    pub(crate) fn from_nonnegative_with_bit_length(
        n: Nonnegative,
        cpu_features: cpu::Features,
    ) -> Result<(Self, bits::BitLength), error::KeyRejected> {
        let limbs = BoxedLimbs::new_unchecked(n.into_limbs());
        Self::from_boxed_limbs(limbs, cpu_features)
    }

    pub(crate) fn from_elem<L>(
        elem: Elem<L, Unencoded>,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::KeyRejected>
    where
        M: SlightlySmallerModulus<L>,
    {
        let (m, _bits) = Self::from_boxed_limbs(
            BoxedLimbs::minimal_width_from_unpadded(&elem.limbs),
            cpu_features,
        )?;
        Ok(m)
    }

    fn from_boxed_limbs(
        n: BoxedLimbs<M>,
        cpu_features: cpu::Features,
    ) -> Result<(Self, bits::BitLength), error::KeyRejected> {
        if n.len() > MODULUS_MAX_LIMBS {
            return Err(error::KeyRejected::too_large());
        }
        if n.len() < MODULUS_MIN_LIMBS {
            return Err(error::KeyRejected::unexpected_error());
        }
        if limb::limbs_are_even_constant_time(&n) != LimbMask::False {
            return Err(error::KeyRejected::invalid_component());
        }
        if limb::limbs_less_than_limb_constant_time(&n, 3) != LimbMask::False {
            return Err(error::KeyRejected::unexpected_error());
        }

        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0::LIMBS_USED` limbs of `n`.
        #[allow(clippy::useless_conversion)]
        let n0 = {
            prefixed_extern! {
                fn bn_neg_inv_mod_r_u64(n: u64) -> u64;
            }

            // XXX: u64::from isn't guaranteed to be constant time.
            let mut n_mod_r: u64 = u64::from(n[0]);

            if N0::LIMBS_USED == 2 {
                // XXX: If we use `<< LIMB_BITS` here then 64-bit builds
                // fail to compile because of `deny(exceeding_bitshifts)`.
                debug_assert_eq!(LIMB_BITS, 32);
                n_mod_r |= u64::from(n[1]) << 32;
            }
            N0::from(unsafe { bn_neg_inv_mod_r_u64(n_mod_r) })
        };

        let bits = limb::limbs_minimal_bits(&n);
        let oneRR = {
            let partial = PartialModulus {
                limbs: &n,
                n0: n0.clone(),
                m: PhantomData,
                cpu_features,
            };

            One::newRR(&partial, bits)
        };

        Ok((
            Self {
                limbs: n,
                n0,
                oneRR,
                cpu_features,
            },
            bits,
        ))
    }

    #[inline]
    pub(super) fn cpu_features(&self) -> cpu::Features {
        self.cpu_features
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        &self.limbs
    }

    #[inline]
    pub(super) fn n0(&self) -> &N0 {
        &self.n0
    }

    #[inline]
    pub(super) fn width(&self) -> Width<M> {
        self.limbs.width()
    }

    pub(super) fn zero<E>(&self) -> Elem<M, E> {
        Elem {
            limbs: BoxedLimbs::zero(self.width()),
            encoding: PhantomData,
        }
    }

    // TODO: Get rid of this
    pub(super) fn one(&self) -> Elem<M, Unencoded> {
        let mut r = self.zero();
        r.limbs[0] = 1;
        r
    }

    pub fn oneRR(&self) -> &One<M, RR> {
        &self.oneRR
    }

    pub fn to_elem<L>(&self, l: &Modulus<L>) -> Elem<L, Unencoded>
    where
        M: SmallerModulus<L>,
    {
        // TODO: Encode this assertion into the `where` above.
        assert_eq!(self.width().num_limbs, l.width().num_limbs);
        Elem {
            limbs: BoxedLimbs::new_unchecked(self.limbs.clone().into_limbs()),
            encoding: PhantomData,
        }
    }

    pub(crate) fn as_partial(&self) -> PartialModulus<M> {
        PartialModulus {
            limbs: &self.limbs,
            n0: self.n0.clone(),
            m: PhantomData,
            cpu_features: self.cpu_features,
        }
    }
}

impl<M: PublicModulus> Modulus<M> {
    pub fn be_bytes(&self) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + '_> {
        LeadingZerosStripped::new(limb::unstripped_be_bytes(&self.limbs))
    }
}

pub(crate) struct PartialModulus<'a, M> {
    limbs: &'a [Limb],
    n0: N0,
    m: PhantomData<M>,
    cpu_features: cpu::Features,
}

impl<M> PartialModulus<'_, M> {
    // TODO: XXX Avoid duplication with `Modulus`.
    pub(super) fn zero(&self) -> Elem<M, R> {
        let width = Width {
            num_limbs: self.limbs.len(),
            m: PhantomData,
        };
        Elem {
            limbs: BoxedLimbs::zero(width),
            encoding: PhantomData,
        }
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        self.limbs
    }

    #[inline]
    pub(super) fn n0(&self) -> &N0 {
        &self.n0
    }

    #[inline]
    pub fn cpu_features(&self) -> cpu::Features {
        self.cpu_features
    }
}
