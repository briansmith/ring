// Copyright 2015-2024 Brian Smith.
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
    super::{
        super::montgomery::{Unencoded, RR, RRR},
        Elem, One, PublicModulus, Uninit, N0,
    },
    Mont, Value,
};
use crate::{
    bits::BitLength,
    cpu,
    error::{self, LenMismatchError},
    limb::{self, LIMB_BITS},
    polyfill::LeadingZerosStripped,
};

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct IntoMont<M, E> {
    value: Value<M>,

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
    //n0: N0,
    one: One<M, E>,
}

impl<M: PublicModulus, E> Clone for IntoMont<M, E> {
    fn clone(&self) -> Self {
        let zero = self.value.alloc_uninit();
        Self {
            value: self.value.clone(),
            one: self.one.clone_into(zero),
        }
    }
}

impl<M> Value<M> {
    pub fn into_modulus(self, cpu: cpu::Features) -> IntoMont<M, RR> {
        let out = self.alloc_uninit();
        let one =
            One::newRR(out, &self, cpu).unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        IntoMont { value: self, one }
    }
}

impl N0 {
    #[allow(clippy::useless_conversion)]
    pub(in super::super) fn calculate_from<M>(value: &Value<M>) -> Self {
        let m = value.limbs();

        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0::LIMBS_USED` limbs of `n`.
        prefixed_extern! {
            fn bn_neg_inv_mod_r_u64(n: u64) -> u64;
        }

        // XXX: u64::from isn't guaranteed to be constant time.
        let mut n_mod_r: u64 = u64::from(m[0]);

        if N0::LIMBS_USED == 2 {
            // XXX: If we use `<< LIMB_BITS` here then 64-bit builds
            // fail to compile because of `deny(exceeding_bitshifts)`.
            debug_assert_eq!(LIMB_BITS, 32);
            n_mod_r |= u64::from(m[1]) << 32;
        }
        N0::precalculated(unsafe { bn_neg_inv_mod_r_u64(n_mod_r) })
    }
}

impl<M, E> IntoMont<M, E> {
    pub fn to_elem<L>(
        &self,
        out: Uninit<L>,
        l: &Mont<L>,
    ) -> Result<Elem<L, Unencoded>, error::Unspecified> {
        out.write_copy_of_slice_padded(self.value.limbs())
            .map_err(error::erase::<LenMismatchError>)
            .and_then(|out| Elem::from_limbs(out, l))
    }

    pub(crate) fn modulus(&self, cpu_features: cpu::Features) -> Mont<'_, M> {
        Mont::from_parts(&self.value, self.one.n0(), cpu_features)
    }

    pub fn len_bits(&self) -> BitLength {
        self.value.len_bits()
    }

    pub fn one(&self) -> &One<M, E> {
        &self.one
    }
}

impl<M> IntoMont<M, RR> {
    pub(crate) fn into_rrr(self, cpu: cpu::Features) -> IntoMont<M, RRR> {
        let Self { value, one } = self;
        let one = One::newRRR(one, &value, cpu);
        IntoMont { value, one }
    }
}

impl<M: PublicModulus, E> IntoMont<M, E> {
    pub fn be_bytes(&self) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + '_> {
        LeadingZerosStripped::new(limb::unstripped_be_bytes(self.value.limbs()))
    }
}
