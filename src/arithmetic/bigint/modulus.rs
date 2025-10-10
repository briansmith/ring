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

use super::{super::montgomery::Unencoded, Elem, OwnedModulusValue, PublicModulus, Uninit, N0};
use crate::{
    bits::BitLength,
    cpu,
    error::{self, LenMismatchError},
    limb::{self, Limb, LIMB_BITS},
    polyfill::LeadingZerosStripped,
};
use core::{marker::PhantomData, num::NonZeroUsize};

pub(crate) use super::modulusvalue::ValidatedInput;

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct OwnedModulus<M> {
    inner: OwnedModulusValue<M>,
    n0: N0,
}

impl<M: PublicModulus> Clone for OwnedModulus<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            n0: self.n0,
        }
    }
}

impl<M> OwnedModulusValue<M> {
    pub fn into_modulus(self) -> OwnedModulus<M> {
        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0::LIMBS_USED` limbs of `n`.
        #[allow(clippy::useless_conversion)]
        let n0 = {
            prefixed_extern! {
                fn bn_neg_inv_mod_r_u64(n: u64) -> u64;
            }

            // XXX: u64::from isn't guaranteed to be constant time.
            let mut n_mod_r: u64 = u64::from(self.limbs()[0]);

            if N0::LIMBS_USED == 2 {
                // XXX: If we use `<< LIMB_BITS` here then 64-bit builds
                // fail to compile because of `deny(exceeding_bitshifts)`.
                debug_assert_eq!(LIMB_BITS, 32);
                n_mod_r |= u64::from(self.limbs()[1]) << 32;
            }
            N0::precalculated(unsafe { bn_neg_inv_mod_r_u64(n_mod_r) })
        };

        OwnedModulus { inner: self, n0 }
    }
}

impl<M> OwnedModulus<M> {
    pub fn to_elem<L>(
        &self,
        out: Uninit<L>,
        l: &Modulus<L>,
    ) -> Result<Elem<L, Unencoded>, error::Unspecified> {
        out.write_copy_of_slice_padded(self.inner.limbs())
            .map_err(error::erase::<LenMismatchError>)
            .and_then(|out| Elem::from_limbs(out, l))
    }

    pub(crate) fn modulus(&self, cpu_features: cpu::Features) -> Modulus<'_, M> {
        Modulus {
            limbs: self.inner.limbs(),
            n0: self.n0,
            len_bits: self.len_bits(),
            m: PhantomData,
            cpu_features,
        }
    }

    pub fn len_bits(&self) -> BitLength {
        self.inner.len_bits()
    }
}

impl<M: PublicModulus> OwnedModulus<M> {
    pub fn be_bytes(&self) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + '_> {
        LeadingZerosStripped::new(limb::unstripped_be_bytes(self.inner.limbs()))
    }
}

pub struct Modulus<'a, M> {
    limbs: &'a [Limb],
    n0: N0,
    len_bits: BitLength,
    m: PhantomData<M>,
    cpu_features: cpu::Features,
}

impl<M> Modulus<'_, M> {
    pub fn alloc_uninit(&self) -> Uninit<M> {
        Uninit::new_less_safe(self.limbs.len())
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        self.limbs
    }

    #[inline]
    pub(super) fn n0(&self) -> &N0 {
        &self.n0
    }

    pub fn num_limbs(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.limbs.len()).unwrap_or_else(|| unreachable!())
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }

    #[inline]
    pub(crate) fn cpu_features(&self) -> cpu::Features {
        self.cpu_features
    }
}
