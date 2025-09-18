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
    super::montgomery::{Unencoded, RR, RRR},
    Elem, One, PublicModulus, Uninit, N0,
};
use crate::{
    bits::BitLength,
    cpu,
    error::{self, LenMismatchError},
    limb::{self, Limb, LIMB_BITS},
    polyfill::LeadingZerosStripped,
};
use core::{marker::PhantomData, num::NonZeroUsize};

pub(crate) use super::modulusvalue::{OwnedModulusValue, ValidatedInput};

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct IntoMont<M, E> {
    inner: OwnedModulusValue<M>,
    one: One<M, E>,
}

impl<M: PublicModulus, E> Clone for IntoMont<M, E> {
    fn clone(&self) -> Self {
        let zero = self.inner.alloc_uninit();
        Self {
            inner: self.inner.clone(),
            one: self.one.clone_into(zero),
        }
    }
}

impl<M> OwnedModulusValue<M> {
    pub fn into_into_mont(self, cpu: cpu::Features) -> IntoMont<M, RR> {
        let out = self.alloc_uninit();
        let one =
            One::newRR(out, &self, cpu).unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        IntoMont { inner: self, one }
    }
}

impl N0 {
    #[allow(clippy::useless_conversion)]
    pub(super) fn calculate_from<M>(value: &OwnedModulusValue<M>) -> Self {
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
        l: &Modulus<L>,
    ) -> Result<Elem<L, Unencoded>, error::Unspecified> {
        out.write_copy_of_slice_padded(self.inner.limbs())
            .map_err(error::erase::<LenMismatchError>)
            .and_then(|out| Elem::from_limbs(out, l))
    }

    pub(crate) fn modulus(&self, cpu_features: cpu::Features) -> Modulus<'_, M> {
        Modulus::from_parts_unchecked_less_safe(&self.inner, self.one.n0(), cpu_features)
    }

    pub fn len_bits(&self) -> BitLength {
        self.inner.len_bits()
    }

    pub fn one(&self) -> &One<M, E> {
        &self.one
    }
}

impl<M> IntoMont<M, RR> {
    pub(crate) fn intoRRR(self, cpu: cpu::Features) -> IntoMont<M, RRR> {
        let Self { inner, one } = self;
        let one = One::newRRR(one, &inner, cpu);
        IntoMont { inner, one }
    }
}

impl<M: PublicModulus, E> IntoMont<M, E> {
    pub fn be_bytes(&self) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + '_> {
        LeadingZerosStripped::new(limb::unstripped_be_bytes(self.inner.limbs()))
    }
}

pub struct Modulus<'a, M> {
    limbs: &'a [Limb],
    n0: &'a N0,
    len_bits: BitLength,
    m: PhantomData<M>,
    cpu_features: cpu::Features,
}

impl<'a, M> Modulus<'a, M> {
    pub(super) fn from_parts_unchecked_less_safe(
        value: &'a OwnedModulusValue<M>,
        n0: &'a N0,
        cpu: cpu::Features,
    ) -> Self {
        Modulus {
            limbs: value.limbs(),
            n0,
            len_bits: value.len_bits(),
            m: PhantomData,
            cpu_features: cpu,
        }
    }
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
        self.n0
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

#[cfg(test)]
pub mod testutil {
    use super::*;
    use crate::cpu;
    use crate::error::KeyRejected;

    pub fn consume_modulus<M>(
        test_case: &mut crate::testutil::TestCase,
        name: &str,
    ) -> IntoMont<M, RR> {
        let value = test_case.consume_bytes(name);
        ValidatedInput::try_from_be_bytes(value.as_slice().into())
            .map_err(error::erase::<KeyRejected>)
            .unwrap()
            .build_value()
            .into_into_mont(cpu::features())
    }
}
