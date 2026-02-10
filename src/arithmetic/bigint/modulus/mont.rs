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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    super::{
        super::montgomery::{limbs_square_mont, Unencoded, RR, RRR},
        modulus::value::Value,
        unwrap_impossible_limb_slice_error, Elem, One, OversizedUninit, PublicModulus, Uninit, N0,
    },
    ValidatedInput,
};
use crate::polyfill::slice::Cursor;
use crate::{
    bits::BitLength,
    cpu,
    error::{self, LenMismatchError},
    limb::{self, Limb, LIMB_BITS},
    polyfill::{self, LeadingZerosStripped},
};
use alloc::boxed::Box;
use core::{marker::PhantomData, num::NonZero};

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct IntoMont<'a, M, E> {
    storage: &'a [Limb],
    len_bits: BitLength,
    n0: N0,
    m: PhantomData<M>,
    encoding: PhantomData<E>,
}

pub struct BoxedIntoMont<M, E> {
    storage: Box<[Limb]>,
    len_bits: BitLength,
    n0: N0,
    m: PhantomData<M>,
    encoding: PhantomData<E>,
}

impl<M: PublicModulus, E> Clone for BoxedIntoMont<M, E> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            n0: self.n0,
            len_bits: self.len_bits,
            m: self.m,
            encoding: self.encoding,
        }
    }
}

impl<M, E> BoxedIntoMont<M, E> {
    pub fn reborrow(&self) -> IntoMont<'_, M, E> {
        IntoMont {
            storage: &self.storage,
            len_bits: self.len_bits,
            n0: self.n0,
            m: self.m,
            encoding: PhantomData,
        }
    }
}

impl ValidatedInput<'_> {
    pub(crate) fn build_boxed_into_mont<M>(&self, cpu: cpu::Features) -> BoxedIntoMont<M, RR> {
        let limbs = self.limbs();
        let mut uninit = Box::new_uninit_slice(limbs.len() * 2);
        let borrowed = polyfill::slice::Uninit::from(uninit.as_mut());
        let mut cursor = borrowed.into_cursor();
        let IntoMont {
            storage: _,
            len_bits,
            n0,
            m,
            encoding,
        } = self
            .write_into_mont(&mut cursor, cpu)
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        cursor
            .check_at_end()
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        let storage = unsafe { uninit.assume_init() };
        BoxedIntoMont {
            storage,
            len_bits,
            n0,
            m,
            encoding,
        }
    }

    pub(crate) fn build_into_mont<'o, M>(
        &self,
        uninit: &'o mut OversizedUninit<2>,
        cpu: cpu::Features,
    ) -> IntoMont<'o, M, RR> {
        self.write_into_mont(&mut uninit.as_const_uninit().into_cursor(), cpu)
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!())
    }

    fn write_into_mont<'o, M>(
        &self,
        out: &mut Cursor<'o, Limb>,
        cpu: cpu::Features,
    ) -> Result<IntoMont<'o, M, RR>, LenMismatchError> {
        let (storage, n0) = out.try_write_with(|out| {
            let value = out.write_iter(self.limbs()).src_empty()?.into_written();
            let value = Value::<M>::from_limbs_unchecked_less_safe(value, self.len_bits());
            let n0 = N0::calculate_from(&value);
            let m = &Mont::from_parts_unchecked_less_safe(value, &n0, cpu);
            let one = One::write_mont_identity(out, m)?;
            One::mul_r(one, m)?;
            Ok(n0)
        })?;
        Ok(IntoMont {
            storage,
            len_bits: self.len_bits(),
            n0,
            m: PhantomData,
            encoding: PhantomData,
        })
    }
}

impl N0 {
    #[allow(clippy::useless_conversion)]
    pub(super) fn calculate_from<M>(value: &Value<M>) -> Self {
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
            n_mod_r |= u64::from(value.limbs()[1]) << 32;
        }
        N0::precalculated(unsafe { bn_neg_inv_mod_r_u64(n_mod_r) })
    }
}

impl<'a, M, E> IntoMont<'a, M, E> {
    fn value(&self) -> Value<'_, M> {
        let (value, _) = self.parts();
        Value::from_limbs_unchecked_less_safe(value, self.len_bits)
    }

    fn parts(&self) -> (&'a [Limb], &'a [Limb]) {
        self.storage
            .as_ref()
            .split_at(self.storage.as_ref().len() / 2)
    }

    fn parts_mut(storage: &mut [Limb]) -> (&[Limb], &mut [Limb]) {
        let (value, one) = storage.split_at_mut(storage.len() / 2);
        (value, one)
    }

    pub fn to_elem<L>(
        &self,
        out: Uninit<L>,
        l: &Mont<L>,
    ) -> Result<Elem<L, Unencoded>, error::Unspecified> {
        out.write_copy_of_slice_padded(self.value().limbs())
            .map_err(error::erase::<LenMismatchError>)
            .and_then(|out| Elem::from_limbs(out, l))
    }

    pub(crate) fn modulus(&self, cpu_features: cpu::Features) -> Mont<'_, M> {
        let (value, _) = self.parts();
        let value = Value::from_limbs_unchecked_less_safe(value, self.len_bits());
        Mont::from_parts_unchecked_less_safe(value, &self.n0, cpu_features)
    }

    pub(crate) fn one(&self) -> One<'_, M, E> {
        let (_, one) = self.parts();
        One::<M, E>::from_limbs_unchecked_less_safe(one)
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }
}

impl<M> BoxedIntoMont<M, RR> {
    pub(crate) fn intoRRR(self, cpu: cpu::Features) -> BoxedIntoMont<M, RRR> {
        let Self {
            mut storage,
            n0,
            len_bits,
            m,
            ..
        } = self;
        let (value, one) = IntoMont::<M, RR>::parts_mut(storage.as_mut());
        let value = Value::<M>::from_limbs_unchecked_less_safe(value, len_bits);
        let mm = Mont::from_parts_unchecked_less_safe(value, &self.n0, cpu);
        let _: &[Limb] = limbs_square_mont(one, mm.limbs(), &self.n0, cpu)
            .unwrap_or_else(unwrap_impossible_limb_slice_error);
        BoxedIntoMont {
            storage,
            n0,
            len_bits,
            m,
            encoding: PhantomData,
        }
    }
}

impl<'a, M: PublicModulus, E> IntoMont<'a, M, E> {
    pub fn be_bytes(&self) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + 'a> {
        let (value, _) = self.parts();
        LeadingZerosStripped::new(limb::unstripped_be_bytes(value))
    }
}

pub struct Mont<'a, M> {
    value: Value<'a, M>,
    n0: &'a N0,
    cpu_features: cpu::Features,
}

impl<'a, M> Mont<'a, M> {
    pub(super) fn from_parts_unchecked_less_safe(
        value: Value<'a, M>,
        n0: &'a N0,
        cpu: cpu::Features,
    ) -> Self {
        Mont {
            value,
            n0,
            cpu_features: cpu,
        }
    }
}

impl<M> Mont<'_, M> {
    pub fn alloc_uninit(&self) -> Uninit<M> {
        Uninit::new_less_safe(self.value.limbs().len())
    }

    #[inline]
    pub(in super::super) fn limbs(&self) -> &[Limb] {
        self.value.limbs()
    }

    #[inline]
    pub(in super::super) fn n0(&self) -> &N0 {
        self.n0
    }

    pub fn num_limbs(&self) -> NonZero<usize> {
        NonZero::new(self.limbs().len()).unwrap_or_else(|| unreachable!())
    }

    pub fn len_bits(&self) -> BitLength {
        self.value.len_bits()
    }

    #[inline]
    pub(crate) fn cpu_features(&self) -> cpu::Features {
        self.cpu_features
    }
}
