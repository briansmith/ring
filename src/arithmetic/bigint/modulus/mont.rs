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
        super::montgomery::{RR, RRR, Unencoded},
        MAX_LIMBS, N0, One, PublicModulus, elem,
        modulus::value::Value,
        unwrap_impossible_limb_slice_error,
    },
    ValidatedInput,
};
use crate::{
    bits::BitLength,
    cpu,
    error::{self, LenMismatchError},
    limb::{self, LIMB_BITS, Limb},
    polyfill::{
        LeadingZerosStripped,
        slice::{Buf, Cursor},
        uninit, usize_from_u32,
    },
};
use core::{marker::PhantomData, mem::MaybeUninit, num::NonZero};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct IntoMont<'a, M, E> {
    // Invariant: `Mont::storage` followed hy `num_limbs` limbs with the value
    // 1 encoded with encoding `E`.
    storage: &'a [Limb],
    m: PhantomData<M>,
    encoding: PhantomData<E>,
}

#[cfg(feature = "alloc")]
pub struct BoxedIntoMont<M, E> {
    storage: Box<[Limb]>,
    m: PhantomData<M>,
    encoding: PhantomData<E>,
}

#[cfg(feature = "alloc")]
impl<M: PublicModulus, E> Clone for BoxedIntoMont<M, E> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            m: self.m,
            encoding: self.encoding,
        }
    }
}

#[cfg(feature = "alloc")]
impl<M, E> BoxedIntoMont<M, E> {
    pub fn reborrow(&self) -> IntoMont<'_, M, E> {
        IntoMont {
            storage: &self.storage,
            m: self.m,
            encoding: PhantomData,
        }
    }
}

pub struct OversizedUninit([MaybeUninit<Limb>; Self::CAPACITY]);

impl OversizedUninit {
    const CAPACITY: usize = into_mont_storage_len_from_num_limbs(MAX_LIMBS).unwrap();

    pub const fn new() -> Self {
        Self([const { MaybeUninit::uninit() }; Self::CAPACITY])
    }
}

impl ValidatedInput<'_> {
    #[cfg(feature = "alloc")]
    pub(crate) fn build_boxed_into_mont<M>(&self, cpu: cpu::Features) -> BoxedIntoMont<M, RR> {
        let num_limbs = self.num_limbs();
        let storage_len =
            into_mont_storage_len_from_num_limbs(num_limbs).unwrap_or_else(|| unreachable!()); // Because `MAX_LIMBS` is small.
        let mut uninit = Box::new_uninit_slice(storage_len);
        let mut buf = Buf::from(uninit.as_mut());
        self.write_into_mont_RR::<M>(buf.unfilled(), cpu)
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        if buf.filled().len() != uninit.len() {
            unreachable!()
        };
        let storage = unsafe { uninit.assume_init() };
        BoxedIntoMont {
            storage,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub(crate) fn build_into_mont<'o, M>(
        &self,
        uninit: &'o mut OversizedUninit,
        cpu: cpu::Features,
    ) -> IntoMont<'o, M, RR> {
        let mut buf = Buf::from(uninit.0.as_mut_slice());
        self.write_into_mont_RR::<M>(buf.unfilled(), cpu)
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!());
        IntoMont {
            storage: buf.into_filled_mut(),
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    fn write_into_mont_RR<M>(
        &self,
        mut out: Cursor<'_, '_, Limb>,
        cpu: cpu::Features,
    ) -> Result<(), LenMismatchError> {
        let num_limbs = self.num_limbs();
        let storage_num_limbs =
            into_mont_storage_len_from_num_limbs(num_limbs).unwrap_or_else(|| unreachable!()); // Already validated
        if out.capacity() < storage_num_limbs {
            return Err(LenMismatchError::new(out.capacity()));
        }
        out.with_unfilled_buf_checked(|out| {
            // We can't compute `n0` until after we've written `value`.
            out.unfilled().write_repeat(limb::ZERO, N0::LIMBS_USED)?;
            out.unfilled().write(limb::limb_from_usize(num_limbs))?;
            limb::limbs_from_be_bytes_padded(out.unfilled(), self.input(), num_limbs)?;
            let (n0, rest) = out
                .filled_mut()
                .split_first_chunk_mut::<{ N0::LIMBS_USED }>()
                .unwrap_or_else(|| unreachable!()); // Since we just wrote it.
            let (_num_limbs, value) = rest.split_first().unwrap_or_else(|| unreachable!()); // Since we just wrote it.
            N0::write_into(uninit::Uninit::from(n0), value)?;

            out.write_with(num_limbs, |init, uninit| {
                let m = &Mont::<'_, M>::from_storage_unchecked_less_safe(init, cpu)
                    .unwrap_or_else(unwrap_impossible_limb_slice_error); // Since we just wrote it.
                let r: elem::Mut<'_, _, RR> =
                    One::write_mont_identity(uninit, m, self.len_bits())?.mul_r(m)?; // in place.
                Ok(r.leak_limbs_into_mut_less_safe())
            })
        })
    }
}

const fn into_mont_storage_len_from_num_limbs(num_limbs: usize) -> Option<usize> {
    let Some(num_limbs_2) = num_limbs.checked_add(num_limbs) else {
        return None;
    };
    MONT_PREFIX_LEN.checked_add(num_limbs_2)
}

impl<'a, M, E> IntoMont<'a, M, E> {
    fn value(&self) -> Value<'a, M> {
        let (mont, _) = self.split_mont();
        let (_, value) = mont
            .split_first_chunk::<{ MONT_PREFIX_LEN }>()
            .unwrap_or_else(|| unreachable!()); // Ensured by invariant.
        Value::from_limbs_unchecked_less_safe(value)
    }

    fn split_mont(&self) -> (&'a [Limb], &'a [Limb]) {
        let num_limbs = (self.storage.len() - MONT_PREFIX_LEN) / 2;
        self.storage.as_ref().split_at(MONT_PREFIX_LEN + num_limbs)
    }

    fn split_mont_mut(storage: &mut [Limb]) -> (&[Limb], &mut [Limb]) {
        let num_limbs = (storage.len() - MONT_PREFIX_LEN) / 2;
        let (mont, one) = storage
            .split_at_mut_checked(MONT_PREFIX_LEN + num_limbs)
            .unwrap_or_else(|| unreachable!()); // by invariant.
        (mont, one)
    }

    pub fn to_elem<'l, L>(
        &self,
        out: &'l mut elem::OversizedUninit,
        l: &Mont<L>,
    ) -> Result<elem::Mut<'l, L, Unencoded>, error::Unspecified> {
        let limbs = out
            .as_uninit(..l.num_limbs().get())
            .map_err(error::erase::<LenMismatchError>)?
            .write_copy_of_slice_padded(self.value().limbs(), Limb::from(limb::ZERO))
            .map_err(error::erase::<LenMismatchError>)?;
        elem::Mut::from_limbs(limbs, l)
    }

    pub(crate) fn modulus(&self, cpu_features: cpu::Features) -> Mont<'_, M> {
        let (mont, _) = self.split_mont();
        Mont::from_storage_unchecked_less_safe(mont, cpu_features)
            .unwrap_or_else(unwrap_impossible_limb_slice_error)
    }

    pub(crate) fn one(&self) -> One<'_, M, E> {
        let (_, one) = self.split_mont();
        One::<M, E>::from_limbs_unchecked_less_safe(one)
    }
}

impl<'a, M: PublicModulus, E> IntoMont<'a, M, E> {
    pub fn len_bits_vartime(&self) -> BitLength {
        let value = self.value().limbs();
        let leading_zero_bits = value
            .last()
            .map(|high| usize_from_u32(high.leading_zeros()))
            .unwrap_or(0);
        // TODO: Can't overflow because.
        let total_bits = value.len() * LIMB_BITS;
        BitLength::from_bits(total_bits - leading_zero_bits)
    }
}

#[cfg(any(test, feature = "alloc"))]
impl<M> BoxedIntoMont<M, RR> {
    pub(crate) fn intoRRR(self, cpu: cpu::Features) -> BoxedIntoMont<M, RRR> {
        let Self { mut storage, m, .. } = self;
        let (mont, one) = IntoMont::<M, RR>::split_mont_mut(storage.as_mut());
        let mm = Mont::from_storage_unchecked_less_safe(mont, cpu)
            .unwrap_or_else(unwrap_impossible_limb_slice_error); // Since we just wrote it.
        let _: elem::Mut<'_, M, RRR> =
            elem::Mut::<'_, M, RR>::assume_in_range_and_encoded_less_safe(one).square(&mm); // in place
        BoxedIntoMont {
            storage,
            m,
            encoding: PhantomData,
        }
    }
}

impl<'a, M: PublicModulus, E> IntoMont<'a, M, E> {
    pub fn be_bytes(
        &self,
    ) -> LeadingZerosStripped<impl ExactSizeIterator<Item = u8> + Clone + 'a + use<'a, M, E>> {
        LeadingZerosStripped::new(limb::unstripped_be_bytes(self.value().limbs()))
    }
}

// See the invariant of `Mont::storage`.
const MONT_PREFIX_LEN: usize = N0::LIMBS_USED + 1;

mod base {
    use super::*;
    use crate::arithmetic::{LimbSliceError, MIN_LIMBS};

    pub struct Mont<'a, M> {
        // Safety Invariant: Contains `N0::LIMBS_USED` limbs containing the
        // value `Self::n0()` followed by one limb containing the length of
        // `Self::limbs()`, followed by the limbs of `Self::limbs()`.
        //
        // Safety Invariant: `Self::limbs()` will be non-empty, and users
        // may rely on this for soundness, especially to infer that
        // pointers to slices of the same length are non-dangling.
        //
        // (Safety?) Invariant: `Self::limbs()` will contain at least
        // `MIN_LIMBS` limbs. (Does anything rely on this for *safety*?
        // Assume so.)
        //
        // Safety Invariant: `Self::limbs()` will never be more than
        // `MAX_LIMBS`, and users may rely on this for soundness,
        // especially to avoid stack overflow.
        //
        //
        // When `N0::LIMBS_USED` is 1 on a 64-bit target, the prefix will be
        // 128 bits, so if `storage` is 128-bit aligned then the value limbs
        // will be too. XXX: On 32-bit x86, the alignment will be off because
        // `N0::LIMBS_USED` is 2. TODO: Does this affect performance at all?;
        // we make no effort to align the storage but the allocator is likely
        // to align it to 128 bits.
        storage: &'a [Limb],
        pub(super) m: PhantomData<M>,
        pub(super) cpu_features: cpu::Features,
    }

    impl<'a, M> Mont<'a, M> {
        // "Less safe" because this assumes `storage` encodes a valid `Mont`.
        // This should only be used where `storage` has been written by this
        // module.
        pub(super) fn from_storage_unchecked_less_safe(
            storage: &'a [Limb],
            cpu: cpu::Features,
        ) -> Result<Self, LimbSliceError> {
            // Enforce the length-related invariants (only).
            let Some((&[.., num_limbs], value)) = storage.split_first_chunk::<MONT_PREFIX_LEN>()
            else {
                return Err(LenMismatchError::new(storage.len()))?;
            };
            let num_limbs = limb::usize_from_limb(num_limbs);
            if num_limbs != value.len() {
                return Err(LenMismatchError::new(storage.len()))?;
            }
            if num_limbs < MIN_LIMBS {
                return Err(LimbSliceError::too_short(num_limbs));
            }
            if num_limbs > MAX_LIMBS {
                return Err(LimbSliceError::too_long(num_limbs));
            }
            Ok(Mont {
                storage,
                m: PhantomData,
                cpu_features: cpu,
            })
        }

        pub(super) fn storage(&self) -> &[Limb] {
            self.storage
        }
    }
}

pub use self::base::Mont;

impl<M> Mont<'_, M> {
    #[inline]
    pub(in super::super) fn limbs(&self) -> &[Limb] {
        let (_n0_num_limbs, value) = self
            .storage()
            .split_first_chunk::<{ MONT_PREFIX_LEN }>()
            .unwrap_or_else(|| unreachable!());
        value
    }

    #[inline]
    pub(in super::super) fn n0(&self) -> N0<'_> {
        let (n0, _value) = self
            .storage()
            .split_first_chunk::<{ N0::LIMBS_USED }>()
            .unwrap_or_else(|| unreachable!());
        N0::from_limbs_unchecked_less_safe(n0)
    }

    pub fn num_limbs(&self) -> NonZero<usize> {
        NonZero::new(self.limbs().len()).unwrap_or_else(|| unreachable!())
    }

    #[inline]
    pub(crate) fn cpu_features(&self) -> cpu::Features {
        self.cpu_features
    }
}
