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

use crate::{
    error::LenMismatchError,
    limb::{self, Limb},
    polyfill,
};
use alloc::{boxed::Box, vec::Vec};
use core::{iter, marker::PhantomData};

/// All `BoxedLimbs<M>` are stored in the same number of limbs.
pub(super) struct BoxedLimbs<M> {
    limbs: Box<[Limb]>,

    /// The modulus *m* that determines the size of `limbx`.
    m: PhantomData<M>,
}

// TODO: `derive(Clone)` after https://github.com/rust-lang/rust/issues/26925
// is resolved or restrict `M: Clone`.
impl<M> Clone for BoxedLimbs<M> {
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            m: self.m,
        }
    }
}

impl<M> BoxedLimbs<M> {
    #[inline(always)]
    pub(super) fn as_ref(&self) -> &[Limb] {
        self.limbs.as_ref()
    }

    #[inline(always)]
    pub(super) fn as_mut(&mut self) -> &mut [Limb] {
        self.limbs.as_mut()
    }

    pub(super) fn into_limbs(self) -> Box<[Limb]> {
        self.limbs
    }

    #[inline(always)]
    pub(super) fn len(&self) -> usize {
        self.limbs.len()
    }
}

pub struct Uninit<M> {
    len: usize,
    m: PhantomData<M>,
}

impl<M> Uninit<M> {
    // "Less safe" because this is what binds `len` to `M`.
    pub fn new_less_safe(len: usize) -> Self {
        Self {
            len,
            m: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn write_zeros(self) -> BoxedLimbs<M> {
        self.write_from_iter_padded(iter::empty())
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!())
    }

    pub(super) fn write_from_be_bytes_padded(
        self,
        input: untrusted::Input,
    ) -> Result<BoxedLimbs<M>, LenMismatchError> {
        let input = limb::limbs_from_big_endian(input, 1..=self.len())?;
        self.write_from_iter_padded(input)
    }

    pub(super) fn write_copy_of_slice_checked(
        self,
        src: &[Limb],
    ) -> Result<BoxedLimbs<M>, LenMismatchError> {
        self.write_iter_checked(src.iter().copied())
    }

    pub(super) fn write_copy_of_slice_padded(
        self,
        src: &[Limb],
    ) -> Result<BoxedLimbs<M>, LenMismatchError> {
        self.write_from_iter_padded(src.iter().copied())
    }

    pub(super) fn write_iter_checked(
        self,
        input: impl ExactSizeIterator<Item = Limb>,
    ) -> Result<BoxedLimbs<M>, LenMismatchError>
    where
        Limb: Copy,
    {
        if input.len() != self.len() {
            return Err(LenMismatchError::new(input.len()));
        }
        let limbs = Vec::from_iter(input).into_boxed_slice();
        Ok(BoxedLimbs { limbs, m: self.m })
    }

    pub(super) fn write_from_iter_padded(
        self,
        input: impl ExactSizeIterator<Item = Limb>,
    ) -> Result<BoxedLimbs<M>, LenMismatchError>
    where
        Limb: Copy,
    {
        let padding_len = self
            .len()
            .checked_sub(input.len())
            .ok_or_else(|| LenMismatchError::new(input.len()))?;
        // TODO(MSRV-1.82): Use `iter::repeat_n`.
        let limbs =
            Vec::from_iter(input.chain(iter::repeat(Limb::from(limb::ZERO)).take(padding_len)))
                .into_boxed_slice();
        Ok(BoxedLimbs { limbs, m: self.m })
    }

    pub(super) fn write_fully_with<EI>(
        self,
        f: impl for<'a> FnOnce(polyfill::slice::Uninit<'a, Limb>) -> Result<&'a mut [Limb], EI>,
    ) -> Result<BoxedLimbs<M>, LenMismatchError>
    where
        LenMismatchError: From<EI>,
    {
        let m = self.m;
        let mut uninit = Box::new_uninit_slice(self.len);
        let (ptr, len) = (uninit.as_mut_ptr(), uninit.len());
        let written = polyfill::slice::Uninit::from(uninit.as_mut()).write_fully_with(f)?;
        // Postconditions of `polyfill::slice::Uninit::write_fully_with`.
        debug_assert_eq!(written.len(), len);
        debug_assert!(polyfill::ptr::addr_eq(written.as_ptr(), ptr.cast::<Limb>()) || len == 0); // cast_init
        let limbs = unsafe { uninit.assume_init() };
        Ok(BoxedLimbs { limbs, m })
    }
}
