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

use super::Modulus;
use crate::{
    error,
    limb::{self, Limb, LimbMask, LIMB_BYTES},
};
use alloc::{boxed::Box, vec};
use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

/// All `BoxedLimbs<M>` are stored in the same number of limbs.
pub(super) struct BoxedLimbs<M> {
    limbs: Box<[Limb]>,

    /// The modulus *m* that determines the size of `limbx`.
    m: PhantomData<M>,
}

impl<M> Deref for BoxedLimbs<M> {
    type Target = [Limb];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.limbs
    }
}

impl<M> DerefMut for BoxedLimbs<M> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.limbs
    }
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
    // The caller must ensure that `limbs.len()` is the same width as the
    // modulus.
    pub(super) fn new_unchecked(limbs: Box<[Limb]>) -> Self {
        Self {
            limbs,
            m: PhantomData,
        }
    }

    pub(super) fn positive_minimal_width_from_be_bytes(
        input: untrusted::Input,
    ) -> Result<Self, error::KeyRejected> {
        // Reject leading zeros. Also reject the value zero ([0]) because zero
        // isn't positive.
        if untrusted::Reader::new(input).peek(0) {
            return Err(error::KeyRejected::invalid_encoding());
        }
        let num_limbs = (input.len() + LIMB_BYTES - 1) / LIMB_BYTES;
        let mut r = Self::zero(num_limbs);
        limb::parse_big_endian_and_pad_consttime(input, &mut r)
            .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
        Ok(r)
    }

    pub(super) fn from_be_bytes_padded_less_than(
        input: untrusted::Input,
        m: &Modulus<M>,
    ) -> Result<Self, error::Unspecified> {
        let mut r = Self::zero(m.limbs().len());
        limb::parse_big_endian_and_pad_consttime(input, &mut r)?;
        if limb::limbs_less_than_limbs_consttime(&r, m.limbs()) != LimbMask::True {
            return Err(error::Unspecified);
        }
        Ok(r)
    }

    #[inline]
    pub(super) fn is_zero(&self) -> bool {
        limb::limbs_are_zero_constant_time(&self.limbs) == LimbMask::True
    }

    pub(super) fn zero(len: usize) -> Self {
        Self {
            limbs: vec![0; len].into_boxed_slice(),
            m: PhantomData,
        }
    }

    pub(super) fn into_limbs(self) -> Box<[Limb]> {
        self.limbs
    }
}
