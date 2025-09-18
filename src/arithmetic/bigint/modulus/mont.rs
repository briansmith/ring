// Copyright 2015-2025 Brian Smith.
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
    super::{Uninit, N0},
    Value,
};
use crate::{bits::BitLength, cpu, limb::Limb};
use core::{marker::PhantomData, num::NonZeroUsize};

pub struct Mont<'a, M> {
    limbs: &'a [Limb],
    n0: &'a N0,
    len_bits: BitLength,
    m: PhantomData<M>,
    cpu_features: cpu::Features,
}

impl<'a, M> Mont<'a, M> {
    pub(super) fn from_parts_unchecked_less_safe(
        value: &'a Value<M>,
        n0: &'a N0,
        cpu: cpu::Features,
    ) -> Self {
        Mont {
            limbs: value.limbs(),
            n0,
            len_bits: value.len_bits(),
            m: PhantomData,
            cpu_features: cpu,
        }
    }
}

impl<M> Mont<'_, M> {
    pub fn alloc_uninit(&self) -> Uninit<M> {
        Uninit::new_less_safe(self.limbs.len())
    }

    #[inline]
    pub(in super::super) fn limbs(&self) -> &[Limb] {
        self.limbs
    }

    #[inline]
    pub(in super::super) fn n0(&self) -> &N0 {
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
