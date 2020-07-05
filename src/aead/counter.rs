// Copyright 2018 Brian Smith.
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

use super::{iv::Iv, Block, Nonce};
use crate::endian::*;
use core::marker::PhantomData;

/// A generator of a monotonically increasing series of `Iv`s.
///
/// Intentionally not `Clone` to ensure counters aren't forked.
#[repr(C)]
pub union Counter<U32: Layout<u32>>
where
    u32: From<U32>,
{
    block: Block,
    u32s: [U32; 4],
    encoding: PhantomData<U32>,
}

impl<U32: Layout<u32>> Counter<U32>
where
    u32: From<U32>,
{
    pub fn zero(nonce: Nonce) -> Self {
        Self::new(nonce, 0)
    }
    pub fn one(nonce: Nonce) -> Self {
        Self::new(nonce, 1)
    }

    // Used by `zero()` and by the tests.
    #[cfg(test)]
    pub fn from_test_vector(nonce: &[u8], initial_counter: u32) -> Self {
        Self::new(
            Nonce::try_assume_unique_for_key(nonce).unwrap(),
            initial_counter,
        )
    }

    fn new(nonce: Nonce, initial_counter: u32) -> Self {
        let mut r = Self {
            block: Block::zero(),
        };
        let block = unsafe { &mut r.block };
        block.overwrite_part_at(U32::NONCE_BYTE_INDEX, nonce.as_ref());
        r.increment_by_less_safe(initial_counter);

        r
    }

    #[inline]
    pub fn increment(&mut self) -> Iv {
        let block = unsafe { &self.block };
        let r = Iv::assume_unique_for_key(block.clone());

        self.increment_by_less_safe(1);

        r
    }

    #[inline]
    pub fn increment_by_less_safe(&mut self, increment_by: u32) {
        let u32s = unsafe { &mut self.u32s };
        let value = &mut u32s[U32::COUNTER_U32_INDEX];
        *value = (u32::from(*value) + increment_by).into();
    }
}

pub trait Layout<T>: Encoding<T>
where
    T: From<Self>,
{
    const COUNTER_U32_INDEX: usize;
    const NONCE_BYTE_INDEX: usize;
}

impl<T> Layout<T> for BigEndian<T>
where
    BigEndian<T>: Encoding<T>,
    T: Copy + From<Self>,
{
    const COUNTER_U32_INDEX: usize = 3;
    const NONCE_BYTE_INDEX: usize = 0;
}

impl<T> Layout<T> for LittleEndian<T>
where
    LittleEndian<T>: Encoding<T>,
    T: Copy + From<Self>,
{
    const COUNTER_U32_INDEX: usize = 0;
    const NONCE_BYTE_INDEX: usize = 4;
}

impl<U32: Layout<u32>> Into<Iv> for Counter<U32>
where
    u32: From<U32>,
{
    fn into(self) -> Iv {
        let block = unsafe { self.block };
        Iv::assume_unique_for_key(block)
    }
}
