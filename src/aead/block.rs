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

use crate::polyfill::ArrayFlatten;
use core::ops::{BitXor, BitXorAssign};

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Block([u8; 16]);

pub const BLOCK_LEN: usize = 16;

impl Block {
    #[inline]
    pub fn zero() -> Self {
        Self([0; 16])
    }

    #[inline]
    pub fn overwrite_part_at(&mut self, index: usize, a: &[u8]) {
        let mut tmp: [u8; BLOCK_LEN] = *self.as_ref();
        tmp[index..][..a.len()].copy_from_slice(a);
        *self = Self::from(&tmp)
    }

    #[inline]
    pub fn zero_from(&mut self, index: usize) {
        let mut tmp: [u8; BLOCK_LEN] = *self.as_ref();
        tmp[index..].fill(0);
        *self = Self::from(&tmp)
    }
}

impl BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, a: Self) {
        // Relies heavily on optimizer to optimize this into word- or vector-
        // level XOR.
        for (r, a) in self.0.iter_mut().zip(a.0.iter()) {
            *r ^= *a;
        }
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, a: Self) -> Self {
        let mut r = self;
        r.bitxor_assign(a);
        r
    }
}

impl<T> From<T> for Block
where
    T: ArrayFlatten<Output = [u8; 16]>,
{
    #[inline]
    fn from(bytes: T) -> Self {
        Self(bytes.array_flatten())
    }
}

impl From<&'_ [u8; BLOCK_LEN]> for Block {
    #[inline]
    fn from(bytes: &[u8; BLOCK_LEN]) -> Self {
        Self(*bytes)
    }
}

impl AsRef<[u8; BLOCK_LEN]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8; BLOCK_LEN] {
        &self.0
    }
}
