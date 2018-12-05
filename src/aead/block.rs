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

use crate::polyfill;

#[repr(C, align(4))]
#[derive(Clone)]
pub struct Block {
    subblocks: [u64; 2],
}

pub const BLOCK_LEN: usize = 16;

impl Block {
    #[inline]
    pub fn zero() -> Self {
        Self {
            subblocks: [0u64; 2],
        }
    }

    #[inline]
    pub fn partial_copy_from(&mut self, a: &[u8]) {
        polyfill::slice::u64_as_u8_mut(&mut self.subblocks)[..a.len()].copy_from_slice(a);
    }
}

impl<'a> From<&'a [u8; BLOCK_LEN]> for Block {
    #[inline]
    fn from(bytes: &[u8; BLOCK_LEN]) -> Self {
        let mut r = Block::zero();
        r.partial_copy_from(bytes);
        r
    }
}

impl From<[u64; 2]> for Block {
    #[inline]
    fn from(subblocks: [u64; 2]) -> Self { Self { subblocks } }
}

impl AsRef<[u8; BLOCK_LEN]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8; BLOCK_LEN] {
        slice_as_array_ref!(polyfill::slice::u64_as_u8(&self.subblocks[..]), BLOCK_LEN).unwrap()
    }
}
