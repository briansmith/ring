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

use crate::{endian::*, polyfill::convert::*};

/// An array of 16 bytes that can (in the x86_64 and AAarch64 ABIs, at least)
/// be efficiently passed by value and returned by value (i.e. in registers),
/// and which meets the alignment requirements of `u32` and `u64` (at least)
/// for the target.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Block {
    subblocks: [u64; 2],
}

pub const BLOCK_LEN: usize = 16;

impl Block {
    #[inline]
    pub fn zero() -> Self { Self { subblocks: [0, 0] } }

    #[inline]
    pub fn from_u64_le(first: LittleEndian<u64>, second: LittleEndian<u64>) -> Self {
        Self {
            subblocks: [unsafe { core::mem::transmute(first) }, unsafe {
                core::mem::transmute(second)
            }],
        }
    }

    /// Replaces the first `a.len()` bytes of the block's value with `a`,
    /// leaving the rest of the block unchanged. Panics if `a` is larger
    /// than a block.
    #[inline]
    pub fn partial_copy_from(&mut self, a: &[u8]) { self.as_mut()[..a.len()].copy_from_slice(a); }
}

impl<'a> From<&'a [u8; BLOCK_LEN]> for Block {
    #[inline]
    fn from(bytes: &[u8; BLOCK_LEN]) -> Self { unsafe { core::mem::transmute_copy(bytes) } }
}

impl<'a> From_<&'a [u8; 2 * BLOCK_LEN]> for [Block; 2] {
    #[inline]
    fn from_(bytes: &[u8; 2 * BLOCK_LEN]) -> Self { unsafe { core::mem::transmute_copy(bytes) } }
}

impl AsRef<[u8; BLOCK_LEN]> for Block {
    #[inline]
    fn as_ref(&self) -> &[u8; BLOCK_LEN] { unsafe { core::mem::transmute(self) } }
}

impl AsMut<[u8; BLOCK_LEN]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8; BLOCK_LEN] { unsafe { core::mem::transmute(self) } }
}

/// Like `AsMut`.
impl From_<&mut [Block; 2]> for &mut [u8; 2 * BLOCK_LEN] {
    #[inline]
    fn from_(bytes: &mut [Block; 2]) -> Self { unsafe { core::mem::transmute(bytes) } }
}
