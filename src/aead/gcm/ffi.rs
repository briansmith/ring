// Copyright 2018 Brian Smith.
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

use crate::{
    bb,
    polyfill::{slice::AsChunks, ArraySplitMap},
};

pub(in super::super) const BLOCK_LEN: usize = 16;
pub(in super::super) type Block = [u8; BLOCK_LEN];
pub(super) const ZERO_BLOCK: Block = [0u8; BLOCK_LEN];

#[repr(transparent)]
pub(in super::super) struct KeyValue([u64; 2]);

impl KeyValue {
    pub(in super::super) fn new(value: Block) -> Self {
        Self(value.array_split_map(u64::from_be_bytes))
    }

    pub(super) fn into_inner(self) -> [u64; 2] {
        self.0
    }
}

/// SAFETY:
///   * `f` must read `len` bytes from `inp`; it may assume
///     that `len` is a (non-zero) multiple of `BLOCK_LEN`.
///   * `f` may inspect CPU features.
#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    all(target_arch = "arm", target_endian = "little"),
    target_arch = "x86",
    target_arch = "x86_64"
))]
impl HTable {
    pub(super) fn new(init: impl FnOnce(&mut HTable)) -> Self {
        let mut r = Self {
            Htable: [U128 { hi: 0, lo: 0 }; HTABLE_LEN],
        };
        init(&mut r);
        r
    }

    #[cfg(any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little")
    ))]
    pub(super) unsafe fn gmult(
        &self,
        f: unsafe extern "C" fn(xi: &mut Xi, h_table: &HTable),
        xi: &mut Xi,
    ) {
        unsafe { f(xi, self) }
    }
}

pub(super) fn with_non_dangling_ptr(
    input: AsChunks<u8, BLOCK_LEN>,
    f: impl FnOnce(*const u8, crate::c::NonZero_size_t),
) {
    use core::num::NonZeroUsize;

    let input = input.as_flattened();

    let input_len = match NonZeroUsize::new(input.len()) {
        Some(len) => len,
        None => {
            return;
        }
    };

    f(input.as_ptr(), input_len);
}

// The alignment is required by some assembly code, such as `ghash-ssse3-*`.
#[derive(Clone)]
#[repr(C, align(16))]
pub(in super::super) struct HTable {
    Htable: [U128; HTABLE_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct U128 {
    pub(super) hi: u64,
    pub(super) lo: u64,
}

const HTABLE_LEN: usize = 16;

#[repr(transparent)]
pub(in super::super) struct Xi(pub(super) Block);

impl Xi {
    #[inline]
    pub(super) fn bitxor_assign(&mut self, a: Block) {
        self.0 = bb::xor_16(self.0, a)
    }
}
