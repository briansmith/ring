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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use crate::{bb, polyfill::ArraySplitMap};

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

pub(super) fn with_non_dangling_ptr(
    input: &[[u8; BLOCK_LEN]],
    f: impl FnOnce(*const u8, crate::c::NonZero_size_t),
) {
    use core::num::NonZeroUsize;

    let input = input.as_flattened();

    let Some(input_len) = NonZeroUsize::new(input.len()) else {
        return;
    };

    f(input.as_ptr(), input_len);
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct U128 {
    pub(super) hi: u64,
    pub(super) lo: u64,
}

#[repr(transparent)]
pub(in super::super) struct Xi(pub(super) Block);

impl Xi {
    #[inline]
    pub(super) fn bitxor_assign(&mut self, a: Block) {
        self.0 = bb::xor_16(self.0, a)
    }
}
