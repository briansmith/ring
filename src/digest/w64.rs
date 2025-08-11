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

use crate::digest::word::Word;
use core::num::Wrapping;

pub type W64 = Wrapping<u64>;

impl Word for W64 {
    const ZERO: Self = Self(0);
    type InputBytes = [u8; 8];

    #[inline(always)]
    fn from_be_bytes(input: Self::InputBytes) -> Self {
        Self(u64::from_be_bytes(input))
    }

    #[inline(always)]
    fn rotr(self, count: u32) -> Self {
        Self(self.0.rotate_right(count))
    }
}
