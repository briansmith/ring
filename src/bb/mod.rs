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

//! Building blocks.

mod boolmask;
mod bytes;
mod leaky;
mod word;

pub(crate) use self::{
    boolmask::BoolMask,
    bytes::{
        byte_leading_zeros_vartime, bytes_are_equal, verify_slices_are_equal, xor_16, xor_assign,
        xor_assign_at_start_bytes,
    },
    leaky::LeakyWord,
    word::{Word, WordOps},
};

/// XORs the first N words of `b` into `a`, where N is
/// `a.len().min(b.len())`.
#[inline(always)]
pub(crate) fn xor_assign_at_start<'a>(
    a: impl IntoIterator<Item = &'a mut Word>,
    b: impl IntoIterator<Item = &'a Word>,
) {
    a.into_iter().zip(b).for_each(|(a, b)| *a ^= *b);
}
