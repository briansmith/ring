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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{BoolMask, Word, WordOps};
use crate::{bits::BitLength, error, polyfill::usize_from_u32};

pub fn byte_leading_zeros_vartime(a: &u8) -> BitLength<usize> {
    BitLength::from_bits(usize_from_u32(a.leading_zeros()))
}

/// Returns `Ok(())` if `a == b` and `Err(error::Unspecified)` otherwise.
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), error::Unspecified> {
    if bytes_are_equal(a, b).leak() {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

#[must_use]
pub fn bytes_are_equal(a: &[u8], b: &[u8]) -> BoolMask {
    let len = a.len(); // Arbitrary choice.
    if b.len() != len {
        return BoolMask::FALSE;
    }
    let (a, a_rem) = a.as_chunks();
    let (b, b_rem) = b.as_chunks();

    let mut acc = a
        .iter()
        .copied()
        .map(Word::from_le_bytes)
        .zip(b.iter().copied().map(Word::from_le_bytes))
        .fold(0, |acc, (a, b)| acc | (a ^ b));

    if !a_rem.is_empty() {
        #[allow(clippy::into_iter_on_ref)]
        let rem = a_rem
            .into_iter()
            .copied()
            .map(Word::from)
            .zip(b_rem.into_iter().copied().map(Word::from))
            .fold(0, |acc, (a, b)| acc | (a ^ b));
        acc |= rem;
    }

    WordOps::is_zero(acc)
}

pub(crate) fn xor_16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let a = u128::from_ne_bytes(a);
    let b = u128::from_ne_bytes(b);
    let r = a ^ b;
    r.to_ne_bytes()
}

#[inline(always)]
pub(crate) fn xor_assign<'a>(a: impl IntoIterator<Item = &'a mut u8>, b: u8) {
    a.into_iter().for_each(|a| *a ^= b);
}

/// XORs the first N bytes of `b` into `a`, where N is `a.len().min(b.len())`.
#[inline(always)]
pub(crate) fn xor_assign_at_start_bytes<'a>(
    a: impl IntoIterator<Item = &'a mut u8>,
    b: impl IntoIterator<Item = &'a u8>,
) {
    a.into_iter().zip(b).for_each(|(a, b)| *a ^= *b);
}
