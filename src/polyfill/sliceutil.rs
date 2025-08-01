// Copyright 2024 Brian Smith.
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

//! Utilities to make dealing with slices less tediuous.

#[allow(unused_imports)]
use super::prelude::*;

/// Replaces the first N elements of `a` with the first N elements of `b`, where
/// N is `a.len().min(b.len())`, leaving the rest unchanged.
pub fn overwrite_at_start<T: Copy>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a = *b;
    });
}

#[inline]
pub fn as_chunks_exact<T, const N: usize>(slice: &[T]) -> Option<&[[T; N]]> {
    match slice.as_chunks::<N>() {
        (w, []) => Some(w),
        _ => None,
    }
}
