// Copyright 2025 Brian Smith.
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

use super::CHAINING_WORDS;
use core::num::Wrapping;

// Used by FFI.
// The alignment should be at least 16 for some SIMD implementations'
// performance, but it's not required for correctness.
#[repr(C, align(16))]
#[derive(Clone)]
pub(in super::super) struct State<T>([Wrapping<T>; CHAINING_WORDS]);

impl<U> State<U> {
    #[inline(always)]
    pub(in super::super) const fn new(initial: [Wrapping<U>; CHAINING_WORDS]) -> Self {
        Self(initial)
    }
    #[inline(always)]
    pub(in super::super) fn as_mut(&mut self) -> &mut [Wrapping<U>; CHAINING_WORDS] {
        &mut self.0
    }
    #[inline(always)]
    pub(in super::super) fn as_ref(&self) -> &[Wrapping<U>; CHAINING_WORDS] {
        &self.0
    }
}
