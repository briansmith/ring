// Copyright 2019-2025 Brian Smith.
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

#[cfg_attr(target_arch = "aarch64", repr(C, align(64)))]
#[cfg_attr(target_arch = "arm", repr(C, align(32)))]
pub(super) struct KTable<T, const ROUNDS_PLUS_1: usize>([T; ROUNDS_PLUS_1]);

impl<T, const ROUNDS_PLUS_1: usize> KTable<T, ROUNDS_PLUS_1> {
    pub(super) const fn new_zero_terminated(values_zero_terminated: [T; ROUNDS_PLUS_1]) -> Self {
        Self(values_zero_terminated)
    }
}

impl<T, const ROUNDS_PLUS_1: usize> AsRef<[T; ROUNDS_PLUS_1]> for KTable<T, ROUNDS_PLUS_1> {
    #[inline(always)]
    fn as_ref(&self) -> &[T; ROUNDS_PLUS_1] {
        &self.0
    }
}
