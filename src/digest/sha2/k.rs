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

pub(super) struct K<T, const ROUNDS: usize>([T; ROUNDS]);

impl<T, const ROUNDS: usize> K<T, ROUNDS> {
    pub(super) const fn new(values: [T; ROUNDS]) -> Self {
        Self(values)
    }
}

impl<T, const ROUNDS: usize> AsRef<[T]> for K<T, ROUNDS> {
    #[inline(always)]
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}
