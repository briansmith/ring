// Copyright 2023 Brian Smith.
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

pub trait ArrayFlatten {
    type Output;

    /// Returns the flattened form of `a`
    fn array_flatten(self) -> Self::Output;
}

impl<T> ArrayFlatten for [[T; 8]; 2] {
    type Output = [T; 16];

    #[inline(always)]
    fn array_flatten(self) -> Self::Output {
        let [[a0, a1, a2, a3, a4, a5, a6, a7], [b0, b1, b2, b3, b4, b5, b6, b7]] = self;
        [
            a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7,
        ]
    }
}

impl<T> ArrayFlatten for [[T; 4]; 4] {
    type Output = [T; 16];

    #[inline(always)]
    fn array_flatten(self) -> Self::Output {
        let [[a0, a1, a2, a3], [b0, b1, b2, b3], [c0, c1, c2, c3], [d0, d1, d2, d3]] = self;
        [
            a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3,
        ]
    }
}
