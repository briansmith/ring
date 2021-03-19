// Copyright 2015-2016 Brian Smith.
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

// TODO: Replace this with use of the array_map feature
// (https://github.com/rust-lang/rust/issues/75243) when it becomes stable.

pub(crate) trait Map<A, B, BArray> {
    fn array_map(self, f: impl Fn(A) -> B) -> BArray;
}

impl<A, B> Map<A, B, [B; 4]> for [A; 4] {
    #[inline]
    fn array_map(self, f: impl Fn(A) -> B) -> [B; 4] {
        let [a0, a1, a2, a3] = self;
        [f(a0), f(a1), f(a2), f(a3)]
    }
}

impl<A, B> Map<A, B, [B; 8]> for [A; 8] {
    #[inline]
    fn array_map(self, f: impl Fn(A) -> B) -> [B; 8] {
        let [a0, a1, a2, a3, a4, a5, a6, a7] = self;
        [f(a0), f(a1), f(a2), f(a3), f(a4), f(a5), f(a6), f(a7)]
    }
}
