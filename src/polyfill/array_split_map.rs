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

pub trait ArraySplitMap<I, O, const CN: usize, const ON: usize> {
    fn array_split_map(self, f: impl Fn([I; CN]) -> O) -> [O; ON];
}

impl<I, O> ArraySplitMap<I, O, 4, 3> for [I; 12] {
    #[inline]
    fn array_split_map(self, f: impl Fn([I; 4]) -> O) -> [O; 3] {
        let [a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3] = self;
        [
            f([a0, a1, a2, a3]),
            f([b0, b1, b2, b3]),
            f([c0, c1, c2, c3]),
        ]
    }
}
