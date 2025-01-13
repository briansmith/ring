// Copyright 2024 Brian Smith.
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

pub struct TooMuchOutputRequestedError {
    /// Note that this might not actually be the (exact) output length
    /// requested, and its units might be lost. For example, it could be any of
    /// the following:
    ///
    ///    * The length in bytes of the entire output.
    ///    * The length in bytes of some *part* of the output.
    ///    * A bit length.
    ///    * A length in terms of "blocks" or other grouping of output values.
    ///    * Some intermediate quantity that was used when checking the output
    ///      length.
    ///    * Some arbitrary value.
    #[allow(dead_code)]
    imprecise_output_length: usize,
}

impl TooMuchOutputRequestedError {
    #[cold]
    #[inline(never)]
    pub(crate) fn new(imprecise_output_length: usize) -> Self {
        Self {
            imprecise_output_length,
        }
    }
}
