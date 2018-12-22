// Copyright 2018 Brian Smith.
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

//! Serialization and deserialization.

#[doc(hidden)]
pub mod der;

#[cfg(feature = "use_heap")]
mod writer;

#[cfg(feature = "use_heap")]
pub(crate) mod der_writer;

/// A serialized positive integer.
#[derive(Copy, Clone)]
pub struct Positive<'a>(untrusted::Input<'a>);

impl<'a> Positive<'a> {
    /// Returns the value, ordered from significant byte to least significant
    /// byte, without any leading zeros. The result is guaranteed to be
    /// non-empty.
    pub fn big_endian_without_leading_zero(&self) -> untrusted::Input<'a> { self.0 }

    /// Returns the first byte.
    ///
    /// Will not panic because the value is guaranteed to have at least one
    /// byte.
    pub fn first_byte(&self) -> u8 {
        // This won't panic because
        self.0.as_slice_less_safe()[0]
    }
}
