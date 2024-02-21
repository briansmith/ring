// Copyright 2016 Brian Smith.
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

//! Bit lengths.

use crate::{error, polyfill};

/// The length of something, in bits.
///
/// This can represent a bit length that isn't a whole number of bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BitLength<T = usize>(T);

pub(crate) trait FromUsizeBytes: Sized {
    /// Constructs a `BitLength` from the given length in bytes.
    ///
    /// Fails if `bytes * 8` is too large for a `T`.
    fn from_usize_bytes(bytes: usize) -> Result<Self, error::Unspecified>;
}

impl FromUsizeBytes for BitLength<usize> {
    #[inline]
    fn from_usize_bytes(bytes: usize) -> Result<Self, error::Unspecified> {
        let bits = bytes.checked_shl(3).ok_or(error::Unspecified)?;
        Ok(Self(bits))
    }
}

impl FromUsizeBytes for BitLength<u64> {
    #[inline]
    fn from_usize_bytes(bytes: usize) -> Result<Self, error::Unspecified> {
        let bytes = polyfill::u64_from_usize(bytes);
        let bits = bytes.checked_shl(3).ok_or(error::Unspecified)?;
        Ok(Self(bits))
    }
}

impl<T: Copy> BitLength<T> {
    /// The number of bits this bit length represents, as a `usize`.
    #[inline]
    pub fn as_bits(self) -> T {
        self.0
    }
}

// Lengths measured in bits, where all arithmetic is guaranteed not to
// overflow.
impl BitLength<usize> {
    /// Constructs a `BitLength` from the given length in bits.
    #[inline]
    pub const fn from_usize_bits(bits: usize) -> Self {
        Self(bits)
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub(crate) fn half_rounded_up(&self) -> Self {
        let round_up = self.0 & 1;
        Self((self.0 / 2) + round_up)
    }

    /// The bit length, rounded up to a whole number of bytes.
    #[cfg(any(target_arch = "aarch64", feature = "alloc"))]
    #[inline]
    pub fn as_usize_bytes_rounded_up(&self) -> usize {
        // Equivalent to (self.0 + 7) / 8, except with no potential for
        // overflow and without branches.

        // Branchless round_up = if self.0 & 0b111 != 0 { 1 } else { 0 };
        let round_up = ((self.0 >> 2) | (self.0 >> 1) | self.0) & 1;

        (self.0 / 8) + round_up
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub(crate) fn try_sub_1(self) -> Result<Self, error::Unspecified> {
        let sum = self.0.checked_sub(1).ok_or(error::Unspecified)?;
        Ok(Self(sum))
    }
}
