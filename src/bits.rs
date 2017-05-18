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

use error;

/// XXX: When `const_fn` is implemented then make the value private to force
/// the constructors to be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub struct BitLength(pub usize);

// Lengths measured in bits, where all arithmetic is guaranteed not to
// overflow.
impl BitLength {
    #[inline]
    pub fn from_usize_bits(bits: usize) -> BitLength { BitLength(bits) }

    #[inline]
    pub fn from_usize_bytes(bytes: usize)
                            -> Result<BitLength, error::Unspecified> {
        let bits = bytes.checked_mul(8).ok_or(error::Unspecified)?;
        Ok(BitLength::from_usize_bits(bits))
    }

    #[inline]
    pub fn half_rounded_up(&self) -> BitLength {
        let round_up = self.0 & 1;
        BitLength((self.0 / 2) + round_up)
    }

    #[inline]
    pub fn as_usize_bits(&self) -> usize { self.0 }

    #[inline]
    pub fn as_usize_bytes_rounded_up(&self) -> usize {
        // Equivalent to (self.0 + 7) / 8, except with no potential for
        // overflow and without branches.

        // Branchless round_up = if self.0 & 0b111 != 0 { 1 } else { 0 };
        let round_up = ((self.0 >> 2) | (self.0 >> 1) | self.0) & 1;

        (self.0 / 8) + round_up
    }

    #[inline]
    pub fn try_sub(self, other: BitLength)
                   -> Result<BitLength, error::Unspecified> {
        let sum = self.0.checked_sub(other.0).ok_or(error::Unspecified)?;
        Ok(BitLength(sum))
    }
}

pub const ONE: BitLength = BitLength(1);
