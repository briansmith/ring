// Copyright 2015-2023 Brian Smith.
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

use crate::{
    bits, error,
    limb::{self, Limb, LimbMask, LIMB_BYTES},
};
use alloc::{boxed::Box, vec, vec::Vec};

/// Nonnegative integers.
pub(crate) struct Nonnegative {
    limbs: Vec<Limb>,
}

impl Nonnegative {
    pub fn from_be_bytes_with_bit_length(
        input: untrusted::Input,
    ) -> Result<(Self, bits::BitLength), error::Unspecified> {
        let mut limbs = vec![0; (input.len() + LIMB_BYTES - 1) / LIMB_BYTES];
        // Rejects empty inputs.
        limb::parse_big_endian_and_pad_consttime(input, &mut limbs)?;
        while limbs.last() == Some(&0) {
            let _ = limbs.pop();
        }
        let r_bits = limb::limbs_minimal_bits(&limbs);
        Ok((Self { limbs }, r_bits))
    }

    #[inline]
    pub fn is_odd(&self) -> bool {
        limb::limbs_are_even_constant_time(&self.limbs) != LimbMask::True
    }

    pub fn verify_less_than(&self, other: &Self) -> Result<(), error::Unspecified> {
        if !greater_than(other, self) {
            return Err(error::Unspecified);
        }
        Ok(())
    }

    #[inline]
    pub fn limbs(&self) -> &[Limb] {
        &self.limbs
    }

    #[inline]
    pub fn into_limbs(self) -> Box<[Limb]> {
        self.limbs.into_boxed_slice()
    }
}

// Returns a > b.
fn greater_than(a: &Nonnegative, b: &Nonnegative) -> bool {
    if a.limbs.len() == b.limbs.len() {
        limb::limbs_less_than_limbs_vartime(&b.limbs, &a.limbs)
    } else {
        a.limbs.len() > b.limbs.len()
    }
}
