// Copyright 2015-2023 Brian Smith.
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

use super::{Limb, Mont, limb};
use crate::error;
use alloc::boxed::Box;

pub struct PrivateExponent {
    // Unlike most `[Limb]` we deal with, these are stored most significant
    // word first.
    limbs: Box<[Limb]>,
}

impl PrivateExponent {
    // `p` is the modulus for which the exponent is in the interval [1, `p` - 1).
    pub fn from_be_bytes_padded<M>(
        input: untrusted::Input,
        p: &Mont<M>,
    ) -> Result<Self, error::Unspecified> {
        let mut dP = p
            .alloc_uninit()
            .into_elem_from_be_bytes_padded(input, p)?
            .leak_limbs_into_box_less_safe();

        // Proof that `dP < p - 1`:
        //
        // If `dP < p` then either `dP == p - 1` or `dP < p - 1`. Since `p` is
        // odd, `p - 1` is even. `d` is odd, and an odd number modulo an even
        // number is odd. Therefore `dP` must be odd. But then it cannot be
        // `p - 1` and so we know `dP < p - 1`.
        //
        // Further we know `dP != 0` because `dP` is not even.
        limb::limbs_reject_even_leak_bit(dP.as_ref())?;
        dP.as_mut().reverse();

        Ok(Self {
            limbs: dP.into_limbs(),
        })
    }

    // Create a `PrivateExponent` with a value that we do not support in
    // production use, to allow testing with additional test vectors.
    #[cfg(test)]
    pub fn from_be_bytes_for_test_only<M>(
        input: untrusted::Input,
        p: &Mont<M>,
    ) -> Result<Self, error::Unspecified> {
        use super::boxed_limbs::Uninit;
        use crate::{error::LenMismatchError, limb::LIMB_BYTES};

        // Do exactly what `from_be_bytes_padded` does for any inputs it accepts.
        if let r @ Ok(_) = Self::from_be_bytes_padded(input, p) {
            return r;
        }

        let num_limbs = input.len().div_ceil(LIMB_BYTES);
        let mut limbs = Uninit::<M>::new_less_safe(num_limbs)
            .write_from_be_bytes_padded(input)
            .map_err(|LenMismatchError { .. }| error::KeyRejected::unexpected_error())?;
        limbs.as_mut().reverse();
        Ok(Self {
            limbs: limbs.into_limbs(),
        })
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        &self.limbs
    }
}
