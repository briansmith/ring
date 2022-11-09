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

use super::{elem_add, elem_sub, limb, BoxedLimbs, Limb, LimbMask, Modulus, Prime};

use crate::error;

// `M` represents the prime modulus for which the exponent is in the interval
// [1, `m` - 1).
pub struct PrivateExponent<M> {
    limbs: BoxedLimbs<M>,
}

impl<M> PrivateExponent<M> {
    pub fn from_be_bytes_padded(
        input: untrusted::Input,
        p: &Modulus<M>,
    ) -> Result<Self, error::Unspecified> {
        let dP = BoxedLimbs::from_be_bytes_padded_less_than(input, p)?;

        // Proof that `dP < p - 1`:
        //
        // If `dP < p` then either `dP == p - 1` or `dP < p - 1`. Since `p` is
        // odd, `p - 1` is even. `d` is odd, and an odd number modulo an even
        // number is odd. Therefore `dP` must be odd. But then it cannot be
        // `p - 1` and so we know `dP < p - 1`.
        //
        // Further we know `dP != 0` because `dP` is not even.
        if limb::limbs_are_even_constant_time(&dP) != LimbMask::False {
            return Err(error::Unspecified);
        }

        Ok(Self { limbs: dP })
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        &self.limbs
    }
}

impl<M: Prime> PrivateExponent<M> {
    // Returns `p - 2`.
    pub(super) fn for_flt(p: &Modulus<M>) -> Self {
        let two = elem_add(p.one(), p.one(), p);
        let p_minus_2 = elem_sub(p.zero(), &two, p);
        Self {
            limbs: p_minus_2.limbs,
        }
    }
}
