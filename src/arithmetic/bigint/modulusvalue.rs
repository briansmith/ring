// Copyright 2015-2024 Brian Smith.
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

use super::{
    super::{MAX_LIMBS, MIN_LIMBS},
    BoxedLimbs, Modulus, PublicModulus,
};
use crate::{
    bits::BitLength,
    error,
    limb::{self, Limb},
};

/// `OwnedModulus`, without the overhead of Montgomery multiplication support.
pub(crate) struct OwnedModulusValue<M> {
    limbs: BoxedLimbs<M>, // Also `value >= 3`.

    len_bits: BitLength,
}

impl<M: PublicModulus> Clone for OwnedModulusValue<M> {
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            len_bits: self.len_bits,
        }
    }
}

impl<M> OwnedModulusValue<M> {
    pub(crate) fn from_be_bytes(input: untrusted::Input) -> Result<Self, error::KeyRejected> {
        let n = BoxedLimbs::positive_minimal_width_from_be_bytes(input)?;
        if n.len() > MAX_LIMBS {
            return Err(error::KeyRejected::too_large());
        }
        const _MODULUS_MIN_LIMBS_AT_LEAST_2: () = assert!(MIN_LIMBS >= 2);
        if n.len() < MIN_LIMBS {
            return Err(error::KeyRejected::unexpected_error());
        }
        // The above implies n >= 3, so we don't need to check it.
        limb::limbs_reject_even_leak_bit(&n)
            .map_err(|_: error::Unspecified| error::KeyRejected::invalid_component())?;

        let len_bits = limb::limbs_minimal_bits(&n);

        Ok(Self { limbs: n, len_bits })
    }

    pub fn verify_less_than<L>(&self, l: &Modulus<L>) -> Result<(), error::Unspecified> {
        if self.len_bits() > l.len_bits()
            || (self.limbs.len() == l.limbs().len()
                && !limb::limbs_less_than_limbs_consttime(&self.limbs, l.limbs()).leak())
        {
            return Err(error::Unspecified);
        }
        Ok(())
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        &self.limbs
    }
}
