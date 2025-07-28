// Copyright 2015-2024 Brian Smith.
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

use super::{
    super::{MAX_LIMBS, MIN_LIMBS},
    BoxedLimbs, Modulus, PublicModulus,
};
use crate::{
    bb,
    bits::{BitLength, FromByteLen as _},
    error::{self, InputTooLongError},
    limb::{self, Limb, LIMB_BITS, LIMB_BYTES},
    polyfill::usize_from_u32,
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
        let num_limbs = (input.len() + LIMB_BYTES - 1) / LIMB_BYTES;
        const _MODULUS_MIN_LIMBS_AT_LEAST_2: () = assert!(MIN_LIMBS >= 2);
        if num_limbs < MIN_LIMBS {
            return Err(error::KeyRejected::too_small());
        }
        if num_limbs > MAX_LIMBS {
            return Err(error::KeyRejected::too_large());
        }

        const _MAX_LIMBS_TIMES_LIMB_BITS_DOES_NOT_OVERFLOW: usize = MAX_LIMBS * LIMB_BITS;
        let len_bits_plus_leading_zeros = BitLength::<usize>::from_byte_len(input.len())
            .unwrap_or_else(|InputTooLongError { .. }| {
                // `num_limbs <= MAX_LIMBS` and `MAX_LIMBS * LIMB_BITS` doesn't overflow.
                unreachable!()
            });

        let hi = input.as_slice_less_safe().first().unwrap_or_else(|| {
            // We know num_limbs >= 2 so there is at least one byte.
            const _: () = _MODULUS_MIN_LIMBS_AT_LEAST_2;
            unreachable!();
        });
        // XXX: Variable-time operation on potentially-secret data. TODO: fix this.
        let leading_zeros = bb::byte_leading_zeros_vartime(hi);

        // Reject leading zero bytes.
        // XXX: Variable-time operation on potentially-secret data. TODO: fix this.
        if leading_zeros.as_bits() == usize_from_u32(u8::BITS) {
            return Err(error::KeyRejected::invalid_encoding());
        }

        let len_bits = len_bits_plus_leading_zeros
            .checked_sub(leading_zeros)
            .unwrap_or_else(|| {
                // Impossible because `len_bits_plus_leading_zeros >= leading_zeros`.
                unreachable!()
            });

        // Having at least 2 limbs where the high-order limb is nonzero implies
        // M >= 3 as required.

        let mut limbs = BoxedLimbs::zero(num_limbs);
        limb::parse_big_endian_and_pad_consttime(input, limbs.as_mut())
            .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
        limb::limbs_reject_even_leak_bit(limbs.as_ref())
            .map_err(|_: error::Unspecified| error::KeyRejected::invalid_component())?;

        Ok(Self { limbs, len_bits })
    }

    pub fn verify_less_than<L>(&self, l: &Modulus<L>) -> Result<(), error::Unspecified> {
        if self.len_bits() > l.len_bits() {
            return Err(error::Unspecified);
        }
        if self.limbs.len() == l.limbs().len() {
            limb::verify_limbs_less_than_limbs_leak_bit(self.limbs.as_ref(), l.limbs())?;
        }
        Ok(())
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        self.limbs.as_ref()
    }
}
