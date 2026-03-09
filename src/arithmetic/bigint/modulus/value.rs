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

use super::super::super::{MAX_LIMBS, MIN_LIMBS};
use crate::{
    bb,
    bits::{BitLength, FromByteLen as _},
    error::{self, InputTooLongError, LenMismatchError},
    limb,
    limb::{LIMB_BITS, LIMB_BYTES, Limb},
    polyfill::usize_from_u32,
};
use core::marker::PhantomData;

/// `OwnedModulus`, without the overhead of Montgomery multiplication support.
pub(crate) struct Value<'a, M> {
    limbs: &'a [Limb], // Also `value >= 3`.
    len_bits: BitLength,
    m: PhantomData<M>,
}

pub struct ValidatedInput<'a> {
    input: untrusted::Input<'a>,
    num_limbs: usize,
    len_bits: BitLength,
}

impl<'a> ValidatedInput<'a> {
    pub fn try_from_be_bytes(input: untrusted::Input<'a>) -> Result<Self, error::KeyRejected> {
        let num_limbs = input.len().div_ceil(LIMB_BYTES);
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

        let lo = input.as_slice_less_safe().last().unwrap_or_else(|| {
            // We know num_limbs >= 2 so there is at least one byte.
            const _: () = _MODULUS_MIN_LIMBS_AT_LEAST_2;
            unreachable!();
        });
        if bb::byte_is_even(lo).leak() {
            return Err(error::KeyRejected::invalid_component());
        };

        // Having at least 2 limbs where the high-order limb is nonzero implies
        // M >= 3 as required.
        Ok(Self {
            input,
            num_limbs,
            len_bits,
        })
    }

    pub(super) fn limbs(&self) -> impl ExactSizeIterator<Item = Limb> + '_ {
        limb::limbs_from_big_endian(self.input(), self.num_limbs..=self.num_limbs)
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!())
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }

    pub fn input(&self) -> untrusted::Input<'_> {
        self.input
    }
}

impl<M> Value<'_, M> {
    pub(super) fn from_limbs_unchecked_less_safe(
        limbs: &[Limb],
        len_bits: BitLength,
    ) -> Value<'_, M> {
        Value {
            limbs,
            len_bits,
            m: PhantomData,
        }
    }

    pub fn len_bits(&self) -> BitLength {
        self.len_bits
    }

    #[inline]
    pub(super) fn limbs(&self) -> &[Limb] {
        self.limbs
    }
}
