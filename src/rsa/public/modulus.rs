use crate::{arithmetic::bigint, bits, error, rsa::N};
use core::ops::RangeInclusive;

pub struct Modulus {
    value: bigint::Modulus<N>,
    bits: bits::BitLength,
}

impl core::fmt::Debug for Modulus {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        self.value.fmt(fmt)
    }
}

impl Modulus {
    pub(super) fn from_be_bytes(
        n: untrusted::Input,
        allowed_bit_lengths: RangeInclusive<bits::BitLength>,
    ) -> Result<Self, error::KeyRejected> {
        // See `public::Key::from_modulus_and_exponent` for background on the step
        // numbering.

        let min_bits = *allowed_bit_lengths.start();
        let max_bits = *allowed_bit_lengths.end();

        // `pkcs1_encode` depends on this not being small. Otherwise,
        // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
        // bytes) for very small keys.
        const MIN_BITS: bits::BitLength = bits::BitLength::from_usize_bits(1024);

        // Step 3 / Step c for `n` (out of order).
        let (value, bits) = bigint::Modulus::from_be_bytes_with_bit_length(n)?;

        // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
        // the public modulus to be exactly 2048 or 3072 bits, but we are more
        // flexible to be compatible with other commonly-used crypto libraries.
        assert!(min_bits >= MIN_BITS);
        let bits_rounded_up =
            bits::BitLength::from_usize_bytes(bits.as_usize_bytes_rounded_up()).unwrap(); // TODO: safe?
        if bits_rounded_up < min_bits {
            return Err(error::KeyRejected::too_small());
        }
        if bits > max_bits {
            return Err(error::KeyRejected::too_large());
        }

        Ok(Self { value, bits })
    }

    #[inline]
    pub(crate) fn len_bits(&self) -> bits::BitLength {
        self.bits
    }

    pub(in super::super) fn value(&self) -> &bigint::Modulus<N> {
        &self.value
    }
}
