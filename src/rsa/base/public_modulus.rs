use crate::{
    arithmetic::{bigint, montgomery::RR},
    bits::{self, FromByteLen as _},
    cpu,
    error::{self, InputTooLongError},
    rsa::N,
};
use core::ops::RangeInclusive;

/// The modulus (n) of an RSA public key.
#[derive(Clone)]
pub struct PublicModulus {
    value: bigint::BoxedIntoMont<N, RR>,
}

/*
impl core::fmt::Debug for PublicModulus {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> Result<(), ::core::fmt::Error> {
        self.value.fmt(fmt)
    }
}*/

pub struct ValidatedInput<'a> {
    input: bigint::modulus::ValidatedInput<'a>,
}

impl<'a> ValidatedInput<'a> {
    pub fn from_be_bytes(
        n: &'a [u8],
        allowed_bit_lengths: RangeInclusive<bits::BitLength>,
    ) -> Result<Self, error::KeyRejected> {
        // See `PublicKey::from_modulus_and_exponent` for background on the step
        // numbering.

        let min_bits = *allowed_bit_lengths.start();
        let max_bits = *allowed_bit_lengths.end();

        // `pkcs1_encode` depends on this not being small. Otherwise,
        // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
        // bytes) for very small keys.
        const MIN_BITS: bits::BitLength = bits::BitLength::from_bits(1024);

        // Step 3 / Step c for `n` (out of order).
        let input = bigint::modulus::ValidatedInput::try_from_be_bytes(n.into())?;
        let bits = input.len_bits();

        // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
        // the public modulus to be exactly 2048 or 3072 bits, but we are more
        // flexible to be compatible with other commonly-used crypto libraries.
        assert!(min_bits >= MIN_BITS);
        let bits_rounded_up = bits::BitLength::from_byte_len(bits.as_usize_bytes_rounded_up())
            .map_err(error::erase::<InputTooLongError>)
            .unwrap(); // TODO: safe?
        if bits_rounded_up < min_bits {
            return Err(error::KeyRejected::too_small());
        }
        if bits > max_bits {
            return Err(error::KeyRejected::too_large());
        }
        Ok(Self { input })
    }

    pub fn input(&self) -> untrusted::Input<'_> {
        self.input.input()
    }

    pub fn len_bits(&self) -> bits::BitLength {
        self.input.len_bits()
    }

    pub(super) fn build(&self, cpu_features: cpu::Features) -> PublicModulus {
        PublicModulus {
            value: self.input.build_boxed_into_mont(cpu_features),
        }
    }
}

impl PublicModulus {
    /// The big-endian encoding of the modulus.
    ///
    /// There are no leading zeros.
    pub fn be_bytes(&self) -> impl ExactSizeIterator<Item = u8> + Clone + '_ {
        self.value.reborrow().be_bytes()
    }

    /// The length of the modulus in bits.
    pub fn len_bits(&self) -> bits::BitLength {
        self.value.reborrow().len_bits()
    }

    pub(in super::super) fn value(&self) -> bigint::IntoMont<'_, N, RR> {
        self.value.reborrow()
    }
}
