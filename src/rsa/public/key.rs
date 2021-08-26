// Copyright 2015-2021 Brian Smith.
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

use super::super::N;
use crate::{arithmetic::bigint, bits, error};

#[derive(Debug)]
pub struct Key {
    pub(in crate::rsa) n: bigint::Modulus<N>,
    pub(in crate::rsa) e: bigint::PublicExponent,
    pub(in crate::rsa) n_bits: bits::BitLength,
}

impl Key {
    pub fn from_modulus_and_exponent(
        n: untrusted::Input,
        e: untrusted::Input,
        n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength,
        e_min_value: bigint::PublicExponent,
    ) -> Result<Self, error::KeyRejected> {
        // This is an incomplete implementation of NIST SP800-56Br1 Section
        // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers
        // to NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key
        // Validation for RSA," "with the caveat that the length of the modulus
        // shall be a length that is specified in this Recommendation." In
        // SP800-89, two different sets of steps are given, one set numbered,
        // and one set lettered. TODO: Document this in the end-user
        // documentation for RSA keys.

        // Step 3 / Step c for `n` (out of order).
        let (n, n_bits) = bigint::Modulus::from_be_bytes_with_bit_length(n)?;

        // `pkcs1_encode` depends on this not being small. Otherwise,
        // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
        // bytes) for very small keys.
        const N_MIN_BITS: bits::BitLength = bits::BitLength::from_usize_bits(1024);

        // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
        // the public modulus to be exactly 2048 or 3072 bits, but we are more
        // flexible to be compatible with other commonly-used crypto libraries.
        assert!(n_min_bits >= N_MIN_BITS);
        let n_bits_rounded_up =
            bits::BitLength::from_usize_bytes(n_bits.as_usize_bytes_rounded_up())
                .map_err(|error::Unspecified| error::KeyRejected::unexpected_error())?;
        if n_bits_rounded_up < n_min_bits {
            return Err(error::KeyRejected::too_small());
        }
        if n_bits > n_max_bits {
            return Err(error::KeyRejected::too_large());
        }

        // Step 2 / Step b.
        // Step 3 / Step c for `e`.
        let e = bigint::PublicExponent::from_be_bytes(e, e_min_value)?;

        // If `n` is less than `e` then somebody has probably accidentally swapped
        // them. The largest acceptable `e` is smaller than the smallest acceptable
        // `n`, so no additional checks need to be done.

        // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
        // case in most other commonly-used crypto libraries.

        Ok(Self { n, e, n_bits })
    }
}
