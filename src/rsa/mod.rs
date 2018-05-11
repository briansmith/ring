// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for
// `RSAKeyPair` components.
#![allow(non_snake_case)]

/// RSA signatures.

use {bits, der, limb, error};
use untrusted;

mod padding;

// `RSA_PKCS1_SHA1` is intentionally not exposed.
#[cfg(feature = "rsa_signing")]
pub use self::padding::RSAEncoding;

pub use self::padding::{
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512
};


// Maximum RSA modulus size supported for signature verification (in bytes).
const PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN: usize =
    bigint::MODULUS_MAX_LIMBS * limb::LIMB_BYTES;

// Keep in sync with the documentation comment for `RSAKeyPair`.
#[cfg(feature = "rsa_signing")]
const PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS: bits::BitLength =
    bits::BitLength(4096);

#[cfg(feature = "rsa_signing")]
const PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS: usize =
    (4096 + limb::LIMB_BITS - 1) / limb::LIMB_BITS;


/// Parameters for RSA verification.
pub struct RSAParameters {
    padding_alg: &'static padding::RSAVerification,
    min_bits: bits::BitLength,
    id: RSAParametersID,
}

#[allow(non_camel_case_types)]
enum RSAParametersID {
    RSA_PKCS1_2048_8192_SHA1,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
}

fn parse_public_key(input: untrusted::Input)
                    -> Result<(untrusted::Input, untrusted::Input),
                              error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            let n = der::positive_integer(input)?;
            let e = der::positive_integer(input)?;
            Ok((n, e))
        })
    })
}

fn check_public_modulus_and_exponent(
        n: untrusted::Input, e: untrusted::Input, n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength, e_min_value: u64)
        -> Result<(bigint::Modulus<N>, bits::BitLength,
                   bigint::PublicExponent), error::Unspecified> {
    // This is an incomplete implementation of NIST SP800-56Br1 Section
    // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers to
    // NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key Validation
    // for RSA," "with the caveat that the length of the modulus shall be a
    // length that is specified in this Recommendation." In SP800-89, two
    // different sets of steps are given, one set numbered, and one set
    // lettered. TODO: Document this in the end-user documentation for RSA
    // keys.

    // Step 3 / Step c for `n` (out of order).
    let (n, n_bits) = bigint::Modulus::from_be_bytes_with_bit_length(n)?;

    // `pkcs1_encode` depends on this not being small. Otherwise,
    // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
    // bytes) for very small keys.
    const N_MIN_BITS: bits::BitLength = bits::BitLength(2048);

    // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
    // the public modulus to be exactly 2048 or 3072 bits, but we are more
    // flexible to be compatible with other commonly-used crypto libraries.
    assert!(n_min_bits >= N_MIN_BITS);
    let n_bits_rounded_up =
        bits::BitLength::from_usize_bytes(n_bits.as_usize_bytes_rounded_up())?;
    if n_bits_rounded_up < n_min_bits {
        return Err(error::Unspecified);
    }
    if n_bits > n_max_bits {
        return Err(error::Unspecified);
    }

    // Step 2 / Step b. NIST SP800-89 defers to FIPS 186-3, which requires
    // `e >= 65537`. We enforce this when signing, but are more flexible in
    // verification, for compatibility. Only small public exponents are
    // supported.
    debug_assert!(e_min_value >= 3);
    debug_assert!(e_min_value & 1 == 1); // `e_min_value` is odd.
    debug_assert!(e_min_value <= bigint::PUBLIC_EXPONENT_MAX_VALUE);

    // Step 3 / Step c for `e`.
    let e = bigint::PublicExponent::from_be_bytes(e, e_min_value)?;

    // If `n` is less than `e` then somebody has probably accidentally swapped
    // them. The largest acceptable `e` is smaller than the smallest acceptable
    // `n`, so no additional checks need to be done.

    // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
    // case in most other commonly-used crypto libraries.

    Ok((n, n_bits, e))
}

// Type-level representation of an RSA public modulus *n*. See
// `super::bigint`'s modulue-level documentation.
#[derive(Copy, Clone)]
pub enum N {}

pub mod verification;

#[cfg(feature = "rsa_signing")]
pub mod signing;

mod bigint;

#[cfg(feature = "rsa_signing")]
mod blinding;

#[cfg(feature = "rsa_signing")]
mod random;
