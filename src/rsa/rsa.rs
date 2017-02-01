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

/// RSA signatures.

use {bits, der, error, limb};
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
const PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN: usize = 8192 / 8;

// Keep in sync with the documentation comment for `RSAKeyPair`.
#[cfg(feature = "rsa_signing")]
const PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS: bits::BitLength =
    bits::BitLength(4096);

const PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS: usize =
    (4096 + limb::LIMB_BITS - 1) / limb::LIMB_BITS;


/// Parameters for RSA verification.
pub struct RSAParameters {
    padding_alg: &'static padding::RSAVerification,
    min_bits: bits::BitLength,
}

fn parse_public_key(input: untrusted::Input)
                    -> Result<(untrusted::Input, untrusted::Input),
                              error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            let n = try!(der::positive_integer(input));
            let e = try!(der::positive_integer(input));
            Ok((n, e))
        })
    })
}

fn check_public_modulus_and_exponent(
        n: bigint::Positive, e: bigint::Positive, n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength)
        -> Result<(bigint::Modulus<N>, bigint::PublicExponent),
                  error::Unspecified> {
    // This is an incomplete implementation of NIST SP800-56Br1 Section
    // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers to
    // NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key Validation
    // for RSA," "with the caveat that the length of the modulus shall be a
    // length that is specified in this Recommendation." In SP800-89, two
    // different sets of steps are given, one set numbered, and one set
    // lettered. TODO: Document this in the end-user documentation for RSA
    // keys.

    // Step 3 / Step c (out of order).
    let n = try!(n.into_odd_positive());
    let e = try!(e.into_odd_positive());

    // `pkcs1_encode` depends on this not being small. Otherwise,
    // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
    // bytes) for very small keys.
    const N_MIN_BITS: bits::BitLength = bits::BitLength(2048);

    // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
    // the public modulus to be exactly 2048 or 3072 bits, but we are more
    // flexible to be compatible with other commonly-used crypto libraries.
    assert!(n_min_bits >= N_MIN_BITS);
    let n_bits = n.bit_length();
    let n_bits_rounded_up =
        try!(bits::BitLength::from_usize_bytes(
            n_bits.as_usize_bytes_rounded_up()));
    if n_bits_rounded_up < n_min_bits {
        return Err(error::Unspecified);
    }
    if n_bits > n_max_bits {
        return Err(error::Unspecified);
    }

    // Step 2 / Step b. XXX: FIPS 186-4 seems to indicate that the minimum
    // exponent value is 2**16 + 1, but it isn't clear if this is just for
    // signing or also for verification. We support exponents of 3 and larger
    // for compatibility with other commonly-used crypto libraries.
    //
    let e_bits = e.bit_length();
    if e_bits < bits::BitLength::from_usize_bits(2) {
        return Err(error::Unspecified);
    }

    let n = try!(n.into_modulus::<N>());

    // Only small public exponents are supported.
    let e = try!(e.into_public_exponent());

    // If `n` is less than `e` then somebody has probably accidentally swapped
    // them. The largest acceptable `e` is smaller than the smallest acceptable
    // `n`, so no additional checks need to be done.
    debug_assert!(bigint::PUBLIC_EXPONENT_MAX_BITS < N_MIN_BITS);

    // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
    // case in most other commonly-used crypto libraries.

    Ok((n, e))
}

// Type-level representation of an RSA public modulus *n*. See
// `super::bigint`'s modulue-level documentation.
pub enum N {}

pub mod verification;

#[cfg(feature = "rsa_signing")]
pub mod signing;

mod bigint;

#[cfg(feature = "rsa_signing")]
mod blinding;

mod random;

// Really a private method; only has public visibility so that C compilation
// can see it.
#[doc(hidden)]
pub use rsa::random::GFp_rand_mod;
