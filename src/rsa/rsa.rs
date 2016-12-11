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
        -> Result<(bigint::OddPositive, bigint::OddPositive),
                  error::Unspecified> {
    let n = try!(n.into_odd_positive());
    let e = try!(e.into_odd_positive());

    // Mitigate DoS attacks by limiting the exponent size. 33 bits was chosen
    // as the limit based on the recommendations in [1] and [2]. Windows
    // CryptoAPI (at least older versions) doesn't support values larger than
    // 32 bits [3], so it is unlikely that exponents larger than 32 bits are
    // being used for anything Windows commonly does.
    //
    // [1] https://www.imperialviolet.org/2012/03/16/rsae.html
    // [2] https://www.imperialviolet.org/2012/03/17/rsados.html
    // [3] https://msdn.microsoft.com/en-us/library/aa387685(VS.85).aspx
    const MAX_EXPONENT_BITS: bits::BitLength = bits::BitLength(33);

    // The public modulus must be large enough. `pkcs1_encode` depends on this
    // not being small. Without it, `pkcs1_encode` would generate padding that
    // is invalid (too few 0xFF bytes) for very small keys.
    const N_MIN_BITS: bits::BitLength = bits::BitLength(2048);
    assert!(n_min_bits >= N_MIN_BITS);
    debug_assert!(MAX_EXPONENT_BITS < N_MIN_BITS);

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

    let e_bits = e.bit_length();
    if e_bits < bits::BitLength::from_usize_bits(2) {
        return Err(error::Unspecified);
    }
    if e_bits > MAX_EXPONENT_BITS {
        return Err(error::Unspecified);
    }

    Ok((n, e))
}

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
