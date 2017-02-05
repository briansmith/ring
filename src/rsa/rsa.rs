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

/// An RSA public key, used for signature verification. Feature: `rsa_signing`.
pub struct RSAPublicKey {
    n: bigint::Modulus<N>,
    e: bigint::PublicExponent,
}

impl RSAPublicKey {
    /// Parse a public key in DER-encoded ASN.1 `RSAPublicKey` form (see
    /// [RFC 3447 Appendix A.1.1]).
    pub fn from_der(input: untrusted::Input)
                    -> Result<RSAPublicKey, error::Unspecified> {
        input.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let n = try!(der::positive_integer(input));
                let e = try!(der::positive_integer(input));
                Self::from_be_bytes(n, e)
            })
        })
    }

    /// Parse a public key from byte arrays containing the public modulus and
    /// exponent in big endian order.
    pub fn from_be_bytes(n: untrusted::Input, e: untrusted::Input)
                         -> Result<RSAPublicKey, error::Unspecified> {
        let n = try!(bigint::Positive::from_be_bytes(n));
        let e = try!(bigint::Positive::from_be_bytes(e));
        Self::from_bn(n, e)
    }

    fn from_bn(n: bigint::Positive, e: bigint::Positive)
               -> Result<RSAPublicKey, error::Unspecified> {
        let n = try!(n.into_odd_positive());
        let e = try!(e.into_odd_positive());

        let n = try!(n.into_modulus::<N>());
        let e = try!(e.into_public_exponent());

        Ok(RSAPublicKey { n: n, e: e })
    }

    fn check_modulus(&self, n_min_bits: bits::BitLength,
                     n_max_bits: bits::BitLength)
                     -> Result<(), error::Unspecified> {
        // This is an incomplete implementation of NIST SP800-56Br1 Section
        // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers to
        // NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key Validation
        // for RSA," "with the caveat that the length of the modulus shall be a
        // length that is specified in this Recommendation." In SP800-89, two
        // different sets of steps are given, one set numbered, and one set
        // lettered. TODO: Document this in the end-user documentation for RSA
        // keys.

        // `pkcs1_encode` depends on this not being small. Otherwise,
        // `pkcs1_encode` would generate padding that is invalid (too few 0xFF
        // bytes) for very small keys.
        const N_MIN_BITS: bits::BitLength = bits::BitLength(2048);

        // Step 1 / Step a. XXX: SP800-56Br1 and SP800-89 require the length of
        // the public modulus to be exactly 2048 or 3072 bits, but we are more
        // flexible to be compatible with other commonly-used crypto libraries.
        assert!(n_min_bits >= N_MIN_BITS);
        let n_bits = self.n.bit_length();
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
        let e_bits = self.e.bit_length();
        if e_bits < bits::BitLength::from_usize_bits(2) {
            return Err(error::Unspecified);
        }

        // If `n` is less than `e` then somebody has probably accidentally swapped
        // them. The largest acceptable `e` is smaller than the smallest acceptable
        // `n`, so no additional checks need to be done.
        debug_assert!(bigint::PUBLIC_EXPONENT_MAX_BITS < N_MIN_BITS);

        // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
        // case in most other commonly-used crypto libraries.

        Ok(())
    }

    /// Verify a message signature using this public key.
    pub fn verify(&self, params: &RSAParameters, msg: untrusted::Input,
                  signature: untrusted::Input)
                  -> Result<(), error::Unspecified> {
        verification::verify_rsa(params, self, msg, signature)
    }

    /// Returns the length in bytes of the public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn modulus_len(&self) -> usize {
        self.n.bit_length().as_usize_bytes_rounded_up()
    }

    /// Extracts the public modulus.
    ///
    /// `out` must be exactly `modulus_len()` bytes long. It will be filled
    /// with the big-endian-encoded bytes, without any padding.
    pub fn export_modulus(&self, out: &mut [u8])
                    -> Result<(), error::Unspecified> {
        if out.len() == self.modulus_len() {
            self.n.fill_be_bytes(out)
        } else {
            Err(error::Unspecified)
        }
    }

    /// Returns the length in bytes of the public exponent.
    pub fn exponent_len(&self) -> usize {
        self.e.bit_length().as_usize_bytes_rounded_up()
    }

    /// Extracts the public exponent.
    ///
    /// `out` must be exactly `exponent_len()` bytes long. It will be filled
    /// with the big-endian-encoded bytes, without any padding.
    pub fn export_exponent(&self, out: &mut [u8])
                    -> Result<(), error::Unspecified> {
        if out.len() == self.exponent_len() {
            self.e.fill_be_bytes(out)
        } else {
            Err(error::Unspecified)
        }
    }
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


#[cfg(test)]
mod tests {
    use {signature, std, untrusted};

    #[test]
    fn test_export() {
        const PUBLIC_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_public_key.der");
        let key_bytes_der = untrusted::Input::from(PUBLIC_KEY_DER);
        let public_key = signature::RSAPublicKey::from_der(key_bytes_der).unwrap();

        let len = public_key.modulus_len();
        let mut buf: std::vec::Vec<u8> = vec![0; len+1];
        assert!(public_key.export_modulus(&mut buf).is_err());
        assert!(public_key.export_modulus(&mut buf[..len]).is_ok());
        assert!(public_key.export_modulus(&mut buf[..len-1]).is_err());

        let len = public_key.exponent_len();
        let mut buf: std::vec::Vec<u8> = vec![0; len+1];
        assert!(public_key.export_exponent(&mut buf).is_err());
        assert!(public_key.export_exponent(&mut buf[..len]).is_ok());
        assert!(public_key.export_exponent(&mut buf[..len-1]).is_err());
    }
}
