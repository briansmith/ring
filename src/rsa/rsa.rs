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

use {bits, c, core, der, error, limb};
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

// Keep in sync with the documentation comment for `RSAKeyPair` and
// `PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS` in rsa.c.
const PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS: usize = 4096;

const PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS: usize =
    (PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS + limb::LIMB_BITS - 1) /
    limb::LIMB_BITS;


/// Parameters for RSA verification.
pub struct RSAParameters {
    padding_alg: &'static padding::RSAVerification,
    min_bits: usize,
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

struct PositiveInteger {
    value: *mut BIGNUM,
}

impl PositiveInteger {
    #[cfg(feature = "rsa_signing")]
    // Parses a single ASN.1 DER-encoded `Integer`, which most be positive.
    fn from_der(input: &mut untrusted::Reader)
                -> Result<PositiveInteger, error::Unspecified> {
        Self::from_be_bytes(try!(der::positive_integer(input)))
    }

    // Turns a sequence of big-endian bytes into a Positive Integer.
    fn from_be_bytes(input: untrusted::Input)
                     -> Result<PositiveInteger, error::Unspecified> {
        // Reject empty inputs.
        if input.len() == 0 {
            return Err(error::Unspecified);
        }
        // Reject leading zeros. Also reject the value zero ([0]) because zero
        // isn't positive.
        if untrusted::Reader::new(input).peek(0) {
            return Err(error::Unspecified);
        }
        let value = unsafe {
            GFp_BN_bin2bn(input.as_slice_less_safe().as_ptr(), input.len(),
                          core::ptr::null_mut())
        };
        if value.is_null() {
            return Err(error::Unspecified);
        }
        Ok(PositiveInteger { value: value })
    }

    unsafe fn as_ref<'a>(&'a self) -> &'a BIGNUM { &*self.value }

    #[cfg(feature = "rsa_signing")]
    fn into_raw(mut self) -> *mut BIGNUM {
        let res = self.value;
        self.value = core::ptr::null_mut();
        res
    }

    fn bit_length(&self) -> bits::BitLength {
        let bits = unsafe { GFp_BN_num_bits(self.as_ref()) };
        bits::BitLength::from_usize_bits(bits)
    }
}

impl<'a> Drop for PositiveInteger {
    fn drop(&mut self) { unsafe { GFp_BN_free(self.value); } }
}

#[cfg(feature = "rsa_signing")]
#[allow(non_camel_case_types)]
enum BN_MONT_CTX {}

enum BIGNUM {}

pub mod verification;

#[cfg(feature = "rsa_signing")]
pub mod signing;


extern {
    fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                     -> *mut BIGNUM;
    fn GFp_BN_free(bn: *mut BIGNUM);
    fn GFp_BN_num_bits(bn: *const BIGNUM) -> c::size_t;
}

#[cfg(feature = "rsa_signing")]
extern {
    fn GFp_BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
}

mod blinding;

// Really a private method; only has public visibility so that C compilation
// can see it.
#[doc(hidden)]
pub use rsa::blinding::GFp_rand_mod;

#[cfg(test)]
mod tests {
    use super::PositiveInteger;
    use untrusted;

    #[test]
    fn test_positive_integer_from_be_bytes_empty() {
        // Empty values are rejected.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[])).is_err());
    }

    #[test]
    fn test_positive_integer_from_be_bytes_zero() {
        // The zero value is rejected.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[0])).is_err());
        // A zero with a leading zero is rejected.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[0, 0])).is_err());
        // A non-zero value with a leading zero is rejected.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[0, 1])).is_err());
        // A non-zero value with no leading zeros is accepted.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[1])).is_ok());
        // A non-zero value with that ends in a zero byte is accepted.
        assert!(PositiveInteger::from_be_bytes(
                    untrusted::Input::from(&[1, 0])).is_ok());
    }
}
