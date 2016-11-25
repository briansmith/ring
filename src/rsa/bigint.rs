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

//! Mutli-precision integers.

use {bits, c, error, untrusted};
use core;
#[cfg(feature = "rsa_signing")]
use der;

/// Non-negative, non-zero integers.
///
/// This set is sometimes called `Natural` or `Counting`, but texts, libraries,
/// and standards disagree on whether to include zero in them, so we avoid
/// those names.
pub struct Positive {
    value: *mut BIGNUM,
}

impl Positive {
    #[cfg(feature = "rsa_signing")]
    // Parses a single ASN.1 DER-encoded `Integer`, which most be positive.
    pub fn from_der(input: &mut untrusted::Reader)
                    -> Result<Positive, error::Unspecified> {
        Self::from_be_bytes(try!(der::positive_integer(input)))
    }

    // Turns a sequence of big-endian bytes into a Positive Integer.
    pub fn from_be_bytes(input: untrusted::Input)
                         -> Result<Positive, error::Unspecified> {
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
        Ok(Positive { value: value })
    }

    pub unsafe fn as_ref<'a>(&'a self) -> &'a BIGNUM { &*self.value }

    #[cfg(feature = "rsa_signing")]
    pub fn into_raw(mut self) -> *mut BIGNUM {
        let res = self.value;
        self.value = core::ptr::null_mut();
        res
    }

    pub fn bit_length(&self) -> bits::BitLength {
        let bits = unsafe { GFp_BN_num_bits(self.as_ref()) };
        bits::BitLength::from_usize_bits(bits)
    }
}

impl<'a> Drop for Positive {
    fn drop(&mut self) { unsafe { GFp_BN_free(self.value); } }
}

#[cfg(feature = "rsa_signing")]
#[allow(non_camel_case_types)]
pub enum BN_MONT_CTX {}

pub enum BIGNUM {}

extern {
    fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                     -> *mut BIGNUM;
    pub fn GFp_BN_free(bn: *mut BIGNUM);
    fn GFp_BN_num_bits(bn: *const BIGNUM) -> c::size_t;

    #[cfg(feature = "rsa_signing")]
    pub fn GFp_BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
}

#[cfg(test)]
mod tests {
    use super::Positive;
    use untrusted;

    #[test]
    fn test_positive_integer_from_be_bytes_empty() {
        // Empty values are rejected.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[])).is_err());
    }

    #[test]
    fn test_positive_integer_from_be_bytes_zero() {
        // The zero value is rejected.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[0])).is_err());
        // A zero with a leading zero is rejected.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[0, 0])).is_err());
        // A non-zero value with a leading zero is rejected.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[0, 1])).is_err());
        // A non-zero value with no leading zeros is accepted.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[1])).is_ok());
        // A non-zero value with that ends in a zero byte is accepted.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[1, 0])).is_ok());
    }
}
