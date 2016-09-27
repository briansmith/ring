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

/// Multi-precision integers.

use {c, core, error};

#[cfg(feature = "rsa_signing")]
use der;

use untrusted;


#[allow(non_camel_case_types)]
pub enum BN_ULONG {}

/// Needs to be kept in sync with `struct bignum_st` (in `include/openssl/bn.h`)
#[repr(C)]
pub struct BIGNUM {
    pub d: *mut BN_ULONG,
    pub top: c::int,
    pub dmax: c::int,
    pub neg: c::int,
    pub flags: c::int,
}

impl BIGNUM {
    pub fn new() -> BIGNUM {
        BIGNUM {
            d: core::ptr::null_mut(),
            top: 0,
            dmax: 0,
            neg: 0,
            flags: 0,
        }
    }
}

extern {
    pub fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                         -> *mut BIGNUM;
    pub fn GFp_BN_bn2bin_padded(out: *mut u8, len: c::size_t,
                                in_: *const BIGNUM)
                                -> c::int;
    pub fn GFp_BN_free(bn: *mut BIGNUM);
    pub fn GFp_BN_init(bn: *mut BIGNUM);
    pub fn GFp_BN_mod_exp_mont_vartime(rr: *mut BIGNUM, a: *const BIGNUM,
                                       p: *const BIGNUM, m: *const BIGNUM,
                                       mont: *const BN_MONT_CTX) -> c::int;
    pub fn GFp_BN_num_bytes(bn: *const BIGNUM) -> usize;
    pub fn GFp_BN_ucmp(a: *const BIGNUM, b: *const BIGNUM) -> c::int;
}

#[allow(non_camel_case_types)]
pub enum BN_MONT_CTX {}

#[cfg(feature = "rsa_signing")]
extern {
    pub fn GFp_BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
}

pub struct PositiveInteger {
    value: Option<*mut BIGNUM>,
}

impl PositiveInteger {
    #[cfg(feature = "rsa_signing")]
    // Parses a single ASN.1 DER-encoded `Integer`, which most be positive.
    pub fn from_der(input: &mut untrusted::Reader)
                -> Result<PositiveInteger, error::Unspecified> {
        Self::from_be_bytes(try!(der::positive_integer(input)))
    }

    // Turns a sequence of big-endian bytes into a Positive Integer.
    pub fn from_be_bytes(input: untrusted::Input)
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
        let res = unsafe {
            GFp_BN_bin2bn(input.as_slice_less_safe().as_ptr(),
                          input.len(),
                          core::ptr::null_mut())
        };
        if res.is_null() {
            return Err(error::Unspecified);
        }
        Ok(PositiveInteger { value: Some(res) })
    }

    pub unsafe fn as_ref<'a>(&'a self) -> &'a BIGNUM { &*self.value.unwrap() }

    #[cfg(feature = "rsa_signing")]
    pub fn into_raw(&mut self) -> *mut BIGNUM {
        let res = self.value.unwrap();
        self.value = None;
        res
    }
}

impl Drop for PositiveInteger {
    fn drop(&mut self) {
        match self.value {
            Some(val) => unsafe {
                GFp_BN_free(val);
            },
            None => {},
        }
    }
}


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
