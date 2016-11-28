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

// XXX TODO: Remove this once RSA verification has been done in Rust.
#![cfg_attr(not(feature = "rsa_signing"), allow(dead_code))]

use {bits, bssl, c, der, error, untrusted};
use core;
use core::marker::PhantomData;

/// Non-negative, non-zero integers.
///
/// This set is sometimes called `Natural` or `Counting`, but texts, libraries,
/// and standards disagree on whether to include zero in them, so we avoid
/// those names.
#[derive(PartialEq, PartialOrd)]
pub struct Positive(Nonnegative);

impl Positive {
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
        Ok(Positive(Nonnegative(value)))
    }

    pub unsafe fn as_ref<'a>(&'a self) -> &'a BIGNUM { self.0.as_ref() }

    pub fn into_elem<F: Field>(mut self, m: &Modulus<F>)
                               -> Result<Elem<F>, error::Unspecified> {
        let cmp = unsafe {
            GFp_BN_cmp(self.as_ref(), GFp_BN_MONT_CTX_get0_n(m.as_ref()))
        };
        if !(cmp < 0) {
            return Err(error::Unspecified);
        }
        try!(bssl::map_result(unsafe {
            GFp_BN_to_mont(self.0.as_mut_ref(), self.as_ref(), m.as_ref())
        }));
        Ok(Elem {
            value: self.0,
            field: PhantomData,
        })
    }

    fn into_elem_decoded<F: Field>(self, m: &Modulus<F>)
            -> Result<ElemDecoded<F>, error::Unspecified> {
        let cmp = unsafe {
            GFp_BN_cmp(self.as_ref(), GFp_BN_MONT_CTX_get0_n(m.as_ref()))
        };
        if !(cmp < 0) {
            return Err(error::Unspecified);
        }
        Ok(ElemDecoded {
            value: self.0,
            field: PhantomData,
        })
    }

    pub fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        self.0.into_odd_positive()
    }

    pub fn into_raw(self) -> *mut BIGNUM { self.0.into_raw() }

    pub fn bit_length(&self) -> bits::BitLength {
        let bits = unsafe { GFp_BN_num_bits(self.as_ref()) };
        bits::BitLength::from_usize_bits(bits)
    }
}


/// Odd positive integers.
#[derive(PartialEq, PartialOrd)]
pub struct OddPositive(Positive);

impl OddPositive {
    pub fn try_clone(&self) -> Result<OddPositive, error::Unspecified> {
        let mut value = try!(Nonnegative::zero());
        try!(bssl::map_result(unsafe {
            GFp_BN_copy(value.as_mut_ref(), self.as_ref())
        }));
        Ok(OddPositive(Positive(value)))
    }

    pub fn into_elem<F: Field>(self, m: &Modulus<F>)
            -> Result<Elem<F>, error::Unspecified> {
        self.0.into_elem(m)
    }

    pub fn into_elem_decoded<F: Field>(self, m: &Modulus<F>)
            -> Result<ElemDecoded<F>, error::Unspecified> {
        self.0.into_elem_decoded(m)
    }

    pub fn into_modulus<F: Field>(self)
                                  -> Result<Modulus<F>, error::Unspecified> {
        let r = Modulus {
            ctx: unsafe { GFp_BN_MONT_CTX_new() },
            field: PhantomData,
        };
        if r.ctx.is_null() {
            return Err(error::Unspecified);
        }
        // XXX: This makes a copy of `self`'s `BIGNUM`. TODO: change this to a
        // move.
        try!(bssl::map_result(unsafe {
            GFp_BN_MONT_CTX_set(&mut *r.ctx, self.as_ref())
        }));
        Ok(r)
    }

    pub fn into_raw(self) -> *mut BIGNUM {
        self.0.into_raw()
    }
}

impl core::ops::Deref for OddPositive {
    type Target = Positive;
    fn deref(&self) -> &Self::Target { &self.0 }
}


/// Every modulus (`n`, `p`, `q`, etc.) should be represented as a separate
/// type implementing `Field`.
pub unsafe trait Field {}

/// A modulus that can be used for Montgomery math.
pub struct Modulus<F: Field> {
    ctx: *mut BN_MONT_CTX,
    field: PhantomData<F>,
}

impl<F: Field> Modulus<F> {
    unsafe fn as_ref(&self) -> &BN_MONT_CTX { &*self.ctx }

    pub fn into_raw(mut self) -> *mut BN_MONT_CTX {
        let r = self.ctx;
        self.ctx = core::ptr::null_mut();
        r
    }
}

impl<F: Field> Drop for Modulus<F> {
    fn drop(&mut self) { unsafe { GFp_BN_MONT_CTX_free(self.ctx); } }
}

/// Montgomery-encoded elements of a field.
pub struct Elem<F: Field> {
    value: Nonnegative,
    field: PhantomData<F>,
}

impl<F: Field> Elem<F> {
    pub fn into_raw_montgomery_encoded(self) -> *mut BIGNUM {
        self.value.into_raw()
    }
}

pub struct ElemDecoded<F: Field> {
    value: Nonnegative,
    field: PhantomData<F>
}

impl<F: Field> ElemDecoded<F> {
    pub fn is_zero(&self) -> bool { self.value.is_zero() }

    pub fn is_one(&self) -> bool { self.value.is_one() }
}

// `a` * `b` (mod `m`).
pub fn elem_mul_mixed<F: Field>(a: &Elem<F>, b: &ElemDecoded<F>, m: &Modulus<F>)
                                -> Result<ElemDecoded<F>, error::Unspecified> {
    let mut r = try!(Nonnegative::zero());
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(r.as_mut_ref(), a.value.as_ref(),
                            b.value.as_ref(), m.as_ref())
    }));
    Ok(ElemDecoded {
        value: r,
        field: PhantomData
    })
}


/// Nonnegative integers: `Positive` ∪ {0}.
struct Nonnegative(*mut BIGNUM);

impl Nonnegative {
    fn zero() -> Result<Self, error::Unspecified> {
        let r = Nonnegative(unsafe { GFp_BN_new() });
        if r.0.is_null() {
            return Err(error::Unspecified);
        }
        debug_assert!(r.is_zero());
        Ok(r)
    }

    fn is_zero(&self) -> bool {
        let is_zero = unsafe { GFp_BN_is_zero(self.as_ref()) };
        is_zero != 0
    }

    fn is_one(&self) -> bool {
        let is_one = unsafe { GFp_BN_is_one(self.as_ref()) };
        is_one != 0
    }

    // XXX: This makes it too easy to break invariants on things. TODO: Remove
    // this ASAP.
    unsafe fn as_mut_ref(&mut self) -> &mut BIGNUM { &mut *self.0 }
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { unsafe { &*self.0 } }

    fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        let is_odd = unsafe { GFp_BN_is_odd(self.as_ref()) };
        if is_odd == 0 {
            return Err(error::Unspecified);
        }
        Ok(OddPositive(Positive(self)))
    }

    fn into_raw(mut self) -> *mut BIGNUM {
        let r = self.0;
        self.0 = core::ptr::null_mut();
        r
    }
}

impl Drop for Nonnegative {
    fn drop(&mut self) { unsafe { GFp_BN_free(self.0); } }
}

impl core::cmp::PartialEq for Nonnegative {
    fn eq(&self, other: &Nonnegative) -> bool {
        self.partial_cmp(other) == Some(core::cmp::Ordering::Equal)
    }
}

impl core::cmp::PartialOrd for Nonnegative {
    fn partial_cmp(&self, other: &Nonnegative) -> Option<core::cmp::Ordering> {
        let r = unsafe { GFp_BN_cmp(self.as_ref(), other.as_ref()) };
        Some(r.cmp(&0))
    }
}


#[allow(non_camel_case_types)]
pub enum BN_MONT_CTX {}

pub enum BIGNUM {}

extern {
    fn GFp_BN_new() -> *mut BIGNUM;
    fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                     -> *mut BIGNUM;
    fn GFp_BN_cmp(a: &BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_is_odd(a: &BIGNUM) -> c::int;
    fn GFp_BN_is_zero(a: &BIGNUM) -> c::int;
    fn GFp_BN_is_one(a: &BIGNUM) -> c::int;
    fn GFp_BN_num_bits(bn: *const BIGNUM) -> c::size_t;
    pub fn GFp_BN_free(bn: *mut BIGNUM);

    // `r` and `a` may alias.
    fn GFp_BN_to_mont(r: *mut BIGNUM, a: *const BIGNUM, m: &BN_MONT_CTX)
                      -> c::int;

    // The use of references here implies lack of aliasing. However,
    // `GFp_BN_mod_mul_mont` does allow `r` to alias `a` or `b` if needed; if
    // we need that then we should change the types to pointers.
    fn GFp_BN_copy(a: &mut BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_mod_mul_mont(r: &mut BIGNUM, a: &BIGNUM, b: &BIGNUM,
                           m: &BN_MONT_CTX) -> c::int;

    fn GFp_BN_MONT_CTX_new() -> *mut BN_MONT_CTX;
    fn GFp_BN_MONT_CTX_set(ctx: &mut BN_MONT_CTX, modulus: &BIGNUM) -> c::int;
    fn GFp_BN_MONT_CTX_get0_n<'a>(ctx: &'a BN_MONT_CTX) -> &'a BIGNUM;
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
