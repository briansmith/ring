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

use {bits, bssl, c, der, error, rand, untrusted};
use core;
use core::marker::PhantomData;

/// This is defined for comparing values instead of using `PartialOrd` because
/// there `PartialOrd` requires `PartialEq`, which we do not otherwise require.
/// Also, this `Result<>`-based interface is more convenient for callers' uses.
pub fn verify_less_than<A: core::convert::AsRef<BIGNUM>,
                        B: core::convert::AsRef<BIGNUM>>(a: &A, b: &B)
        -> Result<(), error::Unspecified> {
    let r = unsafe { GFp_BN_cmp(a.as_ref(), b.as_ref()) };
    if !(r < 0) {
        return Err(error::Unspecified);
    }
    Ok(())
}


impl<F: Field> AsRef<BN_MONT_CTX> for Modulus<F> {
    fn as_ref(&self) -> &BN_MONT_CTX { unsafe { &*self.ctx } }
}

impl<F: Field> AsRef<BIGNUM> for Modulus<F> {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM {
        unsafe { GFp_BN_MONT_CTX_get0_n(self.as_ref()) }
    }
}

impl AsRef<BIGNUM> for OddPositive {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { self.0.as_ref() }
}

impl AsRef<BIGNUM> for Positive {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { self.0.as_ref() }
}

impl AsRef<BIGNUM> for Nonnegative {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { unsafe { &*self.0 } }
}


/// Non-negative, non-zero integers.
///
/// This set is sometimes called `Natural` or `Counting`, but texts, libraries,
/// and standards disagree on whether to include zero in them, so we avoid
/// those names.
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
        // Reject leading zeros. Also reject the value zero ([0]) because zero
        // isn't positive.
        if untrusted::Reader::new(input).peek(0) {
            return Err(error::Unspecified);
        }
        Self::from_be_bytes_padded(input)
    }

    pub fn from_be_bytes_padded(input: untrusted::Input)
                                -> Result<Positive, error::Unspecified> {
        // Reject empty inputs.
        if input.is_empty() {
            return Err(error::Unspecified);
        }
        let value = unsafe {
            GFp_BN_bin2bn(input.as_slice_less_safe().as_ptr(), input.len(),
                          core::ptr::null_mut())
        };
        if value.is_null() {
            return Err(error::Unspecified);
        }
        let r = Nonnegative(value);
        if r.is_zero() {
            return Err(error::Unspecified);
        }
        Ok(Positive(r))
    }

    pub fn into_elem<F: Field>(self, m: &Modulus<F>)
                               -> Result<Elem<F>, error::Unspecified> {
        let decoded = try!(self.into_elem_decoded(m));
        decoded.into_elem(m)
    }

    pub fn into_elem_decoded<F: Field>(self, m: &Modulus<F>)
            -> Result<ElemDecoded<F>, error::Unspecified> {
        try!(verify_less_than(&self, &m));
        Ok(ElemDecoded {
            value: self.0,
            field: PhantomData,
        })
    }

    pub fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        self.0.into_odd_positive()
    }

    pub fn bit_length(&self) -> bits::BitLength {
        let bits = unsafe { GFp_BN_num_bits(self.as_ref()) };
        bits::BitLength::from_usize_bits(bits)
    }
}

/// Odd positive integers.
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

impl<F: Field> Drop for Modulus<F> {
    fn drop(&mut self) { unsafe { GFp_BN_MONT_CTX_free(self.ctx); } }
}

// `Modulus` uniquely owns and references its contents.
unsafe impl<F: Field> Send for Modulus<F> {}

// `Modulus` is immutable.
unsafe impl<F: Field> Sync for Modulus<F> {}

/// Montgomery-encoded elements of a field.
pub struct Elem<F: Field> {
    value: Nonnegative,
    field: PhantomData<F>,
}

impl<F: Field> Elem<F> {
    // There's no need to convert `value` to the Montgomery domain since
    // 0 * R**2 (mod n) == 0, so the modulus isn't even needed to construct a
    // zero-valued element.
    pub fn zero() -> Result<Self, error::Unspecified> {
        let value = try!(Nonnegative::zero());
        Ok(Elem {
            value: value,
            field: PhantomData,
        })
    }

    pub fn as_ref_montgomery_encoded<'a>(&'a self) -> &'a BIGNUM {
        self.value.as_ref()
    }
}

pub struct ElemDecoded<F: Field> {
    value: Nonnegative,
    field: PhantomData<F>
}

impl<F: Field> ElemDecoded<F> {
    pub fn take_storage(e: Elem<F>) -> ElemDecoded<F> {
        ElemDecoded {
            value: e.value,
            field: PhantomData,
        }
    }

    pub fn fill_be_bytes(&self, out: &mut [u8])
                         -> Result<(), error::Unspecified> {
        bssl::map_result(unsafe {
            GFp_BN_bn2bin_padded(out.as_mut_ptr(), out.len(),
                                 self.value.as_ref())
        })
    }

    pub fn is_zero(&self) -> bool { self.value.is_zero() }

    pub fn is_one(&self) -> bool { self.value.is_one() }

    // XXX: This makes it too easy to break the invariants. TODO: Remove this
    // ASAP.
    pub unsafe fn as_mut_ref<'a>(&'a mut self) -> &'a mut BIGNUM {
        self.value.as_mut_ref()
    }

    pub fn into_elem(self, m: &Modulus<F>)
                     -> Result<Elem<F>, error::Unspecified> {
        let mut value = self.value;
        try!(bssl::map_result(unsafe {
            GFp_BN_to_mont(value.as_mut_ref(), value.as_ref(), m.as_ref())
        }));
        Ok(Elem {
            value: value,
            field: PhantomData,
        })
    }

    pub fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        self.value.into_odd_positive()
    }
}

// `a` * `b` (mod `m`).
pub fn elem_mul_mixed<F: Field>(a: &Elem<F>, b: ElemDecoded<F>, m: &Modulus<F>)
                                -> Result<ElemDecoded<F>, error::Unspecified> {
    let /*mut*/ r = b.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(r.0, a.value.as_ref(), r.0, m.as_ref())
    }));
    Ok(ElemDecoded {
        value: r,
        field: PhantomData
    })
}

pub fn elem_squared<F: Field>(a: Elem<F>, m: &Modulus<F>)
                              -> Result<Elem<F>, error::Unspecified> {
    let mut value = a.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(value.as_mut_ref(), value.as_ref(), value.as_ref(),
                            m.as_ref())
    }));
    Ok(Elem {
        value: value,
        field: PhantomData,
    })
}

pub fn elem_exp_vartime<F: Field>(
        mut base: ElemDecoded<F>, exponent: &OddPositive, m: &Modulus<F>)
        -> Result<ElemDecoded<F>, error::Unspecified> {
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_exp_mont_vartime(base.value.as_mut_ref(),
                                    base.value.as_ref(), exponent.as_ref(),
                                    m.as_ref())
    }));
    Ok(base)
}

pub fn elem_randomize<F: Field>(a: &mut ElemDecoded<F>, m: &Modulus<F>,
                                rng: &rand::SecureRandom)
                                -> Result<(), error::Unspecified> {
    let mut rand = rand::RAND::new(rng);
    bssl::map_result(unsafe {
        GFp_BN_rand_range_ex(a.value.as_mut_ref(), m.as_ref(), &mut rand)
    })
}

// r = 1/a (mod m).
pub fn elem_set_to_inverse_blinded<F: Field>(
            r: &mut ElemDecoded<F>, a: &ElemDecoded<F>, m: &Modulus<F>,
            rng: &rand::SecureRandom) -> Result<(), InversionError> {
    let mut no_inverse = 0;
    let mut rand = rand::RAND::new(rng);
    bssl::map_result(unsafe {
        GFp_BN_mod_inverse_blinded(r.value.as_mut_ref(), &mut no_inverse,
                                    a.value.as_ref(), m.as_ref(), &mut rand)
    }).map_err(|_| {
        if no_inverse != 0 {
            InversionError::NoInverse
        } else {
            InversionError::Unspecified
        }
    })
}

pub enum InversionError {
    NoInverse,
    Unspecified
}


/// Nonnegative integers: `Positive` ∪ {0}.
struct Nonnegative(*mut BIGNUM);

impl Drop for Nonnegative {
    fn drop(&mut self) { unsafe { GFp_BN_free(self.0); } }
}

// `Nonnegative` uniquely owns and references its contents.
unsafe impl Send for Nonnegative {}

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

    fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        let is_odd = unsafe { GFp_BN_is_odd(self.as_ref()) };
        if is_odd == 0 {
            return Err(error::Unspecified);
        }
        Ok(OddPositive(Positive(self)))
    }
}

#[allow(non_camel_case_types)]
pub enum BN_MONT_CTX {}

pub enum BIGNUM {}

extern {
    fn GFp_BN_new() -> *mut BIGNUM;
    fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                     -> *mut BIGNUM;
    fn GFp_BN_bn2bin_padded(out_: *mut u8, len: c::size_t, in_: &BIGNUM)
                            -> c::int;
    fn GFp_BN_cmp(a: &BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_is_odd(a: &BIGNUM) -> c::int;
    fn GFp_BN_is_zero(a: &BIGNUM) -> c::int;
    fn GFp_BN_is_one(a: &BIGNUM) -> c::int;
    fn GFp_BN_num_bits(bn: *const BIGNUM) -> c::size_t;
    fn GFp_BN_free(bn: *mut BIGNUM);

    // `r` and `a` may alias.
    fn GFp_BN_to_mont(r: *mut BIGNUM, a: *const BIGNUM, m: &BN_MONT_CTX)
                      -> c::int;
    // `r` and/or 'a' and/or 'b' may alias.
    fn GFp_BN_mod_mul_mont(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM,
                           m: &BN_MONT_CTX) -> c::int;
    // `r` and `a` may alias.
    fn GFp_BN_mod_exp_mont_vartime(r: *mut BIGNUM, a: *const BIGNUM, p: &BIGNUM,
                                   mont: &BN_MONT_CTX) -> c::int;

    // The use of references here implies lack of aliasing.
    fn GFp_BN_copy(a: &mut BIGNUM, b: &BIGNUM) -> c::int;

    fn GFp_BN_MONT_CTX_new() -> *mut BN_MONT_CTX;
    fn GFp_BN_MONT_CTX_set(ctx: &mut BN_MONT_CTX, modulus: &BIGNUM) -> c::int;
    fn GFp_BN_MONT_CTX_get0_n<'a>(ctx: &'a BN_MONT_CTX) -> &'a BIGNUM;
    fn GFp_BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);
}

#[allow(improper_ctypes)]
extern {
    fn GFp_BN_rand_range_ex(r: &mut BIGNUM, max_exclusive: &BIGNUM,
                            rng: &mut rand::RAND) -> c::int;

    fn GFp_BN_mod_inverse_blinded(out: &mut BIGNUM, out_no_inverse: &mut c::int,
                                  a: &BIGNUM, mont: &BN_MONT_CTX,
                                  rng: &mut rand::RAND) -> c::int;
}


#[cfg(test)]
mod tests {
    use super::*;
    use untrusted;
    use test;

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

    struct M {}
    unsafe impl Field for M {}

    #[test]
    fn test_elem_exp_vartime() {
        test::from_file("src/rsa/bigint_elem_exp_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus(test_case, "M");
            let expected_result = consume_elem(test_case, "ModExp", &m);
            let base = consume_elem(test_case, "A", &m);
            let e = consume_odd_positive(test_case, "E");

            let actual_result = elem_exp_vartime(base, &e, &m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    fn consume_elem(test_case: &mut test::TestCase, name: &str, m: &Modulus<M>)
                    -> ElemDecoded<M> {
        let bytes = test_case.consume_bytes(name);
        let value =
            Positive::from_be_bytes(untrusted::Input::from(&bytes)).unwrap();
        value.into_elem_decoded::<M>(m).unwrap()
    }

    fn consume_modulus(test_case: &mut test::TestCase, name: &str)
                       -> Modulus<M> {
        let value = consume_odd_positive(test_case, name);
        value.into_modulus().unwrap()
    }

    fn consume_odd_positive(test_case: &mut test::TestCase, name: &str)
                            -> OddPositive {
        let bytes = test_case.consume_bytes(name);
        let value =
            Positive::from_be_bytes(untrusted::Input::from(&bytes)).unwrap();
        value.into_odd_positive().unwrap()
    }

    fn assert_elem_eq<F: Field>(a: &ElemDecoded<F>, b: &ElemDecoded<F>) {
        let r = unsafe { GFp_BN_cmp(a.value.as_ref(), b.value.as_ref()) };
        assert_eq!(r, 0)
    }
}
