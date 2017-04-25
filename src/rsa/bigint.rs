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

//! Multi-precision integers.
//!
//! # Modular Arithmetic.
//!
//! Modular arithmetic is done in finite commutative rings ℤ/mℤ for some
//! modulus *m*. We work in finite commutative rings instead of finite fields
//! because the RSA public modulus *n* is not prime, which means ℤ/nℤ contains
//! nonzero elements that have no multiplicative inverse, so ℤ/nℤ is not a
//! finite field.
//!
//! In some calculations we need to deal with multiple rings at once. For
//! example, RSA private key operations operate in the rings ℤ/nℤ, ℤ/pℤ, and
//! ℤ/qℤ. Types and functions dealing with such rings are all parameterized
//! over a type `M` to ensure that we don't wrongly mix up the math, e.g. by
//! multiplying an element of ℤ/pℤ by an element of ℤ/qℤ modulo q. This follows
//! the "unit" pattern described in [Static checking of units in Servo]; `Elem`,
//! and `Modulus` are analogous to `geom::Length`, and `super::N` and
//! `super::signing::{P, QQ, Q}` are analogous to `Mm` and `Inch`.
//!
//! `Elem` also uses the static unit checking pattern to statically track the
//! Montgomery factors that need to be canceled out in each value using it's
//! `E` parameter.
//!
//! [Static checking of units in Servo]:
//!     https://blog.mozilla.org/research/2014/06/23/static-checking-of-units-in-servo/


use {bits, bssl, c, error, limb, untrusted};
use arithmetic::montgomery::*;
use core;
use core::marker::PhantomData;

#[cfg(feature = "rsa_signing")]
use {constant_time, der, rand};

impl AsRef<BIGNUM> for Positive {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { self.0.as_ref() }
}

impl AsRef<BIGNUM> for Nonnegative {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { &self.0 }
}


/// Non-negative, non-zero integers.
///
/// This set is sometimes called `Natural` or `Counting`, but texts, libraries,
/// and standards disagree on whether to include zero in them, so we avoid
/// those names.
pub struct Positive(Nonnegative);

impl Positive {
    // Parses a single ASN.1 DER-encoded `Integer`, which most be positive.
    #[cfg(feature = "rsa_signing")]
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
        let mut r = try!(Nonnegative::zero());
        try!(bssl::map_result(unsafe {
            GFp_BN_bin2bn(input.as_slice_less_safe().as_ptr(), input.len(),
                          r.as_mut_ref())
        }));
        if r.is_zero() {
            return Err(error::Unspecified);
        }
        Ok(Positive(r))
    }

    pub fn into_elem<M>(self, m: &Modulus<M>)
                        -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.0.into_elem(m)
    }

    pub fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        self.0.into_odd_positive()
    }

    #[inline]
    pub fn bit_length(&self) -> bits::BitLength { self.0.bit_length() }
}

/// Odd positive integers.
pub struct OddPositive(Positive);

impl OddPositive {
    #[cfg(feature = "rsa_signing")]
    #[inline]
    pub fn verify_less_than(&self, other: &Self)
                            -> Result<(), error::Unspecified> {
        (self.0).0.verify_less_than(&(other.0).0)
    }

    #[cfg(feature = "rsa_signing")]
    pub fn try_clone(&self) -> Result<OddPositive, error::Unspecified> {
        let value = try!((self.0).0.try_clone());
        Ok(OddPositive(Positive(value)))
    }

    #[cfg(feature = "rsa_signing")]
    pub fn into_elem<M>(self, m: &Modulus<M>)
                        -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.0.into_elem(m)
    }

    #[inline]
    pub fn into_modulus<M>(self) -> Result<Modulus<M>, error::Unspecified> {
        Modulus::new(self)
    }

    pub fn into_public_exponent(self)
                                -> Result<PublicExponent, error::Unspecified> {
        let bits = self.bit_length();
        if bits < bits::BitLength::from_usize_bits(2) {
            return Err(error::Unspecified);
        }
        if bits > PUBLIC_EXPONENT_MAX_BITS {
            return Err(error::Unspecified);
        }
        let value = unsafe { GFp_BN_get_positive_u64(self.as_ref()) };
        if value == 0 {
            return Err(error::Unspecified);
        }
        Ok(PublicExponent(value))
    }
}

impl core::ops::Deref for OddPositive {
    type Target = Positive;
    fn deref(&self) -> &Self::Target { &self.0 }
}


/// A modulus *s* that is smaller than another modulus *l* so every element of
/// ℤ/sℤ is also an element of ℤ/lℤ.
pub unsafe trait SmallerModulus<L> {}

/// A modulus *s* where s < l < 2*s for the given larger modulus *l*. This is
/// the precondition for reduction by conditional subtraction,
/// `elem_reduce_once()`.
pub unsafe trait SlightlySmallerModulus<L>: SmallerModulus<L> {}

/// A modulus *s* where √l <= s < l for the given larger modulus *l*. This is
/// the precondition for the more general Montgomery reduction from ℤ/lℤ to
/// ℤ/sℤ.
pub unsafe trait NotMuchSmallerModulus<L>: SmallerModulus<L> {}


/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
pub struct Modulus<M> {
    value: OddPositive, // Also `value >= 3`.

    // n0 * N == -1 (mod r).
    //
    // TODO(perf): Not all 32-bit platforms actually make use of n0[1]. For the
    // ones that don't, we could use a shorter `R` value and use faster `Limb`
    // calculations instead of double-precision `u64` calculations.
    n0: N0,

    m: PhantomData<M>,
}

// `Modulus` uniquely owns and references its contents.
unsafe impl<M> Send for Modulus<M> {}

// `Modulus` is immutable.
unsafe impl<M> Sync for Modulus<M> {}

impl<M> Modulus<M> {
    fn new(value: OddPositive) -> Result<Self, error::Unspecified> {
        // A `Modulus` must be larger than 1.
        if value.bit_length() < bits::BitLength::from_usize_bits(2) {
            return Err(error::Unspecified);
        }
        let n0 = unsafe { GFp_bn_mont_n0(value.as_ref()) };
        Ok(Modulus {
            value: value,
            n0: n0_from_u64(n0),
            m: PhantomData,
        })
    }
}

#[cfg(feature = "rsa_signing")]
impl Modulus<super::N> {
    pub fn value(&self) -> &OddPositive { &self.value }
}

/// Elements of ℤ/mℤ for some modulus *m*.
//
// Defaulting `E` to `Unencoded` is a convenience for callers from outside this
// submodule. However, for maximum clarity, we always explicitly use
// `Unencoded` within the `bigint` submodule.
pub struct Elem<M, E = Unencoded> {
    value: Nonnegative,

    /// The modulus *m* for the ring ℤ/mℤ for which this element is a value.
    m: PhantomData<M>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    encoding: PhantomData<E>,
}

impl<M, E> Elem<M, E> {
    // There's no need to convert `value` to the Montgomery domain since
    // 0 * R**2 (mod m) == 0, so the modulus isn't even needed to construct a
    // zero-valued element.
    pub fn zero() -> Result<Self, error::Unspecified> {
        let value = try!(Nonnegative::zero());
        Ok(Elem {
            value: value,
            m: PhantomData,
            encoding: PhantomData,
        })
    }

    #[cfg(feature = "rsa_signing")]
    pub fn is_zero(&self) -> bool { self.value.is_zero() }

    #[cfg(feature = "rsa_signing")]
    pub fn take_storage<OtherF>(e: Elem<M, OtherF>) -> Elem<M, E> {
        Elem {
            value: e.value,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn try_clone(&self) -> Result<Self, error::Unspecified> {
        let value = try!(self.value.try_clone());
        Ok(Elem {
            value: value,
            m: PhantomData,
            encoding: PhantomData,
        })
    }
}

impl<M> Elem<M, R> {
    #[inline]
    pub fn into_unencoded(self, m: &Modulus<M>)
                          -> Result<Elem<M, Unencoded>, error::Unspecified> {
        elem_reduced_(self, m)
    }
}

impl<M> Elem<M, Unencoded> {
    #[cfg(feature = "rsa_signing")]
    pub fn one() -> Result<Self, error::Unspecified> {
        let value = try!(Nonnegative::one());
        Ok(Elem {
            value: value,
            m: PhantomData,
            encoding: PhantomData,
        })
    }

    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        limb::big_endian_from_limbs_padded(self.value.limbs(), out)
    }

    #[cfg(feature = "rsa_signing")]
    pub fn is_one(&self) -> bool { self.value.is_one() }

    // The result is security-sensitive.
    #[cfg(feature = "rsa_signing")]
    #[inline]
    pub fn bit_length(&self) -> bits::BitLength { self.value.bit_length() }

    #[cfg(feature = "rsa_signing")]
    pub fn into_modulus<MM>(self) -> Result<Modulus<MM>, error::Unspecified> {
        let value = try!(self.value.into_odd_positive());
        value.into_modulus()
    }
}

pub fn elem_mul<M, AF, BF>(a: &Elem<M, AF>, b: Elem<M, BF>, m: &Modulus<M>)
        -> Result<Elem<M, <(AF, BF) as ProductEncoding>::Output>,
                  error::Unspecified>
        where (AF, BF): ProductEncoding {
    let mut r = b.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(&mut r.0, a.value.as_ref(), &r.0, &m.value.as_ref(),
                            &m.n0)
    }));
    Ok(Elem {
        value: r,
        m: PhantomData,
        encoding: PhantomData,
    })
}

// `a` * `b` (mod `m`).
#[cfg(feature = "rsa_signing")]
pub fn elem_set_to_product<M, AF, BF>(
        r: &mut Elem<M, <(AF, BF) as ProductEncoding>::Output>,
        a: &Elem<M, AF>, b: &Elem<M, BF>, m: &Modulus<M>)
        -> Result<(), error::Unspecified>
        where (AF, BF): ProductEncoding {
    bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(r.value.as_mut_ref(), a.value.as_ref(),
                            b.value.as_ref(), &m.value.as_ref(), &m.n0)
    })
}

#[cfg(feature = "rsa_signing")]
pub fn elem_reduced_once<Larger, Smaller: SlightlySmallerModulus<Larger>>(
        a: &Elem<Larger, Unencoded>, m: &Modulus<Smaller>)
        -> Result<Elem<Smaller, Unencoded>, error::Unspecified> {
    let mut r = try!(a.value.try_clone());
    // XXX TODO: Not constant-time.
    if !greater_than(&(m.value.0).0, &a.value) {
        try!(bssl::map_result(unsafe {
            GFp_BN_usub(r.as_mut_ref(), r.as_ref(), m.value.as_ref())
        }));
    }
    debug_assert!(greater_than(&(m.value.0).0, &r));
    Ok(Elem {
        value: r,
        m: PhantomData,
        encoding: PhantomData,
    })
}

#[cfg(feature = "rsa_signing")]
#[inline]
pub fn elem_reduced<Larger, Smaller: NotMuchSmallerModulus<Larger>>(
        a: &Elem<Larger, Unencoded>, m: &Modulus<Smaller>)
        -> Result<Elem<Smaller, RInverse>, error::Unspecified> {
    let tmp = try!(a.try_clone());
    elem_reduced_(tmp, m)
}

fn elem_reduced_<LargerM, E: ReductionEncoding, SmallerM>(
        mut a: Elem<LargerM, E>, m: &Modulus<SmallerM>)
        -> Result<Elem<SmallerM, <E as ReductionEncoding>::Output>,
                  error::Unspecified> {
    let mut r = try!(Elem::zero());
    try!(bssl::map_result(unsafe {
        GFp_BN_from_montgomery_word(r.value.as_mut_ref(), a.value.as_mut_ref(),
                                    &m.value.as_ref(), &m.n0)
    }));
    Ok(r)
}

pub fn elem_squared<M, E>(a: Elem<M, E>, m: &Modulus<M>)
        -> Result<Elem<M, <(E, E) as ProductEncoding>::Output>,
                  error::Unspecified>
        where (E, E): ProductEncoding {
    let mut value = a.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_mul_mont(value.as_mut_ref(), value.as_ref(), value.as_ref(),
                            &m.value.as_ref(), &m.n0)
    }));
    Ok(Elem {
        value: value,
        m: PhantomData,
        encoding: PhantomData,
    })
}

#[cfg(feature = "rsa_signing")]
pub fn elem_widen<Larger, Smaller: SmallerModulus<Larger>>(
        a: Elem<Smaller, Unencoded>) -> Elem<Larger, Unencoded> {
    Elem {
        value: a.value,
        m: PhantomData,
        encoding: PhantomData,
    }
}


// TODO: Document why this works for all Montgomery factors.
#[cfg(feature = "rsa_signing")]
pub fn elem_add<M, E>(a: Elem<M, E>, b: Elem<M, E>, m: &Modulus<M>)
                      -> Result<Elem<M, E>, error::Unspecified> {
    let mut value = b.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_add_quick(&mut value.0, a.value.as_ref(), value.as_ref(),
                             m.value.as_ref())
    }));
    Ok(Elem {
        value: value,
        m: PhantomData,
        encoding: PhantomData,
    })
}

// TODO: Document why this works for all Montgomery factors.
#[cfg(feature = "rsa_signing")]
pub fn elem_sub<M, E>(a: Elem<M, E>, b: &Elem<M, E>, m: &Modulus<M>)
                   -> Result<Elem<M, E>, error::Unspecified> {
    let mut value = a.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_sub_quick(&mut value.0, &value.0, b.value.as_ref(),
                             m.value.as_ref())
    }));
    Ok(Elem {
        value: value,
        m: PhantomData,
        encoding: PhantomData,
    })
}


// The value 1, Montgomery-encoded some number of times.
pub struct One<M, E>(Elem<M, E>);

#[cfg(feature = "rsa_signing")]
impl<M> One<M, R> {
    pub fn newR(oneRR: &One<M, RR>, m: &Modulus<M>)
                -> Result<One<M, R>, error::Unspecified> {
        let value: Elem<M> = try!(Elem::one());
        let value: Elem<M, R> = try!(elem_mul(oneRR.as_ref(), value, &m));
        Ok(One(value))
    }
}

impl<M> One<M, RR> {
    pub fn newRR(m: &Modulus<M>) -> Result<One<M, RR>, error::Unspecified> {
        // RR = R**2 (mod N). R is the smallest power of 2**LIMB_BITS such that
        // R > m. Even though the assembly on some 32-bit platforms works
        // with 64-bit values, using `LIMB_BITS` here, rather than
        // `N0_LIMBS_USED * LIMB_BITS`, is correct because R**2 will still be
        // a multiple of the latter as `N0_LIMBS_USED` is either one or two.
        use limb::LIMB_BITS;
        let lg_R =
            (m.value.bit_length().as_usize_bits() + (LIMB_BITS - 1))
                / LIMB_BITS * LIMB_BITS;

        let mut RR = try!(Elem::zero());
        try!(bssl::map_result(unsafe {
            GFp_bn_mod_exp_base_2_vartime(RR.value.as_mut_ref(), 2 * lg_R,
                                          m.value.as_ref())
        }));
        Ok(One(RR))
    }
}

#[cfg(feature = "rsa_signing")]
impl<M> One<M, RRR> {
    pub fn newRRR(oneRR: One<M, RR>, m: &Modulus<M>)
                  -> Result<One<M, RRR>, error::Unspecified> {
        let oneRRR = try!(elem_squared(oneRR.0, &m));
        Ok(One(oneRRR))
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> { &self.0 }
}

#[cfg(feature = "rsa_signing")]
impl<M, E> One<M, E> {
    pub fn try_clone(&self) -> Result<Self, error::Unspecified> {
        let value = try!(self.0.try_clone());
        Ok(One(value))
    }
}


/// An non-secret odd positive value in the range
/// [3, 2**PUBLIC_EXPONENT_MAX_BITS).
#[derive(Clone, Copy)]
pub struct PublicExponent(u64);

// This limit was chosen to bound the performance of the simple
// exponentiation-by-squaring implementation in `elem_exp_vartime`. In
// particular, it helps mitigate theoretical resource exhaustion attacks. 33
// bits was chosen as the limit based on the recommendations in [1] and
// [2]. Windows CryptoAPI (at least older versions) doesn't support values
// larger than 32 bits [3], so it is unlikely that exponents larger than 32
// bits are being used for anything Windows commonly does.
//
// [1] https://www.imperialviolet.org/2012/03/16/rsae.html
// [2] https://www.imperialviolet.org/2012/03/17/rsados.html
// [3] https://msdn.microsoft.com/en-us/library/aa387685(VS.85).aspx
pub const PUBLIC_EXPONENT_MAX_BITS: bits::BitLength = bits::BitLength(33);

/// Calculates base**exponent (mod m).
// TODO: The test coverage needs to be expanded, e.g. test with the largest
// accepted exponent and with the most common values of 65537 and 3.
pub fn elem_exp_vartime<M>(
        base: Elem<M, R>, PublicExponent(exponent): PublicExponent,
        m: &Modulus<M>) -> Result<Elem<M, R>, error::Unspecified> {
    // Use what [Knuth] calls the "S-and-X binary method", i.e. variable-time
    // square-and-multiply that scans the exponent from the most significant
    // bit to the least significant bit (left-to-right). Left-to-right requires
    // less storage compared to right-to-left scanning, at the cost of needing
    // to compute `exponent.leading_zeros()`, which we assume to be cheap.
    //
    // The vast majority of the time the exponent is either 65537
    // (0b10000000000000001) or 3 (0b11), both of which have a Hamming weight
    // of 2. As explained in [Knuth], exponentiation by squaring is the most
    // efficient algorithm the hamming weight is 2 or less. It isn't the most
    // efficient for all other, uncommon, RSA public exponent values weight,
    // but any suboptimality is tightly bounded by the
    // `PUBLIC_EXPONENT_MAX_BITS` cap.
    //
    // This implementation is slightly simplified by taking advantage of the
    // fact that we require the exponent to be an (odd) positive integer.
    //
    // [Knuth]: The Art of Computer Programming, Volume 2: Seminumerical
    //          Algorithms (3rd Edition), Section 4.6.3.
    debug_assert_eq!(exponent & 1, 1);
    assert!(exponent < (1 << PUBLIC_EXPONENT_MAX_BITS.as_usize_bits()));
    let mut acc = try!(base.try_clone());
    let mut bit = 1 << (64 - 1 - exponent.leading_zeros());
    debug_assert!((exponent & bit) != 0);
    while bit > 1 {
        bit >>= 1;
        acc = try!(elem_squared(acc, m));
        if (exponent & bit) != 0 {
            acc = try!(elem_mul(&base, acc, m));
        }
    }
    Ok(acc)
}

#[cfg(feature = "rsa_signing")]
pub fn elem_exp_consttime<M>(
        base: Elem<M, R>, exponent: &OddPositive, oneR: &One<M, R>,
        m: &Modulus<M>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    let mut r = base.value;
    try!(bssl::map_result(unsafe {
        GFp_BN_mod_exp_mont_consttime(&mut r.0, &r.0, exponent.as_ref(),
                                      oneR.0.value.as_ref(), &m.value.as_ref(),
                                      &m.n0)
    }));
    let r = Elem {
        value: r,
        m: PhantomData,
        encoding: PhantomData,
    };

    // XXX: On x86-64 only, `GFp_BN_mod_exp_mont_consttime` dues the conversion
    // from Montgomery form itself using a special assembly-language reduction
    // function. This means that at this point, whether `r` is Montgomery
    // encoded, and the exact type of `R` (in particular, its `E` type
    // parameter) depends on the platform. Type inference masks this.
    //
    // TODO: Get rid of that special assembly-language reduction function if
    // practical.

    #[cfg(not(target_arch = "x86_64"))]
    let r = try!(r.into_unencoded(m));

    Ok(r)
}

#[cfg(feature = "rsa_signing")]
pub fn elem_randomize<E>(a: &mut Elem<super::N, E>, m: &Modulus<super::N>,
                         rng: &rand::SecureRandom)
                         -> Result<(), error::Unspecified> {
    a.value.randomize(m, rng)
}

// r = 1/a (mod m), blinded with a random element.
//
// This relies on the invariants of `Modulus` that its value is odd and larger
// than one.
#[cfg(feature = "rsa_signing")]
pub fn elem_set_to_inverse_blinded(
            r: &mut Elem<super::N, R>, a: &Elem<super::N, Unencoded>,
            n: &Modulus<super::N>, rng: &rand::SecureRandom)
            -> Result<(), InversionError> {
    let mut blinding_factor = try!(Elem::<super::N, R>::zero());
    try!(elem_randomize(&mut blinding_factor, n, rng));
    let to_blind = try!(a.try_clone());
    let blinded = try!(elem_mul(&blinding_factor, to_blind, n));
    let blinded_inverse = try!(elem_inverse(blinded, n));
    try!(elem_set_to_product(r, &blinding_factor, &blinded_inverse, n));
    Ok(())
}

// r = 1/a (mod m).
//
// This relies on the invariants of `Modulus` that its value is odd and larger
// than one.
#[cfg(feature = "rsa_signing")]
fn elem_inverse<M>(a: Elem<M, Unencoded>, m: &Modulus<M>)
                   -> Result<Elem<M, R>, InversionError> {
    let a_clone = try!(a.try_clone());
    let inverse = try!(nonnegative_mod_inverse(a.value, &(m.value.0).0));
    let r: Elem<M, R> = Elem {
        value: inverse,
        m: PhantomData,
        encoding: PhantomData,
    };

    // Fail safe: Verify a * r == 1 (mod m).
    let check = try!(elem_mul(&r, a_clone, m));
    assert!(check.is_one());

    Ok(r)
}

#[cfg(feature = "rsa_signing")]
fn nonnegative_mod_inverse(a: Nonnegative, m: &Nonnegative)
                           -> Result<Nonnegative, InversionError> {
    use limb::*;

    // Algorithm 2.23 from "Guide to Elliptic Curve Cryptography" [2004] by
    // Darrel Hankerson, Alfred Menezes, and Scott Vanstone.

    debug_assert!(greater_than(m, &a));
    if a.is_zero() {
        return Err(InversionError::NoInverse);
    }

    // n /= 2; i.e. n >>= 1. `n` must be even, and so no bits are lost.
    fn halve(n: &mut Nonnegative) {
        debug_assert!(n.is_even());

        let mut carry = 0;
        for limb in n.limbs_mut().iter_mut().rev() {
            let original_value = *limb;
            *limb = (original_value >> 1) | (carry << (LIMB_BITS - 1));
            carry = original_value & 1;
        }
        n.0.shrunk_by_at_most_one_bit();
    }

    // n *= 2; i.e. n <<= 1.
    fn double(n: &mut Nonnegative) -> Result<(), InversionError> {
        let mut carry = 0;
        for limb in n.limbs_mut() {
            let original_value = *limb;
            *limb = (original_value << 1) | carry;
            carry = original_value >> (LIMB_BITS - 1);
        }
        if carry != 0 {
            try!(n.0.grow_by_one_bit());
        }
        Ok(())
    }

    // n += other.
    #[inline]
    fn add_assign(n: &mut Nonnegative, other: &Nonnegative)
                  -> Result<(), error::Unspecified> {
        bssl::map_result(unsafe {
            GFp_BN_uadd(n.as_mut_ref(), n.as_ref(), other.as_ref())
        })
    }

    // n == other.
    #[inline]
    fn sub_assign(n: &mut Nonnegative, other: &Nonnegative)
                  -> Result<(), error::Unspecified> {
        bssl::map_result(unsafe {
            GFp_BN_usub(n.as_mut_ref(), n.as_ref(), other.as_ref())
        })
    }

    let mut u = a;
    let mut v = try!(m.try_clone());
    let mut x1 = try!(Nonnegative::one());
    let mut x2 = try!(Nonnegative::zero());
    let mut k = 0;

    while !v.is_zero() {
        if v.is_even() {
            halve(&mut v);
            try!(double(&mut x1));
        } else if u.is_even() {
            halve(&mut u);
            try!(double(&mut x2));
        } else if !greater_than(&u, &v) {
            try!(sub_assign(&mut v, &u));
            halve(&mut v);
            try!(add_assign(&mut x2, &x1));
            try!(double(&mut x1));
        } else {
            try!(sub_assign(&mut u, &v));
            halve(&mut u);
            try!(add_assign(&mut x1, &x2));
            try!(double(&mut x2));
        }
        k += 1;
    }

    if !u.is_one() {
        return Err(InversionError::NoInverse);
    }

    if !greater_than(m, &x1) {
        try!(sub_assign(&mut x1, m));
    }
    assert!(greater_than(m, &x1));

    // Use the simpler repeated-subtraction reduction in 2.23.

    let n = m.bit_length().as_usize_bits();
    assert!(k >= n);
    for _ in n..k {
        if !x1.is_even() {
            try!(add_assign(&mut x1, m));
        }
        halve(&mut x1);
    }

    Ok(x1)
}

#[cfg(feature = "rsa_signing")]
pub enum InversionError {
    NoInverse,
    Unspecified
}

#[cfg(feature = "rsa_signing")]
impl From<error::Unspecified> for InversionError {
    fn from(_: error::Unspecified) -> Self { InversionError::Unspecified }
}

#[cfg(feature = "rsa_signing")]
pub fn elem_verify_equal_consttime<M, E>(a: &Elem<M, E>, b: &Elem<M, E>)
                                         -> Result<(), error::Unspecified> {
    // XXX: Not constant-time if the number of limbs in `a` and `b` differ.
    constant_time::verify_slices_are_equal(limb::limbs_as_bytes(a.value.limbs()),
                                           limb::limbs_as_bytes(b.value.limbs()))
}

/// Nonnegative integers: `Positive` ∪ {0}.
struct Nonnegative(BIGNUM);

// `Nonnegative` uniquely owns and references its contents.
unsafe impl Send for Nonnegative {}

impl Nonnegative {
    fn zero() -> Result<Self, error::Unspecified> {
        let r = Nonnegative(BIGNUM::zero());
        debug_assert!(r.is_zero());
        Ok(r)
    }

    #[cfg(feature = "rsa_signing")]
    fn one() -> Result<Self, error::Unspecified> {
        let mut r = try!(Self::zero());
        try!(bssl::map_result(unsafe {
            GFp_BN_set_word(r.as_mut_ref(), 1)
        }));
        Ok(r)
    }

    fn is_zero(&self) -> bool {
        let is_zero = unsafe { GFp_BN_is_zero(self.as_ref()) };
        is_zero != 0
    }

    #[cfg(feature = "rsa_signing")]
    fn is_one(&self) -> bool {
        let is_one = unsafe { GFp_BN_is_one(self.as_ref()) };
        is_one != 0
    }

    #[cfg(feature = "rsa_signing")]
    #[inline]
    fn is_even(&self) -> bool { !self.is_odd() }

    #[inline]
    fn is_odd(&self) -> bool {
        let is_odd = unsafe { GFp_BN_is_odd(self.as_ref()) };
        if is_odd == 0 {
            false
        } else {
            true
        }
    }

    fn bit_length(&self) -> bits::BitLength {
        let bits = unsafe { GFp_BN_num_bits(self.as_ref()) };
        bits::BitLength::from_usize_bits(bits)
    }

    #[inline]
    fn limbs(&self) -> &[limb::Limb] { self.0.limbs() }

    #[cfg(feature = "rsa_signing")]
    #[inline]
    fn limbs_mut(&mut self) -> &mut [limb::Limb] { self.0.limbs_mut() }

    fn verify_less_than(&self, other: &Self)
                        -> Result<(), error::Unspecified> {
        let r = unsafe { GFp_BN_ucmp(self.as_ref(), other.as_ref()) };
        if !(r < 0) {
            return Err(error::Unspecified);
        }
        Ok(())
    }

    #[cfg(feature = "rsa_signing")]
    fn randomize(&mut self, m: &Modulus<super::N>, rng: &rand::SecureRandom)
                 -> Result<(), error::Unspecified> {
        let m = (m.value.0).0.limbs();
        self.0.make_limbs(m.len(), |limbs| {
            super::random::set_to_rand_mod(limbs, m, rng)
        })
    }

    // XXX: This makes it too easy to break invariants on things. TODO: Remove
    // this ASAP.
    unsafe fn as_mut_ref(&mut self) -> &mut BIGNUM { &mut self.0 }

    fn into_elem<M>(self, m: &Modulus<M>)
                    -> Result<Elem<M, Unencoded>, error::Unspecified> {
        try!(self.verify_less_than(&(m.value.0).0));
        Ok(Elem {
            value: self,
            m: PhantomData,
            encoding: PhantomData,
        })
    }

    fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        if !self.is_odd() {
            return Err(error::Unspecified);
        }
        Ok(OddPositive(Positive(self)))
    }

    pub fn try_clone(&self) -> Result<Nonnegative, error::Unspecified> {
        let mut r = try!(Nonnegative::zero());
        try!(bssl::map_result(unsafe {
            GFp_BN_copy(r.as_mut_ref(), self.as_ref())
        }));
        Ok(r)
    }
}

// Returns a > b.
#[cfg(feature = "rsa_signing")]
#[inline]
fn greater_than(a: &Nonnegative, b: &Nonnegative) -> bool {
    let r = unsafe { GFp_BN_ucmp(a.as_ref(), b.as_ref()) };
    r > 0
}

type N0 = [limb::Limb; N0_LIMBS];
const N0_LIMBS: usize = 2;

// const N0_LIMBS_USED: usize = 1;
#[cfg(target_pointer_width = "64")]
#[inline]
fn n0_from_u64(n0: u64) -> N0 {
    [n0, 0]
}

// const N0_LIMBS_USED: usize = 2;
#[cfg(target_pointer_width = "32")]
#[inline]
fn n0_from_u64(n0: u64) -> N0 {
    [n0 as limb::Limb, (n0 >> limb::LIMB_BITS) as limb::Limb]
}

// `BIGNUM` is defined in its own submodule so that its private components are
// not accessible.
mod repr_c {
    use {c, limb};
    use core;
    use libc;

    #[cfg(feature = "rsa_signing")]
    use {bssl, error};

    // Keep in sync with `bignum_st` in openss/bn.h.
    #[repr(C)]
    pub struct BIGNUM {
        d: *mut limb::Limb,
        top: c::int,
        dmax: c::int,
        flags: c::int,
    }

    impl Drop for BIGNUM {
        fn drop(&mut self) {
            // Keep this in sync with `GFp_BN_free()`.

            // In particular, this doesn't work for `BN_FLG_STATIC_DATA`.
            assert_eq!(self.flags, 0);
            unsafe {
                let d: *mut limb::Limb = self.d;
                libc::free(d as *mut libc::c_void)
            }
        }
    }

    impl BIGNUM {
        pub fn zero() -> Self {
            BIGNUM {
                d: core::ptr::null_mut(),
                top: 0,
                dmax: 0,
                flags: 0,
            }
        }

        #[inline]
        pub fn limbs(&self) -> &[limb::Limb] {
            unsafe {
                core::slice::from_raw_parts(self.d, self.top as usize)
            }
        }

        #[cfg(feature = "rsa_signing")]
        #[inline]
        pub fn limbs_mut(&mut self) -> &mut [limb::Limb] {
            unsafe {
                core::slice::from_raw_parts_mut(self.d, self.top as usize)
            }
        }

        #[cfg(feature = "rsa_signing")]
        pub fn grow_by_one_bit(&mut self) -> Result<(), error::Unspecified> {
            let old_top = self.top;
            let new_top = old_top + 1;
            try!(bssl::map_result(unsafe {
                GFp_bn_wexpand(self, new_top)
            }));
            self.top = new_top;
            self.limbs_mut()[old_top as usize] = 1;
            Ok(())
        }

        #[cfg(feature = "rsa_signing")]
        pub fn shrunk_by_at_most_one_bit(&mut self) {
            let has_shrunk = {
                let limbs = self.limbs();
                limbs.len() > 1 && limbs[limbs.len() - 1] == 0
            };
            if has_shrunk {
                self.top -= 1;
            }
        }

        #[cfg(feature = "rsa_signing")]
        pub fn make_limbs<F>(&mut self, num_limbs: usize, f: F)
                             -> Result<(), error::Unspecified>
                where F: FnOnce(&mut [limb::Limb])
                                -> Result<(), error::Unspecified> {
            let num_limbs = num_limbs as c::int; // XXX
            try!(bssl::map_result(unsafe {
                GFp_bn_wexpand(self, num_limbs)
            }));
            self.top = num_limbs;
            try!(f(self.limbs_mut()));
            unsafe {
                GFp_bn_correct_top(self)
            }
            Ok(())
        }
    }

    #[cfg(feature = "rsa_signing")]
    extern {
        fn GFp_bn_correct_top(r: &mut BIGNUM);
        fn GFp_bn_wexpand(r: &mut BIGNUM, words: c::int) -> c::int;
    }
}

pub use self::repr_c::BIGNUM;

extern {
    fn GFp_BN_bin2bn(in_: *const u8, len: c::size_t, ret: &mut BIGNUM)
                     -> c::int;
    fn GFp_BN_ucmp(a: &BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_get_positive_u64(a: &BIGNUM) -> u64;
    fn GFp_BN_is_odd(a: &BIGNUM) -> c::int;
    fn GFp_BN_is_zero(a: &BIGNUM) -> c::int;
    fn GFp_BN_num_bits(bn: *const BIGNUM) -> c::size_t;
    fn GFp_bn_mont_n0(n: &BIGNUM) -> u64;
    fn GFp_bn_mod_exp_base_2_vartime(r: &mut BIGNUM, p: c::size_t,
                                     n: &BIGNUM) -> c::int;

    // `r` and/or 'a' and/or 'b' may alias.
    fn GFp_BN_mod_mul_mont(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM,
                            n: &BIGNUM, n0: &N0) -> c::int;

    // The use of references here implies lack of aliasing.
    fn GFp_BN_copy(a: &mut BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_from_montgomery_word(r: &mut BIGNUM, a: &mut BIGNUM, n: &BIGNUM,
                                   n0: &N0) -> c::int;
}

#[cfg(feature = "rsa_signing")]
extern {
    fn GFp_BN_set_word(r: &mut BIGNUM, w: limb::Limb) -> c::int;
    fn GFp_BN_is_one(a: &BIGNUM) -> c::int;

    // `r` and `a` may alias.
    fn GFp_BN_mod_exp_mont_consttime(r: *mut BIGNUM, a_mont: *const BIGNUM,
                                     p: &BIGNUM, one_mont: &BIGNUM, n: &BIGNUM,
                                     n0: &N0) -> c::int;

    // `r` and/or 'a' and/or 'b' may alias.
    fn GFp_BN_mod_add_quick(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM,
                            m: &BIGNUM) -> c::int;
    fn GFp_BN_mod_sub_quick(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM,
                            m: &BIGNUM) -> c::int;

    // `r` and `a` may alias.
    fn GFp_BN_uadd(r: *mut BIGNUM, a: *const BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_usub(r: *mut BIGNUM, a: *const BIGNUM, b: &BIGNUM) -> c::int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::GFp_BN_ucmp;
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

    #[test]
    fn test_odd_positive_from_even() {
        let x = Positive::from_be_bytes(untrusted::Input::from(&[4])).unwrap();
        assert!(x.into_odd_positive().is_err());
    }


    // Type-level representation of an arbitrary modulus.
    struct M {}

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_exp_consttime() {
        test::from_file("src/rsa/bigint_elem_exp_consttime_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let expected_result = consume_elem(test_case, "ModExp", &m);
            let base = consume_elem(test_case, "A", &m);
            let e = consume_odd_positive(test_case, "E");

            let base = into_encoded(base, &m);
            let oneRR = One::newRR(&m).unwrap();
            let one = One::newR(&oneRR, &m).unwrap();
            let actual_result = elem_exp_consttime(base, &e, &one, &m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    #[test]
    fn test_elem_exp_vartime() {
        test::from_file("src/rsa/bigint_elem_exp_vartime_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let expected_result = consume_elem(test_case, "ModExp", &m);
            let base = consume_elem(test_case, "A", &m);
            let e = consume_public_exponent(test_case, "E");

            let base = into_encoded(base, &m);
            let actual_result = elem_exp_vartime(base, e, &m).unwrap();
            let actual_result = actual_result.into_unencoded(&m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_inverse_invertible() {
        test::from_file("src/rsa/bigint_elem_inverse_invertible_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let a = consume_elem(test_case, "A", &m);
            let expected_result = consume_elem(test_case, "R", &m);
            let actual_result = match elem_inverse(a, &m) {
                Ok(actual_result) => actual_result,
                Err(InversionError::Unspecified) => unreachable!("Unspecified"),
                Err(InversionError::NoInverse) => unreachable!("No Inverse"),
            };
            let one: Elem<M, Unencoded> = try!(Elem::one());
            let actual_result = try!(elem_mul(&one, actual_result, &m));
            assert_elem_eq(&actual_result, &expected_result);
            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_set_to_inverse_blinded_invertible() {
        use super::super::N;

        let rng = rand::SystemRandom::new();

        test::from_file("src/rsa/bigint_elem_inverse_invertible_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let n = consume_modulus::<N>(test_case, "M");
            let a = consume_elem(test_case, "A", &n);
            let expected_result = consume_elem(test_case, "R", &n);
            let mut actual_result = try!(Elem::<N, R>::zero());
            assert!(elem_set_to_inverse_blinded(&mut actual_result, &a, &n,
                                                &rng).is_ok());
            let one: Elem<N, Unencoded> = try!(Elem::one());
            let actual_result = try!(elem_mul(&one, actual_result, &n));
            assert_elem_eq(&actual_result, &expected_result);
            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_inverse_noninvertible() {
        test::from_file("src/rsa/bigint_elem_inverse_noninvertible_tests.txt",
                        |section, test_case| {
                            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let a = consume_elem(test_case, "A", &m);
            match elem_inverse(a, &m) {
                Err(InversionError::NoInverse) => (),
                Err(InversionError::Unspecified) => unreachable!("Unspecified"),
                Ok(..) => unreachable!("No error"),
            }
            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_set_to_inverse_blinded_noninvertible() {
        use super::super::N;

        let rng = rand::SystemRandom::new();

        test::from_file("src/rsa/bigint_elem_inverse_noninvertible_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let n = consume_modulus::<N>(test_case, "M");
            let a = consume_elem(test_case, "A", &n);
            let mut actual_result = try!(Elem::<N, R>::zero());
            match elem_set_to_inverse_blinded(&mut actual_result, &a, &n, &rng) {
                Err(InversionError::NoInverse) => (),
                Err(InversionError::Unspecified) => unreachable!("Unspecified"),
                Ok(..) => unreachable!("No error"),
            }
            Ok(())
        })
    }

    #[test]
    fn test_elem_mul() {
        test::from_file("src/rsa/bigint_elem_mul_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let expected_result = consume_elem(test_case, "ModMul", &m);
            let a = consume_elem(test_case, "A", &m);
            let b = consume_elem(test_case, "B", &m);

            let b = into_encoded(b, &m);
            let a = into_encoded(a, &m);
            let actual_result = elem_mul(&a, b, &m).unwrap();
            let actual_result = actual_result.into_unencoded(&m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    #[test]
    fn test_elem_squared() {
        test::from_file("src/rsa/bigint_elem_squared_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let m = consume_modulus::<M>(test_case, "M");
            let expected_result = consume_elem(test_case, "ModSquare", &m);
            let a = consume_elem(test_case, "A", &m);

            let a = into_encoded(a, &m);
            let actual_result = elem_squared(a, &m).unwrap();
            let actual_result = actual_result.into_unencoded(&m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_reduced() {
        test::from_file("src/rsa/bigint_elem_reduced_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            struct MM {}
            unsafe impl SmallerModulus<MM> for M {}
            unsafe impl NotMuchSmallerModulus<MM> for M {}

            let m = consume_modulus::<M>(test_case, "M");
            let expected_result = consume_elem(test_case, "R", &m);
            let a = consume_elem_unchecked::<MM>(test_case, "A");

            let actual_result = elem_reduced(&a, &m).unwrap();
            let oneRR = One::newRR(&m).unwrap();
            let actual_result =
                elem_mul(oneRR.as_ref(), actual_result, &m).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_elem_reduced_once() {
        test::from_file("src/rsa/bigint_elem_reduced_once_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            struct N {}
            struct QQ {}
            unsafe impl SmallerModulus<N> for QQ {}
            unsafe impl SlightlySmallerModulus<N> for QQ {}

            let qq = consume_modulus::<QQ>(test_case, "QQ");
            let expected_result = consume_elem::<QQ>(test_case, "R", &qq);
            let n = consume_modulus::<N>(test_case, "N");
            let a = consume_elem::<N>(test_case, "A", &n);

            let actual_result = elem_reduced_once(&a, &qq).unwrap();
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    fn consume_elem<M>(test_case: &mut test::TestCase, name: &str, m: &Modulus<M>)
                       -> Elem<M, Unencoded> {
        let value = consume_nonnegative(test_case, name);
        value.into_elem::<M>(m).unwrap()
    }

    #[cfg(feature = "rsa_signing")]
    fn consume_elem_unchecked<M>(test_case: &mut test::TestCase, name: &str)
            -> Elem<M, Unencoded> {
        let value = consume_nonnegative(test_case, name);
        Elem {
            value: value,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    fn consume_modulus<M>(test_case: &mut test::TestCase, name: &str)
                          -> Modulus<M> {
        let value = consume_odd_positive(test_case, name);
        value.into_modulus().unwrap()
    }

    fn consume_public_exponent(test_case: &mut test::TestCase, name: &str)
                               -> PublicExponent {
        let value = consume_odd_positive(test_case, name);
        value.into_public_exponent().unwrap()
    }

    fn consume_odd_positive(test_case: &mut test::TestCase, name: &str)
                            -> OddPositive {
        let bytes = test_case.consume_bytes(name);
        let value =
            Positive::from_be_bytes(untrusted::Input::from(&bytes)).unwrap();
        value.into_odd_positive().unwrap()
    }

    fn consume_nonnegative(test_case: &mut test::TestCase, name: &str)
                           -> Nonnegative {
        let bytes = test_case.consume_bytes(name);
        let mut r = Nonnegative::zero().unwrap();
        bssl::map_result(unsafe {
            GFp_BN_bin2bn(bytes.as_ptr(), bytes.len(), r.as_mut_ref())
        }).unwrap();
        r
    }

    fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        let r = unsafe { GFp_BN_ucmp(a.value.as_ref(), b.value.as_ref()) };
        assert_eq!(r, 0)
    }

    fn into_encoded<M>(a: Elem<M, Unencoded>, m: &Modulus<M>) -> Elem<M, R> {
        let oneRR = One::newRR(&m).unwrap();
        elem_mul(&oneRR.as_ref(), a, m).unwrap()
    }
}
