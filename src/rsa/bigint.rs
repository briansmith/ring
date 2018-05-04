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

#![allow(box_pointers)]

use {bits, bssl, c, error, limb, untrusted};
use arithmetic::montgomery::*;
use core;
use core::marker::PhantomData;

#[cfg(any(test, feature = "rsa_signing"))]
use constant_time;

#[cfg(feature = "rsa_signing")]
use {der, rand};

impl AsRef<BIGNUM> for Positive {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { self.0.as_ref() }
}

impl AsRef<BIGNUM> for Nonnegative {
    fn as_ref<'a>(&'a self) -> &'a BIGNUM { &self.0 }
}

pub unsafe trait Prime {}

pub trait IsOne {
    fn is_one(&self) -> bool;
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
        Self::from_be_bytes(der::positive_integer(input)?)
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
                                -> Result<Self, error::Unspecified> {
        let r = Nonnegative::from_be_bytes_padded(input)?;
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

    #[cfg(feature = "rsa_signing")]
    #[inline]
    pub fn verify_less_than(&self, other: &Self)
                            -> Result<(), error::Unspecified> {
        (self.0).verify_less_than(&other.0)
    }
}

/// Odd positive integers.
pub struct OddPositive(Positive);

impl OddPositive {
    #[cfg(feature = "rsa_signing")]
    pub fn try_clone(&self) -> Result<OddPositive, error::Unspecified> {
        let value = (self.0).0.try_clone()?;
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

        let limbs = (self.0).0.limbs();

        #[cfg(target_pointer_width = "64")]
        let value = {
            assert!(limbs.len() == 1);
            *limbs.first().unwrap()
        };

        #[cfg(target_pointer_width = "32")]
        let value = {
            let mut value = u64::from(limbs[0]);
            if limbs.len() > 1 {
                assert!(limbs.len() == 2);
                value |= u64::from(limbs[1]) << limb::LIMB_BITS;
            };
            value
        };

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
    // r == 2**(N0_LIMBS_USED * LIMB_BITS) and LG_LITTLE_R == lg(r). This
    // ensures that we can do integer division by |r| by simply ignoring
    // `N0_LIMBS_USED` limbs. Similarly, we can calculate values modulo `r` by
    // just looking at the lowest `N0_LIMBS_USED` limbs. This is what makes
    // Montgomery multiplication efficient.
    //
    // As shown in Algorithm 1 of "Fast Prime Field Elliptic Curve Cryptography
    // with 256 Bit Primes" by Shay Gueron and Vlad Krasnov, in the loop of a
    // multi-limb Montgomery multiplication of a * b (mod n), given the
    // unreduced product t == a * b, we repeatedly calculate:
    //
    //    t1 := t % r         |t1| is |t|'s lowest limb (see previous paragraph).
    //    t2 := t1*n0*n
    //    t3 := t + t2
    //    t := t3 / r         copy all limbs of |t3| except the lowest to |t|.
    //
    // In the last step, it would only make sense to ignore the lowest limb of
    // |t3| if it were zero. The middle steps ensure that this is the case:
    //
    //                            t3 ==  0 (mod r)
    //                        t + t2 ==  0 (mod r)
    //                   t + t1*n0*n ==  0 (mod r)
    //                       t1*n0*n == -t (mod r)
    //                        t*n0*n == -t (mod r)
    //                          n0*n == -1 (mod r)
    //                            n0 == -1/n (mod r)
    //
    // Thus, in each iteration of the loop, we multiply by the constant factor
    // n0, the negative inverse of n (mod r). */
    //
    // TODO(perf): Not all 32-bit platforms actually make use of n0[1]. For the
    // ones that don't, we could use a shorter `R` value and use faster `Limb`
    // calculations instead of double-precision `u64` calculations.
    n0: N0,

    m: PhantomData<M>,
}

impl<M> Modulus<M> {
    fn new(n: OddPositive) -> Result<Self, error::Unspecified> {
        // A `Modulus` must be larger than 1.
        if n.bit_length() < bits::BitLength::from_usize_bits(2) {
            return Err(error::Unspecified);
        }

        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0_LIMBS_USED` limbs of `n`.
        let n0 = {
            let n_limbs = (n.0).0.limbs();
            let mut n_mod_r: u64 = u64::from(n_limbs[0]);

            if N0_LIMBS_USED == 2 {
                // XXX: If we use `<< limb::LIMB_BITS` here then 64-bit builds
                // fail to compile because of `deny(exceeding_bitshifts)`.
                debug_assert_eq!(limb::LIMB_BITS, 32);
                n_mod_r |= u64::from(n_limbs[1]) << 32;
            }
            unsafe { GFp_bn_neg_inv_mod_r_u64(n_mod_r) }
        };

        Ok(Modulus {
            value: n,
            n0: n0_from_u64(n0),
            m: PhantomData,
        })
    }
}

#[cfg(feature = "rsa_signing")]
impl Modulus<super::N> {
    pub fn value(&self) -> &OddPositive { &self.value }
}

/// Allows writing generic algorithms that require constraining the result type
/// of the multiplication.
pub trait ModMul<B, M> {
    type Output;
    fn mod_mul(&self, b: B, m: &Modulus<M>)
        -> Result<Self::Output, error::Unspecified>;
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
        let value = Nonnegative::zero()?;
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
        let value = self.value.try_clone()?;
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
        let value = Nonnegative::one()?;
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

    // The result is security-sensitive.
    #[cfg(feature = "rsa_signing")]
    #[inline]
    pub fn bit_length(&self) -> bits::BitLength { self.value.bit_length() }

    #[cfg(feature = "rsa_signing")]
    pub fn into_modulus<MM>(self) -> Result<Modulus<MM>, error::Unspecified> {
        let value = self.value.into_odd_positive()?;
        value.into_modulus()
    }
}

#[cfg(feature = "rsa_signing")]
impl<M> IsOne for Elem<M, Unencoded> {
    fn is_one(&self) -> bool {
        self.value.is_one()
    }
}

#[cfg(feature = "rsa_signing")]
impl<AF, BF, M> ModMul<Elem<M, BF>, M> for Elem<M, AF>
    where (AF, BF): ProductEncoding
{
    type Output = Elem<M, <(AF, BF) as ProductEncoding>::Output>;
    fn mod_mul(&self, b: Elem<M, BF>, m: &Modulus<M>)
        -> Result<<Self as ModMul<Elem<M, BF>, M>>::Output, error::Unspecified>
    {
        elem_mul(self, b, m)
    }
}

pub fn elem_mul<M, AF, BF>(a: &Elem<M, AF>, mut b: Elem<M, BF>, m: &Modulus<M>)
        -> Result<Elem<M, <(AF, BF) as ProductEncoding>::Output>,
                  error::Unspecified>
        where (AF, BF): ProductEncoding {
    let m_limbs = (m.value.0).0.limbs();
    let num_limbs = m_limbs.len();
    bssl::map_result(unsafe {
        GFp_bn_mul_mont_check_num_limbs(num_limbs)
    })?;

    let mut a_limbs;
    let a_limbs = if a.value.limbs().len() == num_limbs {
        a.value.limbs()
    } else {
        assert!(a.value.limbs().len() < num_limbs);
        a_limbs = vec![0; num_limbs];
        a_limbs[..a.value.limbs().len()].copy_from_slice(a.value.limbs());
        &a_limbs
    };

    b.value.0.make_limbs(num_limbs, |b_limbs| {
        assert_eq!(a_limbs.len(), num_limbs);
        assert_eq!(b_limbs.len(), num_limbs);
        unsafe {
            GFp_bn_mul_mont(b_limbs.as_mut_ptr(), a_limbs.as_ptr(),
                            b_limbs.as_ptr(), m_limbs.as_ptr(), &m.n0,
                            num_limbs)
        }
        Ok(())
    })?;

    Ok(Elem {
        value: b.value,
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
    let m_limbs = (m.value.0).0.limbs();
    let num_limbs = m_limbs.len();
    bssl::map_result(unsafe {
        GFp_bn_mul_mont_check_num_limbs(num_limbs)
    })?;

    let mut a_limbs;
    let a_limbs = if a.value.limbs().len() == num_limbs {
        a.value.limbs()
    } else {
        assert!(a.value.limbs().len() < num_limbs);
        a_limbs = vec![0; num_limbs];
        a_limbs[..a.value.limbs().len()].copy_from_slice(a.value.limbs());
        &a_limbs
    };

    let mut b_limbs;
    let b_limbs = if b.value.limbs().len() == num_limbs {
        b.value.limbs()
    } else {
        assert!(b.value.limbs().len() < num_limbs);
        b_limbs = vec![0; num_limbs];
        b_limbs[..b.value.limbs().len()].copy_from_slice(b.value.limbs());
        &b_limbs
    };

    r.value.0.make_limbs(num_limbs, |r_limbs| {
        assert_eq!(r_limbs.len(), num_limbs);
        assert_eq!(a_limbs.len(), num_limbs);
        assert_eq!(b_limbs.len(), num_limbs);
        unsafe {
            GFp_bn_mul_mont(r_limbs.as_mut_ptr(), a_limbs.as_ptr(),
                            b_limbs.as_ptr(), m_limbs.as_ptr(), &m.n0,
                            num_limbs)
        }
        Ok(())
    })
}

#[cfg(feature = "rsa_signing")]
pub fn elem_reduced_once<Larger, Smaller: SlightlySmallerModulus<Larger>>(
        a: &Elem<Larger, Unencoded>, m: &Modulus<Smaller>)
        -> Result<Elem<Smaller, Unencoded>, error::Unspecified> {
    let mut r = a.value.try_clone()?;
    let m_limbs = (m.value.0).0.limbs();
    assert!(r.limbs().len() <= m_limbs.len());
    r.0.make_limbs(m_limbs.len(), |r_limbs| {
        limb::limbs_reduce_once_constant_time(r_limbs, m_limbs);
        Ok(())
    })?;
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
    let tmp = a.try_clone()?;
    elem_reduced_(tmp, m)
}

fn elem_reduced_<LargerM, E: ReductionEncoding, SmallerM>(
        mut a: Elem<LargerM, E>, m: &Modulus<SmallerM>)
        -> Result<Elem<SmallerM, <E as ReductionEncoding>::Output>,
                  error::Unspecified> {
    let mut r = Elem::zero()?;
    bssl::map_result(unsafe {
        GFp_BN_from_montgomery_word(r.value.as_mut_ref(), a.value.as_mut_ref(),
                                    &m.value.as_ref(), &m.n0)
    })?;
    Ok(r)
}

pub fn elem_squared<M, E>(a: Elem<M, E>, m: &Modulus<M>)
        -> Result<Elem<M, <(E, E) as ProductEncoding>::Output>,
                  error::Unspecified>
        where (E, E): ProductEncoding {
    let m_limbs = (m.value.0).0.limbs();
    let num_limbs = m_limbs.len();
    let mut value = a.value;
    value.0.make_limbs(num_limbs, |limbs| {
        assert_eq!(limbs.len(), num_limbs);
        unsafe {
            GFp_bn_mul_mont(limbs.as_mut_ptr(), limbs.as_ptr(), limbs.as_ptr(),
                            m_limbs.as_ptr(), &m.n0, num_limbs)
        }
        Ok(())
    })?;
    Ok(Elem {
        value,
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
pub fn elem_add<M, E>(mut a: Elem<M, E>, mut b: Elem<M, E>, m: &Modulus<M>)
                      -> Result<Elem<M, E>, error::Unspecified> {
    let m = (m.value.0).0.limbs();
    a.value.0.make_limbs(m.len(), |a_limbs| {
        b.value.0.make_limbs(m.len(), |b_limbs| {
            unsafe {
                LIMBS_add_mod(a_limbs.as_mut_ptr(), a_limbs.as_ptr(),
                              b_limbs.as_ptr(), m.as_ptr(), m.len())
            }
            Ok(())
        })
    })?;
    Ok(a)
}

// TODO: Document why this works for all Montgomery factors.
#[cfg(feature = "rsa_signing")]
pub fn elem_sub<M, E>(mut a: Elem<M, E>, b: &Elem<M, E>, m: &Modulus<M>)
                   -> Result<Elem<M, E>, error::Unspecified> {
    let m_limbs = (m.value.0).0.limbs();
    a.value.0.make_limbs(m_limbs.len(), |a_limbs| {
        let b_limbs = b.value.limbs();
        unsafe {
            // XXX Not constant-time, even though it looks like it might be.
            LIMBS_sub_mod_ex(a_limbs.as_mut_ptr(), b_limbs.as_ptr(),
                             m_limbs.as_ptr(), m_limbs.len(), b_limbs.len())
        }
        Ok(())
    })?;
    Ok(a)
}


// The value 1, Montgomery-encoded some number of times.
pub struct One<M, E>(Elem<M, E>);

#[cfg(feature = "rsa_signing")]
impl<M> One<M, R> {
    pub fn newR(oneRR: &One<M, RR>, m: &Modulus<M>)
                -> Result<One<M, R>, error::Unspecified> {
        let value: Elem<M> = Elem::one()?;
        let value: Elem<M, R> = elem_mul(oneRR.as_ref(), value, &m)?;
        Ok(One(value))
    }
}

impl<M> One<M, RR> {
    pub fn newRR(m: &Modulus<M>) -> Result<One<M, RR>, error::Unspecified> {
        let RR = calculate_RR(&(m.value.0).0)?;
        Ok(One(Elem {
            value: RR,
            m: PhantomData,
            encoding: PhantomData,
        }))
    }
}

// Returns 2**(lg R) (mod m).
//
// RR = R**2 (mod N). R is the smallest power of 2**LIMB_BITS such that R > m.
// Even though the assembly on some 32-bit platforms works with 64-bit values,
// using `LIMB_BITS` here, rather than `N0_LIMBS_USED * LIMB_BITS`, is correct
// because R**2 will still be a multiple of the latter as `N0_LIMBS_USED` is
// either one or two.
fn calculate_RR(m: &Nonnegative) -> Result<Nonnegative, error::Unspecified> {
    use limb::LIMB_BITS;

    let m_bits = m.bit_length().as_usize_bits();

    let lg_RR = ((m_bits + (LIMB_BITS - 1)) / LIMB_BITS * LIMB_BITS) * 2;

    let mut r = Nonnegative::zero()?;

    let num_limbs = m.limbs().len();

    r.as_mut_ref().make_limbs(num_limbs, |limbs| {
        // Zero all the limbs.
        for limb in limbs.iter_mut() {
            *limb = 0;
        }

        // Make `r` the highest power of 2 less than `m`.
        let bit = m_bits - 1;
        limbs[bit / LIMB_BITS] = 1 << (bit % LIMB_BITS);

        // Double the value (mod m) until it is 2**(lg RR) (mod m),
        // i.e. RR (mod m).
        for _ in bit..lg_RR {
            unsafe {
                LIMBS_shl_mod(limbs.as_mut_ptr(), limbs.as_ptr(),
                              m.limbs().as_ptr(), num_limbs);
            }
        }

        Ok(())
    })?;

    Ok(r)
}

#[cfg(feature = "rsa_signing")]
impl<M> One<M, RRR> {
    pub fn newRRR(oneRR: One<M, RR>, m: &Modulus<M>)
                  -> Result<One<M, RRR>, error::Unspecified> {
        let oneRRR = elem_squared(oneRR.0, &m)?;
        Ok(One(oneRRR))
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> { &self.0 }
}

#[cfg(feature = "rsa_signing")]
impl<M, E> One<M, E> {
    pub fn try_clone(&self) -> Result<Self, error::Unspecified> {
        let value = self.0.try_clone()?;
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
    let mut acc = base.try_clone()?;
    let mut bit = 1 << (64 - 1 - exponent.leading_zeros());
    debug_assert!((exponent & bit) != 0);
    while bit > 1 {
        bit >>= 1;
        acc = elem_squared(acc, m)?;
        if (exponent & bit) != 0 {
            acc = elem_mul(&base, acc, m)?;
        }
    }
    Ok(acc)
}

#[cfg(feature = "rsa_signing")]
pub fn elem_exp_consttime<M>(
        base: Elem<M, R>, exponent: &OddPositive, oneR: &One<M, R>,
        m: &Modulus<M>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    let mut r = base.value;
    bssl::map_result(unsafe {
        GFp_BN_mod_exp_mont_consttime(&mut r.0, &r.0, exponent.as_ref(),
                                      oneR.0.value.as_ref(), &m.value.as_ref(),
                                      &m.n0)
    })?;
    let r = Elem {
        value: r,
        m: PhantomData,
        encoding: PhantomData,
    };

    // XXX: On x86-64 only, `GFp_BN_mod_exp_mont_consttime` does the conversion
    // from Montgomery form itself using a special assembly-language reduction
    // function. This means that at this point, whether `r` is Montgomery
    // encoded, and the exact type of `R` (in particular, its `E` type
    // parameter) depends on the platform. Type inference masks this.
    //
    // TODO: Get rid of that special assembly-language reduction function if
    // practical.

    #[cfg(not(target_arch = "x86_64"))]
    let r = r.into_unencoded(m)?;

    Ok(r)
}

/// Uses Fermat's Little Theorem to calculate modular inverse in constant time.
#[cfg(feature = "rsa_signing")]
pub fn elem_inverse_consttime<M: Prime>(
        a: Elem<M, R>,
        m: &Modulus<M>,
        oneR: &One<M, R>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    let m_minus_2 = {
        let two = {
            let one: Elem<M> = Elem::one()?;
            let one_ = Elem::one()?;
            elem_add(one, one_, m)?
        };
        let m_minus_2 = elem_sub(Elem::zero()?, &two, m)?;
        m_minus_2.value.into_odd_positive()?
    };
    elem_exp_consttime(a, &m_minus_2, oneR, m)
}

#[cfg(feature = "rsa_signing")]
pub fn elem_randomize<E>(a: &mut Elem<super::N, E>, m: &Modulus<super::N>,
                         rng: &rand::SecureRandom)
                         -> Result<(), error::Unspecified> {
    a.value.randomize(m, rng)
}

/// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
#[cfg(feature = "rsa_signing")]
pub fn verify_inverses_consttime<M, A, B>(a: &A, b: B, m: &Modulus<M>)
    -> Result<(), error::Unspecified> where
    A: ModMul<B, M>,
    <A as ModMul<B, M>>::Output: IsOne
{
    if a.mod_mul(b, m)?.is_one() {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
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
    let mut blinding_factor = Elem::<super::N, R>::zero()?;
    elem_randomize(&mut blinding_factor, n, rng)?;
    let to_blind = a.try_clone()?;
    let blinded = elem_mul(&blinding_factor, to_blind, n)?;
    let blinded_inverse = elem_inverse(blinded, n)?;
    elem_set_to_product(r, &blinding_factor, &blinded_inverse, n)?;
    Ok(())
}

// r = 1/a (mod m).
//
// This relies on the invariants of `Modulus` that its value is odd and larger
// than one.
#[cfg(feature = "rsa_signing")]
fn elem_inverse<M>(a: Elem<M, Unencoded>, m: &Modulus<M>)
                   -> Result<Elem<M, R>, InversionError> {
    let a_clone = a.try_clone()?;
    let inverse = nonnegative_mod_inverse(a.value, &(m.value.0).0)?;
    let r: Elem<M, R> = Elem {
        value: inverse,
        m: PhantomData,
        encoding: PhantomData,
    };
    verify_inverses_consttime(&r, a_clone, m)?;
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
            n.0.grow_by_one_bit()?;
        }
        Ok(())
    }

    // r += a.
    fn add_assign(r: &mut Nonnegative, a: &mut Nonnegative, m_limb_count: usize)
                  -> Result<(), error::Unspecified> {
        let mut carry = 0;
        r.0.make_limbs(m_limb_count, |r_limbs| {
            a.0.make_limbs(m_limb_count, |a_limbs| {
                carry = unsafe {
                    LIMBS_add_assign(r_limbs.as_mut_ptr(), a_limbs.as_ptr(),
                                     m_limb_count)
                };
                Ok(())
            })
        })?;
        // It is possible for the result to be one bit larger than `m`.
        if carry != 0 {
            r.0.grow_by_one_bit()?
        }
        Ok(())
    }

    // r -= a. Requires r > a.
    #[inline]
    fn sub_assign(r: &mut Nonnegative, a: &mut Nonnegative, m_limb_count: usize)
                  -> Result<(), error::Unspecified> {
        r.0.make_limbs(m_limb_count, |r_limbs| {
            a.0.make_limbs(m_limb_count, |a_limbs| {
                unsafe {
                    LIMBS_sub_assign(r_limbs.as_mut_ptr(), a_limbs.as_ptr(),
                                     m_limb_count);
                }
                Ok(())
            })
        })
    }

    let mut u = a;
    let mut v = m.try_clone()?;
    let mut x1 = Nonnegative::one()?;
    let mut x2 = Nonnegative::zero()?;
    let mut k = 0;

    let m_limbs = m.limbs();
    let m_limb_count = m_limbs.len();

    while !v.is_zero() {
        if v.is_even() {
            halve(&mut v);
            double(&mut x1)?;
        } else if u.is_even() {
            halve(&mut u);
            double(&mut x2)?;
        } else if !greater_than(&u, &v) {
            sub_assign(&mut v, &mut u, m_limb_count)?;
            halve(&mut v);
            add_assign(&mut x2, &mut x1, m_limb_count)?;
            double(&mut x1)?;
        } else {
            sub_assign(&mut u, &mut v, m_limb_count)?;
            halve(&mut u);
            add_assign(&mut x1, &mut x2, m_limb_count)?;
            double(&mut x2)?;
        }
        k += 1;
    }

    if !u.is_one() {
        return Err(InversionError::NoInverse);
    }

    // Reduce `x1` once if necessary to ensure it is less than `m`.
    if !greater_than(m, &x1) {
        debug_assert!(x1.limbs().len() <= m_limb_count + 1);
        // If `x` is longer than `m` then chop off that top bit.
        x1.0.make_limbs(m_limb_count, |x1_limbs| {
            unsafe {
                LIMBS_sub_assign(x1_limbs.as_mut_ptr(), m_limbs.as_ptr(),
                                 m_limb_count);
            }
            Ok(())
        })?;
    }
    assert!(greater_than(m, &x1));

    // Use the simpler repeated-subtraction reduction in 2.23.

    let n = m.bit_length().as_usize_bits();
    assert!(k >= n);
    for _ in n..k {
        let mut carry = 0;
        if x1.is_odd() {
            // x1 += m.
            x1.0.make_limbs(m_limb_count, |x1_limbs| {
                carry = unsafe {
                    LIMBS_add_assign(x1_limbs.as_mut_ptr(), m_limbs.as_ptr(),
                                     m_limb_count)
                };
                Ok(())
            })?;
        }

        // x1 /= 2.
        halve(&mut x1);

        // Shift in the carry bit at the top.
        if carry != 0 {
            x1.0.make_limbs(m_limb_count, |limbs| {
                *limbs.last_mut().unwrap() |= 1 << (LIMB_BITS - 1);
                Ok(())
            })?;
        }
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

#[cfg(any(test, feature = "rsa_signing"))]
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
        let mut r = Self::zero()?;
        r.0.make_limbs(1, |limbs| {
            limbs[0] = 1;
            Ok(())
        })?;
        Ok(r)
    }

    pub fn from_be_bytes_padded(input: untrusted::Input)
                                -> Result<Self, error::Unspecified> {
        let mut r = Self::zero()?;
        r.0.make_limbs(
            ((input.len() * limb::LIMB_BYTES) + limb::LIMB_BYTES - 1) /
                limb::LIMB_BYTES, |limbs|  {
            // Rejects empty inputs.
            limb::parse_big_endian_and_pad_consttime(input, limbs)
        })?;
        Ok(r)
    }

    #[inline]
    fn is_zero(&self) -> bool { self.limbs().is_empty() }

    #[cfg(feature = "rsa_signing")]
    #[inline]
    fn is_even(&self) -> bool { !self.is_odd() }

    #[inline]
    fn is_odd(&self) -> bool {
        self.limbs().first().unwrap_or(&0) & 1 == 1
    }

    fn bit_length(&self) -> bits::BitLength {
        let limbs = self.limbs();
        // XXX: This assumes `Limb::leading_zeros()` is constant-time.
        let high_bits = limbs.last()
            .map_or(0, |high_limb|
                limb::LIMB_BITS - (high_limb.leading_zeros() as usize));
        bits::BitLength::from_usize_bits(
            ((limbs.len() - 1) * limb::LIMB_BITS) + high_bits)
    }

    #[inline]
    fn limbs(&self) -> &[limb::Limb] { self.0.limbs() }

    #[cfg(feature = "rsa_signing")]
    #[inline]
    fn limbs_mut(&mut self) -> &mut [limb::Limb] { self.0.limbs_mut() }

    fn verify_less_than(&self, other: &Self)
                        -> Result<(), error::Unspecified> {
        if !greater_than(other, self) {
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
    fn as_mut_ref(&mut self) -> &mut BIGNUM { &mut self.0 }

    fn into_elem<M>(self, m: &Modulus<M>)
                    -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.verify_less_than(&(m.value.0).0)?;
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
        let mut r = Nonnegative::zero()?;
        bssl::map_result(unsafe {
            GFp_BN_copy(r.as_mut_ref(), self.as_ref())
        })?;
        Ok(r)
    }
}

#[cfg(feature = "rsa_signing")]
impl IsOne for Nonnegative {
    fn is_one(&self) -> bool {
        limb::limbs_equal_limb_constant_time(self.limbs(), 1) ==
            limb::LimbMask::True
    }
}

// Returns a > b.
fn greater_than(a: &Nonnegative, b: &Nonnegative) -> bool {
    let a_limbs = a.limbs();
    let b_limbs = b.limbs();
    if a_limbs.len() == b_limbs.len() {
        limb::limbs_less_than_limbs_vartime(b_limbs, a_limbs)
    } else {
        a_limbs.len() > b_limbs.len()
    }
}

type N0 = [limb::Limb; N0_LIMBS];
const N0_LIMBS: usize = 2;

#[cfg(target_pointer_width = "64")]
const N0_LIMBS_USED: usize = 1;

#[cfg(target_pointer_width = "64")]
#[inline]
fn n0_from_u64(n0: u64) -> N0 {
    [n0, 0]
}

#[cfg(target_pointer_width = "32")]
const N0_LIMBS_USED: usize = 2;

#[cfg(target_pointer_width = "32")]
#[inline]
fn n0_from_u64(n0: u64) -> N0 {
    [n0 as limb::Limb, (n0 >> limb::LIMB_BITS) as limb::Limb]
}

// `BIGNUM` is defined in its own submodule so that its private components are
// not accessible.
mod repr_c {
    use {bssl, c, error, limb};
    use core;
    use libc;

    // Keep in sync with `bignum_st` in openss/bn.h.
    #[repr(C)]
    pub struct BIGNUM {
        d: *mut limb::Limb,
        top: c::int,
        dmax: c::int,
    }

    impl Drop for BIGNUM {
        fn drop(&mut self) {
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
            }
        }

        #[inline]
        pub fn limbs(&self) -> &[limb::Limb] {
            unsafe {
                core::slice::from_raw_parts(self.d, self.top as usize)
            }
        }

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
            bssl::map_result(unsafe {
                GFp_bn_wexpand(self, new_top)
            })?;
            self.top = new_top;
            self.limbs_mut()[old_top as usize] = 1;
            Ok(())
        }

        #[cfg(feature = "rsa_signing")]
        pub fn shrunk_by_at_most_one_bit(&mut self) {
            if self.limbs().last().map_or(false, |last| *last == 0) {
                self.top -= 1;
            }
        }

        pub fn make_limbs<F>(&mut self, num_limbs: usize, f: F)
                             -> Result<(), error::Unspecified>
                where F: FnOnce(&mut [limb::Limb])
                                -> Result<(), error::Unspecified> {
            if num_limbs <= self.top as usize {
                self.top = num_limbs as c::int;
            } else {
                let old_top = self.top as usize;
                bssl::map_result(unsafe {
                    GFp_bn_wexpand(self, num_limbs as c::int)
                })?;
                self.top = num_limbs as c::int;

                // Zero the new upper limbs, leaving the old lower limbs untouched.
                for limb in &mut self.limbs_mut()[old_top..] {
                    *limb = 0;
                }
            }

            f(self.limbs_mut())?;

            unsafe {
                GFp_bn_correct_top(self)
            }

            Ok(())
        }
    }

    extern {
        fn GFp_bn_correct_top(r: &mut BIGNUM);
        fn GFp_bn_wexpand(r: &mut BIGNUM, words: c::int) -> c::int;
    }
}

pub use self::repr_c::BIGNUM;

extern {
    // `r` and/or 'a' and/or 'b' may alias.
    fn GFp_bn_mul_mont(r: *mut limb::Limb, a: *const limb::Limb,
                       b: *const limb::Limb, n: *const limb::Limb,
                       n0: &N0, num_limbs: c::size_t);
    fn GFp_bn_mul_mont_check_num_limbs(num_limbs: c::size_t) -> c::int;

    // The use of references here implies lack of aliasing.
    fn GFp_BN_copy(a: &mut BIGNUM, b: &BIGNUM) -> c::int;
    fn GFp_BN_from_montgomery_word(r: &mut BIGNUM, a: &mut BIGNUM, n: &BIGNUM,
                                   n0: &N0) -> c::int;

    fn GFp_bn_neg_inv_mod_r_u64(n: u64) -> u64;

    fn LIMBS_shl_mod(r: *mut limb::Limb, a: *const limb::Limb,
                     m: *const limb::Limb, num_limbs: c::size_t);
}

#[cfg(feature = "rsa_signing")]
extern {
    // `r` and `a` may alias.
    fn GFp_BN_mod_exp_mont_consttime(r: *mut BIGNUM, a_mont: *const BIGNUM,
                                     p: &BIGNUM, one_mont: &BIGNUM, n: &BIGNUM,
                                     n0: &N0) -> c::int;

    // `r` and `a` may alias.
    fn LIMBS_add_mod(r: *mut limb::Limb, a: *const limb::Limb,
                     b: *const limb::Limb, m: *const limb::Limb,
                     num_limbs: c::size_t);
    fn LIMBS_sub_mod_ex(r: *mut limb::Limb, a: *const limb::Limb,
                        m: *const limb::Limb, num_limbs: c::size_t,
                        a_limbs: c::size_t);

    fn LIMBS_add_assign(r: *mut limb::Limb, a: *const limb::Limb,
                        num_limbs: c::size_t) -> limb::Limb;
    fn LIMBS_sub_assign(r: *mut limb::Limb, a: *const limb::Limb,
                        num_limbs: c::size_t);
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
            let one: Elem<M, Unencoded> = Elem::one()?;
            let actual_result = elem_mul(&one, actual_result, &m)?;
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
            let mut actual_result = Elem::<N, R>::zero()?;
            assert!(elem_set_to_inverse_blinded(&mut actual_result, &a, &n,
                                                &rng).is_ok());
            let one: Elem<N, Unencoded> = Elem::one()?;
            let actual_result = elem_mul(&one, actual_result, &n)?;
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
            let mut actual_result = Elem::<N, R>::zero()?;
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
        Nonnegative::from_be_bytes_padded(untrusted::Input::from(&bytes))
            .unwrap()
    }

    fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        elem_verify_equal_consttime(&a, b).unwrap()
    }

    fn into_encoded<M>(a: Elem<M, Unencoded>, m: &Modulus<M>) -> Elem<M, R> {
        let oneRR = One::newRR(&m).unwrap();
        elem_mul(&oneRR.as_ref(), a, m).unwrap()
    }
}
