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
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use std;

#[cfg(any(test, feature = "rsa_signing"))]
use constant_time;

#[cfg(feature = "rsa_signing")]
use rand;

pub unsafe trait Prime {}

pub trait IsOne {
    fn is_one(&self) -> bool;
}

pub struct Width<M> {
    num_limbs: usize,

    /// The modulus *m* that the width originated from.
    m: PhantomData<M>,
}

/// All `BoxedLimbs<M>` are stored in the same number of limbs.
struct BoxedLimbs<M> {
    limbs: std::boxed::Box<[limb::Limb]>,

    /// The modulus *m* that determines the size of `limbx`.
    m: PhantomData<M>,
}

impl<M> Deref for BoxedLimbs<M> {
    type Target = [limb::Limb];
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.limbs
    }
}

impl<M> DerefMut for BoxedLimbs<M> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.limbs
    }
}

// TODO: `derive(Clone)` after https://github.com/rust-lang/rust/issues/26925
// is resolved or restrict `M: Clone`.
impl<M> Clone for BoxedLimbs<M> {
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            m: self.m.clone(),
        }
    }
}

impl<M> BoxedLimbs<M> {
    fn positive_minimal_width_from_be_bytes(input: untrusted::Input)
                                            -> Result<Self, error::Unspecified> {
        // Reject leading zeros. Also reject the value zero ([0]) because zero
        // isn't positive.
        if untrusted::Reader::new(input).peek(0) {
            return Err(error::Unspecified);
        }
        let num_limbs = (input.len() + limb::LIMB_BYTES - 1) / limb::LIMB_BYTES;
        let mut r = Self::zero(Width { num_limbs, m: PhantomData });
        limb::parse_big_endian_and_pad_consttime(input, &mut r)?;
        Ok(r)
    }

    #[cfg(feature = "rsa_signing")]
    fn minimal_width_from_unpadded(limbs: &[limb::Limb]) -> Self {
        debug_assert_ne!(limbs.last(), Some(&0));
        use std::borrow::ToOwned;
        Self {
            limbs: limbs.to_owned().into_boxed_slice(),
            m: PhantomData,
        }
    }

    fn from_be_bytes_padded_less_than(input: untrusted::Input, m: &Modulus<M>)
                                      -> Result<Self, error::Unspecified> {
        let mut r = Self::zero(m.width());
        limb::parse_big_endian_and_pad_consttime(input, &mut r)?;
        if limb::limbs_less_than_limbs_consttime(&r, &m.limbs) !=
            limb::LimbMask::True {
            return Err(error::Unspecified);
        }
        Ok(r)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        limb::limbs_are_zero_constant_time(&self.limbs) == limb::LimbMask::True
    }

    fn zero(width: Width<M>) -> Self {
        use std::borrow::ToOwned;
        Self {
            limbs: vec![0; width.num_limbs].to_owned().into_boxed_slice(),
            m: PhantomData,
        }
    }

    fn width(&self) -> Width<M> {
        Width {
            num_limbs: self.limbs.len(),
            m: PhantomData,
        }
    }
}

/// Non-negative, non-zero integers.
///
/// This set is sometimes called `Natural` or `Counting`, but texts, libraries,
/// and standards disagree on whether to include zero in them, so we avoid
/// those names.
#[cfg(feature = "rsa_signing")]
pub struct Positive(Nonnegative);

#[cfg(feature = "rsa_signing")]
impl Positive {
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

    pub fn from_be_bytes_with_bit_length(input: untrusted::Input)
        -> Result<(Positive, bits::BitLength), error::Unspecified>
    {
        let r = Self::from_be_bytes(input)?;
        let r_bits = minimal_limbs_bit_length(r.0.limbs());
        Ok((r, r_bits))
    }

    pub fn from_be_bytes_padded(input: untrusted::Input)
                                -> Result<Self, error::Unspecified> {
        let r = Nonnegative::from_be_bytes_padded(input)?;
        if r.is_zero() {
            return Err(error::Unspecified);
        }
        Ok(Positive(r))
    }

    pub fn to_elem<M>(&self, m: &Modulus<M>)
                      -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.0.to_elem(m)
    }

    pub fn verify_less_than_modulus<M>(&self, m: &Modulus<M>)
        -> Result<(), error::Unspecified>
    {
        self.0.verify_less_than_modulus(m)
    }

    pub fn into_odd_positive(self) -> Result<OddPositive, error::Unspecified> {
        self.0.into_odd_positive()
    }

    #[inline]
    pub fn verify_less_than(&self, other: &Self)
                            -> Result<(), error::Unspecified> {
        (self.0).verify_less_than(&other.0)
    }
}

/// Odd positive integers.
#[cfg(feature = "rsa_signing")]
pub struct OddPositive(Positive);

#[cfg(feature = "rsa_signing")]
impl OddPositive {
    pub fn to_elem<M>(&self, m: &Modulus<M>)
                      -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.0.to_elem(m)
    }

    #[inline]
    pub fn into_modulus<M>(self) -> Result<Modulus<M>, error::Unspecified> {
        Modulus::from_limbs((self.0).0.limbs())
    }
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

pub const MODULUS_MAX_LIMBS: usize = 8192 / limb::LIMB_BITS;

/// The modulus *m* for a ring ℤ/mℤ, along with the precomputed values needed
/// for efficient Montgomery multiplication modulo *m*. The value must be odd
/// and larger than 2. The larger-than-1 requirement is imposed, at least, by
/// the modular inversion code.
#[derive(Clone)]
pub struct Modulus<M> {
    limbs: BoxedLimbs<M>, // Also `value >= 3`.

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
}

impl<M> Modulus<M> {
    pub fn from_be_bytes_with_bit_length(input: untrusted::Input)
        -> Result<(Self, bits::BitLength), error::Unspecified>
    {
        let limbs = BoxedLimbs::positive_minimal_width_from_be_bytes(input)?;
        let bits = minimal_limbs_bit_length(&limbs);
        Ok((Self::from_boxed_limbs(limbs)?, bits))
    }

    #[cfg(feature = "rsa_signing")]
    fn from_limbs(n: &[limb::Limb]) -> Result<Self, error::Unspecified> {
        Self::from_boxed_limbs(BoxedLimbs::minimal_width_from_unpadded(n))
    }

    fn from_boxed_limbs(n: BoxedLimbs<M>) -> Result<Self, error::Unspecified> {
        if n.len() > MODULUS_MAX_LIMBS {
            return Err(error::Unspecified);
        }
        bssl::map_result(unsafe {
            GFp_bn_mul_mont_check_num_limbs(n.len())
        })?;
        if limb::limbs_are_even_constant_time(&n) != limb::LimbMask::False {
            return Err(error::Unspecified)
        }
        if limb::limbs_less_than_limb_constant_time(&n, 3) != limb::LimbMask::False {
            return Err(error::Unspecified);
        }

        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0_LIMBS_USED` limbs of `n`.
        let n0 = {
            // XXX: u64::from isn't guaranteed to be constant time.
            let mut n_mod_r: u64 = u64::from(n[0]);

            if N0_LIMBS_USED == 2 {
                // XXX: If we use `<< limb::LIMB_BITS` here then 64-bit builds
                // fail to compile because of `deny(exceeding_bitshifts)`.
                debug_assert_eq!(limb::LIMB_BITS, 32);
                n_mod_r |= u64::from(n[1]) << 32;
            }
            unsafe { GFp_bn_neg_inv_mod_r_u64(n_mod_r) }
        };

        Ok(Modulus {
            limbs: n,
            n0: n0_from_u64(n0),
        })
    }

    #[inline]
    fn width(&self) -> Width<M> { self.limbs.width() }

    pub fn zero<E>(&self) -> Elem<M, E> {
        Elem {
            limbs: BoxedLimbs::zero(self.width()),
            encoding: PhantomData,
        }
    }

    // TODO: Get rid of this
    #[cfg(feature = "rsa_signing")]
    fn one(&self) -> Elem<M, Unencoded> {
        let mut r = self.zero();
        r.limbs[0] = 1;
        r
    }

    #[cfg(feature = "rsa_signing")]
    pub fn to_elem<L>(&self, l: &Modulus<L>) -> Elem<L, Unencoded>
        where M: SmallerModulus<L>
    {
        // TODO: Encode this assertion into the `where` above.
        assert_eq!(self.width().num_limbs, l.width().num_limbs);
        let limbs = self.limbs.clone();
        Elem {
            limbs: BoxedLimbs {
                limbs: limbs.limbs,
                m: PhantomData,
            },
            encoding: PhantomData,
        }
    }
}

/// Allows writing generic algorithms that require constraining the result type
/// of the multiplication.
pub trait ModMul<B, M> {
    type Output;
    fn mod_mul(&self, b: B, m: &Modulus<M>) -> Self::Output;
}

/// Elements of ℤ/mℤ for some modulus *m*.
//
// Defaulting `E` to `Unencoded` is a convenience for callers from outside this
// submodule. However, for maximum clarity, we always explicitly use
// `Unencoded` within the `bigint` submodule.
pub struct Elem<M, E = Unencoded> {
    limbs: BoxedLimbs<M>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    encoding: PhantomData<E>,
}

// TODO: `derive(Clone)` after https://github.com/rust-lang/rust/issues/26925
// is resolved or restrict `M: Clone` and `E: Clone`.
impl<M, E> Clone for Elem<M, E> {
    fn clone(&self) -> Self {
        Elem {
            limbs: self.limbs.clone(),
            encoding: self.encoding.clone(),
        }
    }
}

impl<M, E> Elem<M, E> {
    #[inline]
    pub fn is_zero(&self) -> bool { self.limbs.is_zero() }

    // XXX: This is nonsense semantically, but it is a useful optimization.
    #[cfg(feature = "rsa_signing")]
    pub fn take_storage<OtherF>(e: Elem<M, OtherF>) -> Elem<M, E> {
        Elem {
            limbs: e.limbs,
            encoding: PhantomData,
        }
    }
}

impl<M, E: ReductionEncoding> Elem<M, E> {
    fn decode_once(self, m: &Modulus<M>)
        -> Elem<M, <E as ReductionEncoding>::Output>
    {
        // A multiplication isn't required since we're multiplying by the
        // unencoded value one (1); only a Montgomery reduction is needed.
        // However the only non-multiplication Montgomery reduction function we
        // have requires the input to be large, so we avoid using it here.
        let mut limbs = self.limbs;
        let num_limbs = m.width().num_limbs;
        let mut one = [0; MODULUS_MAX_LIMBS];
        one[0] = 1;
        let one = &one[..num_limbs]; // assert!(num_limbs <= MODULUS_MAX_LIMBS);
        unsafe {
            GFp_bn_mul_mont(limbs.as_mut_ptr(), limbs.as_ptr(),
                            one.as_ptr(), m.limbs.as_ptr(), &m.n0, num_limbs)
        }
        Elem {
            limbs,
            encoding: PhantomData,
        }
    }
}

impl<M> Elem<M, R> {
    #[inline]
    pub fn into_unencoded(self, m: &Modulus<M>) -> Elem<M, Unencoded> {
        self.decode_once(m)
    }
}

impl<M> Elem<M, Unencoded> {
    pub fn from_be_bytes_padded(input: untrusted::Input, m: &Modulus<M>)
                                -> Result<Self, error::Unspecified> {
        Ok(Elem {
            limbs: BoxedLimbs::from_be_bytes_padded_less_than(input, m)?,
            encoding: PhantomData,
        })
    }

    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        limb::big_endian_from_limbs_padded(&self.limbs, out)
    }

    #[cfg(feature = "rsa_signing")]
    pub fn into_modulus<MM>(self) -> Result<Modulus<MM>, error::Unspecified> {
        Modulus::from_limbs(&self.limbs)
    }
}

#[cfg(feature = "rsa_signing")]
impl<M> IsOne for Elem<M, Unencoded> {
    fn is_one(&self) -> bool {
        limb::limbs_equal_limb_constant_time(&self.limbs, 1) ==
            limb::LimbMask::True
    }
}

#[cfg(feature = "rsa_signing")]
impl<AF, BF, M> ModMul<Elem<M, BF>, M> for Elem<M, AF>
    where (AF, BF): ProductEncoding
{
    type Output = Elem<M, <(AF, BF) as ProductEncoding>::Output>;
    fn mod_mul(&self, b: Elem<M, BF>, m: &Modulus<M>)
        -> <Self as ModMul<Elem<M, BF>, M>>::Output
    {
        elem_mul(self, b, m)
    }
}

pub fn elem_mul<M, AF, BF>(a: &Elem<M, AF>, mut b: Elem<M, BF>, m: &Modulus<M>)
        -> Elem<M, <(AF, BF) as ProductEncoding>::Output>
        where (AF, BF): ProductEncoding {
    unsafe {
        GFp_bn_mul_mont(b.limbs.as_mut_ptr(), a.limbs.as_ptr(),
                        b.limbs.as_ptr(), m.limbs.as_ptr(), &m.n0,
                        m.limbs.len());
    }
    Elem {
        limbs: b.limbs,
        encoding: PhantomData,
    }
}

// `a` * `b` (mod `m`).
#[cfg(feature = "rsa_signing")]
pub fn elem_set_to_product<M, AF, BF>(
        r: &mut Elem<M, <(AF, BF) as ProductEncoding>::Output>,
        a: &Elem<M, AF>, b: &Elem<M, BF>, m: &Modulus<M>)
        where (AF, BF): ProductEncoding {
    unsafe {
        GFp_bn_mul_mont(r.limbs.as_mut_ptr(), a.limbs.as_ptr(),
                        b.limbs.as_ptr(), m.limbs.as_ptr(), &m.n0,
                        m.limbs.len())
    }
}

#[cfg(feature = "rsa_signing")]
pub fn elem_reduced_once<Larger, Smaller: SlightlySmallerModulus<Larger>>(
        a: &Elem<Larger, Unencoded>, m: &Modulus<Smaller>)
        -> Elem<Smaller, Unencoded> {
    let mut r = a.limbs.clone();
    assert!(r.len() <= m.limbs.len());
    limb::limbs_reduce_once_constant_time(&mut r, &m.limbs);
    Elem {
        limbs: BoxedLimbs {
            limbs: r.limbs,
            m: PhantomData,
        },
        encoding: PhantomData,
    }
}

#[cfg(feature = "rsa_signing")]
#[inline]
pub fn elem_reduced<Larger, Smaller: NotMuchSmallerModulus<Larger>>(
        a: &Elem<Larger, Unencoded>, m: &Modulus<Smaller>)
        -> Result<Elem<Smaller, RInverse>, error::Unspecified> {
    let mut tmp = [0; MODULUS_MAX_LIMBS];
    let tmp = &mut tmp[..a.limbs.len()];
    tmp.copy_from_slice(&a.limbs);

    let mut r = m.zero();
    bssl::map_result(unsafe {
        GFp_bn_from_montgomery_in_place(r.limbs.as_mut_ptr(), r.limbs.len(),
                                        tmp.as_mut_ptr(), tmp.len(),
                                        m.limbs.as_ptr(), m.limbs.len(), &m.n0)
    })?;
    Ok(r)
}

pub fn elem_squared<M, E>(mut a: Elem<M, E>, m: &Modulus<M>)
        -> Elem<M, <(E, E) as ProductEncoding>::Output>
        where (E, E): ProductEncoding {
    unsafe {
        GFp_bn_mul_mont(a.limbs.as_mut_ptr(), a.limbs.as_ptr(),
                        a.limbs.as_ptr(), m.limbs.as_ptr(), &m.n0,
                        m.limbs.len());
    };
    Elem {
        limbs: a.limbs,
        encoding: PhantomData,
    }
}

#[cfg(feature = "rsa_signing")]
pub fn elem_widen<Larger, Smaller: SmallerModulus<Larger>>(
    a: Elem<Smaller, Unencoded>, m: &Modulus<Larger>)
    -> Elem<Larger, Unencoded>
{
    let mut r = m.zero();
    r.limbs[..a.limbs.len()].copy_from_slice(&a.limbs);
    r
}


// TODO: Document why this works for all Montgomery factors.
#[cfg(feature = "rsa_signing")]
pub fn elem_add<M, E>(mut a: Elem<M, E>, b: Elem<M, E>, m: &Modulus<M>)
    -> Elem<M, E>
{
    unsafe {
        LIMBS_add_mod(a.limbs.as_mut_ptr(), a.limbs.as_ptr(),
                      b.limbs.as_ptr(), m.limbs.as_ptr(), m.limbs.len())
    }
    a
}

// TODO: Document why this works for all Montgomery factors.
#[cfg(feature = "rsa_signing")]
pub fn elem_sub<M, E>(mut a: Elem<M, E>, b: &Elem<M, E>, m: &Modulus<M>)
    -> Elem<M, E>
{
    unsafe {
        LIMBS_sub_mod(a.limbs.as_mut_ptr(), a.limbs.as_ptr(), b.limbs.as_ptr(),
                      m.limbs.as_ptr(), m.limbs.len());
    }
    a
}


// The value 1, Montgomery-encoded some number of times.
#[derive(Clone)]
pub struct One<M, E>(Elem<M, E>);

#[cfg(feature = "rsa_signing")]
impl<M> One<M, R> {
    pub fn newR(oneRR: &One<M, RR>, m: &Modulus<M>) -> One<M, R> {
        One(oneRR.0.clone().decode_once(m))
    }
}

impl<M> One<M, RR> {
    // Returns 2**(lg R) (mod m).
    //
    // RR = R**2 (mod N). R is the smallest power of 2**LIMB_BITS such that R > m.
    // Even though the assembly on some 32-bit platforms works with 64-bit values,
    // using `LIMB_BITS` here, rather than `N0_LIMBS_USED * LIMB_BITS`, is correct
    // because R**2 will still be a multiple of the latter as `N0_LIMBS_USED` is
    // either one or two.
    pub fn newRR(m: &Modulus<M>) -> One<M, RR> {
        use limb::LIMB_BITS;

        let m_bits = minimal_limbs_bit_length(&m.limbs).as_usize_bits();

        let lg_RR = ((m_bits + (LIMB_BITS - 1)) / LIMB_BITS * LIMB_BITS) * 2;

        let mut r = m.zero();

        // Make `r` the highest power of 2 less than `m`.
        let bit = m_bits - 1;
        r.limbs[bit / LIMB_BITS] = 1 << (bit % LIMB_BITS);

        let num_limbs = r.limbs.len();

        // Double the value (mod m) until it is 2**(lg RR) (mod m),
        // i.e. RR (mod m).
        for _ in bit..lg_RR {
            unsafe {
                LIMBS_shl_mod(r.limbs.as_mut_ptr(), r.limbs.as_ptr(),
                              m.limbs.as_ptr(), num_limbs);
            }
        }

        One(r)
    }
}

#[cfg(feature = "rsa_signing")]
impl<M> One<M, RRR> {
    pub fn newRRR(oneRR: One<M, RR>, m: &Modulus<M>) -> One<M, RRR> {
        One(elem_squared(oneRR.0, &m))
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> { &self.0 }
}

/// An non-secret odd positive value in the range
/// [3, PUBLIC_EXPONENT_MAX_VALUE].
#[derive(Clone, Copy)]
pub struct PublicExponent(u64);

impl PublicExponent {
    pub fn from_be_bytes(input: untrusted::Input, min_value: u64)
                         -> Result<Self, error::Unspecified> {
        if input.len() > 5 {
            return Err(error::Unspecified);
        }
        let value = input.read_all_mut(error::Unspecified, |input| {
            // The exponent can't be zero and it can't be prefixed with
            // zero-valued bytes.
            if input.peek(0) {
                return Err(error::Unspecified);
            }
            let mut value = 0u64;
            loop {
                let byte = input.read_byte()?;
                value = (value << 8) | u64::from(byte);
                if input.at_end() {
                    return Ok(value);
                }
            }
        })?;
        if value & 1 != 1 {
            return Err(error::Unspecified);
        }
        if value < min_value {
            return Err(error::Unspecified);
        }
        if value > PUBLIC_EXPONENT_MAX_VALUE {
            return Err(error::Unspecified);
        }
        Ok(PublicExponent(value))
    }
}

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
pub const PUBLIC_EXPONENT_MAX_VALUE: u64 = (1u64 << 33) - 1;

/// Calculates base**exponent (mod m).
// TODO: The test coverage needs to be expanded, e.g. test with the largest
// accepted exponent and with the most common values of 65537 and 3.
pub fn elem_exp_vartime<M>(
        base: Elem<M, R>, PublicExponent(exponent): PublicExponent,
        m: &Modulus<M>) -> Elem<M, R> {
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
    // `PUBLIC_EXPONENT_MAX_VALUE` cap.
    //
    // This implementation is slightly simplified by taking advantage of the
    // fact that we require the exponent to be an (odd) positive integer.
    //
    // [Knuth]: The Art of Computer Programming, Volume 2: Seminumerical
    //          Algorithms (3rd Edition), Section 4.6.3.
    debug_assert_eq!(exponent & 1, 1);
    assert!(exponent <= PUBLIC_EXPONENT_MAX_VALUE);
    let mut acc = base.clone();
    let mut bit = 1 << (64 - 1 - exponent.leading_zeros());
    debug_assert!((exponent & bit) != 0);
    while bit > 1 {
        bit >>= 1;
        acc = elem_squared(acc, m);
        if (exponent & bit) != 0 {
            acc = elem_mul(&base, acc, m);
        }
    }
    acc
}

// `M` represents the prime modulus for which the exponent is in the interval
// [1, `m` - 1).
#[cfg(feature = "rsa_signing")]
#[derive(Clone)]
pub struct PrivateExponent<M> {
    limbs: BoxedLimbs<M>,
}

#[cfg(feature = "rsa_signing")]
impl<M> PrivateExponent<M> {
    pub fn from_be_bytes_padded(input: untrusted::Input, p: &Modulus<M>)
                                -> Result<Self, error::Unspecified> {
        let dP = BoxedLimbs::from_be_bytes_padded_less_than(input, p)?;

        // Proof that `dP < p - 1`:
        //
        // If `dP < p` then either `dP == p - 1` or `dP < p - 1`. Since `p` is
        // odd, `p - 1` is even. `d` is odd, and an odd number modulo an even
        // number is odd. Therefore `dP` must be odd. But then it cannot be
        // `p - 1` and so we know `dP < p - 1`.
        //
        // Further we know `dP != 0` because `dP` is not even.
        if limb::limbs_are_even_constant_time(&dP) != limb::LimbMask::False {
            return Err(error::Unspecified);
        }

        Ok(PrivateExponent {
            limbs: dP,
        })
    }
}

#[cfg(feature = "rsa_signing")]
impl<M: Prime> PrivateExponent<M> {
    // Returns `p - 2`.
    fn for_flt(p: &Modulus<M>) -> Self {
        let two = elem_add(p.one(), p.one(), p);
        let p_minus_2 = elem_sub(p.zero(), &two, p);
        PrivateExponent {
            limbs: p_minus_2.limbs,
        }
    }
}

#[cfg(feature = "rsa_signing")]
pub fn elem_exp_consttime<M>(
        base: Elem<M, R>, exponent: &PrivateExponent<M>, oneR: &One<M, R>,
        m: &Modulus<M>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    let mut r = Elem {
        limbs: base.limbs,
        encoding: PhantomData,
    };
    bssl::map_result(unsafe {
        GFp_BN_mod_exp_mont_consttime(r.limbs.as_mut_ptr(), r.limbs.as_ptr(),
                                      exponent.limbs.as_ptr(),
                                      oneR.0.limbs.as_ptr(), m.limbs.as_ptr(),
                                      m.limbs.len(), &m.n0)
    })?;

    // XXX: On x86-64 only, `GFp_BN_mod_exp_mont_consttime` does the conversion
    // from Montgomery form itself using a special assembly-language reduction
    // function. This means that at this point, whether `r` is Montgomery
    // encoded, and the exact type of `R` (in particular, its `E` type
    // parameter) depends on the platform. Type inference masks this.
    //
    // TODO: Get rid of that special assembly-language reduction function if
    // practical.

    #[cfg(not(target_arch = "x86_64"))]
    let r = r.into_unencoded(m);

    Ok(r)
}

/// Uses Fermat's Little Theorem to calculate modular inverse in constant time.
#[cfg(feature = "rsa_signing")]
pub fn elem_inverse_consttime<M: Prime>(
        a: Elem<M, R>,
        m: &Modulus<M>,
        oneR: &One<M, R>) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    elem_exp_consttime(a, &PrivateExponent::for_flt(&m), oneR, m)
}

#[cfg(feature = "rsa_signing")]
pub fn elem_randomize<E>(a: &mut Elem<super::N, E>, m: &Modulus<super::N>,
                         rng: &rand::SecureRandom)
                         -> Result<(), error::Unspecified> {
    super::random::set_to_rand_mod(&mut a.limbs, &m.limbs, rng)
}

/// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
#[cfg(feature = "rsa_signing")]
pub fn verify_inverses_consttime<M, A, B>(a: &A, b: B, m: &Modulus<M>)
    -> Result<(), error::Unspecified> where
    A: ModMul<B, M>,
    <A as ModMul<B, M>>::Output: IsOne
{
    if a.mod_mul(b, m).is_one() {
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
    let blinding_factor = {
        let mut tmp = n.zero::<R>();
        elem_randomize(&mut tmp, n, rng)?;
        tmp
    };
    let to_blind = a.clone();
    let blinded = elem_mul(&blinding_factor, to_blind, n);
    let blinded_inverse = elem_inverse(blinded, n)?;
    elem_set_to_product(r, &blinding_factor, &blinded_inverse, n);
    Ok(())
}

// r = 1/a (mod m).
//
// This relies on the invariants of `Modulus` that its value is odd and larger
// than one.
#[cfg(feature = "rsa_signing")]
fn elem_inverse<M>(a: Elem<M, Unencoded>, m: &Modulus<M>)
                   -> Result<Elem<M, R>, InversionError> {
    let inverse = nonnegative_mod_inverse(Nonnegative::from_limbs(&a.limbs)?,
                                          Nonnegative::from_limbs(&m.limbs)?,
                                          &m.limbs)?;
    let r: Elem<M, R> = Elem {
        // TODO: The check done by to_elem() isn't necessary, right?
        limbs: inverse.to_elem(&m)?.limbs,
        encoding: PhantomData,
    };
    verify_inverses_consttime(&r, a, m)?;
    Ok(r)
}

#[cfg(feature = "rsa_signing")]
fn nonnegative_mod_inverse(a: Nonnegative, m: Nonnegative,
                           m_limbs: &[limb::Limb])
                           -> Result<Nonnegative, InversionError> {
    use limb::*;

    // Algorithm 2.23 from "Guide to Elliptic Curve Cryptography" [2004] by
    // Darrel Hankerson, Alfred Menezes, and Scott Vanstone.

    debug_assert!(greater_than(&m, &a));
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
    let mut v = m.try_clone()?; // TODO: avoid clone
    let mut x1 = Nonnegative::one()?;
    let mut x2 = Nonnegative::zero()?;
    let mut k = 0;

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
    if !greater_than(&m, &x1) {
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
    assert!(greater_than(&m, &x1));

    // Use the simpler repeated-subtraction reduction in 2.23.

    let n = minimal_limbs_bit_length(m.limbs()).as_usize_bits();
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
    constant_time::verify_slices_are_equal(limb::limbs_as_bytes(&a.limbs),
                                           limb::limbs_as_bytes(&b.limbs))
}

/// Nonnegative integers: `Positive` ∪ {0}.
#[cfg(feature = "rsa_signing")]
struct Nonnegative(BIGNUM);

#[cfg(feature = "rsa_signing")]
impl Nonnegative {
    fn zero() -> Result<Self, error::Unspecified> {
        let r = Nonnegative(BIGNUM::zero());
        debug_assert!(r.is_zero());
        Ok(r)
    }

    pub fn from_limbs(source: &[limb::Limb])
        -> Result<Self, error::Unspecified>
    {
        let mut r = Self::zero()?;
        r.0.make_limbs(source.len(), |limbs| {
            limbs.copy_from_slice(source);
            Ok(())
        })?;
        Ok(r)
    }

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
            (input.len() + limb::LIMB_BYTES - 1) / limb::LIMB_BYTES, |limbs|  {
            // Rejects empty inputs.
            limb::parse_big_endian_and_pad_consttime(input, limbs)
        })?;
        Ok(r)
    }

    #[inline]
    fn is_zero(&self) -> bool { self.limbs().is_empty() }

    #[inline]
    fn is_even(&self) -> bool { !self.is_odd() }

    #[inline]
    fn is_odd(&self) -> bool {
        limb::limbs_are_even_constant_time(self.limbs()) == limb::LimbMask::False
    }

    #[inline]
    fn limbs(&self) -> &[limb::Limb] { self.0.limbs() }

    #[inline]
    fn limbs_mut(&mut self) -> &mut [limb::Limb] { self.0.limbs_mut() }

    fn verify_less_than(&self, other: &Self)
                        -> Result<(), error::Unspecified> {
        if !greater_than(other, self) {
            return Err(error::Unspecified);
        }
        Ok(())
    }

    // XXX: This makes it too easy to break invariants on things. TODO: Remove
    // this ASAP.
    fn as_mut_ref(&mut self) -> &mut BIGNUM { &mut self.0 }

    fn to_elem<M>(&self, m: &Modulus<M>)
                  -> Result<Elem<M, Unencoded>, error::Unspecified> {
        self.verify_less_than_modulus(&m)?;
        let mut r = m.zero();
        r.limbs[0..self.limbs().len()].copy_from_slice(self.limbs());
        Ok(r)
    }

    pub fn verify_less_than_modulus<M>(&self, m: &Modulus<M>)
                                       -> Result<(), error::Unspecified>
    {
        if self.limbs().len() > m.limbs.len() {
            return Err(error::Unspecified);
        }
        if self.limbs().len() == m.limbs.len() {
            if limb::limbs_less_than_limbs_consttime(self.limbs(), &m.limbs)
                != limb::LimbMask::True {
                return Err(error::Unspecified)
            }
        }
        return Ok(())
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
            GFp_BN_copy(r.as_mut_ref(), &self.0)
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

// Returns the number of bits in `a` assuming that the top word of `a` is not
// zero.
fn minimal_limbs_bit_length(a: &[limb::Limb]) -> bits::BitLength {
    let bits = match a.last() {
        Some(limb) => {
            assert_ne!(*limb, 0);
            // XXX: This assumes `Limb::leading_zeros()` is constant-time.
            let high_bits = a.last().map_or(0, |high_limb| {
                limb::LIMB_BITS - (high_limb.leading_zeros() as usize)
            });
            ((a.len() - 1) * limb::LIMB_BITS) + high_bits
        },
        None => 0,
    };
    bits::BitLength::from_usize_bits(bits)
}

// Returns a > b.
#[cfg(feature = "rsa_signing")]
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
#[cfg(feature = "rsa_signing")]
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

#[cfg(feature = "rsa_signing")]
pub use self::repr_c::BIGNUM;

extern {
    // `r` and/or 'a' and/or 'b' may alias.
    fn GFp_bn_mul_mont(r: *mut limb::Limb, a: *const limb::Limb,
                       b: *const limb::Limb, n: *const limb::Limb,
                       n0: &N0, num_limbs: c::size_t);
    fn GFp_bn_mul_mont_check_num_limbs(num_limbs: c::size_t) -> c::int;

    fn GFp_bn_neg_inv_mod_r_u64(n: u64) -> u64;

    fn LIMBS_shl_mod(r: *mut limb::Limb, a: *const limb::Limb,
                     m: *const limb::Limb, num_limbs: c::size_t);
}

#[cfg(feature = "rsa_signing")]
extern {
    // The use of references here implies lack of aliasing.
    fn GFp_BN_copy(a: &mut BIGNUM, b: &BIGNUM) -> c::int;

    fn GFp_bn_from_montgomery_in_place(r: *mut limb::Limb, num_r: c::size_t,
                                       a: *mut limb::Limb, num_a: c::size_t,
                                       n: *const limb::Limb, num_n: c::size_t,
                                       n0: &N0) -> c::int;

    // `r` and `a` may alias.
    fn GFp_BN_mod_exp_mont_consttime(r: *mut limb::Limb,
                                     a_mont: *const limb::Limb,
                                     p: *const limb::Limb,
                                     one_mont: *const limb::Limb,
                                     n: *const limb::Limb,
                                     num_limbs: c::size_t, n0: &N0) -> c::int;

    // `r` and `a` may alias.
    fn LIMBS_add_mod(r: *mut limb::Limb, a: *const limb::Limb,
                     b: *const limb::Limb, m: *const limb::Limb,
                     num_limbs: c::size_t);
    fn LIMBS_sub_mod(r: *mut limb::Limb, a: *const limb::Limb,
                     b: *const limb::Limb, m: *const limb::Limb,
                     num_limbs: c::size_t);

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

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_positive_integer_from_be_bytes_empty() {
        // Empty values are rejected.
        assert!(Positive::from_be_bytes(
                    untrusted::Input::from(&[])).is_err());
    }

    #[cfg(feature = "rsa_signing")]
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

    #[cfg(feature = "rsa_signing")]
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
            let e = {
                let bytes = test_case.consume_bytes("E");
                PrivateExponent::from_be_bytes_padded(
                    untrusted::Input::from(&bytes), &m).expect("valid exponent")
            };
            let base = into_encoded(base, &m);
            let oneRR = One::newRR(&m);
            let one = One::newR(&oneRR, &m);
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
            let actual_result = elem_exp_vartime(base, e, &m);
            let actual_result = actual_result.into_unencoded(&m);
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
            let actual_result = elem_mul(&m.one(), actual_result, &m);
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
            let mut actual_result = n.zero();
            assert!(elem_set_to_inverse_blinded(&mut actual_result, &a, &n,
                                                &rng).is_ok());
            let actual_result = elem_mul(&n.one(), actual_result, &n);
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
            let mut actual_result = n.zero();
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
            let actual_result = elem_mul(&a, b, &m);
            let actual_result = actual_result.into_unencoded(&m);
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
            let actual_result = elem_squared(a, &m);
            let actual_result = actual_result.into_unencoded(&m);
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
            let a = consume_elem_unchecked::<MM>(
                test_case, "A", expected_result.limbs.len() * 2);

            let actual_result = elem_reduced(&a, &m).unwrap();
            let oneRR = One::newRR(&m);
            let actual_result = elem_mul(oneRR.as_ref(), actual_result, &m);
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

            let actual_result = elem_reduced_once(&a, &qq);
            assert_elem_eq(&actual_result, &expected_result);

            Ok(())
        })
    }

    fn consume_elem<M>(test_case: &mut test::TestCase, name: &str, m: &Modulus<M>)
                       -> Elem<M, Unencoded> {
        let value = test_case.consume_bytes(name);
        Elem::from_be_bytes_padded(untrusted::Input::from(&value), m).unwrap()
    }

    #[cfg(feature = "rsa_signing")]
    fn consume_elem_unchecked<M>(test_case: &mut test::TestCase, name: &str,
                                 num_limbs: usize) -> Elem<M, Unencoded> {
        let value = consume_nonnegative(test_case, name);
        let mut limbs = BoxedLimbs::zero(Width { num_limbs, m: PhantomData });
        limbs[0..value.limbs().len()].copy_from_slice(value.limbs());
        Elem {
            limbs,
            encoding: PhantomData,
        }
    }

    fn consume_modulus<M>(test_case: &mut test::TestCase, name: &str)
                          -> Modulus<M> {
        let value = test_case.consume_bytes(name);
        let (value, _) = Modulus::from_be_bytes_with_bit_length(
            untrusted::Input::from(&value)).unwrap();
        value
    }

    fn consume_public_exponent(test_case: &mut test::TestCase, name: &str)
                               -> PublicExponent {
        let bytes = test_case.consume_bytes(name);
        PublicExponent::from_be_bytes(
            untrusted::Input::from(&bytes), 3).unwrap()
    }

    #[cfg(feature = "rsa_signing")]
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
        let oneRR = One::newRR(&m);
        elem_mul(&oneRR.as_ref(), a, m)
    }
}
