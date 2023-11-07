// Copyright 2015-2023 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
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
//! the "unit" pattern described in [Static checking of units in Servo].
//!
//! `Elem` also uses the static unit checking pattern to statically track the
//! Montgomery factors that need to be canceled out in each value using it's
//! `E` parameter.
//!
//! [Static checking of units in Servo]:
//!     https://blog.mozilla.org/research/2014/06/23/static-checking-of-units-in-servo/

use self::boxed_limbs::BoxedLimbs;
pub(crate) use self::{
    modulus::{Modulus, OwnedModulusWithOne, MODULUS_MAX_LIMBS},
    private_exponent::PrivateExponent,
};
use super::n0::N0;
pub(crate) use super::nonnegative::Nonnegative;
use crate::{
    arithmetic::montgomery::*,
    c, cpu, error,
    limb::{self, Limb, LimbMask, LIMB_BITS},
    polyfill::u64_from_usize,
};
use alloc::vec;
use core::{marker::PhantomData, num::NonZeroU64};

mod boxed_limbs;
mod modulus;
mod private_exponent;

/// A prime modulus.
///
/// # Safety
///
/// Some logic may assume a `Prime` number is non-zero, and thus a non-empty
/// array of limbs, or make similar assumptions. TODO: Any such logic should
/// be encapsulated here, or this trait should be made non-`unsafe`. TODO:
/// non-zero-ness and non-empty-ness should be factored out into a separate
/// trait. (In retrospect, this shouldn't have been made an `unsafe` trait
/// preemptively.)
pub unsafe trait Prime {}

/// A modulus *s* that is smaller than another modulus *l* so every element of
/// ℤ/sℤ is also an element of ℤ/lℤ.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value, e.g. by assuming the larger modulus has at least as many limbs.
/// TODO: Any such logic should be encapsulated here, or this trait should be
/// made non-`unsafe`. (In retrospect, this shouldn't have been made an `unsafe`
/// trait preemptively.)
pub unsafe trait SmallerModulus<L> {}

/// A modulus *s* where s < l < 2*s for the given larger modulus *l*. This is
/// the precondition for reduction by conditional subtraction,
/// `elem_reduce_once()`.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value, e.g. by assuming that the smaller modulus is at most one limb
/// smaller than the larger modulus. TODO: Any such logic should be
/// encapsulated here, or this trait should be made non-`unsafe`. (In retrospect,
/// this shouldn't have been made an `unsafe` trait preemptively.)
pub unsafe trait SlightlySmallerModulus<L>: SmallerModulus<L> {}

/// A modulus *s* where √l <= s < l for the given larger modulus *l*. This is
/// the precondition for the more general Montgomery reduction from ℤ/lℤ to
/// ℤ/sℤ.
///
/// # Safety
///
/// Some logic may assume that the invariant holds when accessing limbs within
/// a value. TODO: Any such logic should be encapsulated here, or this trait
/// should be made non-`unsafe`. (In retrospect, this shouldn't have been made
/// an `unsafe` trait preemptively.)
pub unsafe trait NotMuchSmallerModulus<L>: SmallerModulus<L> {}

pub trait PublicModulus {}

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
        Self {
            limbs: self.limbs.clone(),
            encoding: self.encoding,
        }
    }
}

impl<M, E> Elem<M, E> {
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_zero()
    }
}

/// Does a Montgomery reduction on `limbs` assuming they are Montgomery-encoded ('R') and assuming
/// they are the same size as `m`, but perhaps not reduced mod `m`. The result will be
/// fully reduced mod `m`.
fn from_montgomery_amm<M>(limbs: BoxedLimbs<M>, m: &Modulus<M>) -> Elem<M, Unencoded> {
    debug_assert_eq!(limbs.len(), m.limbs().len());

    let mut limbs = limbs;
    let mut one = [0; MODULUS_MAX_LIMBS];
    one[0] = 1;
    let one = &one[..m.limbs().len()];
    limbs_mont_mul(&mut limbs, one, m.limbs(), m.n0(), m.cpu_features());
    Elem {
        limbs,
        encoding: PhantomData,
    }
}

#[cfg(any(test, not(target_arch = "x86_64")))]
impl<M> Elem<M, R> {
    #[inline]
    pub fn into_unencoded(self, m: &Modulus<M>) -> Elem<M, Unencoded> {
        from_montgomery_amm(self.limbs, m)
    }
}

impl<M> Elem<M, Unencoded> {
    pub fn from_be_bytes_padded(
        input: untrusted::Input,
        m: &Modulus<M>,
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            limbs: BoxedLimbs::from_be_bytes_padded_less_than(input, m)?,
            encoding: PhantomData,
        })
    }

    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        // See Falko Strenzke, "Manger's Attack revisited", ICICS 2010.
        limb::big_endian_from_limbs(&self.limbs, out)
    }

    fn is_one(&self) -> bool {
        limb::limbs_equal_limb_constant_time(&self.limbs, 1) == LimbMask::True
    }
}

pub fn elem_mul<M, AF, BF>(
    a: &Elem<M, AF>,
    mut b: Elem<M, BF>,
    m: &Modulus<M>,
) -> Elem<M, <(AF, BF) as ProductEncoding>::Output>
where
    (AF, BF): ProductEncoding,
{
    limbs_mont_mul(&mut b.limbs, &a.limbs, m.limbs(), m.n0(), m.cpu_features());
    Elem {
        limbs: b.limbs,
        encoding: PhantomData,
    }
}

fn elem_mul_by_2<M, AF>(a: &mut Elem<M, AF>, m: &Modulus<M>) {
    prefixed_extern! {
        fn LIMBS_shl_mod(r: *mut Limb, a: *const Limb, m: *const Limb, num_limbs: c::size_t);
    }
    unsafe {
        LIMBS_shl_mod(
            a.limbs.as_mut_ptr(),
            a.limbs.as_ptr(),
            m.limbs().as_ptr(),
            m.limbs().len(),
        );
    }
}

pub fn elem_reduced_once<Larger, Smaller: SlightlySmallerModulus<Larger>>(
    a: &Elem<Larger, Unencoded>,
    m: &Modulus<Smaller>,
) -> Elem<Smaller, Unencoded> {
    let mut r = a.limbs.clone();
    assert!(r.len() <= m.limbs().len());
    limb::limbs_reduce_once_constant_time(&mut r, m.limbs());
    Elem {
        limbs: BoxedLimbs::new_unchecked(r.into_limbs()),
        encoding: PhantomData,
    }
}

#[inline]
pub fn elem_reduced<Larger, Smaller: NotMuchSmallerModulus<Larger>>(
    a: &Elem<Larger, Unencoded>,
    m: &Modulus<Smaller>,
) -> Elem<Smaller, RInverse> {
    let mut tmp = [0; MODULUS_MAX_LIMBS];
    let tmp = &mut tmp[..a.limbs.len()];
    tmp.copy_from_slice(&a.limbs);

    let mut r = m.zero();
    limbs_from_mont_in_place(&mut r.limbs, tmp, m.limbs(), m.n0());
    r
}

fn elem_squared<M, E>(
    mut a: Elem<M, E>,
    m: &Modulus<M>,
) -> Elem<M, <(E, E) as ProductEncoding>::Output>
where
    (E, E): ProductEncoding,
{
    limbs_mont_square(&mut a.limbs, m.limbs(), m.n0(), m.cpu_features());
    Elem {
        limbs: a.limbs,
        encoding: PhantomData,
    }
}

pub fn elem_widen<Larger, Smaller: SmallerModulus<Larger>>(
    a: Elem<Smaller, Unencoded>,
    m: &Modulus<Larger>,
) -> Elem<Larger, Unencoded> {
    let mut r = m.zero();
    r.limbs[..a.limbs.len()].copy_from_slice(&a.limbs);
    r
}

// TODO: Document why this works for all Montgomery factors.
pub fn elem_add<M, E>(mut a: Elem<M, E>, b: Elem<M, E>, m: &Modulus<M>) -> Elem<M, E> {
    limb::limbs_add_assign_mod(&mut a.limbs, &b.limbs, m.limbs());
    a
}

// TODO: Document why this works for all Montgomery factors.
pub fn elem_sub<M, E>(mut a: Elem<M, E>, b: &Elem<M, E>, m: &Modulus<M>) -> Elem<M, E> {
    prefixed_extern! {
        // `r` and `a` may alias.
        fn LIMBS_sub_mod(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            m: *const Limb,
            num_limbs: c::size_t,
        );
    }
    unsafe {
        LIMBS_sub_mod(
            a.limbs.as_mut_ptr(),
            a.limbs.as_ptr(),
            b.limbs.as_ptr(),
            m.limbs().as_ptr(),
            m.limbs().len(),
        );
    }
    a
}

// The value 1, Montgomery-encoded some number of times.
pub struct One<M, E>(Elem<M, E>);

impl<M> One<M, RR> {
    // Returns RR = = R**2 (mod n) where R = 2**r is the smallest power of
    // 2**LIMB_BITS such that R > m.
    //
    // Even though the assembly on some 32-bit platforms works with 64-bit
    // values, using `LIMB_BITS` here, rather than `N0::LIMBS_USED * LIMB_BITS`,
    // is correct because R**2 will still be a multiple of the latter as
    // `N0::LIMBS_USED` is either one or two.
    fn newRR(m: &Modulus<M>) -> Self {
        let m_bits = m.len_bits().as_usize_bits();
        let r = (m_bits + (LIMB_BITS - 1)) / LIMB_BITS * LIMB_BITS;

        // base = 2**(lg m - 1).
        let bit = m_bits - 1;
        let mut base = m.zero();
        base.limbs[bit / LIMB_BITS] = 1 << (bit % LIMB_BITS);

        // Double `base` so that base == R == 2**r (mod m). For normal moduli
        // that have the high bit of the highest limb set, this requires one
        // doubling. Unusual moduli require more doublings but we are less
        // concerned about the performance of those.
        //
        // Then double `base` again so that base == 2*R (mod n), i.e. `2` in
        // Montgomery form (`elem_exp_vartime()` requires the base to be in
        // Montgomery form). Then compute
        // RR = R**2 == base**r == R**r == (2**r)**r (mod n).
        //
        // Take advantage of the fact that `elem_mul_by_2` is faster than
        // `elem_squared` by replacing some of the early squarings with shifts.
        // TODO: Benchmark shift vs. squaring performance to determine the
        // optimal value of `LG_BASE`.
        const LG_BASE: usize = 2; // Shifts vs. squaring trade-off.
        debug_assert_eq!(LG_BASE.count_ones(), 1); // Must be 2**n for n >= 0.
        let shifts = r - bit + LG_BASE;
        // `m_bits >= LG_BASE` (for the currently chosen value of `LG_BASE`)
        // since we require the modulus to have at least `MODULUS_MIN_LIMBS`
        // limbs. `r >= m_bits` as seen above. So `r >= LG_BASE` and thus
        // `r / LG_BASE` is non-zero.
        //
        // The maximum value of `r` is determined by
        // `MODULUS_MAX_LIMBS * LIMB_BITS`. Further `r` is a multiple of
        // `LIMB_BITS` so the maximum Hamming Weight is bounded by
        // `MODULUS_MAX_LIMBS`. For the common case of {2048, 4096, 8192}-bit
        // moduli the Hamming weight is 1. For the other common case of 3072
        // the Hamming weight is 2.
        let exponent = NonZeroU64::new(u64_from_usize(r / LG_BASE)).unwrap();
        for _ in 0..shifts {
            elem_mul_by_2(&mut base, m)
        }
        let RR = elem_exp_vartime(base, exponent, m);

        Self(Elem {
            limbs: RR.limbs,
            encoding: PhantomData, // PhantomData<RR>
        })
    }
}

impl<M, E> AsRef<Elem<M, E>> for One<M, E> {
    fn as_ref(&self) -> &Elem<M, E> {
        &self.0
    }
}

impl<M: PublicModulus, E> Clone for One<M, E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Calculates base**exponent (mod m).
///
/// The run time  is a function of the number of limbs in `m` and the bit
/// length and Hamming Weight of `exponent`. The bounds on `m` are pretty
/// obvious but the bounds on `exponent` are less obvious. Callers should
/// document the bounds they place on the maximum value and maximum Hamming
/// weight of `exponent`.
// TODO: The test coverage needs to be expanded, e.g. test with the largest
// accepted exponent and with the most common values of 65537 and 3.
pub(crate) fn elem_exp_vartime<M>(
    base: Elem<M, R>,
    exponent: NonZeroU64,
    m: &Modulus<M>,
) -> Elem<M, R> {
    // Use what [Knuth] calls the "S-and-X binary method", i.e. variable-time
    // square-and-multiply that scans the exponent from the most significant
    // bit to the least significant bit (left-to-right). Left-to-right requires
    // less storage compared to right-to-left scanning, at the cost of needing
    // to compute `exponent.leading_zeros()`, which we assume to be cheap.
    //
    // As explained in [Knuth], exponentiation by squaring is the most
    // efficient algorithm when the Hamming weight is 2 or less. It isn't the
    // most efficient for all other, uncommon, exponent values but any
    // suboptimality is bounded at least by the small bit length of `exponent`
    // as enforced by its type.
    //
    // This implementation is slightly simplified by taking advantage of the
    // fact that we require the exponent to be a positive integer.
    //
    // [Knuth]: The Art of Computer Programming, Volume 2: Seminumerical
    //          Algorithms (3rd Edition), Section 4.6.3.
    let exponent = exponent.get();
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

/// Uses Fermat's Little Theorem to calculate modular inverse in constant time.
pub fn elem_inverse_consttime<M: Prime>(
    a: Elem<M, R>,
    m: &OwnedModulusWithOne<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    elem_exp_consttime(a, &PrivateExponent::for_flt(&m.modulus()), m)
}

#[cfg(not(target_arch = "x86_64"))]
pub fn elem_exp_consttime<M>(
    base: Elem<M, R>,
    exponent: &PrivateExponent,
    m: &OwnedModulusWithOne<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    let oneRR = m.oneRR();
    let m = &m.modulus();

    use crate::{bssl, limb::Window};

    const WINDOW_BITS: usize = 5;
    const TABLE_ENTRIES: usize = 1 << WINDOW_BITS;

    let num_limbs = m.limbs().len();

    let mut table = vec![0; TABLE_ENTRIES * num_limbs];

    fn gather<M>(table: &[Limb], acc: &mut Elem<M, R>, i: Window) {
        prefixed_extern! {
            fn LIMBS_select_512_32(
                r: *mut Limb,
                table: *const Limb,
                num_limbs: c::size_t,
                i: Window,
            ) -> bssl::Result;
        }
        Result::from(unsafe {
            LIMBS_select_512_32(acc.limbs.as_mut_ptr(), table.as_ptr(), acc.limbs.len(), i)
        })
        .unwrap();
    }

    fn power<M>(
        table: &[Limb],
        mut acc: Elem<M, R>,
        m: &Modulus<M>,
        i: Window,
        mut tmp: Elem<M, R>,
    ) -> (Elem<M, R>, Elem<M, R>) {
        for _ in 0..WINDOW_BITS {
            acc = elem_squared(acc, m);
        }
        gather(table, &mut tmp, i);
        let acc = elem_mul(&tmp, acc, m);
        (acc, tmp)
    }

    fn entry(table: &[Limb], i: usize, num_limbs: usize) -> &[Limb] {
        &table[(i * num_limbs)..][..num_limbs]
    }
    fn entry_mut(table: &mut [Limb], i: usize, num_limbs: usize) -> &mut [Limb] {
        &mut table[(i * num_limbs)..][..num_limbs]
    }

    // table[0] = base**0 (i.e. 1).
    {
        let acc = entry_mut(&mut table, 0, num_limbs);
        // `table` was initialized to zero and hasn't changed.
        debug_assert!(acc.iter().all(|&value| value == 0));
        acc[0] = 1;
        limbs_mont_mul(acc, &oneRR.0.limbs, m.limbs(), m.n0(), m.cpu_features());
    }

    entry_mut(&mut table, 1, num_limbs).copy_from_slice(&base.limbs);
    for i in 2..TABLE_ENTRIES {
        let (src1, src2) = if i % 2 == 0 {
            (i / 2, i / 2)
        } else {
            (i - 1, 1)
        };
        let (previous, rest) = table.split_at_mut(num_limbs * i);
        let src1 = entry(previous, src1, num_limbs);
        let src2 = entry(previous, src2, num_limbs);
        let dst = entry_mut(rest, 0, num_limbs);
        limbs_mont_product(dst, src1, src2, m.limbs(), m.n0(), m.cpu_features());
    }

    let tmp = m.zero();
    let mut acc = Elem {
        limbs: base.limbs,
        encoding: PhantomData,
    };
    let (acc, _) = limb::fold_5_bit_windows(
        exponent.limbs(),
        |initial_window| {
            gather(&table, &mut acc, initial_window);
            (acc, tmp)
        },
        |(acc, tmp), window| power(&table, acc, m, window, tmp),
    );

    Ok(acc.into_unencoded(m))
}

#[cfg(target_arch = "x86_64")]
pub fn elem_exp_consttime<M>(
    base: Elem<M, R>,
    exponent: &PrivateExponent,
    m: &OwnedModulusWithOne<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    use crate::limb::LIMB_BYTES;

    let oneRR = m.oneRR();
    let m = &m.modulus();

    // Pretty much all the math here requires CPU feature detection to have
    // been done. `cpu_features` isn't threaded through all the internal
    // functions, so just make it clear that it has been done at this point.
    let cpu_features = m.cpu_features();

    // The x86_64 assembly was written under the assumption that the input data
    // is aligned to `MOD_EXP_CTIME_ALIGN` bytes, which was/is 64 in OpenSSL.
    // Similarly, OpenSSL uses the x86_64 assembly functions by giving it only
    // inputs `tmp`, `am`, and `np` that immediately follow the table. All the
    // awkwardness here stems from trying to use the assembly code like OpenSSL
    // does.

    use crate::limb::Window;

    const WINDOW_BITS: usize = 5;
    const TABLE_ENTRIES: usize = 1 << WINDOW_BITS;

    let num_limbs = m.limbs().len();

    const ALIGNMENT: usize = 64;
    assert_eq!(ALIGNMENT % LIMB_BYTES, 0);
    let mut table = vec![0; ((TABLE_ENTRIES + 3) * num_limbs) + ALIGNMENT];
    let (table, state) = {
        let misalignment = (table.as_ptr() as usize) % ALIGNMENT;
        let table = &mut table[((ALIGNMENT - misalignment) / LIMB_BYTES)..];
        assert_eq!((table.as_ptr() as usize) % ALIGNMENT, 0);
        table.split_at_mut(TABLE_ENTRIES * num_limbs)
    };

    fn scatter(table: &mut [Limb], acc: &[Limb], i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_scatter5(a: *const Limb, a_len: c::size_t, table: *mut Limb, i: Window);
        }
        unsafe { bn_scatter5(acc.as_ptr(), num_limbs, table.as_mut_ptr(), i) }
    }

    fn gather(table: &[Limb], acc: &mut [Limb], i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_gather5(r: *mut Limb, a_len: c::size_t, table: *const Limb, i: Window);
        }
        unsafe { bn_gather5(acc.as_mut_ptr(), num_limbs, table.as_ptr(), i) }
    }

    fn limbs_mul_mont_gather5_amm(
        table: &[Limb],
        acc: &mut [Limb],
        base: &[Limb],
        m: &[Limb],
        n0: &N0,
        i: Window,
        num_limbs: usize,
    ) {
        prefixed_extern! {
            fn bn_mul_mont_gather5(
                rp: *mut Limb,
                ap: *const Limb,
                table: *const Limb,
                np: *const Limb,
                n0: &N0,
                num: c::size_t,
                power: Window,
            );
        }
        unsafe {
            bn_mul_mont_gather5(
                acc.as_mut_ptr(),
                base.as_ptr(),
                table.as_ptr(),
                m.as_ptr(),
                n0,
                num_limbs,
                i,
            );
        }
    }

    fn power_amm(
        table: &[Limb],
        acc: &mut [Limb],
        m_cached: &[Limb],
        n0: &N0,
        i: Window,
        num_limbs: usize,
    ) {
        prefixed_extern! {
            fn bn_power5(
                r: *mut Limb,
                a: *const Limb,
                table: *const Limb,
                n: *const Limb,
                n0: &N0,
                num: c::size_t,
                i: Window,
            );
        }
        unsafe {
            bn_power5(
                acc.as_mut_ptr(),
                acc.as_ptr(),
                table.as_ptr(),
                m_cached.as_ptr(),
                n0,
                num_limbs,
                i,
            );
        }
    }

    // These are named `(tmp, am, np)` in BoringSSL.
    let (acc, base_cached, m_cached): (&mut [Limb], &[Limb], &[Limb]) = {
        let (acc, rest) = state.split_at_mut(num_limbs);
        let (base_cached, rest) = rest.split_at_mut(num_limbs);

        // Upstream, the input `base` is not Montgomery-encoded, so they compute a
        // Montgomery-encoded copy and store it here.
        base_cached.copy_from_slice(&base.limbs);

        let m_cached = &mut rest[..num_limbs];
        // "To improve cache locality" according to upstream.
        m_cached.copy_from_slice(m.limbs());

        (acc, base_cached, m_cached)
    };

    let n0 = m.n0();

    // Fill in all the powers of 2 of `acc` into the table using only squaring and without any
    // gathering, storing the last calculated power into `acc`.
    fn scatter_powers_of_2(
        table: &mut [Limb],
        acc: &mut [Limb],
        m_cached: &[Limb],
        n0: &N0,
        mut i: Window,
        num_limbs: usize,
        cpu_features: cpu::Features,
    ) {
        loop {
            scatter(table, acc, i, num_limbs);
            i *= 2;
            if i >= (TABLE_ENTRIES as Window) {
                break;
            }
            limbs_mont_square(acc, m_cached, n0, cpu_features);
        }
    }

    // All entries in `table` will be Montgomery encoded.

    // acc = table[0] = base**0 (i.e. 1).
    // `acc` was initialized to zero and hasn't changed. Change it to 1 and then Montgomery
    // encode it.
    debug_assert!(acc.iter().all(|&value| value == 0));
    acc[0] = 1;
    limbs_mont_mul(acc, &oneRR.0.limbs, m_cached, n0, cpu_features);
    scatter(table, acc, 0, num_limbs);

    // acc = base**1 (i.e. base).
    acc.copy_from_slice(base_cached);

    // Fill in entries 1, 2, 4, 8, 16.
    scatter_powers_of_2(table, acc, m_cached, n0, 1, num_limbs, cpu_features);
    // Fill in entries 3, 6, 12, 24; 5, 10, 20, 30; 7, 14, 28; 9, 18; 11, 22; 13, 26; 15, 30;
    // 17; 19; 21; 23; 25; 27; 29; 31.
    for i in (3..(TABLE_ENTRIES as Window)).step_by(2) {
        limbs_mul_mont_gather5_amm(table, acc, base_cached, m_cached, n0, i - 1, num_limbs);
        scatter_powers_of_2(table, acc, m_cached, n0, i, num_limbs, cpu_features);
    }

    let acc = limb::fold_5_bit_windows(
        exponent.limbs(),
        |initial_window| {
            gather(table, acc, initial_window, num_limbs);
            acc
        },
        |acc, window| {
            power_amm(table, acc, m_cached, n0, window, num_limbs);
            acc
        },
    );

    let mut r_amm = base.limbs;
    r_amm.copy_from_slice(acc);

    Ok(from_montgomery_amm(r_amm, m))
}

/// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
pub fn verify_inverses_consttime<M>(
    a: &Elem<M, R>,
    b: Elem<M, Unencoded>,
    m: &Modulus<M>,
) -> Result<(), error::Unspecified> {
    if elem_mul(a, b, m).is_one() {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

#[inline]
pub fn elem_verify_equal_consttime<M, E>(
    a: &Elem<M, E>,
    b: &Elem<M, E>,
) -> Result<(), error::Unspecified> {
    if limb::limbs_equal_limbs_consttime(&a.limbs, &b.limbs) == LimbMask::True {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

// TODO: Move these methods from `Nonnegative` to `Modulus`.
impl Nonnegative {
    pub fn verify_less_than_modulus<M>(&self, m: &Modulus<M>) -> Result<(), error::Unspecified> {
        if self.limbs().len() > m.limbs().len() {
            return Err(error::Unspecified);
        }
        if self.limbs().len() == m.limbs().len() {
            if limb::limbs_less_than_limbs_consttime(self.limbs(), m.limbs()) != LimbMask::True {
                return Err(error::Unspecified);
            }
        }
        Ok(())
    }
}

/// r *= a
fn limbs_mont_mul(r: &mut [Limb], a: &[Limb], m: &[Limb], n0: &N0, _cpu_features: cpu::Features) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            a.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

/// r = a * b
#[cfg(not(target_arch = "x86_64"))]
fn limbs_mont_product(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    m: &[Limb],
    n0: &N0,
    _cpu_features: cpu::Features,
) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    debug_assert_eq!(b.len(), m.len());

    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

/// r = r**2
fn limbs_mont_square(r: &mut [Limb], m: &[Limb], n0: &N0, _cpu_features: cpu::Features) {
    debug_assert_eq!(r.len(), m.len());
    unsafe {
        bn_mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            r.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
        )
    }
}

prefixed_extern! {
    // `r` and/or 'a' and/or 'b' may alias.
    fn bn_mul_mont(
        r: *mut Limb,
        a: *const Limb,
        b: *const Limb,
        n: *const Limb,
        n0: &N0,
        num_limbs: c::size_t,
    );
}

#[cfg(test)]
mod tests {
    use super::{modulus::MODULUS_MIN_LIMBS, *};
    use crate::{limb::LIMB_BYTES, test};
    use alloc::format;

    // Type-level representation of an arbitrary modulus.
    struct M {}

    impl PublicModulus for M {}

    #[test]
    fn test_elem_exp_consttime() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("../../crypto/fipsmodule/bn/test/mod_exp_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m_ = consume_modulus::<M>(test_case, "M", cpu_features);
                let m = m_.modulus();
                let expected_result = consume_elem(test_case, "ModExp", &m);
                let base = consume_elem(test_case, "A", &m);
                let e = {
                    let bytes = test_case.consume_bytes("E");
                    PrivateExponent::from_be_bytes_for_test_only(untrusted::Input::from(&bytes), &m)
                        .expect("valid exponent")
                };
                let base = into_encoded(base, &m_);
                let actual_result = elem_exp_consttime(base, &e, &m_).unwrap();
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    // TODO: fn test_elem_exp_vartime() using
    // "src/rsa/bigint_elem_exp_vartime_tests.txt". See that file for details.
    // In the meantime, the function is tested indirectly via the RSA
    // verification and signing tests.
    #[test]
    fn test_elem_mul() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("../../crypto/fipsmodule/bn/test/mod_mul_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m_ = consume_modulus::<M>(test_case, "M", cpu_features);
                let m = m_.modulus();
                let expected_result = consume_elem(test_case, "ModMul", &m);
                let a = consume_elem(test_case, "A", &m);
                let b = consume_elem(test_case, "B", &m);

                let b = into_encoded(b, &m_);
                let a = into_encoded(a, &m_);
                let actual_result = elem_mul(&a, b, &m);
                let actual_result = actual_result.into_unencoded(&m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_squared() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_squared_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m_ = consume_modulus::<M>(test_case, "M", cpu_features);
                let m = m_.modulus();
                let expected_result = consume_elem(test_case, "ModSquare", &m);
                let a = consume_elem(test_case, "A", &m);

                let a = into_encoded(a, &m_);
                let actual_result = elem_squared(a, &m);
                let actual_result = actual_result.into_unencoded(&m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_reduced_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct MM {}
                unsafe impl SmallerModulus<MM> for M {}
                unsafe impl NotMuchSmallerModulus<MM> for M {}

                let m_ = consume_modulus::<M>(test_case, "M", cpu_features);
                let m = m_.modulus();
                let expected_result = consume_elem(test_case, "R", &m);
                let a =
                    consume_elem_unchecked::<MM>(test_case, "A", expected_result.limbs.len() * 2);

                let actual_result = elem_reduced(&a, &m);
                let oneRR = m_.oneRR();
                let actual_result = elem_mul(oneRR.as_ref(), actual_result, &m);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_elem_reduced_once() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_reduced_once_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                struct N {}
                struct QQ {}
                unsafe impl SmallerModulus<N> for QQ {}
                unsafe impl SlightlySmallerModulus<N> for QQ {}

                let qq = consume_modulus::<QQ>(test_case, "QQ", cpu_features);
                let expected_result = consume_elem::<QQ>(test_case, "R", &qq.modulus());
                let n = consume_modulus::<N>(test_case, "N", cpu_features);
                let a = consume_elem::<N>(test_case, "A", &n.modulus());

                let actual_result = elem_reduced_once(&a, &qq.modulus());
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }

    #[test]
    fn test_modulus_debug() {
        let modulus = OwnedModulusWithOne::<M>::from_be_bytes(
            untrusted::Input::from(&[0xff; LIMB_BYTES * MODULUS_MIN_LIMBS]),
            cpu::features(),
        )
        .unwrap();
        assert_eq!("Modulus", format!("{:?}", modulus));
    }

    fn consume_elem<M>(
        test_case: &mut test::TestCase,
        name: &str,
        m: &Modulus<M>,
    ) -> Elem<M, Unencoded> {
        let value = test_case.consume_bytes(name);
        Elem::from_be_bytes_padded(untrusted::Input::from(&value), m).unwrap()
    }

    fn consume_elem_unchecked<M>(
        test_case: &mut test::TestCase,
        name: &str,
        num_limbs: usize,
    ) -> Elem<M, Unencoded> {
        let value = consume_nonnegative(test_case, name);
        let mut limbs = BoxedLimbs::zero(num_limbs);
        limbs[0..value.limbs().len()].copy_from_slice(value.limbs());
        Elem {
            limbs,
            encoding: PhantomData,
        }
    }

    fn consume_modulus<M>(
        test_case: &mut test::TestCase,
        name: &str,
        cpu_features: cpu::Features,
    ) -> OwnedModulusWithOne<M> {
        let value = test_case.consume_bytes(name);
        OwnedModulusWithOne::from_be_bytes(untrusted::Input::from(&value), cpu_features).unwrap()
    }

    fn consume_nonnegative(test_case: &mut test::TestCase, name: &str) -> Nonnegative {
        let bytes = test_case.consume_bytes(name);
        let (r, _r_bits) =
            Nonnegative::from_be_bytes_with_bit_length(untrusted::Input::from(&bytes)).unwrap();
        r
    }

    fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        if elem_verify_equal_consttime(a, b).is_err() {
            panic!("{:x?} != {:x?}", &*a.limbs, &*b.limbs);
        }
    }

    fn into_encoded<M>(a: Elem<M, Unencoded>, m: &OwnedModulusWithOne<M>) -> Elem<M, R> {
        elem_mul(m.oneRR().as_ref(), a, &m.modulus())
    }
}
