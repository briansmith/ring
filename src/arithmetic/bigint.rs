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
    modulus::{Modulus, OwnedModulus, MODULUS_MAX_LIMBS},
    private_exponent::PrivateExponent,
};
use crate::{
    arithmetic::montgomery::*,
    bits::BitLength,
    c, error,
    limb::{self, Limb, LimbMask, LIMB_BITS},
};
use alloc::vec;
use core::{marker::PhantomData, num::NonZeroU64};

mod boxed_limbs;
mod modulus;
mod private_exponent;

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

// r *= 2.
fn elem_double<M, AF>(r: &mut Elem<M, AF>, m: &Modulus<M>) {
    limb::limbs_double_mod(&mut r.limbs, m.limbs())
}

// TODO: This is currently unused, but we intend to eventually use this to
// reduce elements (x mod q) mod p in the RSA CRT. If/when we do so, we
// should update the testing so it is reflective of that usage, instead of
// the old usage.
pub fn elem_reduced_once<A, M>(
    a: &Elem<A, Unencoded>,
    m: &Modulus<M>,
    other_modulus_len_bits: BitLength,
) -> Elem<M, Unencoded> {
    assert_eq!(m.len_bits(), other_modulus_len_bits);

    let mut r = a.limbs.clone();
    limb::limbs_reduce_once_constant_time(&mut r, m.limbs());
    Elem {
        limbs: BoxedLimbs::new_unchecked(r.into_limbs()),
        encoding: PhantomData,
    }
}

#[inline]
pub fn elem_reduced<Larger, Smaller>(
    a: &Elem<Larger, Unencoded>,
    m: &Modulus<Smaller>,
    other_prime_len_bits: BitLength,
) -> Elem<Smaller, RInverse> {
    // This is stricter than required mathematically but this is what we
    // guarantee and this is easier to check. The real requirement is that
    // that `a < m*R` where `R` is the Montgomery `R` for `m`.
    assert_eq!(other_prime_len_bits, m.len_bits());

    // `limbs_from_mont_in_place` requires this.
    assert_eq!(a.limbs.len(), m.limbs().len() * 2);

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

pub fn elem_widen<Larger, Smaller>(
    a: Elem<Smaller, Unencoded>,
    m: &Modulus<Larger>,
    smaller_modulus_bits: BitLength,
) -> Result<Elem<Larger, Unencoded>, error::Unspecified> {
    if smaller_modulus_bits >= m.len_bits() {
        return Err(error::Unspecified);
    }
    let mut r = m.zero();
    r.limbs[..a.limbs.len()].copy_from_slice(&a.limbs);
    Ok(r)
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
    pub(crate) fn newRR(m: &Modulus<M>) -> Self {
        // The number of limbs in the numbers involved.
        let w = m.limbs().len();

        // The length of the numbers involved, in bits. R = 2**r.
        let r = w * LIMB_BITS;

        let mut acc: Elem<M, R> = m.zero();
        m.oneR(&mut acc.limbs);

        // 2**t * R can be calculated by t doublings starting with R.
        //
        // Choose a t that divides r and where t doublings are cheaper than 1 squaring.
        //
        // We could choose other values of t than w. But if t < d then the exponentiation that
        // follows would require multiplications. Normally d is 1 (i.e. the modulus length is a
        // power of two: RSA 1024, 2048, 4097, 8192) or 3 (RSA 1536, 3072).
        //
        // XXX(perf): Currently t = w / 2 is slightly faster. TODO(perf): Optimize `elem_double`
        // and re-run benchmarks to rebalance this.
        let t = w;
        let z = w.trailing_zeros();
        let d = w >> z;
        debug_assert_eq!(w, d * (1 << z));
        debug_assert!(d <= t);
        debug_assert!(t < r);
        for _ in 0..t {
            elem_double(&mut acc, m);
        }

        // Because t | r:
        //
        //     MontExp(2**t * R, r / t)
        //   = (2**t)**(r / t)   * R (mod m) by definition of MontExp.
        //   = (2**t)**(1/t * r) * R (mod m)
        //   = (2**(t * 1/t))**r * R (mod m)
        //   = (2**1)**r         * R (mod m)
        //   = 2**r              * R (mod m)
        //   = R * R                 (mod m)
        //   = RR
        //
        // Like BoringSSL, use t = w (`m.limbs.len()`) which ensures that the exponent is a power
        // of two. Consequently, there will be no multiplications in the Montgomery exponentiation;
        // there will only be lg(r / t) squarings.
        //
        //     lg(r / t)
        //   = lg((w * 2**b) / t)
        //   = lg((t * 2**b) / t)
        //   = lg(2**b)
        //   = b
        // TODO(MSRV:1.67): const B: u32 = LIMB_BITS.ilog2();
        const B: u32 = if cfg!(target_pointer_width = "64") {
            6
        } else if cfg!(target_pointer_width = "32") {
            5
        } else {
            panic!("unsupported target_pointer_width")
        };
        #[allow(clippy::assertions_on_constants)]
        const _LIMB_BITS_IS_2_POW_B: () = assert!(LIMB_BITS == 1 << B);
        debug_assert_eq!(r, t * (1 << B));
        for _ in 0..B {
            acc = elem_squared(acc, m);
        }

        Self(Elem {
            limbs: acc.limbs,
            encoding: PhantomData, // PhantomData<RR>
        })
    }
}

impl<M> One<M, RRR> {
    pub(crate) fn newRRR(One(oneRR): One<M, RR>, m: &Modulus<M>) -> Self {
        Self(elem_squared(oneRR, m))
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

#[cfg(not(target_arch = "x86_64"))]
pub fn elem_exp_consttime<M>(
    base: Elem<M, R>,
    exponent: &PrivateExponent,
    m: &Modulus<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
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
    m.oneR(entry_mut(&mut table, 0, num_limbs));

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
    m: &Modulus<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    use crate::{cpu, limb::LIMB_BYTES};

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
    m.oneR(acc);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cpu, test};

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

                let m = consume_modulus::<M>(test_case, "M");
                let m = m.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModExp", &m);
                let base = consume_elem(test_case, "A", &m);
                let e = {
                    let bytes = test_case.consume_bytes("E");
                    PrivateExponent::from_be_bytes_for_test_only(untrusted::Input::from(&bytes), &m)
                        .expect("valid exponent")
                };
                let base = into_encoded(base, &m);
                let actual_result = elem_exp_consttime(base, &e, &m).unwrap();
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

                let m = consume_modulus::<M>(test_case, "M");
                let m = m.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModMul", &m);
                let a = consume_elem(test_case, "A", &m);
                let b = consume_elem(test_case, "B", &m);

                let b = into_encoded(b, &m);
                let a = into_encoded(a, &m);
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

                let m = consume_modulus::<M>(test_case, "M");
                let m = m.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "ModSquare", &m);
                let a = consume_elem(test_case, "A", &m);

                let a = into_encoded(a, &m);
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

                struct M {}

                let m_ = consume_modulus::<M>(test_case, "M");
                let m = m_.modulus(cpu_features);
                let expected_result = consume_elem(test_case, "R", &m);
                let a =
                    consume_elem_unchecked::<M>(test_case, "A", expected_result.limbs.len() * 2);
                let other_modulus_len_bits = m_.len_bits();

                let actual_result = elem_reduced(&a, &m, other_modulus_len_bits);
                let oneRR = One::newRR(&m);
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

                struct M {}
                struct O {}
                let m = consume_modulus::<M>(test_case, "m");
                let m = m.modulus(cpu_features);
                let a = consume_elem_unchecked::<O>(test_case, "a", m.limbs().len());
                let expected_result = consume_elem::<M>(test_case, "r", &m);
                let other_modulus_len_bits = m.len_bits();

                let actual_result = elem_reduced_once(&a, &m, other_modulus_len_bits);
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
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
        let bytes = test_case.consume_bytes(name);
        let mut limbs = BoxedLimbs::zero(num_limbs);
        limb::parse_big_endian_and_pad_consttime(untrusted::Input::from(&bytes), &mut limbs)
            .unwrap();
        Elem {
            limbs,
            encoding: PhantomData,
        }
    }

    fn consume_modulus<M>(test_case: &mut test::TestCase, name: &str) -> OwnedModulus<M> {
        let value = test_case.consume_bytes(name);
        OwnedModulus::from_be_bytes(untrusted::Input::from(&value)).unwrap()
    }

    fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        if elem_verify_equal_consttime(a, b).is_err() {
            panic!("{:x?} != {:x?}", &*a.limbs, &*b.limbs);
        }
    }

    fn into_encoded<M>(a: Elem<M, Unencoded>, m: &Modulus<M>) -> Elem<M, R> {
        let oneRR = One::newRR(m);
        elem_mul(oneRR.as_ref(), a, m)
    }
}
