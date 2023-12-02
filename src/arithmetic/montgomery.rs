// Copyright 2017-2023 Brian Smith.
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

pub use super::n0::N0;
use crate::cpu;

// Indicates that the element is not encoded; there is no *R* factor
// that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum Unencoded {}

// Indicates that the element is encoded; the value has one *R*
// factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum R {}

// Indicates the element is encoded three times; the value has three
// *R* factors that need to be canceled out.
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub enum RRR {}

// Indicates the element is encoded twice; the value has two *R*
// factors that need to be canceled out.
#[derive(Copy, Clone)]
pub enum RR {}

// Indicates the element is inversely encoded; the value has one
// 1/*R* factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum RInverse {}

pub trait Encoding {}

impl Encoding for RRR {}
impl Encoding for RR {}
impl Encoding for R {}
impl Encoding for Unencoded {}
impl Encoding for RInverse {}

/// The encoding of the result of a reduction.
pub trait ReductionEncoding {
    type Output: Encoding;
}

impl ReductionEncoding for RRR {
    type Output = RR;
}

impl ReductionEncoding for RR {
    type Output = R;
}
impl ReductionEncoding for R {
    type Output = Unencoded;
}
impl ReductionEncoding for Unencoded {
    type Output = RInverse;
}

/// The encoding of the result of a multiplication.
pub trait ProductEncoding {
    type Output: Encoding;
}

impl<E: ReductionEncoding> ProductEncoding for (Unencoded, E) {
    type Output = E::Output;
}

impl<E: Encoding> ProductEncoding for (R, E) {
    type Output = E;
}

impl ProductEncoding for (RR, RR) {
    type Output = RRR;
}

impl<E: ReductionEncoding> ProductEncoding for (RInverse, E)
where
    E::Output: ReductionEncoding,
{
    type Output = <<E as ReductionEncoding>::Output as ReductionEncoding>::Output;
}

// XXX: Rust doesn't allow overlapping impls,
// TODO (if/when Rust allows it):
// impl<E1, E2: ReductionEncoding> ProductEncoding for
//         (E1, E2) {
//     type Output = <(E2, E1) as ProductEncoding>::Output;
// }
impl ProductEncoding for (RR, Unencoded) {
    type Output = <(Unencoded, RR) as ProductEncoding>::Output;
}
impl ProductEncoding for (RR, RInverse) {
    type Output = <(RInverse, RR) as ProductEncoding>::Output;
}

impl ProductEncoding for (RRR, RInverse) {
    type Output = <(RInverse, RRR) as ProductEncoding>::Output;
}

#[allow(unused_imports)]
use crate::{bssl, c, limb::Limb};

#[inline(always)]
unsafe fn mul_mont(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    n: *const Limb,
    n0: &N0,
    num_limbs: c::size_t,
    _: cpu::Features,
) {
    bn_mul_mont(r, a, b, n, n0, num_limbs)
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
// TODO: Stop calling this from C and un-export it.
#[allow(deprecated)]
prefixed_export! {
    unsafe fn bn_mul_mont(
        r: *mut Limb,
        a: *const Limb,
        b: *const Limb,
        n: *const Limb,
        n0: &N0,
        num_limbs: c::size_t,
    ) {
        // The mutable pointer `r` may alias `a` and/or `b`, so the lifetimes of
        // any slices for `a` or `b` must not overlap with the lifetime of any
        // mutable for `r`.

        // Nothing aliases `n`
        let n = unsafe { core::slice::from_raw_parts(n, num_limbs) };

        let mut tmp = [0; 2 * super::BIGINT_MODULUS_MAX_LIMBS];
        let tmp = &mut tmp[..(2 * num_limbs)];
        {
            let a: &[Limb] = unsafe { core::slice::from_raw_parts(a, num_limbs) };
            let b: &[Limb] = unsafe { core::slice::from_raw_parts(b, num_limbs) };
            limbs_mul(tmp, a, b);
        }
        let r: &mut [Limb] = unsafe { core::slice::from_raw_parts_mut(r, num_limbs) };
        limbs_from_mont_in_place(r, tmp, n, n0);
    }
}

// `bigint` needs then when the `alloc` feature is enabled. `bn_mul_mont` above needs this when
// we are using the platforms for which we don't have `bn_mul_mont` in assembly.
#[cfg(any(
    feature = "alloc",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64"
    ))
))]
pub(super) fn limbs_from_mont_in_place(r: &mut [Limb], tmp: &mut [Limb], m: &[Limb], n0: &N0) {
    prefixed_extern! {
        fn bn_from_montgomery_in_place(
            r: *mut Limb,
            num_r: c::size_t,
            a: *mut Limb,
            num_a: c::size_t,
            n: *const Limb,
            num_n: c::size_t,
            n0: &N0,
        ) -> bssl::Result;
    }
    Result::from(unsafe {
        bn_from_montgomery_in_place(
            r.as_mut_ptr(),
            r.len(),
            tmp.as_mut_ptr(),
            tmp.len(),
            m.as_ptr(),
            m.len(),
            n0,
        )
    })
    .unwrap()
}

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
fn limbs_mul(r: &mut [Limb], a: &[Limb], b: &[Limb]) {
    debug_assert_eq!(r.len(), 2 * a.len());
    debug_assert_eq!(a.len(), b.len());
    let ab_len = a.len();

    r[..ab_len].fill(0);
    for (i, &b_limb) in b.iter().enumerate() {
        r[ab_len + i] = unsafe {
            limbs_mul_add_limb(r[i..][..ab_len].as_mut_ptr(), a.as_ptr(), b_limb, ab_len)
        };
    }
}

#[cfg(any(
    test,
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))
))]
prefixed_extern! {
    // `r` must not alias `a`
    #[must_use]
    fn limbs_mul_add_limb(r: *mut Limb, a: *const Limb, b: Limb, num_limbs: c::size_t) -> Limb;
}

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86_64",
    target_arch = "x86"
))]
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

/// r *= a
pub(super) fn limbs_mont_mul(
    r: &mut [Limb],
    a: &[Limb],
    m: &[Limb],
    n0: &N0,
    cpu_features: cpu::Features,
) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    unsafe {
        mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            a.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
            cpu_features,
        )
    }
}

/// r = a * b
#[cfg(not(target_arch = "x86_64"))]
pub(super) fn limbs_mont_product(
    r: &mut [Limb],
    a: &[Limb],
    b: &[Limb],
    m: &[Limb],
    n0: &N0,
    cpu_features: cpu::Features,
) {
    debug_assert_eq!(r.len(), m.len());
    debug_assert_eq!(a.len(), m.len());
    debug_assert_eq!(b.len(), m.len());

    unsafe {
        mul_mont(
            r.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
            cpu_features,
        )
    }
}

/// r = r**2
pub(super) fn limbs_mont_square(r: &mut [Limb], m: &[Limb], n0: &N0, cpu_features: cpu::Features) {
    debug_assert_eq!(r.len(), m.len());
    unsafe {
        mul_mont(
            r.as_mut_ptr(),
            r.as_ptr(),
            r.as_ptr(),
            m.as_ptr(),
            n0,
            r.len(),
            cpu_features,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::limb::Limb;

    #[test]
    // TODO: wasm
    fn test_mul_add_words() {
        const ZERO: Limb = 0;
        const MAX: Limb = ZERO.wrapping_sub(1);
        static TEST_CASES: &[(&[Limb], &[Limb], Limb, Limb, &[Limb])] = &[
            (&[0], &[0], 0, 0, &[0]),
            (&[MAX], &[0], MAX, 0, &[MAX]),
            (&[0], &[MAX], MAX, MAX - 1, &[1]),
            (&[MAX], &[MAX], MAX, MAX, &[0]),
            (&[0, 0], &[MAX, MAX], MAX, MAX - 1, &[1, MAX]),
            (&[1, 0], &[MAX, MAX], MAX, MAX - 1, &[2, MAX]),
            (&[MAX, 0], &[MAX, MAX], MAX, MAX, &[0, 0]),
            (&[0, 1], &[MAX, MAX], MAX, MAX, &[1, 0]),
            (&[MAX, MAX], &[MAX, MAX], MAX, MAX, &[0, MAX]),
        ];

        for (i, (r_input, a, w, expected_retval, expected_r)) in TEST_CASES.iter().enumerate() {
            let mut r = [0; super::super::BIGINT_MODULUS_MAX_LIMBS];
            let r = {
                let r = &mut r[..r_input.len()];
                r.copy_from_slice(r_input);
                r
            };
            assert_eq!(r.len(), a.len()); // Sanity check
            let actual_retval =
                unsafe { limbs_mul_add_limb(r.as_mut_ptr(), a.as_ptr(), *w, a.len()) };
            assert_eq!(&r, expected_r, "{}: {:x?} != {:x?}", i, r, expected_r);
            assert_eq!(
                actual_retval, *expected_retval,
                "{}: {:x?} != {:x?}",
                i, actual_retval, *expected_retval
            );
        }
    }
}
