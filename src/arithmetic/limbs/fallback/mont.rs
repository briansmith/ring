// Copyright 2017-2025 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::super::super::{
    montgomery::{limbs_from_mont_in_place, N0},
    MAX_LIMBS,
};
use crate::{c, limb::Limb};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            all(target_arch = "x86", target_feature = "sse2"),
            target_arch = "x86_64")))] {
        use super::super::super::{
            ffi::bn_mul_mont_ffi,
            inout::AliasingSlices3,
            LimbSliceError,
            MIN_LIMBS,
        };

        #[inline]
        pub fn limbs_mul_mont(
            in_out: impl AliasingSlices3<Limb>,
            n: &[Limb],
            n0: &N0,
        ) -> Result<(), LimbSliceError> {
            const MOD_FALLBACK: usize = 1;
            // Use the fallback implementation through the FFI wrapper so that
            // Rust and C code both go through `bn_mul_mont`.
            // This isn't really an FFI call; it's defined below.
            bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
                (MIN_LIMBS, MOD_FALLBACK, ()) => bn_mul_mont_fallback
            })
        }

        // TODO: Stop calling this from C and un-export it.
        prefixed_export! {
            #[cfg_attr(target_arch = "x86", cold)]
            #[cfg_attr(target_arch = "x86", inline(never))]
            unsafe extern "C" fn bn_mul_mont_fallback(
                r: *mut Limb,
                a: *const Limb,
                b: *const Limb,
                n: *const Limb,
                n0: &N0,
                num_limbs: c::NonZero_size_t,
            ) {
                unsafe { bn_mul_mont_fallback_impl(r, a, b, n, n0, num_limbs) }
            }
        }
    }
}

#[allow(dead_code)]
#[inline]
unsafe extern "C" fn bn_mul_mont_fallback_impl(
    r: *mut Limb,
    a: *const Limb,
    b: *const Limb,
    n: *const Limb,
    n0: &N0,
    num_limbs: c::NonZero_size_t,
) {
    let num_limbs = num_limbs.get();

    // The mutable pointer `r` may alias `a` and/or `b`, so the lifetimes of
    // any slices for `a` or `b` must not overlap with the lifetime of any
    // mutable for `r`.

    // Nothing aliases `n`
    let n = unsafe { core::slice::from_raw_parts(n, num_limbs) };

    let mut tmp = [0; 2 * MAX_LIMBS];
    let tmp = &mut tmp[..(2 * num_limbs)];
    {
        let a: &[Limb] = unsafe { core::slice::from_raw_parts(a, num_limbs) };
        let b: &[Limb] = unsafe { core::slice::from_raw_parts(b, num_limbs) };
        limbs_mul(tmp, a, b);
    }
    let r: &mut [Limb] = unsafe { core::slice::from_raw_parts_mut(r, num_limbs) };
    limbs_from_mont_in_place(r, tmp, n, n0);
}

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

prefixed_extern! {
    // `r` must not alias `a`
    #[must_use]
    fn limbs_mul_add_limb(r: *mut Limb, a: *const Limb, b: Limb, num_limbs: c::size_t) -> Limb;
}

#[cfg(test)]
mod tests {
    use super::super::super::super::MAX_LIMBS;
    use super::*;

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
            let mut r = [0; MAX_LIMBS];
            let r = {
                let r = &mut r[..r_input.len()];
                r.copy_from_slice(r_input);
                r
            };
            assert_eq!(r.len(), a.len()); // Sanity check
            let actual_retval =
                unsafe { limbs_mul_add_limb(r.as_mut_ptr(), a.as_ptr(), *w, a.len()) };
            assert_eq!(&r, expected_r, "{i}: {r:x?} != {expected_r:x?}");
            assert_eq!(
                actual_retval, *expected_retval,
                "{}: {:x?} != {:x?}",
                i, actual_retval, *expected_retval
            );
        }
    }
}
