// Copyright 2015-2022 Brian Smith.
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

#![cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]

use super::{limbs_from_mont_in_place, limbs_mul, Limb, MODULUS_MAX_LIMBS, N0};
use crate::c;

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

        let mut tmp = [0; 2 * MODULUS_MAX_LIMBS];
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
