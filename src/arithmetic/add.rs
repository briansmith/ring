// Copyright 2015-2025 Brian Smith.
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

use super::inout::AliasingSlices3;
use crate::{c, error::LenMismatchError, limb::*};
use core::num::NonZeroUsize;

/// Equivalent to `r = if a < m { a } else { a - m };`
#[inline]
pub fn limbs_reduce_once(r: &mut [Limb], a: &[Limb], m: &[Limb]) -> Result<(), LenMismatchError> {
    let num_limbs = NonZeroUsize::new(m.len()).ok_or_else(|| LenMismatchError::new(0))?;
    let underflow = limbs_sub((r.as_mut(), a, m), num_limbs)?;
    limbs_cmov(r, a, num_limbs, underflow)
}

// `r = a - b`, returning true on underflow, false otherwise.
fn limbs_sub(
    in_out: impl AliasingSlices3<Limb>,
    num_limbs: NonZeroUsize,
) -> Result<LimbMask, LenMismatchError> {
    prefixed_extern! {
        // `r`, 'a', and/or `b` may alias.
        fn LIMBS_sub(r: *mut Limb, a: *const Limb, b: *const Limb, num_limbs: c::NonZero_size_t)
            -> LimbMask;
    }
    in_out.with_non_dangling_non_null_pointers_rab(num_limbs, |r, a, b| unsafe {
        LIMBS_sub(r, a, b, num_limbs)
    })
}

// `if cond { r = a; }`
fn limbs_cmov(
    r: &mut [Limb],
    a: &[Limb],
    num_limbs: NonZeroUsize,
    cond: LimbMask,
) -> Result<(), LenMismatchError> {
    prefixed_extern! {
        // r, a, and/or b may alias.
        fn LIMBS_select(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            num_limbs: c::NonZero_size_t,
            cond: LimbMask);
    }
    (r, a).with_non_dangling_non_null_pointers_rab(num_limbs, |r, a, b| unsafe {
        LIMBS_select(r, b, a, num_limbs, cond)
    })
}
