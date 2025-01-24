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

use crate::{c, error::LenMismatchError, limb::*, polyfill::AliasingSlices as _};
use core::num::NonZeroUsize;

/// Equivalent to `r = if a < m { a } else { a - m };`
#[inline]
pub fn limbs_reduce_once(r: &mut [Limb], a: &[Limb], m: &[Limb]) -> Result<(), LenMismatchError> {
    let underflow = limbs_sub(r, a, m)?;
    limbs_cmov(r, a, underflow)
}

// `r = a - b`, returning true on underflow, false otherwise.
fn limbs_sub(r: &mut [Limb], a: &[Limb], b: &[Limb]) -> Result<LimbMask, LenMismatchError> {
    prefixed_extern! {
        // `r`, 'a', and/or `b` may alias.
        fn LIMBS_sub(r: *mut Limb, a: *const Limb, b: *const Limb, num_limbs: c::NonZero_size_t)
            -> LimbMask;
    }
    let num_limbs = NonZeroUsize::new(r.len()).ok_or_else(|| LenMismatchError::new(r.len()))?;
    (r, a, b).with_pointers(num_limbs.into(), |r, a, b| unsafe {
        LIMBS_sub(r, a, b, num_limbs)
    })
}
