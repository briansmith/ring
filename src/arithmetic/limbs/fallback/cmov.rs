// Copyright 2025 Brian Smith.
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

use super::super::super::inout::AliasingSlices3;
use crate::{c, error::LenMismatchError, limb::*};
use core::num::NonZeroUsize;

// `if cond { r = a; }`, assuming `cond` is 0 (false) or 0xff..ff (true).
pub fn limbs_cmov(
    cond: Limb,
    r: &mut [Limb],
    a: &[Limb],
    num_limbs: NonZeroUsize,
) -> Result<(), LenMismatchError> {
    prefixed_extern! {
        // r, a, and/or b may alias.
        fn LIMBS_select(
            cond: Limb,
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            num_limbs: c::NonZero_size_t);
    }
    (r, a).with_non_dangling_non_null_pointers_rab(num_limbs, |r, a, b| unsafe {
        LIMBS_select(cond, r, b, a, num_limbs)
    })
}
