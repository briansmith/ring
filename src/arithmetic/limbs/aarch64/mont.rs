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

#![cfg(all(target_arch = "aarch64", target_endian = "little"))]

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::super::super::{
    inout::{AliasingSlices2, AliasingSlices3},
    n0::N0,
    LimbSliceError, MAX_LIMBS, MIN_LIMBS,
};
use crate::{
    c,
    limb::{Limb, LIMB_BYTES},
};
use core::num::NonZeroUsize;

// On Windows, at least, if a function stack allocates 4KB then it
// must call `__chkstk` or do equivalent work. We check 3KB instead so
// that we don't have to precisely audit the code.
const _TWICE_MAX_LIMBS_LE_3KB: () = assert!((2 * MAX_LIMBS) * LIMB_BYTES <= 3 * 1024);

#[inline]
pub(in super::super::super) fn mul_mont(
    in_out: impl AliasingSlices3<Limb>,
    n: &[Limb],
    n0: &N0,
) -> Result<(), LimbSliceError> {
    const MIN_4X: usize = 4;
    const MOD_4X: usize = 4;
    const MOD_FALLBACK: usize = 1;

    if n.len() >= MIN_4X && n.len() % MOD_4X == 0 {
        const _CHKSTK_NOT_NEEDED: () = _TWICE_MAX_LIMBS_LE_3KB;
        bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
            (MIN_4X, MOD_4X, ()) => bn_mul4x_mont
        })
    } else {
        const _CHKSTK_NOT_NEEDED: () = _TWICE_MAX_LIMBS_LE_3KB;
        bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
            (MIN_LIMBS, MOD_FALLBACK, ()) => bn_mul_mont_nohw
        })
    }
}

#[inline]
pub(in super::super::super) fn sqr_mont5(
    in_out: impl AliasingSlices2<Limb>,
    n: &[[Limb; 8]],
    n0: &N0,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // `r` and/or 'a' may alias.
        // XXX: BoringSSL (kinda, implicitly) declares this to return `int`.
        // `num` must be a non-zero multiple of 8.
        fn bn_sqr8x_mont(
            rp: *mut Limb,
            ap: *const Limb,
            ap_again: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t);
    }

    let n = n.as_flattened();
    let num_limbs = NonZeroUsize::new(n.len()).ok_or_else(|| LimbSliceError::too_short(n.len()))?;

    // Avoid stack overflow from the alloca inside.
    //
    // On Windows, at least, if a function stack allocates 4KB then it
    // must call `__chkstk` or do equivalent work. We check 3KB instead so
    // that we don't have to precisely audit the code.
    const _CHKSTK_NOT_NEEDED: () = _TWICE_MAX_LIMBS_LE_3KB;
    if num_limbs.get() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(num_limbs.get()));
    }

    in_out
        .with_non_dangling_non_null_pointers_ra(num_limbs, |r, a| {
            let n = n.as_ptr(); // Non-dangling because num_limbs > 0.
            unsafe { bn_sqr8x_mont(r, a, a, n, n0, num_limbs) };
        })
        .map_err(LimbSliceError::len_mismatch)
}
