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

#![cfg(target_arch = "x86_64")]

use super::{inout::AliasingSlices2, n0::N0, LimbSliceError, MAX_LIMBS};
use crate::{
    c,
    cpu::{
        self,
        intel::{Adx, Bmi2},
        GetFeature as _,
    },
    error::LenMismatchError,
    limb::{LeakyWindow, Limb, Window},
    polyfill::slice::{AsChunks, AsChunksMut},
};
use core::num::NonZeroUsize;

#[inline]
pub(super) fn sqr_mont5(
    mut in_out: AsChunksMut<Limb, 8>,
    n: AsChunks<Limb, 8>,
    n0: &N0,
    cpu: cpu::Features,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // `r` and/or 'a' may alias.
        // XXX: BoringSSL declares this to return `int`.
        // `num` must be a non-zero multiple of 8.
        fn bn_sqr8x_mont(
            rp: *mut Limb,
            ap: *const Limb,
            mulx_adx_capable: Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t);
    }

    let in_out = in_out.as_flattened_mut();
    let n = n.as_flattened();
    let num_limbs = NonZeroUsize::new(n.len()).ok_or_else(|| LimbSliceError::too_short(n.len()))?;

    // Avoid stack overflow from the alloca inside.
    if num_limbs.get() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(num_limbs.get()));
    }

    let mulx_adx: Option<(Adx, Bmi2)> = cpu.get_feature();
    // `Limb::from(mulx_adx.is_some())`, but intentionally branchy.
    let mulx_adx_capable = match mulx_adx {
        Some(_) => Limb::from(true),
        None => Limb::from(false),
    };

    in_out
        .with_non_dangling_non_null_pointers_ra(num_limbs, |r, a| {
            let n = n.as_ptr(); // Non-dangling because num_limbs > 0.
            unsafe { bn_sqr8x_mont(r, a, mulx_adx_capable, n, n0, num_limbs) };
        })
        .map_err(LimbSliceError::len_mismatch)
}

#[inline(always)]
pub(super) fn scatter5(
    a: &[Limb],
    table: &mut [Limb],
    power: LeakyWindow,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream uses `num: c::size_t` too, and `power: c::size_t`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_scatter5(
            inp: *const Limb,
            num: c::NonZero_size_t,
            table: *mut Limb,
            power: LeakyWindow,
        );
    }
    let num_limbs = check_common(a, table)?;
    assert!(power < 32);
    unsafe { bn_scatter5(a.as_ptr(), num_limbs, table.as_mut_ptr(), power) };
    Ok(())
}

// SAFETY: `power` must be less than 32.
#[inline(always)]
pub(super) unsafe fn gather5(
    r: &mut [Limb],
    table: &[Limb],
    power: Window,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream uses `num: c::size_t` too, and `power: c::size_t`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        pub(super) fn bn_gather5(
            out: *mut Limb,
            num: c::NonZero_size_t,
            table: *const Limb,
            power: Window);
    }
    let num_limbs = check_common(r, table)?;
    // SAFETY: We cannot assert that `power` is in range because it is secret.
    // TODO: Create a `Window5` type that is guaranteed to be in range.
    unsafe { bn_gather5(r.as_mut_ptr(), num_limbs, table.as_ptr(), power) };
    Ok(())
}

// SAFETY: `power` must be less than 32.
#[inline(always)]
pub(super) unsafe fn mul_mont_gather5_amm(
    r: &mut [Limb],
    a: &[Limb],
    table: &[Limb],
    n: &[Limb],
    n0: &N0,
    power: Window,
    _maybe_adx_bmi1_bmi2: cpu::Features, // TODO: Option<(Adx, Bmi1, Bmi2)>,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream has `num: c::int` and `power: c::int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        pub(super) fn bn_mul_mont_gather5(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window,
        );
    }
    let num_limbs = check_common_with_n(r, table, n)?;
    if a.len() != num_limbs.get() {
        return Err(LimbSliceError::len_mismatch(LenMismatchError::new(a.len())));
    }
    // SAFETY: We cannot assert that `power` is in range because it is secret.
    // TODO: Create a `Window5` type that is guaranteed to be in range.
    unsafe {
        bn_mul_mont_gather5(
            r.as_mut_ptr(),
            a.as_ptr(),
            table.as_ptr(),
            n.as_ptr(),
            n0,
            num_limbs,
            power,
        )
    };
    Ok(())
}

// SAFETY: `power` must be less than 32.
#[inline(always)]
pub(super) unsafe fn power5_amm(
    in_out: &mut [Limb],
    table: &[Limb],
    n: &[Limb],
    n0: &N0,
    power: Window,
    _maybe_adx_bmi1_bmi2: cpu::Features, // TODO: Option<(Adx, Bmi1, Bmi2)>,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream has `num: c::int` and `power: c::int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_power5(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window,
        );
    }
    let num_limbs = check_common_with_n(in_out, table, n)?;
    // SAFETY: We cannot assert that `power` is in range because it is secret.
    // TODO: Create a `Window5` type that is guaranteed to be in range.
    unsafe {
        bn_power5(
            in_out.as_mut_ptr(),
            in_out.as_ptr(),
            table.as_ptr(),
            n.as_ptr(),
            n0,
            num_limbs,
            power,
        );
    }
    Ok(())
}

// Helps the compiler will be able to hoist all of these checks out of the
// loops in the caller. Try to help the compiler by doing the checks
// consistently in each function and also by inlining this function and all the
// callers.
#[inline(always)]
fn check_common(a: &[Limb], table: &[Limb]) -> Result<NonZeroUsize, LimbSliceError> {
    assert_eq!((table.as_ptr() as usize) % 16, 0); // According to BoringSSL.
    let num_limbs = NonZeroUsize::new(a.len()).ok_or_else(|| LimbSliceError::too_short(a.len()))?;
    if num_limbs.get() % 8 != 0 {
        // TODO: Use a different error.
        return Err(LimbSliceError::len_mismatch(LenMismatchError::new(a.len())));
    }
    if num_limbs.get() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(a.len()));
    }
    if num_limbs.get() * 32 != table.len() {
        return Err(LimbSliceError::len_mismatch(LenMismatchError::new(
            table.len(),
        )));
    };
    Ok(num_limbs)
}

#[inline(always)]
fn check_common_with_n(
    a: &[Limb],
    table: &[Limb],
    n: &[Limb],
) -> Result<NonZeroUsize, LimbSliceError> {
    // Choose `a` instead of `n` so that every function starts with
    // `check_common` passing the exact same arguments, so that the compiler
    // can easily de-dupe the checks.
    let num_limbs = check_common(a, table)?;
    if n.len() != num_limbs.get() {
        return Err(LimbSliceError::len_mismatch(LenMismatchError::new(n.len())));
    }
    Ok(num_limbs)
}
