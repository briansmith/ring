// Copyright 2015-2025 Brian Smith.
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

#![cfg(target_arch = "x86_64")]

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use crate::polyfill::SmallerChunks;

use super::super::super::{
    inout::{AliasingSlices2, AliasingSlices3},
    limbs512::storage::{check_common, check_common_with_n},
    n0::N0,
    LimbSliceError, MAX_LIMBS,
};
use crate::{
    c,
    cpu::intel::{Adx, Bmi1, Bmi2},
    error::LenMismatchError,
    limb::Limb,
    window5::Window5,
};
use core::num::NonZeroUsize;

const _512_IS_LIMB_BITS_TIMES_8: () = assert!(8 * Limb::BITS == 512);

#[inline]
pub(in super::super::super) fn mul_mont5(
    r: &mut [[Limb; 8]],
    a: &[[Limb; 8]],
    b: &[[Limb; 8]],
    m: &[[Limb; 8]],
    n0: &N0,
    maybe_adx_bmi2: Option<(Adx, Bmi2)>,
) -> Result<(), LimbSliceError> {
    mul_mont5_4x(
        (r.as_flattened_mut(), a.as_flattened(), b.as_flattened()),
        SmallerChunks::as_smaller_chunks(m),
        n0,
        maybe_adx_bmi2,
    )
}

pub const MIN_4X: usize = 8;

#[inline]
pub(in super::super::super) fn mul_mont5_4x(
    in_out: impl AliasingSlices3<Limb>,
    n: &[[Limb; 4]],
    n0: &N0,
    maybe_adx_bmi2: Option<(Adx, Bmi2)>,
) -> Result<(), LimbSliceError> {
    const MOD_4X: usize = 4;
    let n = n.as_flattened();
    if let Some(cpu) = maybe_adx_bmi2 {
        bn_mul_mont_ffi!(in_out, n, n0, cpu, unsafe {
            (MIN_4X, MOD_4X, (Adx, Bmi2)) => bn_mulx4x_mont
        })
    } else {
        bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
            (MIN_4X, MOD_4X, ()) => bn_mul4x_mont
        })
    }
}

#[inline]
pub(in super::super::super) fn sqr_mont5(
    in_out: impl AliasingSlices2<Limb>,
    n: &[[Limb; 8]],
    n0: &N0,
    maybe_adx_bmi2: Option<(Adx, Bmi2)>,
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

    let n = n.as_flattened();
    let num_limbs = NonZeroUsize::new(n.len()).ok_or_else(|| LimbSliceError::too_short(n.len()))?;

    // Avoid stack overflow from the alloca inside.
    if num_limbs.get() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(num_limbs.get()));
    }

    // `Limb::from(mulx_adx.is_some())`, but intentionally branchy.
    let mulx_adx_capable = match maybe_adx_bmi2 {
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
pub(in super::super::super) fn gather5(
    r: &mut [[Limb; 8]],
    table: &[[Limb; 8]],
    power: Window5,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream uses `num: c::size_t` too, and `power: c::size_t`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_gather5(
            out: *mut Limb,
            num: c::NonZero_size_t,
            table: *const Limb,
            power: Window5);
    }
    let num_limbs = check_common(r, table)?;
    let r = r.as_flattened_mut();
    let table = table.as_flattened();
    unsafe { bn_gather5(r.as_mut_ptr(), num_limbs, table.as_ptr(), power) };
    Ok(())
}

#[inline(always)]
pub(in super::super::super) fn mul_mont_gather5_amm(
    r: &mut [[Limb; 8]],
    a: &[[Limb; 8]],
    table: &[[Limb; 8]],
    n: &[[Limb; 8]],
    n0: &N0,
    power: Window5,
    maybe_adx_bmi1_bmi2: Option<(Adx, Bmi1, Bmi2)>,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream has `num: c_int` and `power: c_int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_mul4x_mont_gather5(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window5,
        );
        // Upstream has `num: c_int` and `power: c_int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_mulx4x_mont_gather5(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window5,
        );
    }
    let num_limbs = check_common_with_n(r, table, n)?;
    let a = a.as_flattened();
    if a.len() != num_limbs.get() {
        return Err(LimbSliceError::len_mismatch(LenMismatchError::new(a.len())));
    }
    let r = r.as_flattened_mut();
    let r = r.as_mut_ptr();
    let a = a.as_ptr();
    let table = table.as_flattened();
    let table = table.as_ptr();
    let n = n.as_flattened();
    let n = n.as_ptr();
    if maybe_adx_bmi1_bmi2.is_some() {
        unsafe { bn_mulx4x_mont_gather5(r, a, table, n, n0, num_limbs, power) }
    } else {
        unsafe { bn_mul4x_mont_gather5(r, a, table, n, n0, num_limbs, power) }
    };
    Ok(())
}

// SAFETY: `power` must be less than 32.
#[inline(always)]
pub(in super::super::super) fn power5_amm(
    in_out: &mut [[Limb; 8]],
    table: &[[Limb; 8]],
    n: &[[Limb; 8]],
    n0: &N0,
    power: Window5,
    maybe_adx_bmi1_bmi2: Option<(Adx, Bmi1, Bmi2)>,
) -> Result<(), LimbSliceError> {
    prefixed_extern! {
        // Upstream has `num: c_int` and `power: c_int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_power5_nohw(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window5,
        );
        // Upstream has `num: c_int` and `power: c_int`; see
        // `_MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES`.
        fn bn_powerx5(
            rp: *mut Limb,
            ap: *const Limb,
            table: *const Limb,
            np: *const Limb,
            n0: &N0,
            num: c::NonZero_size_t,
            power: Window5,
        );
    }
    let num_limbs = check_common_with_n(in_out, table, n)?;
    let in_out = in_out.as_flattened_mut();
    let r = in_out.as_mut_ptr();
    let a = in_out.as_ptr();
    let table = table.as_flattened();
    let table = table.as_ptr();
    let n = n.as_flattened();
    let n = n.as_ptr();
    if maybe_adx_bmi1_bmi2.is_some() {
        unsafe { bn_powerx5(r, a, table, n, n0, num_limbs, power) }
    } else {
        unsafe { bn_power5_nohw(r, a, table, n, n0, num_limbs, power) }
    };
    Ok(())
}
