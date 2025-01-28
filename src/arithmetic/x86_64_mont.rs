// Copyright 2024-2025 Brian Smith.
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

use super::{inout::AliasingSlices2, n0::N0, MAX_LIMBS};
use crate::{
    c,
    cpu::{
        self,
        intel::{Adx, Bmi2},
        GetFeature as _,
    },
    error::LenMismatchError,
    limb::Limb,
};
use core::ops::ControlFlow;

#[inline]
pub(super) fn bn_sqr8x_mont(
    in_out: &mut [Limb],
    n: &[Limb],
    n0: &N0,
    cpu: cpu::Features,
) -> ControlFlow<Result<(), LenMismatchError>> {
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
            num: c::size_t);
    }

    let num_limbs = n.len();
    if num_limbs < 8 {
        return ControlFlow::Continue(());
    }
    if num_limbs % 8 != 0 {
        return ControlFlow::Continue(());
    }
    // Avoid stack overflow from the alloca inside.
    if num_limbs > MAX_LIMBS {
        return ControlFlow::Continue(());
    }

    let mulx_adx: Option<(Adx, Bmi2)> = cpu.get_feature();
    // `Limb::from(mulx_adx.is_some())`, but intentionally branchy.
    let mulx_adx_capable = match mulx_adx {
        Some(_) => Limb::from(true),
        None => Limb::from(false),
    };

    // It's OK if the pointers are dangling because `bn_sqr8x_mont` is an
    // assembly language function. But also, we know `num_limbs > 0` from
    // above.
    let r = in_out.with_potentially_dangling_non_null_pointers_ra(num_limbs, |r, a| {
        let n = n.as_ptr();
        unsafe { bn_sqr8x_mont(r, a, mulx_adx_capable, n, n0, num_limbs) };
    });
    ControlFlow::Break(r)
}
