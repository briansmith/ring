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

use super::{n0::N0, MAX_LIMBS};
use crate::{
    c,
    cpu::{
        self,
        intel::{Adx, Bmi2},
        GetFeature as _,
    },
    limb::Limb,
};
use core::ops::ControlFlow;

#[inline]
pub(super) fn bn_sqr8x_mont(
    in_out: &mut [Limb],
    n: &[Limb],
    n0: &N0,
    cpu: cpu::Features,
) -> ControlFlow<(), ()> {
    prefixed_extern! {
        // `r` and/or 'a' may alias.
        // XXX: BoringSSL declares this to return `int`.
        fn bn_sqr8x_mont(
            rp: *mut Limb,
            ap: *const Limb,
            mulx_adx_capable: Limb,
            np: *const Limb,
            n0: &N0,
            num: c::size_t);
    }

    if n.len() < 8 {
        return ControlFlow::Continue(());
    }
    if n.len() % 8 != 0 {
        return ControlFlow::Continue(());
    }
    // Avoid stack overflow from the alloca inside.
    if n.len() > MAX_LIMBS {
        return ControlFlow::Continue(());
    }

    let rp = in_out.as_mut_ptr();
    let ap = in_out.as_ptr();
    let mulx_adx: Option<(Adx, Bmi2)> = cpu.get_feature();
    // `Limb::from(mulx_adx.is_some())`, but intentionally branchy.
    let mulx_adx_capable = match mulx_adx {
        Some(_) => Limb::from(true),
        None => Limb::from(false),
    };
    let np = n.as_ptr();
    let num = n.len();
    unsafe { bn_sqr8x_mont(rp, ap, mulx_adx_capable, np, n0, num) };

    ControlFlow::Break(())
}
