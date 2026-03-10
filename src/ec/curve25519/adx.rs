// Copyright 2015-2026 Brian Smith.
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

use super::ops::{P3, Scalar};
use crate::cpu::{
    self, GetFeature as _,
    intel::{Adx, Bmi1, Bmi2},
};
use core::mem::MaybeUninit;

pub type RequiredFeatures = (Adx, Bmi1, Bmi2);

#[inline(always)]
pub(super) fn get_features(cpu: cpu::Features) -> Option<RequiredFeatures> {
    cpu.get_feature()
}

pub fn scalarmult_base(a: &Scalar, _cpu: RequiredFeatures) -> P3 {
    prefixed_extern! {
        unsafe fn x25519_ge_scalarmult_base_adx(t: &mut MaybeUninit<[[u8; 32]; 4]>, a: &Scalar);
        unsafe fn x25519_ge_scalarmult_base_adx_from_bytes(h: &mut MaybeUninit<P3>, t: &[[u8; 32]; 4]);
    }

    let mut t = MaybeUninit::uninit();
    let t = unsafe {
        x25519_ge_scalarmult_base_adx(&mut t, a);
        t.assume_init_ref()
    };
    let mut h = MaybeUninit::uninit();
    unsafe {
        x25519_ge_scalarmult_base_adx_from_bytes(&mut h, t);
        h.assume_init()
    }
}
