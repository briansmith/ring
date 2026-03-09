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
    let mut e: MaybeUninit<Digits> = MaybeUninit::uninit();
    let e = unsafe {
        x25519_ge_scalarmult_base_adx_recode(&mut e, a);
        e.assume_init_ref()
    };
    let mut r = ge_p3_4::new_0_1_1_0();
    unsafe {
        x25519_ge_scalarmult_base_adx_add_odd(&mut r, e);
        x25519_ge_scalarmult_base_adx_dbl_4_4(&mut r);
        x25519_ge_scalarmult_base_adx_add_even(&mut r, e);
    }
    let mut t: MaybeUninit<ge_p3_4_bytes> = MaybeUninit::uninit();
    let t = unsafe {
        x25519_ge_scalarmult_base_adx_canon(&mut t, &mut r);
        t.assume_init_ref()
    };
    let mut h = MaybeUninit::uninit();
    unsafe {
        x25519_ge_scalarmult_base_adx_from_bytes(&mut h, t);
        h.assume_init()
    }
}

type Digits = [i8; 64];

// Keep in sync with ge_p3_4 in curve25519_64_adx.h
#[repr(C)]
struct ge_p3_4 {
    X: fe4,
    Y: fe4,
    Z: fe4,
    T: fe4,
}

type ge_p3_4_bytes = [[u8; 32]; 4];

impl ge_p3_4 {
    fn new_0_1_1_0() -> Self {
        const ZERO: fe4 = [0, 0, 0, 0];
        const ONE: fe4 = [1, 0, 0, 0];
        Self {
            X: ZERO,
            Y: ONE,
            Z: ONE,
            T: ZERO,
        }
    }
}

type fe4 = [u64; 4];

prefixed_extern! {
    // Postcondition: `e` is a valid `E` for the value `a`.
    unsafe fn x25519_ge_scalarmult_base_adx_recode(e: &mut MaybeUninit<Digits>, a: &Scalar);
    unsafe fn x25519_ge_scalarmult_base_adx_add_odd(r: &mut ge_p3_4, e: &Digits);
    unsafe fn x25519_ge_scalarmult_base_adx_dbl_4_4(r: &mut ge_p3_4);
    unsafe fn x25519_ge_scalarmult_base_adx_add_even(r: &mut ge_p3_4, e: &Digits);
    unsafe fn x25519_ge_scalarmult_base_adx_canon(t: &mut MaybeUninit<ge_p3_4_bytes>, r: &mut ge_p3_4);
    unsafe fn x25519_ge_scalarmult_base_adx_from_bytes(h: &mut MaybeUninit<P3>, t: &ge_p3_4_bytes);
}
