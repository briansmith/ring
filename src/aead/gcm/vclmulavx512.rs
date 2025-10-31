// Copyright 2018-2025 Brian Smith.
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
#![cfg_attr(any(target_os = "macos", target_vendor = "apple"), allow(dead_code))]

use super::{ffi, ffi::KeyValue, UpdateBlock, Xi};
use crate::{
    aead::gcm::ffi::BLOCK_LEN,
    c,
    cpu::intel::{Avx2, Avx512_BW_VL_ZMM, Bmi2, VAesClmul},
    polyfill::slice::AsChunks,
};
use core::mem::MaybeUninit;

#[derive(Clone)]
#[repr(transparent)]
pub struct Key([ffi::U128; 16]);

impl Key {
    pub(in super::super) fn new(
        value: KeyValue,
        _cpu: (Avx2, Avx512_BW_VL_ZMM, Bmi2, VAesClmul),
    ) -> Self {
        prefixed_extern! {
            fn gcm_init_vpclmulqdq_avx512(HTable: *mut Key, h: &KeyValue);
        }
        let mut uninit = MaybeUninit::<Key>::uninit();
        unsafe {
            gcm_init_vpclmulqdq_avx512(uninit.as_mut_ptr(), &value);
        }
        unsafe { uninit.assume_init() }
    }
}

impl UpdateBlock for Key {
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        prefixed_extern! {
            fn gcm_ghash_vpclmulqdq_avx512_16(
                xi: &mut Xi,
                Htable: &Key,
                inp: *const u8,
                len: c::NonZero_size_t,
            );
        }
        let input: AsChunks<u8, BLOCK_LEN> = (&a).into();
        ffi::with_non_dangling_ptr(input, |input, len| unsafe {
            gcm_ghash_vpclmulqdq_avx512_16(xi, self, input, len)
        })
    }
}
