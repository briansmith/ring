// Copyright 2018-2024 Brian Smith.
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

#![cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    all(target_arch = "arm", target_endian = "little")
))]

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{ffi, KeyValue, UpdateBlock, UpdateBlocks, Xi, BLOCK_LEN};
use crate::{c, cpu};
use core::mem::MaybeUninit;

#[derive(Clone)]
#[repr(transparent)]
pub struct Key([ffi::U128; 1]);

impl Key {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn new(value: KeyValue, _cpu: cpu::aarch64::Neon) -> Self {
        prefixed_extern! {
            fn gcm_init_neon(HTable: *mut Key, h: &KeyValue);
        }
        let mut uninit = MaybeUninit::uninit();
        unsafe { gcm_init_neon(uninit.as_mut_ptr(), &value) };
        unsafe { uninit.assume_init() }
    }

    #[cfg(all(target_arch = "arm", target_endian = "little"))]
    pub(in super::super) fn new(value: KeyValue, _cpu: cpu::arm::Neon) -> Self {
        prefixed_extern! {
            fn gcm_init_neon(HTable: *mut Key, h: &KeyValue);
        }
        let mut uninit = MaybeUninit::uninit();
        unsafe { gcm_init_neon(uninit.as_mut_ptr(), &value) };
        unsafe { uninit.assume_init() }
    }
}

impl UpdateBlock for Key {
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        prefixed_extern! {
            fn gcm_gmult_neon(xi: &mut Xi, Htable: &Key);
        }
        xi.bitxor_assign(a);
        unsafe { gcm_gmult_neon(xi, self) };
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: &[[u8; BLOCK_LEN]]) {
        prefixed_extern! {
            fn gcm_ghash_neon(
                xi: &mut Xi,
                Htable: &Key,
                inp: *const u8,
                len: c::NonZero_size_t,
            );
        }
        ffi::with_non_dangling_ptr(input, |input, len| unsafe {
            gcm_ghash_neon(xi, self, input, len)
        });
    }
}
