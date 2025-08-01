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

#![cfg(target_arch = "x86_64")]

use super::{ffi, KeyValue, UpdateBlock, UpdateBlocks, Xi, BLOCK_LEN};
use crate::{c, cpu::intel};
use core::{mem::MaybeUninit, slice};

#[derive(Clone)]
#[repr(transparent)]
pub struct Key([ffi::U128; 12]);

impl Key {
    #[inline(never)]
    pub(in super::super) fn new(
        value: KeyValue,
        _required_cpu_features: (intel::ClMul, intel::Avx, intel::Movbe),
    ) -> Self {
        prefixed_extern! {
            fn gcm_init_avx(HTable: *mut Key, h: &KeyValue);
        }
        let mut uninit = MaybeUninit::<Key>::uninit();
        unsafe {
            gcm_init_avx(uninit.as_mut_ptr(), &value);
        }
        unsafe { uninit.assume_init() }
    }
}

impl UpdateBlock for Key {
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        self.update_blocks(xi, slice::from_ref(&a))
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: &[[u8; BLOCK_LEN]]) {
        prefixed_extern! {
            fn gcm_ghash_avx(
                xi: &mut Xi,
                Htable: &Key,
                inp: *const u8,
                len: c::NonZero_size_t,
            );
        }
        ffi::with_non_dangling_ptr(input, |input, len| unsafe {
            gcm_ghash_avx(xi, self, input, len)
        })
    }
}
