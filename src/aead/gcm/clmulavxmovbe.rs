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

use super::{ffi, HTable, KeyValue, UpdateBlock, UpdateBlocks, Xi, BLOCK_LEN};
use crate::{c, cpu::intel, polyfill::slice::AsChunks};

#[derive(Clone)]
pub struct Key {
    h_table: HTable,
}

impl Key {
    #[inline(never)]
    pub(in super::super) fn new(
        value: KeyValue,
        _required_cpu_features: (intel::ClMul, intel::Avx, intel::Movbe),
    ) -> Self {
        prefixed_extern! {
            fn gcm_init_avx(HTable: *mut HTable, h: &KeyValue);
        }
        Self {
            h_table: HTable::new(|table| unsafe { gcm_init_avx(table, &value) }),
        }
    }

    pub(super) fn inner(&self) -> &HTable {
        &self.h_table
    }
}

impl UpdateBlock for Key {
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        self.update_blocks(xi, (&a).into())
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: AsChunks<u8, BLOCK_LEN>) {
        prefixed_extern! {
            fn gcm_ghash_avx(
                xi: &mut Xi,
                Htable: &HTable,
                inp: *const u8,
                len: c::NonZero_size_t,
            );
        }
        let htable = self.inner();
        ffi::with_non_dangling_ptr(input, |input, len| unsafe {
            gcm_ghash_avx(xi, htable, input, len)
        })
    }
}
