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
    target_arch = "x86",
    target_arch = "x86_64"
))]

use super::{
    ffi::{KeyValue, BLOCK_LEN},
    HTable, UpdateBlock, Xi,
};
use crate::cpu;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {super::UpdateBlocks, crate::polyfill::slice::AsChunks};

#[derive(Clone)]
pub struct Key {
    h_table: HTable,
}

impl Key {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn new(value: KeyValue, _cpu: cpu::aarch64::PMull) -> Self {
        prefixed_extern! {
            fn gcm_init_clmul(HTable: *mut HTable, h: &KeyValue);
        }
        Self {
            h_table: HTable::new(|table| unsafe { gcm_init_clmul(table, &value) }),
        }
    }

    #[cfg(target_arch = "x86")]
    pub(in super::super) fn new(
        value: KeyValue,
        _cpu: (cpu::intel::ClMul, cpu::intel::Ssse3),
    ) -> Self {
        prefixed_extern! {
            fn gcm_init_clmul(HTable: *mut HTable, h: &KeyValue);
        }
        Self {
            h_table: HTable::new(|htable| unsafe { gcm_init_clmul(htable, &value) }),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(never)]
    pub(in super::super) fn new(
        value: KeyValue,
        _cpu: (cpu::intel::ClMul, cpu::intel::Ssse3),
    ) -> Self {
        prefixed_extern! {
            fn gcm_init_clmul(HTable: *mut HTable, h: &KeyValue);
        }
        Self {
            h_table: HTable::new(|table| unsafe { gcm_init_clmul(table, &value) }),
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn inner(&self) -> &HTable {
        &self.h_table
    }
}

impl UpdateBlock for Key {
    #[cfg(target_arch = "aarch64")]
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        prefixed_extern! {
            fn gcm_gmult_clmul(xi: &mut Xi, Htable: &HTable);
        }
        xi.bitxor_assign(a);
        unsafe { self.h_table.gmult(gcm_gmult_clmul, xi) };
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        self.update_blocks(xi, (&a).into())
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: AsChunks<u8, { BLOCK_LEN }>) {
        unsafe { ghash!(gcm_ghash_clmul, xi, &self.h_table, input) }
    }
}
