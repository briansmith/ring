// Copyright 2018-2024 Brian Smith.
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

#![cfg(all(perlasm, any(target_arch = "aarch64", target_arch = "arm")))]

use super::{Gmult, HTable, KeyValue, UpdateBlocks, Xi, BLOCK_LEN};
use crate::cpu;

pub(in super::super) type RequiredCpuFeatures = cpu::arm::Neon;

#[derive(Clone)]
pub struct Key {
    h_table: HTable,
}

impl Key {
    pub(in super::super) fn new(value: KeyValue, _cpu: RequiredCpuFeatures) -> Self {
        Self {
            h_table: unsafe { htable_new!(gcm_init_neon, value) },
        }
    }
}

impl Gmult for Key {
    fn gmult(&self, xi: &mut Xi) {
        unsafe { gmult!(gcm_gmult_neon, xi, &self.h_table) }
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: &[[u8; BLOCK_LEN]]) {
        unsafe { ghash!(gcm_ghash_neon, xi, &self.h_table, input) }
    }
}
