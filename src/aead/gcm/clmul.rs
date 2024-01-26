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

#![cfg(all(
    perlasm,
    any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
))]

use super::{ffi::KeyValue, Gmult, HTable, Xi};
use crate::cpu;

#[cfg(target_arch = "aarch64")]
pub(in super::super) type RequiredCpuFeatures = cpu::arm::PMull;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(in super::super) type RequiredCpuFeatures = (cpu::intel::ClMul, cpu::intel::Fxsr);

#[derive(Clone)]
pub struct Key {
    h_table: HTable,
}

impl Key {
    pub(in super::super) fn new(value: KeyValue, _cpu: RequiredCpuFeatures) -> Self {
        Self {
            h_table: unsafe { htable_new!(gcm_init_clmul, value) },
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn new_avx(
        value: KeyValue,
        _cpu_features: super::clmulavxmovbe::RequiredCpuFeatures,
    ) -> Self {
        Self {
            h_table: unsafe { htable_new!(gcm_init_avx, value) },
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(super) fn inner(&self) -> &HTable {
        &self.h_table
    }
}

impl Gmult for Key {
    fn gmult(&self, xi: &mut Xi) {
        unsafe { gmult!(gcm_gmult_clmul, xi, &self.h_table) }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl super::UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: &[[u8; super::BLOCK_LEN]]) {
        let _: cpu::Features = cpu::features();
        unsafe { ghash!(gcm_ghash_clmul, xi, &self.h_table, input) }
    }
}
