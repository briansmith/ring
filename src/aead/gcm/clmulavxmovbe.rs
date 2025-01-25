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

#![cfg(target_arch = "x86_64")]

use super::{clmul, Gmult, HTable, KeyValue, UpdateBlocks, Xi, BLOCK_LEN};
use crate::{cpu, polyfill::slice::AsChunks};

pub(in super::super) type RequiredCpuFeatures = (
    clmul::RequiredCpuFeatures,
    cpu::intel::Avx,
    cpu::intel::Movbe,
);

#[derive(Clone)]
pub struct Key {
    inner: clmul::Key,
}

impl Key {
    pub(in super::super) fn new(key_value: KeyValue, cpu: RequiredCpuFeatures) -> Self {
        Self {
            inner: clmul::Key::new_avx(key_value, cpu),
        }
    }

    pub(super) fn inner(&self) -> &HTable {
        self.inner.inner()
    }
}

impl Gmult for Key {
    fn gmult(&self, xi: &mut Xi) {
        self.inner.gmult(xi)
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: AsChunks<u8, BLOCK_LEN>) {
        unsafe { ghash!(gcm_ghash_avx, xi, &self.inner.inner(), input) }
    }
}
