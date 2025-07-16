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

use super::{ffi::AES_KEY, Block, Counter, EncryptBlock, EncryptCtr32, Iv, KeyBytes, Overlapping};
use crate::cpu;

#[derive(Clone)]
#[repr(transparent)]
pub struct Key {
    inner: AES_KEY,
}

impl Key {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _required_cpu_features: cpu::aarch64::Aes,
        _optional_cpu_features: Option<()>,
    ) -> Self {
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key }
        Self {
            inner: unsafe { AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key) },
        }
    }

    #[cfg(target_arch = "x86")]
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _required_cpu_features: (cpu::intel::Aes, cpu::intel::Ssse3),
        optional_cpu_features: Option<cpu::intel::Avx>,
    ) -> Self {
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key_alt };
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key_base };
        Self {
            inner: if let Some(cpu::intel::Avx { .. }) = optional_cpu_features {
                // Ssse3 is required, but upstream only uses this if there is also Avx;
                // presumably the base version is faster on pre-AVX CPUs.
                unsafe { AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key_alt) }
            } else {
                unsafe { AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key_base) }
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _required_cpu_features: (cpu::intel::Aes, cpu::intel::Ssse3),
        optional_cpu_features: Option<cpu::intel::Avx>,
    ) -> Self {
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key_alt };
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key_base };
        Self {
            inner: if let Some(cpu::intel::Avx { .. }) = optional_cpu_features {
                // Ssse3 is required, but upstream only uses this if there is also Avx;
                // presumably the base version is faster on pre-AVX CPUs.
                unsafe { AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key_alt) }
            } else {
                unsafe { AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key_base) }
            },
        }
    }
}

impl EncryptBlock for Key {
    fn encrypt_block(&self, block: Block) -> Block {
        super::encrypt_block_using_encrypt_iv_xor_block(self, block)
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_ctr32(self, iv, block)
    }
}

impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, in_out: Overlapping<'_>, ctr: &mut Counter) {
        prefixed_extern_ctr32_encrypt_blocks! { aes_hw_ctr32_encrypt_blocks }
        unsafe {
            self.inner
                .ctr32_encrypt_blocks(in_out, ctr, aes_hw_ctr32_encrypt_blocks)
        }
    }
}
