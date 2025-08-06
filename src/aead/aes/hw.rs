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

use super::{cpu, Block, EncryptBlock, Iv, KeyBytes};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use super::{ffi::AES_KEY, Counter, EncryptCtr32, Overlapping};
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use {super::ffi, crate::bits::BitLength, core::ffi::c_int};

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[derive(Clone)]
pub enum Key {
    Aes128(ffi::Aes128RoundKeys),
    Aes256(ffi::Aes256RoundKeys),
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone)]
#[repr(transparent)]
pub struct Key {
    inner: AES_KEY,
}

impl Key {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn new(bytes: KeyBytes<'_>, cpu: cpu::aarch64::Aes) -> Self {
        match bytes {
            KeyBytes::AES_128(user_key) => Self::Aes128(unsafe {
                ffi::assume_init(|key| Self::set_encrypt_key_128(user_key, key, cpu))
            }),
            KeyBytes::AES_256(user_key) => Self::Aes256(unsafe {
                ffi::assume_init(|key| Self::set_encrypt_key_256(user_key, key, cpu))
            }),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn rd_keys_and_rounds(&self) -> (*const ffi::RdKey, ffi::Rounds) {
        match self {
            Key::Aes128(rd_keys) => (rd_keys.as_ptr(), ffi::Rounds::Aes128),
            Key::Aes256(rd_keys) => (rd_keys.as_ptr(), ffi::Rounds::Aes256),
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
impl Key {
    unsafe fn set_encrypt_key_128(
        user_key: &<ffi::Aes128RoundKeys as ffi::RoundKeys>::UserKey,
        key: *mut ffi::Aes128RoundKeys,
        _cpu: cpu::aarch64::Aes,
    ) {
        prefixed_extern! {
            fn aes_hw_set_encrypt_key_128(
                user_key: &<ffi::Aes128RoundKeys as ffi::RoundKeys>::UserKey,
                ignored: BitLength<c_int>,
                key: *mut ffi::Aes128RoundKeys);
        }
        unsafe { aes_hw_set_encrypt_key_128(user_key, BitLength::from_bits(0), key) };
    }

    unsafe fn set_encrypt_key_256(
        user_key: &<ffi::Aes256RoundKeys as ffi::RoundKeys>::UserKey,
        key: *mut ffi::Aes256RoundKeys,
        _cpu: cpu::aarch64::Aes,
    ) {
        prefixed_extern! {
            fn aes_hw_set_encrypt_key_256(
                user_key: &<ffi::Aes256RoundKeys as ffi::RoundKeys>::UserKey,
                ignored: BitLength<c_int>,
                key: *mut ffi::Aes256RoundKeys);
        }
        unsafe { aes_hw_set_encrypt_key_256(user_key, BitLength::from_bits(0), key) };
    }
}

impl Key {
    #[cfg(target_arch = "x86")]
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _required_cpu_features: (cpu::intel::Aes, cpu::intel::Ssse3),
        _optional_cpu_features: Option<()>,
    ) -> Self {
        prefixed_extern_set_encrypt_key! { aes_hw_set_encrypt_key_base };
        Self {
            inner: unsafe {
                AES_KEY::new_using_set_encrypt_key(bytes, aes_hw_set_encrypt_key_base)
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

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    fn encrypt_iv_xor_block(&self, iv: Iv, mut block: Block) -> Block {
        prefixed_extern! {
            fn aes_hw_encrypt_xor_block(iv: &Block, in_out: &mut Block,
                rd_keys: *const ffi::RdKey, rounds: ffi::Rounds);
        }
        let (rd_keys, rounds) = self.rd_keys_and_rounds();
        unsafe {
            aes_hw_encrypt_xor_block(iv.as_ref(), &mut block, rd_keys, rounds);
        }
        block
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_ctr32(self, iv, block)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, in_out: Overlapping<'_>, ctr: &mut Counter) {
        prefixed_extern_ctr32_encrypt_blocks! { aes_hw_ctr32_encrypt_blocks }
        unsafe {
            self.inner
                .ctr32_encrypt_blocks(in_out, ctr, aes_hw_ctr32_encrypt_blocks)
        }
    }
}
