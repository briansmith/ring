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

#![cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]

use super::{
    Block, EncryptBlock, EncryptCtr32, InOutLenInconsistentWithIvBlockLenError, Iv, IvBlock,
    KeyBytes, AES_KEY,
};
use crate::{cpu, error};
use core::ops::RangeFrom;

#[cfg(target_arch = "aarch64")]
pub(in super::super) type RequiredCpuFeatures = cpu::arm::Aes;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(in super::super) type RequiredCpuFeatures = cpu::intel::Aes;

#[derive(Clone)]
pub struct Key {
    inner: AES_KEY,
}

impl Key {
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _cpu: RequiredCpuFeatures,
    ) -> Result<Self, error::Unspecified> {
        let inner = unsafe { set_encrypt_key!(aes_hw_set_encrypt_key, bytes) }?;
        Ok(Self { inner })
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[must_use]
    pub(in super::super) fn inner_less_safe(&self) -> &AES_KEY {
        &self.inner
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
    fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        iv_block: IvBlock,
    ) -> Result<(), InOutLenInconsistentWithIvBlockLenError> {
        #[cfg(target_arch = "x86_64")]
        let _: cpu::Features = cpu::features();
        unsafe {
            ctr32_encrypt_blocks!(
                aes_hw_ctr32_encrypt_blocks,
                in_out,
                src,
                &self.inner,
                iv_block
            )
        }
    }
}
