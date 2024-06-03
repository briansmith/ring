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

#![cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
))]

use super::{
    Block, EncryptBlock, EncryptCtr32, InOutLenInconsistentWithIvBlockLenError, Iv, IvBlock,
    KeyBytes, AES_KEY,
};
use crate::{cpu, error};
use core::ops::RangeFrom;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
type RequiredCpuFeatures = cpu::arm::Neon;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
type RequiredCpuFeatures = cpu::intel::Ssse3;

#[derive(Clone)]
pub(in super::super) struct Key {
    inner: AES_KEY,
}

impl Key {
    pub(in super::super) fn new(
        bytes: KeyBytes<'_>,
        _cpu: RequiredCpuFeatures,
    ) -> Result<Self, error::Unspecified> {
        let inner = unsafe { set_encrypt_key!(vpaes_set_encrypt_key, bytes) }?;
        Ok(Self { inner })
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
impl EncryptBlock for Key {
    fn encrypt_block(&self, block: Block) -> Block {
        super::encrypt_block_using_encrypt_iv_xor_block(self, block)
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_ctr32(self, iv, block)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        iv_block: IvBlock,
    ) -> Result<(), InOutLenInconsistentWithIvBlockLenError> {
        unsafe {
            ctr32_encrypt_blocks!(
                vpaes_ctr32_encrypt_blocks,
                in_out,
                src,
                &self.inner,
                iv_block
            )
        }
    }
}

#[cfg(target_arch = "arm")]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        iv_block: IvBlock,
    ) -> Result<(), InOutLenInconsistentWithIvBlockLenError> {
        use super::{bs, BLOCK_LEN};

        let blocks = in_out[src.clone()].len() / BLOCK_LEN;

        // bsaes operates in batches of 8 blocks.
        let bsaes_blocks = if blocks >= 8 && (blocks % 8) < 6 {
            // It's faster to use bsaes for all the full batches and then
            // switch to vpaes for the last partial batch (if any).
            blocks - (blocks % 8)
        } else if blocks >= 8 {
            // It's faster to let bsaes handle everything including
            // the last partial batch.
            blocks
        } else {
            // It's faster to let vpaes handle everything.
            0
        };
        let (bsaes_iv_block, vpaes_iv_block) = iv_block.split_at(bsaes_blocks)?;
        let bsaes_in_out_len = bsaes_blocks * BLOCK_LEN;

        if let Some(iv_block) = bsaes_iv_block {
            // SAFETY:
            //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
            //    as required by `bsaes_ctr32_encrypt_blocks_with_vpaes_key`.
            unsafe {
                bs::ctr32_encrypt_blocks_with_vpaes_key(
                    &mut in_out[..(src.start + bsaes_in_out_len)],
                    src.clone(),
                    &self.inner,
                    iv_block,
                )
            }?;
        }

        if let Some(iv_block) = vpaes_iv_block {
            let in_out = &mut in_out[bsaes_in_out_len..];
            // SAFETY:
            //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
            //    as required by `vpaes_ctr32_encrypt_blocks`.
            //  * `vpaes_ctr32_encrypt_blocks` satisfies the contract for
            //    `ctr32_encrypt_blocks`.
            unsafe {
                ctr32_encrypt_blocks!(
                    vpaes_ctr32_encrypt_blocks,
                    in_out,
                    src,
                    &self.inner,
                    iv_block
                )
            }?;
        }

        Ok(())
    }
}

#[cfg(target_arch = "x86")]
impl EncryptBlock for Key {
    fn encrypt_block(&self, block: Block) -> Block {
        unsafe { encrypt_block!(vpaes_encrypt, block, &self.inner) }
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_encrypt_block(self, iv, block)
    }
}

#[cfg(target_arch = "x86")]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        iv_block: IvBlock,
    ) -> Result<(), InOutLenInconsistentWithIvBlockLenError> {
        let (input_blocks, leftover): (&[[u8; super::BLOCK_LEN]], _) =
            crate::polyfill::slice::as_chunks(&in_out[src.clone()]);
        debug_assert_eq!(leftover.len(), 0);
        let mut ctr = iv_block.into_counter_less_safe(input_blocks.len())?;
        super::super::shift::shift_full_blocks(in_out, src, |input| {
            self.encrypt_iv_xor_block(ctr.increment_unchecked_less_safe(), *input)
        });
        Ok(())
    }
}
