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
    all(target_arch = "arm", target_endian = "little"),
    target_arch = "x86",
    target_arch = "x86_64"
))]

use super::{Block, Counter, EncryptBlock, EncryptCtr32, Iv, KeyBytes, OverlappingBlocks, AES_KEY};
use crate::cpu;

#[derive(Clone)]
pub(in super::super) struct Key {
    inner: AES_KEY,
}

impl Key {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(in super::super) fn new(bytes: KeyBytes<'_>, _cpu: cpu::aarch64::Neon) -> Self {
        Self {
            inner: unsafe { set_encrypt_key!(vpaes_set_encrypt_key, bytes) },
        }
    }

    #[cfg(all(target_arch = "arm", target_endian = "little"))]
    pub(in super::super) fn new(bytes: KeyBytes<'_>, _cpu: cpu::arm::Neon) -> Self {
        Self {
            inner: unsafe { set_encrypt_key!(vpaes_set_encrypt_key, bytes) },
        }
    }

    #[cfg(target_arch = "x86")]
    pub(in super::super) fn new(bytes: KeyBytes<'_>, _cpu: cpu::intel::Ssse3) -> Self {
        Self {
            inner: unsafe { set_encrypt_key!(vpaes_set_encrypt_key, bytes) },
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(in super::super) fn new(bytes: KeyBytes<'_>, _cpu: cpu::intel::Ssse3) -> Self {
        Self {
            inner: unsafe { set_encrypt_key!(vpaes_set_encrypt_key, bytes) },
        }
    }
}

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    all(target_arch = "arm", target_endian = "little"),
    target_arch = "x86_64"
))]
impl EncryptBlock for Key {
    fn encrypt_block(&self, block: Block) -> Block {
        super::encrypt_block_using_encrypt_iv_xor_block(self, block)
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_ctr32(self, iv, block)
    }
}

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    target_arch = "x86_64"
))]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, in_out: OverlappingBlocks<'_>, ctr: &mut Counter) {
        unsafe { ctr32_encrypt_blocks!(vpaes_ctr32_encrypt_blocks, in_out, &self.inner, ctr) }
    }
}

#[cfg(all(target_arch = "arm", target_endian = "little"))]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, in_out: Overlapping<'_>, ctr: &mut Counter) {
        use super::{super::overlapping::IndexError, bs, BLOCK_LEN};

        let in_out = {
            let blocks = in_out.len() / BLOCK_LEN;

            // bsaes operates in batches of 8 blocks.
            if blocks >= 8 {
                let vpaes_blocks = if (blocks % 8) < 6 {
                    // It's faster to use bsaes for all the full batches and then
                    // switch to vpaes for the last partial batch (if any).
                    blocks % 8
                } else {
                    // It's faster to let bsaes handle everything including
                    // the last partial batch.
                    0
                };
                let bsaes_blocks = blocks - vpaes_blocks;
                let bsaes_in_out_len = bsaes_blocks * BLOCK_LEN;
                in_out
                    .split_at(bsaes_in_out_len, |bsaes_in_out| {
                        // SAFETY:
                        //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
                        //    as required by `bsaes_ctr32_encrypt_blocks_with_vpaes_key`.
                        unsafe {
                            bs::ctr32_encrypt_blocks_with_vpaes_key(bsaes_in_out, &self.inner, ctr);
                        }
                    })
                    .unwrap_or_else(|_: IndexError| {
                        // `bsaes_in_out_len` is never larger than `in_out.len()`.
                        unreachable!()
                    })
            } else {
                // It's faster to let vpaes handle everything.
                in_out
            }
        };

        // SAFETY:
        //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
        //    as required by `vpaes_ctr32_encrypt_blocks`.
        //  * `vpaes_ctr32_encrypt_blocks` satisfies the contract for
        //    `ctr32_encrypt_blocks`.
        unsafe { ctr32_encrypt_blocks!(vpaes_ctr32_encrypt_blocks, in_out, &self.inner, ctr) }
    }
}

#[cfg(target_arch = "x86")]
impl EncryptBlock for Key {
    fn encrypt_block(&self, mut block: Block) -> Block {
        prefixed_extern! {
            // `a` and `r` may alias.
            fn vpaes_encrypt(a: *const Block, r: *mut Block, key: &AES_KEY);
        }
        let block_out: *mut Block = &mut block;
        unsafe {
            vpaes_encrypt(block_out.cast_const(), block_out, &self.inner);
        }
        block
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        let encrypted_iv = self.encrypt_block(iv.0);
        crate::bb::xor_16(encrypted_iv, block)
    }
}

#[cfg(target_arch = "x86")]
impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, mut in_out: Overlapping<'_>, ctr: &mut Counter) {
        use super::{overlapping::IndexError, BLOCK_LEN};
        use crate::polyfill::sliceutil;

        assert_eq!(in_out.len() % BLOCK_LEN, 0);
        let blocks = in_out.len() / BLOCK_LEN;
        for _ in 0..blocks {
            in_out = in_out
                .split_first_chunk(|in_out| {
                    let out = self.encrypt_iv_xor_block(ctr.increment(), *in_out.input());
                    sliceutil::overwrite_at_start(in_out.into_unwritten_output(), &out);
                })
                .unwrap_or_else(|IndexError { .. }| unreachable!());
        }
    }
}
