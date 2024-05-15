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

use super::{Block, Counter, EncryptBlock, EncryptCtr32, Iv, KeyBytes, Overlapping, AES_KEY};

#[derive(Clone)]
pub struct Key {
    inner: AES_KEY,
}

impl Key {
    pub(in super::super) fn new(bytes: KeyBytes<'_>) -> Self {
        prefixed_extern! {
            fn aes_nohw_setup_key_128(key: *mut AES_KEY, input: &[u8; 128 / 8]);
            fn aes_nohw_setup_key_256(key: *mut AES_KEY, input: &[u8; 256 / 8]);
        }
        let mut r = Self {
            inner: AES_KEY::invalid_zero(),
        };
        match bytes {
            KeyBytes::AES_128(bytes) => unsafe { aes_nohw_setup_key_128(&mut r.inner, bytes) },
            KeyBytes::AES_256(bytes) => unsafe { aes_nohw_setup_key_256(&mut r.inner, bytes) },
        }
        r
    }
}

impl EncryptBlock for Key {
    fn encrypt_block(&self, block: Block) -> Block {
        unsafe { encrypt_block!(aes_nohw_encrypt, block, &self.inner) }
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_encrypt_block(self, iv, block)
    }
}

impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, in_out: Overlapping<'_>, ctr: &mut Counter) {
        unsafe { ctr32_encrypt_blocks!(aes_nohw_ctr32_encrypt_blocks, in_out, &self.inner, ctr) }
    }
}
