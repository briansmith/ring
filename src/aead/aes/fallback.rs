// Copyright (c) 2019, Google Inc.
// Portions Copyright 2018-2025 Brian Smith.
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

use super::{
    Block, Counter, EncryptBlock, EncryptCtr32, Iv, KeyBytes, Overlapping, AES_KEY, BLOCK_LEN,
    MAX_ROUNDS,
};
use crate::{bb, c, polyfill::usize_from_u32};
use core::{
    array,
    mem::{size_of, MaybeUninit},
};

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
    fn encrypt_block(&self, mut block: Block) -> Block {
        encrypt_block(&self.inner, &mut block);
        block
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

type Word = bb::Word;
const WORD_SIZE: usize = size_of::<Word>();
const BATCH_SIZE: usize = WORD_SIZE / 2;

const BLOCK_WORDS: usize = 16 / WORD_SIZE;

// An AES_NOHW_BATCH stores |AES_NOHW_BATCH_SIZE| blocks. Unless otherwise
// specified, it is in bitsliced form.
#[repr(C)]
struct Batch {
    w: [Word; 8],
}

impl Batch {
    // aes_nohw_to_batch initializes |out| with the |num_blocks| blocks from |in|.
    // |num_blocks| must be at most |AES_NOHW_BATCH|.
    fn from_bytes(input: &[[u8; BLOCK_LEN]]) -> Self {
        prefixed_extern! {
            fn aes_nohw_to_batch(out: *mut Batch, input: *const u8, num_blocks: c::size_t);
        }
        let mut r = MaybeUninit::uninit();
        unsafe {
            aes_nohw_to_batch(r.as_mut_ptr(), input.as_ptr().cast::<u8>(), input.len());
            r.assume_init()
        }
    }

    // aes_nohw_batch_set sets the |i|th block of |batch| to |in|. |batch| is in
    // compact form.
    fn set(&mut self, input: &[Word; BLOCK_WORDS], i: usize) {
        prefixed_extern! {
            fn aes_nohw_batch_set(batch: *mut Batch, input: &[Word; BLOCK_WORDS], i: usize);
        }
        unsafe { aes_nohw_batch_set(self, input, i) }
    }

    // aes_nohw_transpose converts |batch| to and from bitsliced form. It divides
    // the 8 × word_size bits into AES_NOHW_BATCH_SIZE × AES_NOHW_BATCH_SIZE squares
    // and transposes each square.
    fn transpose(&mut self) {
        prefixed_extern! {
            fn aes_nohw_transpose(batch: &mut Batch);
        }
        unsafe {
            aes_nohw_transpose(self);
        }
    }

    // aes_nohw_to_batch writes the first |num_blocks| blocks in |batch| to |out|.
    // |num_blocks| must be at most |AES_NOHW_BATCH|.
    fn into_bytes(self, out: &mut [[u8; BLOCK_LEN]]) {
        prefixed_extern! {
            fn aes_nohw_from_batch(out: *mut u8, num_blocks: c::size_t, batch: &Batch);
        }
        unsafe { aes_nohw_from_batch(out.as_mut_ptr().cast::<u8>(), out.len(), &self) }
    }

    fn encrypt(&mut self, key: &Schedule, num_rounds: usize) {
        prefixed_extern! {
            fn aes_nohw_encrypt_batch(key: &Schedule, num_rounds: usize, batch: &mut Batch);
        }
        unsafe { aes_nohw_encrypt_batch(key, num_rounds, self) }
    }
}

// Key schedule.

// An AES_NOHW_SCHEDULE is an expanded bitsliced AES key schedule. It is
// suitable for encryption or decryption. It is as large as |AES_NOHW_BATCH|
// |AES_KEY|s so it should not be used as a long-term key representation.
#[repr(C)]
struct Schedule {
    // keys is an array of batches, one for each round key. Each batch stores
    // |AES_NOHW_BATCH_SIZE| copies of the round key in bitsliced form.
    keys: [Batch; MAX_ROUNDS + 1],
}

impl Schedule {
    fn expand_round_keys(key: &AES_KEY) -> Self {
        Self {
            keys: array::from_fn(|i| {
                let tmp: [Word; BLOCK_WORDS] = unsafe { core::mem::transmute(key.rd_key[i]) };

                let mut r = Batch { w: [0; 8] };
                // Copy the round key into each block in the batch.
                for j in 0..BATCH_SIZE {
                    r.set(&tmp, j);
                }
                r.transpose();
                r
            }),
        }
    }
}

fn encrypt_block(key: &AES_KEY, in_out: &mut [u8; BLOCK_LEN]) {
    let sched = Schedule::expand_round_keys(key);
    let mut batch = Batch::from_bytes(core::slice::from_ref(in_out));
    batch.encrypt(&sched, usize_from_u32(key.rounds));
    batch.into_bytes(core::slice::from_mut(in_out));
}
