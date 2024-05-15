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
    super::overlapping::IndexError, Block, Counter, EncryptBlock, EncryptCtr32, Iv, KeyBytes,
    Overlapping, AES_KEY, BLOCK_LEN, MAX_ROUNDS,
};
use crate::{bb, c, polyfill::usize_from_u32};
use core::{
    array, cmp,
    mem::{self, size_of, MaybeUninit},
    num::NonZeroU32,
    slice,
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

type Word = bb::Word;
const WORD_SIZE: usize = size_of::<Word>();
const BATCH_SIZE: usize = WORD_SIZE / 2;
#[allow(clippy::cast_possible_truncation)]
const BATCH_SIZE_U32: u32 = BATCH_SIZE as u32;

const BLOCK_WORDS: usize = 16 / WORD_SIZE;

fn compact_block(input: &[u8; 16]) -> [Word; BLOCK_WORDS] {
    prefixed_extern! {
        fn aes_nohw_compact_block(out: *mut [Word; BLOCK_WORDS], input: &[u8; 16]);
    }
    let mut block = MaybeUninit::uninit();
    unsafe {
        aes_nohw_compact_block(block.as_mut_ptr(), input);
        block.assume_init()
    }
}

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
        let mut r = Self {
            w: Default::default(),
        };
        input.iter().enumerate().for_each(|(i, input)| {
            let block = compact_block(input);
            r.set(&block, i);
        });
        r.transpose();
        r
    }

    // aes_nohw_batch_set sets the |i|th block of |batch| to |in|. |batch| is in
    // compact form.
    fn set(&mut self, input: &[Word; BLOCK_WORDS], i: usize) {
        prefixed_extern! {
            fn aes_nohw_batch_set(batch: *mut Batch, input: &[Word; BLOCK_WORDS], i: usize);
        }
        unsafe { aes_nohw_batch_set(self, input, i) }
    }

    fn encrypt(mut self, key: &Schedule, rounds: usize, out: &mut [[u8; BLOCK_LEN]]) {
        assert!(out.len() <= BATCH_SIZE);
        prefixed_extern! {
            fn aes_nohw_encrypt_batch(key: &Schedule, num_rounds: usize, batch: &mut Batch);
            fn aes_nohw_from_batch(out: *mut [u8; BLOCK_LEN], num_blocks: c::size_t, batch: &Batch);
        }
        unsafe {
            aes_nohw_encrypt_batch(key, rounds, &mut self);
            aes_nohw_from_batch(out.as_mut_ptr(), out.len(), &self);
        }
    }

    fn transpose(&mut self) {
        prefixed_extern! {
            fn aes_nohw_transpose(batch: &mut Batch);
        }
        unsafe { aes_nohw_transpose(self) }
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
                let tmp: [Word; BLOCK_WORDS] = unsafe { mem::transmute(key.rd_key[i]) };

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

impl EncryptBlock for Key {
    fn encrypt_block(&self, mut block: Block) -> Block {
        let sched = Schedule::expand_round_keys(&self.inner);
        let batch = Batch::from_bytes(slice::from_ref(&block));
        batch.encrypt(
            &sched,
            usize_from_u32(self.inner.rounds),
            slice::from_mut(&mut block),
        );
        block
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_encrypt_block(self, iv, block)
    }
}

impl EncryptCtr32 for Key {
    fn ctr32_encrypt_within(&self, mut in_out: Overlapping<'_>, ctr: &mut Counter) {
        assert_eq!(in_out.len() % BLOCK_LEN, 0);

        // XXX(unwrap): The caller is responsible for ensuring that the input is
        // short enough to avoid overflow.
        let blocks = match NonZeroU32::new(u32::try_from(in_out.len() / 16).unwrap()) {
            Some(n) => n,
            None => return,
        };

        let sched = Schedule::expand_round_keys(&self.inner);

        let initial_iv = *ctr.as_bytes_less_safe();
        // XXX(overflow): The caller is responsible to ensure this doesn't
        // wrap/overflow.
        ctr.increment_by_less_safe(blocks);

        const _ALIGNMENT_MAKES_SENSE: () =
            assert!(size_of::<Word>() == 4 || size_of::<Word>() == 8 || size_of::<Word>() == 16);

        #[repr(align(16))] // Was `align(WORD_SIZE)` in the C version.
        struct AlignedIvs([[u8; BLOCK_LEN]; BATCH_SIZE]);

        let ctr: &[u8; 4] = initial_iv[12..].try_into().unwrap();
        let mut ctr = u32::from_be_bytes(*ctr);

        let mut ivs = AlignedIvs([initial_iv; BATCH_SIZE]);

        // XXX(perf): Unwanted zero initialization here that isn't in the original.
        let mut enc_ivs: AlignedIvs = AlignedIvs([[0u8; BLOCK_LEN]; BATCH_SIZE]);

        let mut blocks = usize_from_u32(blocks.get());
        assert!(blocks > 0);

        loop {
            // Update counters.
            for i in 0..BATCH_SIZE_U32 {
                let iv = &mut ivs.0[usize_from_u32(i)];
                let iv_ctr: &mut [u8; 4] = (&mut iv[12..]).try_into().unwrap();
                // HAZARD: The caller is responsible for ensuring this is a
                // valid, unused, counter.
                // HAZARD: The caller is responsible for ensuring this addition
                // doesn't actually wrap.
                *iv_ctr = ctr.wrapping_add(i).to_be_bytes();
            }

            let todo = cmp::min(BATCH_SIZE, blocks);
            let batch = Batch::from_bytes(&ivs.0[..todo]);
            let enc_ivs = &mut enc_ivs.0[..todo];
            batch.encrypt(&sched, usize_from_u32(self.inner.rounds), enc_ivs);

            for enc_iv in enc_ivs {
                in_out = in_out
                    .split_first_chunk::<BLOCK_LEN>(|in_out| {
                        bb::xor_assign_at_start(enc_iv.as_mut(), in_out.input());
                        in_out.into_unwritten_output().copy_from_slice(enc_iv);
                    })
                    .unwrap_or_else(|_: IndexError| unreachable!());
            }

            blocks -= todo;
            if blocks == 0 {
                break;
            }
            ctr = ctr.wrapping_add(BATCH_SIZE_U32);
        }
    }
}
