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
use crate::{
    bb,
    polyfill::{self, usize_from_u32},
};
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

type Word = bb::Word;
const WORD_SIZE: usize = size_of::<Word>();
const BATCH_SIZE: usize = WORD_SIZE / 2;
#[allow(clippy::cast_possible_truncation)]
const BATCH_SIZE_U32: u32 = BATCH_SIZE as u32;

const BLOCK_WORDS: usize = 16 / WORD_SIZE;

#[inline(always)]
fn shift_left<const I: u32>(a: Word) -> Word {
    a << (I * BATCH_SIZE_U32)
}

#[inline(always)]
fn shift_right<const I: u32>(a: Word) -> Word {
    a >> (I * BATCH_SIZE_U32)
}

#[inline(always)]
fn words_to_u32s(words: [Word; BLOCK_WORDS]) -> [u32; 4] {
    unsafe { mem::transmute(words) }
}

#[inline(always)]
fn u32s_to_words(u32s: [u32; 4]) -> [Word; BLOCK_WORDS] {
    unsafe { mem::transmute(u32s) }
}

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

fn uncompact_block(input: &[Word; BLOCK_WORDS], out: &mut [u8; BLOCK_LEN]) {
    prefixed_extern! {
        fn aes_nohw_uncompact_block(out: *mut [u8; BLOCK_LEN], input: &[Word; BLOCK_WORDS]);
    }
    unsafe {
        aes_nohw_uncompact_block(out, input);
    }
}

// aes_nohw_swap_bits is a variation on a delta swap. It swaps the bits in
// |*a & (mask << shift)| with the bits in |*b & mask|. |mask| and
// |mask << shift| must not overlap. |mask| is specified as a |uint32_t|, but it
// is repeated to the full width of |aes_word_t|.
fn swap_bits<const A: usize, const B: usize, const MASK_BYTE: u8, const SHIFT: u8>(
    w: &mut [Word; 8],
) {
    // TODO: const MASK: Word = ...
    let mask = Word::from_ne_bytes([MASK_BYTE; core::mem::size_of::<Word>()]);

    // This is a variation on a delta swap.
    let swap = ((w[A] >> SHIFT) ^ w[B]) & mask;
    w[A] ^= swap << SHIFT;
    w[B] ^= swap;
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
        assert!(i < self.w.len());
        prefixed_extern! {
            fn aes_nohw_batch_set(batch: *mut Batch, input: &[Word; BLOCK_WORDS], i: usize);
        }
        unsafe { aes_nohw_batch_set(self, input, i) }
    }

    // aes_nohw_batch_get writes the |i|th block of |batch| to |out|. |batch| is in
    // compact form.
    fn get(&self, i: usize) -> [Word; BLOCK_WORDS] {
        assert!(i < self.w.len());
        array::from_fn(|j| {
            #[cfg(target_pointer_width = "64")]
            const STRIDE: usize = 4;
            #[cfg(target_pointer_width = "32")]
            const STRIDE: usize = 2;

            self.w[i + (j * STRIDE)]
        })
    }

    fn sub_bytes(&mut self) {
        prefixed_extern! {
            fn aes_nohw_sub_bytes(batch: &mut Batch);
        }
        unsafe { aes_nohw_sub_bytes(self) };
    }

    fn add_round_key(&mut self, key: &Batch) {
        bb::xor_assign_at_start(&mut self.w, &key.w)
    }

    fn shift_rows(&mut self) {
        prefixed_extern! {
            fn aes_nohw_shift_rows(batch: &mut Batch);
        }
        unsafe { aes_nohw_shift_rows(self) };
    }

    fn mix_columns(&mut self) {
        prefixed_extern! {
            fn aes_nohw_mix_columns(batch: &mut Batch);
        }
        unsafe { aes_nohw_mix_columns(self) };
    }

    // aes_nohw_from_batch writes the first |num_blocks| blocks in |batch| to |out|.
    // |num_blocks| must be at most |AES_NOHW_BATCH|.
    pub fn into_bytes(self, out: &mut [[u8; BLOCK_LEN]]) {
        assert!(out.len() <= BATCH_SIZE);

        // TODO: Why did the original code copy `self`?
        let mut copy = self;
        copy.transpose();
        out.iter_mut().enumerate().for_each(|(i, out)| {
            let block = copy.get(i);
            uncompact_block(&block, out);
        });
    }

    fn encrypt(mut self, key: &Schedule, rounds: usize, out: &mut [[u8; BLOCK_LEN]]) {
        assert!(out.len() <= BATCH_SIZE);
        self.add_round_key(&key.keys[0]);
        key.keys[1..rounds].iter().for_each(|key| {
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(key);
        });
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(&key.keys[rounds]);
        self.into_bytes(out);
    }

    // aes_nohw_transpose converts |batch| to and from bitsliced form. It divides
    // the 8 × word_size bits into AES_NOHW_BATCH_SIZE × AES_NOHW_BATCH_SIZE squares
    // and transposes each square.
    fn transpose(&mut self) {
        const _: () = assert!(BATCH_SIZE == 2 || BATCH_SIZE == 4);

        // Swap bits with index 0 and 1 mod 2 (0x55 = 0b01010101).
        swap_bits::<0, 1, 0x55, 1>(&mut self.w);
        swap_bits::<2, 3, 0x55, 1>(&mut self.w);
        swap_bits::<4, 5, 0x55, 1>(&mut self.w);
        swap_bits::<6, 7, 0x55, 1>(&mut self.w);

        if BATCH_SIZE >= 4 {
            // Swap bits with index 0-1 and 2-3 mod 4 (0x33 = 0b00110011).
            swap_bits::<0, 2, 0x33, 2>(&mut self.w);
            swap_bits::<1, 3, 0x33, 2>(&mut self.w);
            swap_bits::<4, 6, 0x33, 2>(&mut self.w);
            swap_bits::<5, 7, 0x33, 2>(&mut self.w);
        }
    }
}

#[inline(always)]
fn rotate_rows_down(v: Word) -> Word {
    #[cfg(target_pointer_width = "64")]
    {
        ((v >> 4) & 0x0fff0fff0fff0fff) | ((v << 12) & 0xf000f000f000f000)
    }

    #[cfg(target_pointer_width = "32")]
    {
        ((v >> 2) & 0x3f3f3f3f) | ((v << 6) & 0xc0c0c0c0)
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
                let tmp: [Word; BLOCK_WORDS] = u32s_to_words(key.rd_key[i]);

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

impl Key {
    pub(in super::super) fn new(bytes: KeyBytes<'_>) -> Self {
        let mut r = Self {
            inner: AES_KEY::invalid_zero(),
        };
        match bytes {
            KeyBytes::AES_128(bytes) => setup_key_128(&mut r.inner, bytes),
            KeyBytes::AES_256(bytes) => setup_key_256(&mut r.inner, bytes),
        }
        r
    }
}

static RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// aes_nohw_rcon_slice returns the |i|th group of |AES_NOHW_BATCH_SIZE| bits in
// |rcon|, stored in a |aes_word_t|.
#[inline(always)]
fn rcon_slice(rcon: u8, i: usize) -> Word {
    let rcon = (rcon >> (i * BATCH_SIZE)) & ((1 << BATCH_SIZE) - 1);
    rcon.into()
}

fn setup_key_128(key: &mut AES_KEY, input: &[u8; 128 / 8]) {
    key.rounds = 10;

    let mut block = compact_block(input);
    key.rd_key[0] = words_to_u32s(block);

    key.rd_key[1..=10]
        .iter_mut()
        .zip(RCON)
        .for_each(|(rd_key, rcon)| {
            let sub = sub_block(&block);
            *rd_key = derive_round_key(&mut block, sub, rcon);
        });
}

fn encrypt_block(key: &AES_KEY, in_out: &mut [u8; BLOCK_LEN]) {
    let sched = Schedule::expand_round_keys(key);
    let batch = Batch::from_bytes(core::slice::from_ref(in_out));
    batch.encrypt(&sched, usize_from_u32(key.rounds), array::from_mut(in_out));
}

fn setup_key_256(key: &mut AES_KEY, input: &[u8; 32]) {
    key.rounds = 14;

    // Each key schedule iteration produces two round keys.
    let (input, _) = polyfill::slice::as_chunks(input);
    let mut block1 = compact_block(&input[0]);
    key.rd_key[0] = words_to_u32s(block1);
    let mut block2 = compact_block(&input[1]);
    key.rd_key[1] = words_to_u32s(block2);

    key.rd_key[2..=14]
        .chunks_mut(2)
        .zip(RCON)
        .for_each(|(rd_key_pair, rcon)| {
            let sub = sub_block(&block2);
            rd_key_pair[0] = derive_round_key(&mut block1, sub, rcon);

            if let Some(rd_key_2) = rd_key_pair.get_mut(1) {
                let sub = sub_block(&block1);
                block2.iter_mut().zip(sub).for_each(|(w, sub)| {
                    // Incorporate the transformed word into the first word.
                    *w ^= shift_right::<12>(sub);
                    // Propagate to the remaining words.
                    let v = *w;
                    *w ^= shift_left::<4>(v);
                    *w ^= shift_left::<8>(v);
                    *w ^= shift_left::<12>(v);
                });
                *rd_key_2 = words_to_u32s(block2);
            }
        });
}

fn derive_round_key(
    block: &mut [Word; BLOCK_WORDS],
    sub: [Word; BLOCK_WORDS],
    rcon: u8,
) -> [u32; 4] {
    block
        .iter_mut()
        .zip(sub)
        .enumerate()
        .for_each(|(j, (w, sub))| {
            // Incorporate |rcon| and the transformed word into the first word.
            *w ^= rcon_slice(rcon, j);
            *w ^= shift_right::<12>(rotate_rows_down(sub));
            // Propagate to the remaining words.
            let v = *w;
            *w ^= shift_left::<4>(v);
            *w ^= shift_left::<8>(v);
            *w ^= shift_left::<12>(v);
        });
    words_to_u32s(*block)
}

fn sub_block(input: &[Word; BLOCK_WORDS]) -> [Word; BLOCK_WORDS] {
    let mut batch = Batch {
        w: Default::default(),
    };
    batch.set(input, 0);
    batch.transpose();
    batch.sub_bytes();
    batch.transpose();
    batch.get(0)
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
                        bb::xor_assign_at_start_bytes(enc_iv.as_mut(), in_out.input());
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
