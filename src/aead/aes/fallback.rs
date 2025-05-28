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
    Overlapping, BLOCK_LEN,
};
use crate::{
    bb,
    polyfill::{self, usize_from_u32},
};
use cfg_if::cfg_if;
use core::{array, cmp, mem::size_of, num::NonZeroU32};

#[derive(Clone)]
pub struct Key {
    rd_key_storage: [[Word; BLOCK_WORDS]; Rounds::MAX.into() + 1],
    rounds: Rounds,
}

#[derive(Clone, Copy)]
enum Rounds {
    Aes128,
    Aes256,
}

impl Rounds {
    const MAX: Self = Self::Aes256;

    const fn into(self) -> usize {
        match self {
            Self::Aes128 => 10,
            Self::Aes256 => 14,
        }
    }
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

// aes_nohw_delta_swap returns |a| with bits |a & mask| and
// |a & (mask << shift)| swapped. |mask| and |mask << shift| may not overlap.
#[inline(always)]
fn delta_swap<const MASK: Word, const SHIFT: u8>(a: Word) -> Word {
    // See
    // https://reflectionsonsecurity.wordpress.com/2014/05/11/efficient-bit-permutation-using-delta-swaps/
    let b = (a ^ (a >> SHIFT)) & MASK;
    a ^ b ^ (b << SHIFT)
}

// In the 32-bit and 64-bit implementations, a block spans multiple words.
// |aes_nohw_compact_block| must permute bits across different words. First we
// implement |aes_nohw_compact_word| which performs a smaller version of the
// transformation which stays within a single word.
//
// These transformations are generalizations of the output of
// http://programming.sirrida.de/calcperm.php on smaller inputs.
#[inline(always)]
fn compact_word(a: Word) -> Word {
    let a = Word::from_le(a);
    cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            // Numbering the 64/2 = 16 4-bit chunks, least to most significant, we swap
            // quartets of those chunks:
            //   0 1 2 3 | 4 5 6 7 | 8  9 10 11 | 12 13 14 15 =>
            //   0 2 1 3 | 4 6 5 7 | 8 10  9 11 | 12 14 13 15
            let a = delta_swap::<0x00f000f000f000f0, 4>(a);
            // Swap quartets of 8-bit chunks (still numbering by 4-bit chunks):
            //   0 2 1 3 | 4 6 5 7 | 8 10  9 11 | 12 14 13 15 =>
            //   0 2 4 6 | 1 3 5 7 | 8 10 12 14 |  9 11 13 15
            let a = delta_swap::<0x0000ff000000ff00, 8>(a);
            // Swap quartets of 16-bit chunks (still numbering by 4-bit chunks):
            //   0 2 4 6 | 1  3  5  7 | 8 10 12 14 | 9 11 13 15 =>
            //   0 2 4 6 | 8 10 12 14 | 1  3  5  7 | 9 11 13 15
            delta_swap::<0x00000000ffff0000, 16>(a)
        } else if #[cfg(target_pointer_width = "32")] {
            // Numbering the 32/2 = 16 pairs of bits, least to most significant, we swap:
            //   0 1 2 3 | 4 5 6 7 | 8  9 10 11 | 12 13 14 15 =>
            //   0 4 2 6 | 1 5 3 7 | 8 12 10 14 |  9 13 11 15
            // Note:  0x00cc = 0b0000_0000_1100_1100
            //   0x00cc << 6 = 0b0011_0011_0000_0000
            let a = delta_swap::<0x00cc00cc, 6>(a);
            // Now we swap groups of four bits (still numbering by pairs):
            //   0 4 2  6 | 1 5 3  7 | 8 12 10 14 | 9 13 11 15 =>
            //   0 4 8 12 | 1 5 9 13 | 2  6 10 14 | 3  7 11 15
            // Note: 0x0000_f0f0 << 12 = 0x0f0f_0000
            delta_swap::<0x0000f0f0, 12>(a)
        } else {
            unimplemented!()
        }
    }
}

#[inline(always)]
fn uncompact_word(a: Word) -> Word {
    #[cfg(target_pointer_width = "64")]
    let r = {
        // Reverse the steps of |aes_nohw_uncompact_word|.
        let a = delta_swap::<0x00000000ffff0000, 16>(a);
        let a = delta_swap::<0x0000ff000000ff00, 8>(a);
        delta_swap::<0x00f000f000f000f0, 4>(a)
    };

    #[cfg(target_pointer_width = "32")]
    let r = {
        let a = delta_swap::<0x0000f0f0, 12>(a);
        delta_swap::<0x00cc00cc, 6>(a)
    };

    Word::to_le(r)
}

fn compact_block(input: &[u8; 16]) -> [Word; BLOCK_WORDS] {
    let (input, _) = polyfill::slice::as_chunks(input);
    let out: [Word; BLOCK_WORDS] = array::from_fn(|i| Word::from_ne_bytes(input[i]));
    let a0 = compact_word(out[0]);
    let a1 = compact_word(out[1]);

    #[cfg(target_pointer_width = "64")]
    let r = [
        (a0 & 0x00000000ffffffff) | (a1 << 32),
        (a1 & 0xffffffff00000000) | (a0 >> 32),
    ];

    #[cfg(target_pointer_width = "32")]
    let r = {
        let a2 = compact_word(out[2]);
        let a3 = compact_word(out[3]);
        // Note clang, when building for ARM Thumb2, will sometimes miscompile
        // expressions such as (a0 & 0x0000ff00) << 8, particularly when building
        // without optimizations. This bug was introduced in
        // https://reviews.llvm.org/rL340261 and fixed in
        // https://reviews.llvm.org/rL351310. The following is written to avoid this.
        [
            Word::from_le_bytes([lo(a0), lo(a1), lo(a2), lo(a3)]),
            Word::from_le_bytes([lo(a0 >> 8), lo(a1 >> 8), lo(a2 >> 8), lo(a3 >> 8)]),
            Word::from_le_bytes([lo(a0 >> 16), lo(a1 >> 16), lo(a2 >> 16), lo(a3 >> 16)]),
            Word::from_le_bytes([lo(a0 >> 24), lo(a1 >> 24), lo(a2 >> 24), lo(a3 >> 24)]),
        ]
    };

    r
}

fn uncompact_block(out: &mut [u8; BLOCK_LEN], input: &[Word; BLOCK_WORDS]) {
    let a0 = input[0];
    let a1 = input[1];

    #[cfg(target_pointer_width = "64")]
    let [b0, b1] = {
        [
            (a0 & 0x00000000ffffffff) | (a1 << 32),
            (a1 & 0xffffffff00000000) | (a0 >> 32),
        ]
    };

    #[cfg(target_pointer_width = "32")]
    let [b0, b1, b2, b3] = {
        let a2 = input[2];
        let a3 = input[3];

        // Note clang, when building for ARM Thumb2, will sometimes miscompile
        // expressions such as (a0 & 0x0000ff00) << 8, particularly when building
        // without optimizations. This bug was introduced in
        // https://reviews.llvm.org/rL340261 and fixed in
        // https://reviews.llvm.org/rL351310. The following is written to avoid this.
        let b0 = Word::from_le_bytes([lo(a0), lo(a1), lo(a2), lo(a3)]);
        let b1 = Word::from_le_bytes([lo(a0 >> 8), lo(a1 >> 8), lo(a2 >> 8), lo(a3 >> 8)]);
        let b2 = Word::from_le_bytes([lo(a0 >> 16), lo(a1 >> 16), lo(a2 >> 16), lo(a3 >> 16)]);
        let b3 = Word::from_le_bytes([lo(a0 >> 24), lo(a1 >> 24), lo(a2 >> 24), lo(a3 >> 24)]);
        [b0, b1, b2, b3]
    };

    let b0 = uncompact_word(b0);
    let b1 = uncompact_word(b1);

    #[cfg(target_pointer_width = "32")]
    let (b2, b3) = (uncompact_word(b2), uncompact_word(b3));

    let mut out = out.chunks_mut(size_of::<Word>());
    out.next().unwrap().copy_from_slice(&Word::to_ne_bytes(b0));
    out.next().unwrap().copy_from_slice(&Word::to_ne_bytes(b1));

    #[cfg(target_pointer_width = "32")]
    {
        out.next().unwrap().copy_from_slice(&Word::to_ne_bytes(b2));
        out.next().unwrap().copy_from_slice(&Word::to_ne_bytes(b3));
    }
}

#[cfg(target_pointer_width = "32")]
#[inline(always)]
fn lo(w: Word) -> u8 {
    w as u8
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

        // Note the words are interleaved. The order comes from |aes_nohw_transpose|.
        // If |i| is zero and this is the 64-bit implementation, in[0] contains bits
        // 0-3 and in[1] contains bits 4-7. We place in[0] at w[0] and in[1] at
        // w[4] so that bits 0 and 4 are in the correct position. (In general, bits
        // along diagonals of |AES_NOHW_BATCH_SIZE| by |AES_NOHW_BATCH_SIZE| squares
        // will be correctly placed.)
        cfg_if! {
            if #[cfg(target_pointer_width = "64")] {
                self.w[i] = input[0];
                self.w[i + 4] = input[1];
            } else if #[cfg(target_pointer_width = "32")] {
                self.w[i] = input[0];
                self.w[i + 2] = input[1];
                self.w[i + 4] = input[2];
                self.w[i + 6] = input[3];
            } else {
                todo!()
            }
        }
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
            uncompact_block(out, &block);
        });
    }

    fn encrypt(mut self, key: &Schedule, out: &mut [[u8; BLOCK_LEN]]) {
        assert!(out.len() <= BATCH_SIZE);
        self.add_round_key(&key.keys[0]);
        key.keys[1..key.rounds].iter().for_each(|key| {
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(key);
        });
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(&key.keys[key.rounds]);
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
struct Schedule {
    // keys is an array of batches, one for each round key. Each batch stores
    // |AES_NOHW_BATCH_SIZE| copies of the round key in bitsliced form.
    keys: [Batch; Rounds::MAX.into() + 1],
    rounds: usize,
}

impl Schedule {
    fn expand_round_keys(key: &Key) -> Self {
        let rounds = key.rounds.into();

        Self {
            keys: array::from_fn(|i| {
                if i <= rounds {
                    let tmp: [Word; BLOCK_WORDS] = key.rd_key_storage[i];

                    let mut r = Batch { w: [0; 8] };
                    // Copy the round key into each block in the batch.
                    for j in 0..BATCH_SIZE {
                        r.set(&tmp, j);
                    }
                    r.transpose();
                    r
                } else {
                    Batch { w: [0; 8] }
                }
            }),
            rounds,
        }
    }
}

impl Key {
    pub(in super::super) fn new(bytes: KeyBytes<'_>) -> Self {
        match bytes {
            KeyBytes::AES_128(bytes) => setup_key_128(bytes),
            KeyBytes::AES_256(bytes) => setup_key_256(bytes),
        }
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

fn setup_key_128(input: &[u8; 128 / 8]) -> Key {
    let mut block = compact_block(input);

    Key {
        rd_key_storage: array::from_fn(|i| {
            if i == 0 {
                block
            } else if i <= Rounds::Aes128.into() {
                let rcon = RCON[i - 1];
                let sub = sub_block(&block);
                derive_round_key(&mut block, sub, rcon)
            } else {
                Default::default()
            }
        }),
        rounds: Rounds::Aes128,
    }
}

fn setup_key_256(input: &[u8; 32]) -> Key {
    // Each key schedule iteration produces two round keys.
    let (input, _) = polyfill::slice::as_chunks(input);
    let mut block1 = compact_block(&input[0]);
    let mut block2 = compact_block(&input[1]);

    Key {
        rd_key_storage: array::from_fn(|i| {
            if i == 0 {
                block1
            } else if i == 1 {
                block2
            } else {
                let rcon = RCON[(i / 2) - 1];
                if i % 2 == 0 {
                    let sub = sub_block(&block2);
                    derive_round_key(&mut block1, sub, rcon)
                } else {
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
                    block2
                }
            }
        }),
        rounds: Rounds::Aes256,
    }
}

fn derive_round_key(
    block: &mut [Word; BLOCK_WORDS],
    sub: [Word; BLOCK_WORDS],
    rcon: u8,
) -> [Word; BLOCK_WORDS] {
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
    *block
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
    fn encrypt_block(&self, block: Block) -> Block {
        super::encrypt_block_using_encrypt_iv_xor_block(self, block)
    }

    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block {
        super::encrypt_iv_xor_block_using_ctr32(self, iv, block)
    }
}

impl EncryptCtr32 for Key {
    #[inline(never)]
    fn ctr32_encrypt_within(&self, mut in_out: Overlapping<'_>, ctr: &mut Counter) {
        assert_eq!(in_out.len() % BLOCK_LEN, 0);

        // XXX(unwrap): The caller is responsible for ensuring that the input is
        // short enough to avoid overflow.
        let blocks = match NonZeroU32::new(u32::try_from(in_out.len() / 16).unwrap()) {
            Some(n) => n,
            None => return,
        };

        let sched = Schedule::expand_round_keys(self);

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
            batch.encrypt(&sched, enc_ivs);

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
