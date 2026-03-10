// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM4 block cipher (GB/T 32907-2016).
//!
//! SM4 uses a 128-bit key, processes 128-bit blocks, and applies 32 rounds
//! of a Feistel-like structure. This module provides only the block cipher
//! primitive; AEAD mode is in [`super::sm4_gcm`].
//!
//! # Security note
//! This is an unaudited, experimental pure-Rust implementation using a
//! lookup-table S-box. It is NOT constant-time with respect to the key
//! or plaintext due to table lookups.

use super::{aes::Counter, Overlapping};

/// SM4 key length: 128 bits = 16 bytes.
pub(in super::super) const KEY_LEN: usize = 16;

pub(in super::super) const BLOCK_LEN: usize = 16;

const ZERO_BLOCK: [u8; BLOCK_LEN] = [0u8; BLOCK_LEN];

// GB/T 32907-2016 Section 6.2.1: S-box.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

// GB/T 32907-2016 Section 6.3.3: Family key FK.
const FK: [u32; 4] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC];

// GB/T 32907-2016 Section 6.3.3: Constant key CK.
#[rustfmt::skip]
const CK: [u32; 32] = [
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
];

// Non-linear transformation τ: apply S-box to each of the four bytes (Section 6.2.1).
#[inline(always)]
fn tau(a: u32) -> u32 {
    let b = a.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

// Linear transformation L for the round function (Section 6.2.2).
// L(B) = B XOR (B<<<2) XOR (B<<<10) XOR (B<<<18) XOR (B<<<24)
#[inline(always)]
fn l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

// Linear transformation L' for key expansion (Section 6.3.2).
// L'(B) = B XOR (B<<<13) XOR (B<<<23)
#[inline(always)]
fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

// Round function T = L ∘ τ (Section 6.2.3).
#[inline(always)]
fn t_round(a: u32) -> u32 {
    l(tau(a))
}

// Key expansion transformation T' = L' ∘ τ (Section 6.3.2).
#[inline(always)]
fn t_key(a: u32) -> u32 {
    l_prime(tau(a))
}

/// Expanded SM4 key (32 round subkeys).
#[derive(Clone)]
pub(in super::super) struct Key {
    rk: [u32; 32],
}

impl Key {
    /// Derive 32 round keys from a 16-byte SM4 key (GB/T 32907-2016 Section 6.3).
    pub(in super::super) fn new(key_bytes: &[u8; KEY_LEN]) -> Self {
        // Load master key as four big-endian u32 words.
        let mk: [u32; 4] = core::array::from_fn(|i| {
            u32::from_be_bytes(key_bytes[4 * i..4 * i + 4].try_into().unwrap())
        });

        // k[0..4] = MK XOR FK (initialization).
        let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

        // Generate each of the 32 round keys.
        let mut rk = [0u32; 32];
        for (i, rk_i) in rk.iter_mut().enumerate() {
            // rk[i] = k[i] XOR T'(k[i+1] XOR k[i+2] XOR k[i+3] XOR CK[i])
            let next = k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i];
            *rk_i = k[i % 4] ^ t_key(next);
            k[i % 4] = *rk_i;
        }

        Self { rk }
    }

    /// Encrypt one 16-byte block using SM4 (GB/T 32907-2016 Section 6.1).
    #[inline]
    pub(in super::super) fn encrypt_block(&self, block: [u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        // Load as four big-endian u32 words X[0..4].
        let mut x: [u32; 4] = core::array::from_fn(|i| {
            u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
        });

        // Apply 32 rounds: X[i+4] = X[i] XOR T(X[i+1] XOR X[i+2] XOR X[i+3] XOR rk[i]).
        for i in 0..32usize {
            let tmp = x[1] ^ x[2] ^ x[3] ^ self.rk[i];
            let new_x = x[0] ^ t_round(tmp);
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = new_x;
        }

        // Reverse output: ciphertext = (X[35], X[34], X[33], X[32]).
        let mut out = [0u8; BLOCK_LEN];
        for i in 0..4usize {
            out[4 * i..4 * i + 4].copy_from_slice(&x[3 - i].to_be_bytes());
        }
        out
    }

    /// CTR32 mode over a mutable slice of blocks. Increments the counter's last four bytes
    /// (big-endian) once per block. Used by SM4-GCM for whole-block encryption/decryption.
    #[inline]
    pub(in super::super) fn ctr32_encrypt_blocks(
        &self,
        data: &mut [[u8; BLOCK_LEN]],
        ctr: &mut Counter,
    ) {
        for block in data.iter_mut() {
            let iv = ctr.increment();
            let keystream = self.encrypt_block(*iv.as_ref());
            for (d, k) in block.iter_mut().zip(keystream.iter()) {
                *d ^= k;
            }
        }
    }

    /// CTR32 mode over an `Overlapping` buffer (in-place, input may alias output).
    /// The buffer length must be a multiple of `BLOCK_LEN`.
    ///
    /// Reason: GCM open needs to read ciphertext (for GHASH) and write plaintext into
    /// the same buffer; `Overlapping` expresses this aliasing relationship.
    pub(in super::super) fn ctr32_encrypt_within(
        &self,
        in_out: Overlapping<'_>,
        ctr: &mut Counter,
    ) {
        // SAFETY: `with_input_output_len` provides raw pointers satisfying the Overlapping
        // invariant: `input` is valid for `len` reads and `output` is valid for `len` writes.
        in_out.with_input_output_len(|input: *const u8, output: *mut u8, len| {
            assert_eq!(len % BLOCK_LEN, 0);
            let n_blocks = len / BLOCK_LEN;
            for i in 0..n_blocks {
                let iv = ctr.increment();
                let keystream = self.encrypt_block(*iv.as_ref());
                let in_block: [u8; BLOCK_LEN] = unsafe {
                    core::ptr::read(input.add(i * BLOCK_LEN) as *const [u8; BLOCK_LEN])
                };
                let mut out_block = ZERO_BLOCK;
                for j in 0..BLOCK_LEN {
                    out_block[j] = in_block[j] ^ keystream[j];
                }
                unsafe {
                    core::ptr::write(output.add(i * BLOCK_LEN) as *mut [u8; BLOCK_LEN], out_block);
                }
            }
        });
    }
}
