// Copyright 2015-2016 Brian Smith.
// Copyright 2016 Simon Sapin.
// Copyright 2016 Sam Scott.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use c;
use core::num::Wrapping;
use polyfill;

use super::MAX_CHAINING_LEN;

// SHA-256: 512-bit blocks.
const BLOCK_LEN_256: usize = 512 / 8;

// SHA-384, SHA-512: 1024-bit blocks.
const BLOCK_LEN_512: usize = 1024 / 8;

// SHA-256: state is 256 bits.
pub const CHAINING_LEN_256: usize = 256 / 8;
// SHA-384, SHA-512: state is 512 bits.
pub const CHAINING_LEN_512: usize = 512 / 8;

// Length of the state as number of words.
const CHAINING_WORDS_256: usize = CHAINING_LEN_256 / 4;
const CHAINING_WORDS_512: usize = CHAINING_LEN_512 / 8;

type W32 = Wrapping<u32>;
type W64 = Wrapping<u64>;

macro_rules! ch {
    ($x:expr, $y:expr, $z:expr) => (($x & $y) ^ (!$x & $z))
}
macro_rules! parity {
    ($x:expr, $y:expr, $z:expr) => ($x ^ $y ^ $z)
}
macro_rules! maj {
    ($x:expr, $y:expr, $z:expr) => (($x & $y) ^ ($x & $z) ^ ($y & $z))
}
macro_rules! rotr {
    ($x:expr, $n:expr) => (Wrapping($x.0.rotate_right($n)))
}

// SHA256 sigma functions
#[inline]
fn big_s0_256(x: W32) -> W32   { rotr!(rotr!(rotr!(x, 9) ^ x, 11) ^ x, 2) }

#[inline]
fn big_s1_256(x: W32) -> W32   { rotr!(rotr!(rotr!(x, 14) ^ x, 5) ^ x, 6) }

#[inline]
fn small_s0_256(x: W32) -> W32 { rotr!((rotr!(x, 11) ^ x), 7)  ^ (x >> 3) }

#[inline]
fn small_s1_256(x: W32) -> W32 { rotr!((rotr!(x, 2)  ^ x), 17) ^ (x >> 10) }

// SHA512 sigma functions
#[inline]
fn big_s0_512(x: W64) -> W64   { rotr!(rotr!(rotr!(x, 5) ^ x, 6) ^ x, 28) }

#[inline]
fn big_s1_512(x: W64) -> W64   { rotr!(rotr!(rotr!(x, 23) ^ x, 4) ^ x, 14) }

#[inline]
fn small_s0_512(x: W64) -> W64 { rotr!((rotr!(x, 7) ^ x), 1)  ^ (x >> 7) }

#[inline]
fn small_s1_512(x: W64) -> W64 { rotr!((rotr!(x, 42) ^ x), 19)  ^ (x >> 6) }

pub fn block_data_order_256(state: &mut [u64; MAX_CHAINING_LEN / 8],
                            data: &[u8],
                            num: c::size_t) {

    // Converts state to array of Wrapping<u32> values.
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = polyfill::slice::as_wrapping_mut(state);
    let state = &mut state[..CHAINING_WORDS_256];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS_256).unwrap();

    // Message schedule
    let mut w: [W32; 64] = [Wrapping(0); 64];
    for i in 0..num {
        let block = &data[i * BLOCK_LEN_256..][..BLOCK_LEN_256];
        for t in 0..16 {
            let word = slice_as_array_ref!(&block[t * 4..][..4], 4).unwrap();
            w[t] = Wrapping(polyfill::slice::u32_from_be_u8(word))
        }
        for t in 16..64 {
            w[t] = small_s1_256(w[t - 2])  + w[t - 7]
                 + small_s0_256(w[t - 15]) + w[t - 16];
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for t in 0..64 {
            let t1 = h + big_s1_256(e) + ch!(e, f, g)
                       + Wrapping(K_256[t]) + w[t];

            let t2 = big_s0_256(a) + maj!(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state[0] = a + state[0];
        state[1] = b + state[1];
        state[2] = c + state[2];
        state[3] = d + state[3];
        state[4] = e + state[4];
        state[5] = f + state[5];
        state[6] = g + state[6];
        state[7] = h + state[7];
    }
}

pub fn block_data_order_512(state: &mut [u64; MAX_CHAINING_LEN / 8],
                            data: &[u8],
                            num: c::size_t) {

    // Converts state to array of Wrapping<u64> values.
    let state = polyfill::slice::as_wrapping_mut(state);
    let state = &mut state[..CHAINING_WORDS_512];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS_512).unwrap();

    // Message schedule
    let mut w: [W64; 80] = [Wrapping(0); 80];
    for i in 0..num {
        let block = &data[i * BLOCK_LEN_512..][..BLOCK_LEN_512];
        for t in 0..16 {
            let word = slice_as_array_ref!(&block[t * 8..][..8], 8).unwrap();
            w[t] = Wrapping(polyfill::slice::u64_from_be_u8(word))
        }
        for t in 16..80 {
            w[t] = small_s1_512(w[t - 2]) + w[t - 7]
                 + small_s0_512(w[t - 15]) + w[t - 16];
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for t in 0..80 {
            let t1 = h + big_s1_512(e) + ch!(e, f, g) + Wrapping(K_512[t])
                       + w[t];

            let t2 = big_s0_512(a) + maj!(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state[0] = a + state[0];
        state[1] = b + state[1];
        state[2] = c + state[2];
        state[3] = d + state[3];
        state[4] = e + state[4];
        state[5] = f + state[5];
        state[6] = g + state[6];
        state[7] = h + state[7];
    }
}

// SHA256 constants K
const K_256: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

// SHA512 constants K
const K_512: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd,
      0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
      0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
      0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c,
      0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
      0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2,
      0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4,
      0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210,
      0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2,
      0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
      0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
      0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8,
      0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364,
      0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
      0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a,
      0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
      0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63,
      0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
      0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72,
      0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9,
      0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
      0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
      0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae,
      0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493,
      0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6,
      0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];
