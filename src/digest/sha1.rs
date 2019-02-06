// Copyright 2015-2016 Brian Smith.
// Copyright 2016 Simon Sapin.
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

use crate::polyfill;
use core::{self, num::Wrapping};
use libc::size_t;

pub const BLOCK_LEN: usize = 512 / 8;
pub const CHAINING_LEN: usize = 160 / 8;
pub const OUTPUT_LEN: usize = 160 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

type W32 = Wrapping<u32>;

#[inline]
fn ch(x: W32, y: W32, z: W32) -> W32 { (x & y) | (!x & z) }

#[inline]
fn parity(x: W32, y: W32, z: W32) -> W32 { x ^ y ^ z }

#[inline]
fn maj(x: W32, y: W32, z: W32) -> W32 { (x & y) | (x & z) | (y & z) }

/// The main purpose in retaining this is to support legacy protocols and OCSP,
/// none of which need a fast SHA-1 implementation.
/// This implementation therefore favors size and simplicity over speed.
/// Unlike SHA-256, SHA-384, and SHA-512,
/// there is no assembly language implementation.
pub(super) unsafe extern "C" fn block_data_order(
    state: &mut super::State, data: *const u8, num: size_t,
) {
    let data = data as *const [[u8; 4]; 16];
    let blocks = core::slice::from_raw_parts(data, num);
    block_data_order_safe(&mut state.as32, blocks)
}

#[inline(always)]
fn block_data_order_safe(state: &mut [Wrapping<u32>; 256 / 32], blocks: &[[[u8; 4]; 16]]) {
    let state = &mut state[..CHAINING_WORDS];

    let mut w: [W32; 80] = [Wrapping(0); 80];
    for block in blocks {
        for t in 0..16 {
            w[t] = Wrapping(polyfill::slice::u32_from_be_u8(block[t]))
        }
        for t in 16..80 {
            let wt = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = polyfill::wrapping_rotate_left_u32(wt, 1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];

        for t in 0..80 {
            let (k, f) = match t {
                0..=19 => (0x5a827999, ch(b, c, d)),
                20..=39 => (0x6ed9eba1, parity(b, c, d)),
                40..=59 => (0x8f1bbcdc, maj(b, c, d)),
                60..=79 => (0xca62c1d6, parity(b, c, d)),
                _ => unreachable!(),
            };
            let tt = polyfill::wrapping_rotate_left_u32(a, 5) + f + e + Wrapping(k) + w[t];
            e = d;
            d = c;
            c = polyfill::wrapping_rotate_left_u32(b, 30);
            b = a;
            a = tt;
        }

        state[0] = state[0] + a;
        state[1] = state[1] + b;
        state[2] = state[2] + c;
        state[3] = state[3] + d;
        state[4] = state[4] + e;
    }
}
