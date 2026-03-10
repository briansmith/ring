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

//! SM3 compression function (GB/T 32905-2016).
//!
//! SM3 processes 512-bit (64-byte) blocks and maintains an 8×32-bit chaining
//! state, structurally identical to SHA-256. This module provides only the
//! inner compression logic; padding and state management are handled by the
//! parent [`crate::digest`] framework via [`sm3_block_data_order`].
//!
//! # Security note
//! This is an unaudited, experimental implementation. The SM3 compression
//! function itself does not process secret key material, so constant-time
//! precautions (beyond those inherent in pure arithmetic) are not required
//! here—in contrast to the SM2 and SM4 implementations.

use super::{BlockLen, sha2::State32};
use core::num::Wrapping;

/// SM3 block length: 512 bits = 64 bytes (same as SHA-256).
pub(super) const BLOCK_LEN: BlockLen = BlockLen::_512;

// GB/T 32905-2016 Section 4.4: Round constants.
// T_j = 79CC4519 for rounds j = 0..15, used as T0.rotate_left(j) each round.
const T0: u32 = 0x79cc4519;
// T_j = 7A879D8A for rounds j = 16..63, used as T1.rotate_left(j) each round.
const T1: u32 = 0x7a879d8a;

// GB/T 32905-2016 Section 4.4, P0: X XOR (X <<< 9) XOR (X <<< 17).
// Used in the round function to update E.
#[inline(always)]
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

// GB/T 32905-2016 Section 4.4, P1: X XOR (X <<< 15) XOR (X <<< 23).
// Used in message expansion to extend W[16..68].
#[inline(always)]
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// Entry point called by [`super::dynstate::sm3_block_data_order`].
///
/// Applies the SM3 compression function to each 64-byte block in `data`,
/// updating `state` in-place. `state` must contain the current 8-word
/// chaining value (initialized to the SM3 IV for the first call).
pub(super) fn sm3_block_data_order(state: &mut State32, data: &[[u8; BLOCK_LEN.into()]]) {
    // Convert Wrapping<u32> chaining state to plain u32 for computation.
    let mut v: [u32; 8] = core::array::from_fn(|i| state[i].0);
    for block in data {
        v = compress(v, block);
    }
    // Write results back as Wrapping<u32>.
    for (s, &vi) in state.iter_mut().zip(v.iter()) {
        *s = Wrapping(vi);
    }
}

/// GB/T 32905-2016 Section 6.2: SM3 compression function.
///
/// Takes the current chaining value `v` and a 64-byte message block,
/// returns the updated chaining value.
#[inline]
#[rustfmt::skip]
fn compress(v: [u32; 8], block: &[u8; BLOCK_LEN.into()]) -> [u32; 8] {
    // --- Message Expansion (GB/T 32905-2016 Section 6.2.2) ---
    //
    // The 512-bit block is expanded into W[0..68] and implicitly W'[j] = W[j] XOR W[j+4].
    let (chunks, remainder) = block.as_chunks::<4>();
    debug_assert!(remainder.is_empty());

    let mut w = [0u32; 68];
    // W[0..15]: load from block bytes in big-endian order.
    for (i, chunk) in chunks.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    // W[j] = P1(W[j-16] XOR W[j-9] XOR (W[j-3] <<< 15)) XOR (W[j-13] <<< 7) XOR W[j-6]
    for j in 16..68 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
    }

    // --- Compression (GB/T 32905-2016 Section 6.2.3) ---
    //
    // Initialize working variables from current chaining value V.
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = v;

    // Rounds 0-15: FF = XOR (parity), GG = XOR (parity).
    for j in 0u32..16 {
        // Reason: T_j is defined as T0 rotated left by j; since j < 32, no masking needed.
        let t_j  = T0.rotate_left(j);
        let ss1  = a.rotate_left(12).wrapping_add(e).wrapping_add(t_j).rotate_left(7);
        let ss2  = ss1 ^ a.rotate_left(12);
        // W'[j] = W[j] XOR W[j+4], used inline to avoid a separate array.
        let jj = j as usize;
        let tt1  = (a ^ b ^ c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w[jj] ^ w[jj + 4]);
        let tt2  = (e ^ f ^ g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[jj]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    // Rounds 16-63: FF = majority, GG = choice.
    for j in 16u32..64 {
        // Reason: T_j is T1 rotated left by j; rotate_left wraps j > 31 via masking internally.
        let t_j  = T1.rotate_left(j);
        let ss1  = a.rotate_left(12).wrapping_add(e).wrapping_add(t_j).rotate_left(7);
        let ss2  = ss1 ^ a.rotate_left(12);
        let jj = j as usize;
        let tt1  = ((a & b) | (a & c) | (b & c))
            .wrapping_add(d).wrapping_add(ss2).wrapping_add(w[jj] ^ w[jj + 4]);
        let tt2  = ((e & f) | (!e & g))
            .wrapping_add(h).wrapping_add(ss1).wrapping_add(w[jj]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }

    // Step 4: XOR working variables with the input chaining value.
    [
        v[0] ^ a, v[1] ^ b, v[2] ^ c, v[3] ^ d,
        v[4] ^ e, v[5] ^ f, v[6] ^ g, v[7] ^ h,
    ]
}
