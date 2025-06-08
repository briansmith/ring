// Copyright (c) 2019, Google Inc.
// Portions Copyright 2020-2024 Brian Smith.
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

// This file is based on BoringSSL's gcm_nohw.c.

// This file contains a implementation of GHASH based on the notes
// in https://bearssl.org/constanttime.html#ghash-for-gcm and the reduction
// algorithm described in
// https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf.
//
// Unlike the BearSSL notes, we use u128 in the 64-bit implementation.

pub(super) fn gcm_mul64_nohw(a: u64, b: u64) -> (u64, u64) {
    #[allow(clippy::cast_possible_truncation)]
    #[inline(always)]
    fn lo(a: u128) -> u64 {
        a as u64
    }

    #[inline(always)]
    fn hi(a: u128) -> u64 {
        lo(a >> 64)
    }

    #[inline(always)]
    fn mul(a: u64, b: u64) -> u128 {
        u128::from(a) * u128::from(b)
    }

    // One term every four bits means the largest term is 64/4 = 16, which barely
    // overflows into the next term. Using one term every five bits would cost 25
    // multiplications instead of 16. It is faster to mask off the bottom four
    // bits of |a|, giving a largest term of 60/4 = 15, and apply the bottom bits
    // separately.
    let a0 = a & 0x1111111111111110;
    let a1 = a & 0x2222222222222220;
    let a2 = a & 0x4444444444444440;
    let a3 = a & 0x8888888888888880;

    let b0 = b & 0x1111111111111111;
    let b1 = b & 0x2222222222222222;
    let b2 = b & 0x4444444444444444;
    let b3 = b & 0x8888888888888888;

    let c0 = mul(a0, b0) ^ mul(a1, b3) ^ mul(a2, b2) ^ mul(a3, b1);
    let c1 = mul(a0, b1) ^ mul(a1, b0) ^ mul(a2, b3) ^ mul(a3, b2);
    let c2 = mul(a0, b2) ^ mul(a1, b1) ^ mul(a2, b0) ^ mul(a3, b3);
    let c3 = mul(a0, b3) ^ mul(a1, b2) ^ mul(a2, b1) ^ mul(a3, b0);

    // Multiply the bottom four bits of |a| with |b|.
    let a0_mask = 0u64.wrapping_sub(a & 1);
    let a1_mask = 0u64.wrapping_sub((a >> 1) & 1);
    let a2_mask = 0u64.wrapping_sub((a >> 2) & 1);
    let a3_mask = 0u64.wrapping_sub((a >> 3) & 1);
    let extra = u128::from(a0_mask & b)
        ^ (u128::from(a1_mask & b) << 1)
        ^ (u128::from(a2_mask & b) << 2)
        ^ (u128::from(a3_mask & b) << 3);

    let lo = (lo(c0) & 0x1111111111111111)
        ^ (lo(c1) & 0x2222222222222222)
        ^ (lo(c2) & 0x4444444444444444)
        ^ (lo(c3) & 0x8888888888888888)
        ^ lo(extra);
    let hi = (hi(c0) & 0x1111111111111111)
        ^ (hi(c1) & 0x2222222222222222)
        ^ (hi(c2) & 0x4444444444444444)
        ^ (hi(c3) & 0x8888888888888888)
        ^ hi(extra);
    (lo, hi)
}
