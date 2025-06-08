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

fn gcm_mul32_nohw(a: u32, b: u32) -> u64 {
    #[inline(always)]
    fn mul(a: u32, b: u32) -> u64 {
        u64::from(a) * u64::from(b)
    }

    // One term every four bits means the largest term is 32/4 = 8, which does not
    // overflow into the next term.
    let a0 = a & 0x11111111;
    let a1 = a & 0x22222222;
    let a2 = a & 0x44444444;
    let a3 = a & 0x88888888;

    let b0 = b & 0x11111111;
    let b1 = b & 0x22222222;
    let b2 = b & 0x44444444;
    let b3 = b & 0x88888888;

    let c0 = mul(a0, b0) ^ mul(a1, b3) ^ mul(a2, b2) ^ mul(a3, b1);
    let c1 = mul(a0, b1) ^ mul(a1, b0) ^ mul(a2, b3) ^ mul(a3, b2);
    let c2 = mul(a0, b2) ^ mul(a1, b1) ^ mul(a2, b0) ^ mul(a3, b3);
    let c3 = mul(a0, b3) ^ mul(a1, b2) ^ mul(a2, b1) ^ mul(a3, b0);

    (c0 & 0x1111111111111111)
        | (c1 & 0x2222222222222222)
        | (c2 & 0x4444444444444444)
        | (c3 & 0x8888888888888888)
}

pub(super) fn gcm_mul64_nohw(a: u64, b: u64) -> (u64, u64) {
    #[inline(always)]
    fn lo(a: u64) -> u32 {
        a as u32
    }
    #[inline(always)]
    fn hi(a: u64) -> u32 {
        lo(a >> 32)
    }

    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    // Karatsuba multiplication.
    let lo = gcm_mul32_nohw(a0, b0);
    let hi = gcm_mul32_nohw(a1, b1);
    let mid = gcm_mul32_nohw(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    (lo ^ (mid << 32), hi ^ (mid >> 32))
}
