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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{ffi::U128, KeyValue, UpdateBlock, UpdateBlocks, Xi, BLOCK_LEN};
use crate::polyfill::ArraySplitMap as _;

#[derive(Clone)]
pub struct Key {
    h: U128,
}

impl Key {
    pub(in super::super) fn new(value: KeyValue) -> Self {
        Self { h: init(value) }
    }
}

impl UpdateBlock for Key {
    fn update_block(&self, xi: &mut Xi, a: [u8; BLOCK_LEN]) {
        xi.bitxor_assign(a);
        gmult(xi, self.h);
    }
}

impl UpdateBlocks for Key {
    fn update_blocks(&self, xi: &mut Xi, input: &[[u8; BLOCK_LEN]]) {
        ghash(xi, self.h, input);
    }
}

match_target_word_bits! {
    64 => {
        mod w64;
        use w64::gcm_mul64_nohw;
    },
    32 => {
        mod w32;
        use w32::gcm_mul64_nohw;
    },
}

fn init(value: KeyValue) -> U128 {
    let xi = value.into_inner();

    // We implement GHASH in terms of POLYVAL, as described in RFC 8452. This
    // avoids a shift by 1 in the multiplication, needed to account for bit
    // reversal losing a bit after multiplication, that is,
    // rev128(X) * rev128(Y) = rev255(X*Y).
    //
    // Per Appendix A, we run mulX_POLYVAL. Note this is the same transformation
    // applied by |gcm_init_clmul|, etc. Note |Xi| has already been byteswapped.
    //
    // See also slide 16 of
    // https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
    let mut lo = xi[1];
    let mut hi = xi[0];

    let mut carry = hi >> 63;
    carry = 0u64.wrapping_sub(carry);

    hi <<= 1;
    hi |= lo >> 63;
    lo <<= 1;

    // The irreducible polynomial is 1 + x^121 + x^126 + x^127 + x^128, so we
    // conditionally add 0xc200...0001.
    lo ^= carry & 1;
    hi ^= carry & 0xc200000000000000;

    // This implementation does not use the rest of |Htable|.
    U128 { hi, lo }
}

fn gcm_polyval_nohw(xi: &mut [u64; 2], h: U128) {
    // Karatsuba multiplication. The product of |Xi| and |H| is stored in |r0|
    // through |r3|. Note there is no byte or bit reversal because we are
    // evaluating POLYVAL.
    let (r0, mut r1) = gcm_mul64_nohw(xi[0], h.lo);
    let (mut r2, mut r3) = gcm_mul64_nohw(xi[1], h.hi);
    let (mut mid0, mut mid1) = gcm_mul64_nohw(xi[0] ^ xi[1], h.hi ^ h.lo);
    mid0 ^= r0 ^ r2;
    mid1 ^= r1 ^ r3;
    r2 ^= mid1;
    r1 ^= mid0;

    // Now we multiply our 256-bit result by x^-128 and reduce. |r2| and
    // |r3| shifts into position and we must multiply |r0| and |r1| by x^-128. We
    // have:
    //
    //       1 = x^121 + x^126 + x^127 + x^128
    //  x^-128 = x^-7 + x^-2 + x^-1 + 1
    //
    // This is the GHASH reduction step, but with bits flowing in reverse.

    // The x^-7, x^-2, and x^-1 terms shift bits past x^0, which would require
    // another reduction steps. Instead, we gather the excess bits, incorporate
    // them into |r0| and |r1| and reduce once. See slides 17-19
    // of https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf.
    r1 ^= (r0 << 63) ^ (r0 << 62) ^ (r0 << 57);

    // 1
    r2 ^= r0;
    r3 ^= r1;

    // x^-1
    r2 ^= r0 >> 1;
    r2 ^= r1 << 63;
    r3 ^= r1 >> 1;

    // x^-2
    r2 ^= r0 >> 2;
    r2 ^= r1 << 62;
    r3 ^= r1 >> 2;

    // x^-7
    r2 ^= r0 >> 7;
    r2 ^= r1 << 57;
    r3 ^= r1 >> 7;

    *xi = [r2, r3];
}

fn gmult(xi: &mut Xi, h: U128) {
    with_swapped_xi(xi, |swapped| {
        gcm_polyval_nohw(swapped, h);
    })
}

fn ghash(xi: &mut Xi, h: U128, input: &[[u8; BLOCK_LEN]]) {
    with_swapped_xi(xi, |swapped| {
        input.iter().for_each(|&input| {
            let input = input.array_split_map(u64::from_be_bytes);
            swapped[0] ^= input[1];
            swapped[1] ^= input[0];
            gcm_polyval_nohw(swapped, h);
        });
    });
}

#[inline]
fn with_swapped_xi(Xi(xi): &mut Xi, f: impl FnOnce(&mut [u64; 2])) {
    let unswapped: [u64; 2] = xi.array_split_map(u64::from_be_bytes);
    let mut swapped: [u64; 2] = [unswapped[1], unswapped[0]];
    f(&mut swapped);
    let (xi_0, xi_1) = xi.split_at_mut(BLOCK_LEN / 2);
    xi_0.copy_from_slice(&u64::to_be_bytes(swapped[1]));
    xi_1.copy_from_slice(&u64::to_be_bytes(swapped[0]));
}
