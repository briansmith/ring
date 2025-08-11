// Copyright 2019-2025 Brian Smith.
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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    super::{sha2::sha2_32::K_32, w32::W32, w64::W64, word::Word},
    CHAINING_WORDS,
};
use crate::digest::sha2::sha2_64::K_64;
use core::ops::{BitXor, Shr};

#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86_64"
    ),
    allow(dead_code)
)]
#[inline]
pub(super) fn block_data_order<S, const BLOCK_LEN: usize, const BYTES_LEN: usize>(
    mut H: [S; CHAINING_WORDS],
    M: &[[u8; BLOCK_LEN]],
) -> [S; CHAINING_WORDS]
where
    for<'a> &'a S::Bytes: From<&'a [u8; BYTES_LEN]>,
    S: Sha2 + From<S::Leaky>,
{
    for M in M {
        let (M, remainder) = M.as_chunks::<BYTES_LEN>();
        debug_assert!(remainder.is_empty());

        // FIPS 180-4 {6.2.2, 6.4.2} Step 1
        //
        // TODO(MSRV): Use `let W: [S::from(0); S::ROUNDS]` instead; depends on
        // https://github.com/rust-lang/rust/issues/43408.
        let mut W = S::zero_w();
        let W = W.as_mut();
        W.iter_mut().zip(M).for_each(|(Wt, Mt)| {
            let Mt: &S::Bytes = Mt.into();
            *Wt = S::from_be_bytes(*Mt);
        });
        for t in 16..S::ROUNDS {
            W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16]
        }

        // FIPS 180-4 {6.2.2, 6.4.2} Step 2
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = H;

        // FIPS 180-4 {6.2.2, 6.4.2} Step 3
        for (Kt, Wt) in S::k_table().as_ref().iter().zip(W.iter()) {
            let Kt = S::from(*Kt);
            let T1 = h + SIGMA_1(e) + ch(e, f, g) + Kt + *Wt;
            let T2 = SIGMA_0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // FIPS 180-4 {6.2.2, 6.4.2} Step 4
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    H
}

// FIPS 180-4 {4.1.1, 4.1.2, 4.1.3}
#[inline(always)]
pub(in super::super) fn ch<W: Word>(x: W, y: W, z: W) -> W {
    (x & y) | (!x & z)
}

// FIPS 180-4 {4.1.1, 4.1.2, 4.1.3}
#[inline(always)]
pub(in super::super) fn maj<W: Word>(x: W, y: W, z: W) -> W {
    (x & y) | (x & z) | (y & z)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn SIGMA_0<S: Sha2>(x: S) -> S {
    x.rotr(S::BIG_SIGMA_0.0) ^ x.rotr(S::BIG_SIGMA_0.1) ^ x.rotr(S::BIG_SIGMA_0.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn SIGMA_1<S: Sha2>(x: S) -> S {
    x.rotr(S::BIG_SIGMA_1.0) ^ x.rotr(S::BIG_SIGMA_1.1) ^ x.rotr(S::BIG_SIGMA_1.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn sigma_0<S: Sha2>(x: S) -> S {
    x.rotr(S::SMALL_SIGMA_0.0) ^ x.rotr(S::SMALL_SIGMA_0.1) ^ (x >> S::SMALL_SIGMA_0.2)
}

// FIPS 180-4 {4.1.2, 4.1.3}
#[inline(always)]
fn sigma_1<S: Sha2>(x: S) -> S {
    x.rotr(S::SMALL_SIGMA_1.0) ^ x.rotr(S::SMALL_SIGMA_1.1) ^ (x >> S::SMALL_SIGMA_1.2)
}

/// A SHA-2 input word.
pub(super) trait Sha2: Word + BitXor<Output = Self> + Shr<usize, Output = Self> {
    const BIG_SIGMA_0: (u32, u32, u32);
    const BIG_SIGMA_1: (u32, u32, u32);
    const SMALL_SIGMA_0: (u32, u32, usize);
    const SMALL_SIGMA_1: (u32, u32, usize);

    const ROUNDS: usize;

    type W: AsRef<[Self]> + AsMut<[Self]>;
    fn zero_w() -> Self::W;

    type KTable: AsRef<[Self::Leaky]> + Sized;
    fn k_table() -> &'static Self::KTable;
}

// SHA-256
impl Sha2 for W32 {
    // FIPS 180-4 4.1.2
    const BIG_SIGMA_0: (u32, u32, u32) = (2, 13, 22);
    const BIG_SIGMA_1: (u32, u32, u32) = (6, 11, 25);
    const SMALL_SIGMA_0: (u32, u32, usize) = (7, 18, 3);
    const SMALL_SIGMA_1: (u32, u32, usize) = (17, 19, 10);

    // FIPS 180-4 {6.2.2} Step 1
    const ROUNDS: usize = 64;

    type W = [Self; Self::ROUNDS];
    fn zero_w() -> Self::W {
        [Self::zero(); Self::ROUNDS]
    }

    // FIPS 180-4 4.2.2
    type KTable = [Self::Leaky; Self::ROUNDS];
    fn k_table() -> &'static Self::KTable {
        K_32.as_ref()
    }
}

// SHA-384 and SHA-512
impl Sha2 for W64 {
    // FIPS 180-4 4.1.3
    const BIG_SIGMA_0: (u32, u32, u32) = (28, 34, 39);
    const BIG_SIGMA_1: (u32, u32, u32) = (14, 18, 41);
    const SMALL_SIGMA_0: (u32, u32, usize) = (1, 8, 7);
    const SMALL_SIGMA_1: (u32, u32, usize) = (19, 61, 6);

    // FIPS 180-4 {6.4.2} Step 1
    const ROUNDS: usize = 80;

    type W = [Self; Self::ROUNDS];
    fn zero_w() -> Self::W {
        [Self::zero(); Self::ROUNDS]
    }

    // FIPS 180-4 4.2.3
    type KTable = [Self::Leaky; Self::ROUNDS];
    fn k_table() -> &'static Self::KTable {
        K_64.as_ref()
    }
}
