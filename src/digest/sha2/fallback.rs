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
    super::{w32::W32, w64::W64, word::Word},
    CHAINING_WORDS,
};
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
        for (Kt, Wt) in S::K.as_ref().iter().zip(W.iter()) {
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

    type LeakyW: AsRef<[Self::Leaky]>;
    const K: &'static Self::LeakyW;
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
    type LeakyW = [Self::Leaky; Self::ROUNDS];
    const K: &'static Self::LeakyW = &[
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
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
    type LeakyW = [Self::Leaky; Self::ROUNDS];
    const K: &'static Self::LeakyW = &[
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];
}
