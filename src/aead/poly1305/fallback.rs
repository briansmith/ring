// Copyright 2015-2025 Brian Smith.
// Portions Copyright (c) 2014, 2015, Google Inc.
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

use super::{Key, Tag, BLOCK_LEN, TAG_LEN};
use crate::polyfill::sliceutil;
use core::num::Wrapping;

type W32 = Wrapping<u32>;
type W64 = Wrapping<u64>;

#[inline(always)]
fn lo(a: W64) -> W32 {
    #[allow(clippy::cast_possible_truncation)]
    Wrapping(a.0 as u32)
}

#[inline(always)]
fn widen(a: W32) -> W64 {
    Wrapping(u64::from(a.0))
}

#[inline(always)]
fn w64(hi: W32, lo: W32) -> W64 {
    (widen(hi) << 32) | widen(lo)
}

#[inline(always)]
fn widening_mul(a: W32, b: W32) -> W64 {
    widen(a) * widen(b)
}

const _5: W32 = Wrapping(5);
#[allow(non_upper_case_globals)]
const _0x3ffffff: W32 = Wrapping(0x3ffffff);

// XXX/TODO(MSRV): change to `pub(super)`.
#[repr(align(64))]
pub(in super::super) struct State {
    r0: W32,
    r1: W32,
    r2: W32,
    r3: W32,
    r4: W32,
    s1: W32,
    s2: W32,
    s3: W32,
    s4: W32,
    h0: W32,
    h1: W32,
    h2: W32,
    h3: W32,
    h4: W32,
    key: [u8; BLOCK_LEN],
}

impl State {
    pub(super) fn new_context(key: Key) -> super::Context {
        let (t, key) = key.split();
        let (t, _) = t[..].as_chunks();

        let mut t0 = Wrapping(u32::from_le_bytes(t[0]));
        let mut t1 = Wrapping(u32::from_le_bytes(t[1]));
        let mut t2 = Wrapping(u32::from_le_bytes(t[2]));
        let mut t3 = Wrapping(u32::from_le_bytes(t[3]));

        let r0 = t0 & Wrapping(0x3ffffff);
        t0 >>= 26;
        t0 |= t1 << 6;
        let r1 = t0 & Wrapping(0x3ffff03);
        t1 >>= 20;
        t1 |= t2 << 12;
        let r2 = t1 & Wrapping(0x3ffc0ff);
        t2 >>= 14;
        t2 |= t3 << 18;
        let r3 = t2 & Wrapping(0x3f03fff);
        t3 >>= 8;
        let r4 = t3 & Wrapping(0x00fffff);

        super::Context::Fallback(Self {
            r0,
            r1,
            r2,
            r3,
            r4,
            s1: r1 * _5,
            s2: r2 * _5,
            s3: r3 * _5,
            s4: r4 * _5,
            h1: Wrapping(0),
            h2: Wrapping(0),
            h3: Wrapping(0),
            h4: Wrapping(0),
            h0: Wrapping(0),
            key: *key,
        })
    }

    // `input.len % BLOCK_LEN == 0` must be true for every call except the
    // final one.
    pub(super) fn update_internal(&mut self, input: &[u8]) {
        let (whole, remainder) = input.as_chunks::<BLOCK_LEN>();

        whole.iter().for_each(|input| {
            let (input, _) = input.as_chunks();
            let t0 = Wrapping(u32::from_le_bytes(input[0]));
            let t1 = Wrapping(u32::from_le_bytes(input[1]));
            let t2 = Wrapping(u32::from_le_bytes(input[2]));
            let t3 = Wrapping(u32::from_le_bytes(input[3]));

            self.h0 += t0 & _0x3ffffff;
            self.h1 += lo(w64(t1, t0) >> 26) & _0x3ffffff;
            self.h2 += lo(w64(t2, t1) >> 20) & _0x3ffffff;
            self.h3 += lo(w64(t3, t2) >> 14) & _0x3ffffff;
            self.h4 += (t3 >> 8) | Wrapping(1 << 24);

            self.mul()
        });

        if !remainder.is_empty() {
            let mut mp = [0; BLOCK_LEN];
            sliceutil::overwrite_at_start(&mut mp, remainder);
            mp[remainder.len()] = 1;

            let (input, _) = mp.as_chunks();
            let t0 = Wrapping(u32::from_le_bytes(input[0]));
            let t1 = Wrapping(u32::from_le_bytes(input[1]));
            let t2 = Wrapping(u32::from_le_bytes(input[2]));
            let t3 = Wrapping(u32::from_le_bytes(input[3]));

            self.h0 += t0 & _0x3ffffff;
            self.h1 += lo(w64(t1, t0) >> 26) & _0x3ffffff;
            self.h2 += lo(w64(t2, t1) >> 20) & _0x3ffffff;
            self.h3 += lo(w64(t3, t2) >> 14) & _0x3ffffff;
            self.h4 += t3 >> 8;

            self.mul();
        }
    }

    #[inline(always)]
    fn mul(&mut self) {
        let mut t: [W64; 5] = [
            widening_mul(self.h0, self.r0)
                + widening_mul(self.h1, self.s4)
                + widening_mul(self.h2, self.s3)
                + widening_mul(self.h3, self.s2)
                + widening_mul(self.h4, self.s1),
            widening_mul(self.h0, self.r1)
                + widening_mul(self.h1, self.r0)
                + widening_mul(self.h2, self.s4)
                + widening_mul(self.h3, self.s3)
                + widening_mul(self.h4, self.s2),
            widening_mul(self.h0, self.r2)
                + widening_mul(self.h1, self.r1)
                + widening_mul(self.h2, self.r0)
                + widening_mul(self.h3, self.s4)
                + widening_mul(self.h4, self.s3),
            widening_mul(self.h0, self.r3)
                + widening_mul(self.h1, self.r2)
                + widening_mul(self.h2, self.r1)
                + widening_mul(self.h3, self.r0)
                + widening_mul(self.h4, self.s4),
            widening_mul(self.h0, self.r4)
                + widening_mul(self.h1, self.r3)
                + widening_mul(self.h2, self.r2)
                + widening_mul(self.h3, self.r1)
                + widening_mul(self.h4, self.r0),
        ];

        self.h0 = lo(t[0]) & _0x3ffffff;
        let c = t[0] >> 26;
        t[1] += c;
        self.h1 = lo(t[1]) & _0x3ffffff;
        let b = lo(t[1] >> 26);
        t[2] += widen(b);
        self.h2 = lo(t[2]) & _0x3ffffff;
        let b = lo(t[2] >> 26);
        t[3] += widen(b);
        self.h3 = lo(t[3]) & _0x3ffffff;
        let b = lo(t[3] >> 26);
        t[4] += widen(b);
        self.h4 = lo(t[4]) & _0x3ffffff;
        let b = lo(t[4] >> 26);
        self.h0 += b * _5;
    }

    pub(super) fn finish(mut self) -> Tag {
        let mut b = self.h0 >> 26;
        self.h0 &= _0x3ffffff;
        self.h1 += b;
        b = self.h1 >> 26;
        self.h1 &= _0x3ffffff;
        self.h2 += b;
        b = self.h2 >> 26;
        self.h2 &= _0x3ffffff;
        self.h3 += b;
        b = self.h3 >> 26;
        self.h3 &= _0x3ffffff;
        self.h4 += b;
        b = self.h4 >> 26;
        self.h4 &= _0x3ffffff;
        self.h0 += b * _5;

        let mut g0 = self.h0 + _5;
        b = g0 >> 26;
        g0 &= _0x3ffffff;
        let mut g1 = self.h1 + b;
        b = g1 >> 26;
        g1 &= _0x3ffffff;
        let mut g2 = self.h2 + b;
        b = g2 >> 26;
        g2 &= _0x3ffffff;
        let mut g3 = self.h3 + b;
        b = g3 >> 26;
        g3 &= _0x3ffffff;
        let g4 = self.h4 + b - Wrapping(1 << 26);

        b = (g4 >> 31) - Wrapping(1);
        let nb = !b;
        self.h0 = (self.h0 & nb) | (g0 & b);
        self.h1 = (self.h1 & nb) | (g1 & b);
        self.h2 = (self.h2 & nb) | (g2 & b);
        self.h3 = (self.h3 & nb) | (g3 & b);
        self.h4 = (self.h4 & nb) | (g4 & b);

        #[inline(always)]
        fn f<const H0: u8, const H1: u8, const I: usize>(
            h0: W32,
            h1: W32,
            key: &[u8; BLOCK_LEN],
        ) -> W64 {
            let h = (h0.0 >> H0) | (h1.0 << H1);
            let key: &[u8; 4] = (&key[(I * 4)..][..4]).try_into().unwrap();
            let key = u32::from_le_bytes(*key);
            Wrapping(u64::from(h)) + Wrapping(u64::from(key))
        }
        let f0 = f::<0, 26, 0>(self.h0, self.h1, &self.key);
        let mut f1 = f::<6, 20, 1>(self.h1, self.h2, &self.key);
        let mut f2 = f::<12, 14, 2>(self.h2, self.h3, &self.key);
        let mut f3 = f::<18, 8, 3>(self.h3, self.h4, &self.key);

        #[inline(always)]
        fn store_le_lo_bytes<const I: usize>(tag: &mut Tag, a: W64) {
            let out: &mut [u8; 4] = (&mut tag.0[(I * 4)..][..4]).try_into().unwrap();
            *out = lo(a).0.to_le_bytes();
        }
        let mut tag = Tag([0u8; TAG_LEN]);
        store_le_lo_bytes::<0>(&mut tag, f0);
        f1 += f0 >> 32;
        store_le_lo_bytes::<1>(&mut tag, f1);
        f2 += f1 >> 32;
        store_le_lo_bytes::<2>(&mut tag, f2);
        f3 += f2 >> 32;
        store_le_lo_bytes::<3>(&mut tag, f3);

        tag
    }
}
