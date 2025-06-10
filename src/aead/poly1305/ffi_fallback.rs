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

use super::{Key, Tag, BLOCK_LEN, TAG_LEN};
use crate::{c, polyfill};
use core::num::{NonZeroUsize, Wrapping};

type W32 = Wrapping<u32>;
type W64 = Wrapping<u64>;

#[inline(always)]
fn lo(a: W64) -> W32 {
    #[allow(clippy::cast_possible_truncation)]
    Wrapping(a.0 as u32)
}

const _5: W32 = Wrapping(5);

// XXX/TODO(MSRV): change to `pub(super)`.
pub(in super::super) struct State {
    state: poly1305_state_st,
}

// Keep in sync with `poly1305_state_st` in poly1305.c
#[repr(C, align(64))]
struct poly1305_state_st {
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
    pub(super) fn new_context(Key { key }: Key) -> super::Context {
        let (t, key) = key.split_at(BLOCK_LEN);
        let t: &[u8; BLOCK_LEN] = t.try_into().unwrap();
        let key: &[u8; BLOCK_LEN] = key.try_into().unwrap();

        let (t, _) = polyfill::slice::as_chunks(&t[..]);

        let mut t1 = Wrapping(u32::from_le_bytes(t[1]));
        let mut t2 = Wrapping(u32::from_le_bytes(t[2]));
        let mut t3 = Wrapping(u32::from_le_bytes(t[3]));
        let mut t0 = Wrapping(u32::from_le_bytes(t[0]));

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
            state: poly1305_state_st {
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
            },
        })
    }

    // `input.len % BLOCK_LEN == 0` must be true for every call except the
    // final one.
    pub(super) fn update_internal(&mut self, input: &[u8]) {
        prefixed_extern! {
            fn CRYPTO_poly1305_update(
                state: &mut poly1305_state_st,
                input: *const u8,
                in_len: c::NonZero_size_t);
        }
        if let Some(len) = NonZeroUsize::new(input.len()) {
            let input = input.as_ptr();
            unsafe { CRYPTO_poly1305_update(&mut self.state, input, len) }
        }
    }

    pub(super) fn finish(mut self) -> Tag {
        #[allow(non_upper_case_globals)]
        const _0x3ffffff: W32 = Wrapping(0x3ffffff);

        let state = &mut self.state;

        let mut b = state.h0 >> 26;
        state.h0 &= _0x3ffffff;
        state.h1 += b;
        b = state.h1 >> 26;
        state.h1 &= _0x3ffffff;
        state.h2 += b;
        b = state.h2 >> 26;
        state.h2 &= _0x3ffffff;
        state.h3 += b;
        b = state.h3 >> 26;
        state.h3 &= _0x3ffffff;
        state.h4 += b;
        b = state.h4 >> 26;
        state.h4 &= _0x3ffffff;
        state.h0 += b * _5;

        let mut g0 = state.h0 + _5;
        b = g0 >> 26;
        g0 &= _0x3ffffff;
        let mut g1 = state.h1 + b;
        b = g1 >> 26;
        g1 &= _0x3ffffff;
        let mut g2 = state.h2 + b;
        b = g2 >> 26;
        g2 &= _0x3ffffff;
        let mut g3 = state.h3 + b;
        b = g3 >> 26;
        g3 &= _0x3ffffff;
        let g4 = state.h4 + b - Wrapping(1 << 26);

        b = (g4 >> 31) - Wrapping(1);
        let nb = !b;
        state.h0 = (state.h0 & nb) | (g0 & b);
        state.h1 = (state.h1 & nb) | (g1 & b);
        state.h2 = (state.h2 & nb) | (g2 & b);
        state.h3 = (state.h3 & nb) | (g3 & b);
        state.h4 = (state.h4 & nb) | (g4 & b);

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
        let f0 = f::<0, 26, 0>(state.h0, state.h1, &state.key);
        let mut f1 = f::<6, 20, 1>(state.h1, state.h2, &state.key);
        let mut f2 = f::<12, 14, 2>(state.h2, state.h3, &state.key);
        let mut f3 = f::<18, 8, 3>(state.h3, state.h4, &state.key);

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
