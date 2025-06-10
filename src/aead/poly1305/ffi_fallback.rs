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
        prefixed_extern! {
            fn CRYPTO_poly1305_finish(statep: &mut poly1305_state_st, mac: &mut [u8; TAG_LEN]);
        }
        let mut tag = Tag([0u8; TAG_LEN]);
        unsafe { CRYPTO_poly1305_finish(&mut self.state, &mut tag.0) }
        tag
    }
}
