// Copyright (c) 2014, Google Inc.
// Portions Copyright 2015-2025 Brian Smith.
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

// This implementation was taken from the public domain, neon2 version in
// SUPERCOP by D. J. Bernstein and Peter Schwabe.

#![cfg(all(target_arch = "arm", target_endian = "little"))]

use super::{Key, Tag, BLOCK_LEN};
use crate::{c, cpu::arm::Neon, polyfill::sliceutil};
use core::{ffi::c_int, num::Wrapping};

type W32 = Wrapping<u32>;
const ZERO: W32 = Wrapping(0);
const _1: W32 = Wrapping(1);
const _5: W32 = Wrapping(5);
#[allow(non_upper_case_globals)]
const _3ffffff: W32 = Wrapping(0x3ffffff);

#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct fe1305x2 {
    v: [W32; 12], // for alignment; only using 10
}

impl fe1305x2 {
    const ZERO: Self = Self { v: [ZERO; 12] };
}

prefixed_extern! {
    // `r` may alias with `x`.
    fn openssl_poly1305_neon2_addmulmod(r: *mut fe1305x2, x: *const fe1305x2, y: &fe1305x2,
                                        c: &fe1305x2);
}

fn addmulmod(r: &mut fe1305x2, x: &fe1305x2, y: &fe1305x2, c: &fe1305x2, _: Neon) {
    unsafe { openssl_poly1305_neon2_addmulmod(r, x, y, c) }
}

fn addmulmod_assign(r: &mut fe1305x2, y: &fe1305x2, c: &fe1305x2, _: Neon) {
    let r_mut: *mut fe1305x2 = r;
    let r_const: *const fe1305x2 = r_mut;
    unsafe { openssl_poly1305_neon2_addmulmod(r_mut, r_const, y, c) }
}

fn blocks(r: &mut fe1305x2, precomp: &[fe1305x2; 2], input: &[u8], _: Neon) -> usize {
    prefixed_extern! {
        // TODO: `len: c::NonZero_size_t`?
        fn openssl_poly1305_neon2_blocks(
            x: &mut fe1305x2,
            precomp: &[fe1305x2; 2],
            input: *const u8,
            len: c::size_t) -> c_int;
    }
    let bytes_read =
        unsafe { openssl_poly1305_neon2_blocks(r, precomp, input.as_ptr(), input.len()) };
    bytes_read as usize
}

impl fe1305x2 {
    fn freeze(&mut self) {
        let mut x0 = self.v[0];
        let mut x1 = self.v[2];
        let mut x2 = self.v[4];
        let mut x3 = self.v[6];
        let mut x4 = self.v[8];

        for _ in 0..3 {
            x1 += x0 >> 26;
            x0 &= _3ffffff;
            x2 += x1 >> 26;
            x1 &= _3ffffff;
            x3 += x2 >> 26;
            x2 &= _3ffffff;
            x4 += x3 >> 26;
            x3 &= _3ffffff;
            x0 += _5 * (x4 >> 26);
            x4 &= _3ffffff;
        }

        let mut y0 = x0 + _5;
        let mut y1 = x1 + (y0 >> 26);
        y0 &= _3ffffff;
        let mut y2 = x2 + (y1 >> 26);
        y1 &= _3ffffff;
        let mut y3 = x3 + (y2 >> 26);
        y2 &= _3ffffff;
        let mut y4 = x4 + (y3 >> 26);
        y3 &= _3ffffff;
        let swap = -(y4 >> 26);
        y4 &= _3ffffff;

        y0 ^= x0;
        y1 ^= x1;
        y2 ^= x2;
        y3 ^= x3;
        y4 ^= x4;

        y0 &= swap;
        y1 &= swap;
        y2 &= swap;
        y3 &= swap;
        y4 &= swap;

        y0 ^= x0;
        y1 ^= x1;
        y2 ^= x2;
        y3 ^= x3;
        y4 ^= x4;

        self.v[0] = y0;
        self.v[2] = y1;
        self.v[4] = y2;
        self.v[6] = y3;
        self.v[8] = y4;
    }

    // fe1305x2_tobytearray
    fn to_bytes(&self) -> [u8; BLOCK_LEN] {
        let mut x0 = self.v[0];
        let mut x1 = self.v[2];
        let mut x2 = self.v[4];
        let mut x3 = self.v[6];
        let mut x4 = self.v[8];

        x1 += x0 >> 26;
        x0 &= _3ffffff;
        x2 += x1 >> 26;
        x1 &= _3ffffff;
        x3 += x2 >> 26;
        x2 &= _3ffffff;
        x4 += x3 >> 26;
        x3 &= _3ffffff;

        let mut r = [0u8; 16];
        store32(&mut r, 0, x0 + (x1 << 26));
        store32(&mut r, 4, (x1 >> 6) + (x2 << 20));
        store32(&mut r, 8, (x2 >> 12) + (x3 << 14));
        store32(&mut r, 12, (x3 >> 18) + (x4 << 8));
        r
    }

    // fe1305x2_frombytearray
    fn assign_bytes(&mut self, mut x: &[u8]) {
        let mut t = [0u8; BLOCK_LEN + 1];

        sliceutil::overwrite_at_start(&mut t[..BLOCK_LEN], x);
        let i = x.len().min(BLOCK_LEN);
        x = &x[i..];
        t[i] = 1;

        self.v[0] = _3ffffff & load32(&t, 0);
        self.v[2] = _3ffffff & (load32(&t, 3) >> 2);
        self.v[4] = _3ffffff & (load32(&t, 6) >> 4);
        self.v[6] = _3ffffff & (load32(&t, 9) >> 6);
        self.v[8] = load32(&t, 13);

        if !x.is_empty() {
            sliceutil::overwrite_at_start(&mut t[..BLOCK_LEN], x);
            let i = x.len().min(BLOCK_LEN);
            t[i] = 1;
            t[(i + 1)..].fill(0);

            self.v[1] = _3ffffff & load32(&t, 0);
            self.v[3] = _3ffffff & (load32(&t, 3) >> 2);
            self.v[5] = _3ffffff & (load32(&t, 6) >> 4);
            self.v[7] = _3ffffff & (load32(&t, 9) >> 6);
            self.v[9] = load32(&t, 13);
        } else {
            self.v[1] = ZERO;
            self.v[3] = ZERO;
            self.v[5] = ZERO;
            self.v[7] = ZERO;
            self.v[9] = ZERO;
        }
    }
}

// TODO: Does this really need to be `#[repr(C)]` or `#[repr(align(16))`]? We
// need to read the assembly code and see what assumptions it makes on the
// layout of its inputs. We've already made `fe1305x2` 16-byte aligned and that
// might be all we need.
//
// XXX/TODO(MSRV): change to `pub(super)`.
#[repr(C, align(16))]
pub(in super::super) struct State {
    r: fe1305x2,
    h: fe1305x2,
    c: fe1305x2,
    precomp: [fe1305x2; 2],
    data: [u8; data_len()], // TODO: Does the assembly code use this?

    buf: [u8; 2 * BLOCK_LEN],
    buf_used: c::size_t,

    key: [u8; BLOCK_LEN],

    neon: Neon,
}

impl State {
    // CRYPTO_poly1305_init_neon
    pub(super) fn new_context(key: Key, neon: Neon) -> super::Context {
        let (t, key) = key.split();
        let rv_0_1 = _3ffffff & load32(t, 0);
        let rv_2_3 = Wrapping(0x3ffff03) & (load32(t, 3) >> 2);
        let rv_4_5 = Wrapping(0x3ffc0ff) & (load32(t, 6) >> 4);
        let rv_6_7 = Wrapping(0x3f03fff) & (load32(t, 9) >> 6);
        let rv_8_9 = Wrapping(0x00fffff) & (load32(t, 12) >> 8);
        let rv_10_11 = ZERO;

        let mut result = super::Context::ArmNeon(Self {
            r: fe1305x2 {
                v: [
                    rv_0_1, rv_0_1, rv_2_3, rv_2_3, rv_4_5, rv_4_5, rv_6_7, rv_6_7, rv_8_9, rv_8_9,
                    rv_10_11, rv_10_11,
                ],
            },
            h: fe1305x2 { v: [ZERO; 12] },
            c: fe1305x2 { v: [ZERO; 12] },
            precomp: [fe1305x2 { v: [ZERO; 12] }; 2],
            data: [0u8; data_len()],

            buf: Default::default(),
            buf_used: 0,

            key: *key,

            neon,
        });
        match &mut result {
            super::Context::ArmNeon(State {
                r,
                precomp: [precomp0, precomp1],
                ..
            }) => {
                addmulmod(precomp0, r, r, &fe1305x2::ZERO, neon); // precompute r^2
                addmulmod(precomp1, precomp0, precomp0, &fe1305x2::ZERO, neon); // precompute r^4
            }
            _ => unreachable!(),
        };
        result
    }

    // CRYPTO_poly1305_update_neon
    pub(super) fn update_internal(&mut self, mut input: &[u8]) {
        let neon = self.neon;

        if self.buf_used > 0 {
            let available = &mut self.buf[self.buf_used..];
            let todo = available.len().min(input.len());
            sliceutil::overwrite_at_start(available, input);
            self.buf_used += todo;
            input = &input[todo..];

            if self.buf_used == self.buf.len() && !input.is_empty() {
                addmulmod_assign(&mut self.h, &self.precomp[0], &fe1305x2::ZERO, neon);
                self.c.assign_bytes(&self.buf);
                self.h.v[..10]
                    .iter_mut()
                    .zip(&self.c.v)
                    .for_each(|(v, c)| *v += *c);
                self.buf_used = 0;
            }
        }

        while input.len() > self.buf.len() {
            let mut tlen = input.len().min(1048576);
            tlen -= blocks(&mut self.h, &self.precomp, &input[..tlen], neon);
            input = &input[tlen..];
        }

        if !input.is_empty() {
            sliceutil::overwrite_at_start(&mut self.buf, input);
            self.buf_used = input.len();
        }
    }

    // CRYPTO_poly1305_finish_neon
    pub(super) fn finish(mut self) -> Tag {
        let neon = self.neon;

        let r = &mut self.r;
        let h = &mut self.h;
        let c = &mut self.c;
        let precomp = &mut self.precomp[0];

        addmulmod_assign(h, precomp, &fe1305x2::ZERO, neon);

        if self.buf_used > BLOCK_LEN {
            c.assign_bytes(&self.buf[..self.buf_used]);
            precomp.v[1] = r.v[1];
            precomp.v[3] = r.v[3];
            precomp.v[5] = r.v[5];
            precomp.v[7] = r.v[7];
            precomp.v[9] = r.v[9];
            addmulmod_assign(h, precomp, c, neon);
        } else if self.buf_used > 0 {
            c.assign_bytes(&self.buf[..self.buf_used]);
            r.v[1] = _1;
            r.v[3] = ZERO;
            r.v[5] = ZERO;
            r.v[7] = ZERO;
            r.v[9] = ZERO;
            addmulmod_assign(h, r, c, neon);
        }

        h.v[0] += h.v[1];
        h.v[2] += h.v[3];
        h.v[4] += h.v[5];
        h.v[6] += h.v[7];
        h.v[8] += h.v[9];
        h.freeze();

        c.assign_bytes(&self.key);
        c.v[8] ^= _1 << 24;

        h.v[0] += c.v[0];
        h.v[2] += c.v[2];
        h.v[4] += c.v[4];
        h.v[6] += c.v[6];
        h.v[8] += c.v[8];
        Tag(h.to_bytes())
    }
}

const fn data_len() -> usize {
    128
}

fn store32<'o>(output: &'o mut [u8; BLOCK_LEN], i: usize, value: W32) {
    let output: &'o mut [u8; 4] = (&mut output[i..][..4]).try_into().unwrap();
    *output = u32::to_le_bytes(value.0);
}

#[inline]
fn load32<'i>(t: &'i [u8], i: usize) -> W32 {
    let t: &'i [u8; 4] = (&t[i..][..4]).try_into().unwrap();
    Wrapping(u32::from_le_bytes(*t))
}
