// Copyright 2015-2016 Brian Smith.
// Portions Copyright (c) 2014, 2015, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// TODO: enforce maximum input length.

use super::{Tag, TAG_LEN};
use crate::{bssl, c, constant_time, error, polyfill};
use core;

/// A Poly1305 key.
pub struct Key([u8; KEY_LEN]);

impl From<[u8; KEY_LEN]> for Key {
    fn from(value: [u8; 32]) -> Self { Key(value) }
}

pub struct Context {
    opaque: Opaque,
    nonce: Nonce,
    buf: [u8; BLOCK_LEN],
    buf_used: usize,
    func: Funcs,
}

/// The memory manipulated by the assembly.
#[repr(C, align(8))]
struct Opaque([u8; OPAQUE_LEN]);
const OPAQUE_LEN: usize = 192;

impl Context {
    #[inline]
    pub fn from_key(Key(key): Key) -> Context {
        extern "C" {
            fn GFp_poly1305_blocks(
                state: &mut Opaque, input: *const u8, len: c::size_t, should_pad: Pad,
            );
            fn GFp_poly1305_emit(state: &mut Opaque, mac: &mut [u8; TAG_LEN], nonce: &Nonce);
        }

        #[inline]
        fn read_u32(buf: &[u8]) -> u32 {
            polyfill::slice::u32_from_le_u8(slice_as_array_ref!(buf, 4).unwrap())
        }

        let (key, nonce) = key.split_at(16);
        let key = DerivedKey(slice_as_array_ref!(key, 16).unwrap());

        let mut ctx = Context {
            opaque: Opaque([0u8; OPAQUE_LEN]),
            // TODO: When we can get explicit alignment, make `nonce` an
            // aligned `u8[16]` and get rid of this `u8[16]` -> `u32[4]`
            // conversion.
            nonce: Nonce([
                read_u32(&nonce[0..4]),
                read_u32(&nonce[4..8]),
                read_u32(&nonce[8..12]),
                read_u32(&nonce[12..16]),
            ]),
            buf: [0; BLOCK_LEN],
            buf_used: 0,
            func: Funcs {
                blocks_fn: GFp_poly1305_blocks,
                emit_fn: GFp_poly1305_emit,
            },
        };

        // On some platforms `init()` doesn't initialize `funcs`. The
        // return value of `init()` indicates whether it did or not. Since
        // we already gave `func` a default value above, we can ignore the
        // return value assuming `init()` doesn't change `func` if it chose
        // not to initialize it. Note that this is different than what
        // BoringSSL does.
        let _ = init(&mut ctx.opaque, key, &mut ctx.func);

        ctx
    }

    pub fn update(&mut self, mut input: &[u8]) {
        let Context {
            opaque,
            buf,
            buf_used,
            func,
            ..
        } = self;
        if *buf_used != 0 {
            let todo = core::cmp::min(input.len(), BLOCK_LEN - *buf_used);

            buf[*buf_used..(*buf_used + todo)].copy_from_slice(&input[..todo]);
            *buf_used += todo;
            input = &input[todo..];

            if *buf_used == BLOCK_LEN {
                func.blocks(opaque, buf, Pad::Pad);
                *buf_used = 0;
            }
        }

        if input.len() >= BLOCK_LEN {
            let todo = input.len() & !(BLOCK_LEN - 1);
            let (complete_blocks, remainder) = input.split_at(todo);
            func.blocks(opaque, complete_blocks, Pad::Pad);
            input = remainder;
        }

        if input.len() != 0 {
            buf[..input.len()].copy_from_slice(input);
            *buf_used = input.len();
        }
    }

    pub(super) fn finish(mut self) -> Tag {
        let Context {
            opaque,
            nonce,
            buf,
            buf_used,
            func,
        } = &mut self;
        if *buf_used != 0 {
            buf[*buf_used] = 1;
            for byte in &mut buf[(*buf_used + 1)..] {
                *byte = 0;
            }
            func.blocks(opaque, &buf[..], Pad::AlreadyPadded);
        }

        func.emit(opaque, nonce)
    }
}

pub fn verify(key: Key, msg: &[u8], tag: &[u8; 16]) -> Result<(), error::Unspecified> {
    let Tag(calculated_tag) = sign(key, msg);
    constant_time::verify_slices_are_equal(&calculated_tag, tag)
}

pub(super) fn sign(key: Key, msg: &[u8]) -> Tag {
    let mut ctx = Context::from_key(key);
    ctx.update(msg);
    ctx.finish()
}

#[cfg(test)]
pub fn check_state_layout() {
    let required_state_size = if cfg!(target_arch = "x86") {
        // See comment above `_poly1305_init_sse2` in poly1305-x86.pl.
        Some(4 * (5 + 1 + 4 + 2 + 4 * 9))
    } else if cfg!(target_arch = "x86_64") {
        // See comment above `__poly1305_block` in poly1305-x86_64.pl.
        Some(4 * (5 + 1 + 2 * 2 + 2 + 4 * 9))
    } else {
        // TODO(davidben): Figure out the layout of the struct. For now,
        // `OPAQUE_LEN` is taken from OpenSSL.
        None
    };

    if let Some(required_state_size) = required_state_size {
        assert!(core::mem::size_of::<Opaque>() >= required_state_size);
    }
}

/// The length of a `key`.
pub const KEY_LEN: usize = 2 * BLOCK_LEN;

struct DerivedKey<'a>(&'a [u8; BLOCK_LEN]);

#[repr(transparent)]
struct Nonce([u32; BLOCK_LEN / 4]);

const BLOCK_LEN: usize = 16;

#[repr(C)]
struct Funcs {
    blocks_fn:
        unsafe extern "C" fn(&mut Opaque, input: *const u8, input_len: c::size_t, should_pad: Pad),
    emit_fn: unsafe extern "C" fn(&mut Opaque, &mut [u8; TAG_LEN], nonce: &Nonce),
}

#[inline]
fn init(state: &mut Opaque, key: DerivedKey, func: &mut Funcs) -> Result<(), error::Unspecified> {
    extern "C" {
        fn GFp_poly1305_init_asm(
            state: &mut Opaque, key: &[u8; BLOCK_LEN], out_func: &mut Funcs,
        ) -> bssl::Result;
    }
    Result::from(unsafe { GFp_poly1305_init_asm(state, &key.0, func) })
}

#[repr(u32)]
enum Pad {
    AlreadyPadded = 0,
    Pad = 1,
}

impl Funcs {
    #[inline]
    fn blocks(&self, state: &mut Opaque, data: &[u8], should_pad: Pad) {
        unsafe {
            (self.blocks_fn)(state, data.as_ptr(), data.len(), should_pad);
        }
    }

    #[inline]
    fn emit(&self, state: &mut Opaque, nonce: &Nonce) -> Tag {
        let mut tag = Tag([0; TAG_LEN]);
        unsafe {
            (self.emit_fn)(state, &mut tag.0, nonce);
        }
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::{TAG_LEN, *};
    use crate::{error, test};
    use core;

    #[test]
    pub fn test_state_layout() { check_state_layout(); }

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::from_file("src/aead/poly1305_test.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, KEY_LEN).unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let expected_mac = slice_as_array_ref!(&expected_mac, TAG_LEN).unwrap();

            // Test single-shot operation.
            {
                let key = Key::from(key.clone());
                let mut ctx = Context::from_key(key);
                ctx.update(&input);
                let Tag(actual_mac) = ctx.finish();
                assert_eq!(expected_mac, &actual_mac);
            }
            {
                let key = Key::from(key.clone());
                let Tag(actual_mac) = sign(key, &input);
                assert_eq!(expected_mac, &actual_mac);
            }
            {
                let key = Key::from(key.clone());
                assert_eq!(Ok(()), verify(key, &input, &expected_mac));
            }

            // Test streaming byte-by-byte.
            {
                let key = Key::from(key.clone());
                let mut ctx = Context::from_key(key);
                for chunk in input.chunks(1) {
                    ctx.update(chunk);
                }
                let Tag(actual_mac) = ctx.finish();
                assert_eq!(expected_mac, &actual_mac);
            }

            test_poly1305_simd(0, key, &input, expected_mac)?;
            test_poly1305_simd(16, key, &input, expected_mac)?;
            test_poly1305_simd(32, key, &input, expected_mac)?;
            test_poly1305_simd(48, key, &input, expected_mac)?;

            Ok(())
        })
    }

    fn test_poly1305_simd(
        excess: usize, key: &[u8; KEY_LEN], input: &[u8], expected_mac: &[u8; TAG_LEN],
    ) -> Result<(), error::Unspecified> {
        let key = Key::from(key.clone());
        let mut ctx = Context::from_key(key);

        // Some implementations begin in non-SIMD mode and upgrade on demand.
        // Stress the upgrade path.
        let init = core::cmp::min(input.len(), 16);
        ctx.update(&input[..init]);

        let long_chunk_len = 128 + excess;
        for chunk in input[init..].chunks(long_chunk_len + excess) {
            if chunk.len() > long_chunk_len {
                let (long, short) = chunk.split_at(long_chunk_len);

                // Feed 128 + |excess| bytes to test SIMD mode.
                ctx.update(long);

                // Feed |excess| bytes to ensure SIMD mode can handle short
                // inputs.
                ctx.update(short);
            } else {
                // Handle the last chunk.
                ctx.update(chunk);
            }
        }

        let Tag(actual_mac) = ctx.finish();
        assert_eq!(expected_mac, &actual_mac);

        Ok(())
    }
}
