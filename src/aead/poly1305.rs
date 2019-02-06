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

use super::{
    block::{Block, BLOCK_LEN},
    Tag,
};
use crate::{bssl, error};
use libc::size_t;

/// A Poly1305 key.
pub struct Key([Block; KEY_BLOCKS]);

impl From<[Block; KEY_BLOCKS]> for Key {
    fn from(value: [Block; KEY_BLOCKS]) -> Self { Key(value) }
}

pub const KEY_BLOCKS: usize = 2;

pub struct Context {
    opaque: Opaque,
    nonce: Nonce,
    func: Funcs,
}

/// The memory manipulated by the assembly.
#[repr(C, align(8))]
struct Opaque([u8; OPAQUE_LEN]);
const OPAQUE_LEN: usize = 192;

impl Context {
    #[inline]
    pub fn from_key(Key(key_and_nonce): Key) -> Context {
        extern "C" {
            fn GFp_poly1305_blocks(
                state: &mut Opaque, input: *const u8, len: size_t, should_pad: Pad,
            );
            fn GFp_poly1305_emit(state: &mut Opaque, tag: &mut Tag, nonce: &Nonce);
        }

        let key = DerivedKey(key_and_nonce[0].clone());
        let nonce = Nonce(key_and_nonce[1].clone());

        let mut ctx = Context {
            opaque: Opaque([0u8; OPAQUE_LEN]),
            nonce,
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

    pub fn update_block(&mut self, block: Block, pad: Pad) {
        self.func.blocks(&mut self.opaque, block.as_ref(), pad);
    }

    pub fn update_blocks(&mut self, input: &[u8]) {
        debug_assert_eq!(input.len() % BLOCK_LEN, 0);
        self.func.blocks(&mut self.opaque, input, Pad::Pad);
    }

    pub(super) fn finish(mut self) -> Tag { self.func.emit(&mut self.opaque, &self.nonce) }
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

#[repr(C)]
struct DerivedKey(Block);

/// This is *not* an "AEAD nonce"; it's a Poly1305-specific nonce.
#[repr(C)]
struct Nonce(Block);

#[repr(C)]
struct Funcs {
    blocks_fn:
        unsafe extern "C" fn(&mut Opaque, input: *const u8, input_len: size_t, should_pad: Pad),
    emit_fn: unsafe extern "C" fn(&mut Opaque, &mut Tag, nonce: &Nonce),
}

#[inline]
fn init(state: &mut Opaque, key: DerivedKey, func: &mut Funcs) -> Result<(), error::Unspecified> {
    extern "C" {
        fn GFp_poly1305_init_asm(
            state: &mut Opaque, key: &DerivedKey, out_func: &mut Funcs,
        ) -> bssl::Result;
    }
    Result::from(unsafe { GFp_poly1305_init_asm(state, &key, func) })
}

#[repr(u32)]
pub enum Pad {
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
        let mut tag = Tag(Block::zero());
        unsafe {
            (self.emit_fn)(state, &mut tag, nonce);
        }
        tag
    }
}

/// Implements the original, non-IETF padding semantics.
///
/// This is used by chacha20_poly1305_openssh and the standalone
/// poly1305 test vectors.
pub(super) fn sign(key: Key, input: &[u8]) -> Tag {
    let mut ctx = Context::from_key(key);
    let remainder_len = input.len() % BLOCK_LEN;
    let full_blocks_len = input.len() - remainder_len;
    let (full_blocks, remainder) = input.split_at(full_blocks_len);
    ctx.update_blocks(full_blocks);
    if remainder_len > 0 {
        let mut bytes = [0; BLOCK_LEN];
        bytes[..remainder_len].copy_from_slice(remainder);
        bytes[remainder_len] = 1;
        ctx.update_block(Block::from(&bytes), Pad::AlreadyPadded);
    }
    ctx.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{polyfill::convert::*, test};

    #[test]
    pub fn test_state_layout() { check_state_layout(); }

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::run(test_file!("poly1305_test.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key: &[u8; BLOCK_LEN * 2] = key.as_slice().try_into_().unwrap();
            let key: [Block; 2] = key.into_();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let key = Key::from(key);
            let Tag(actual_mac) = sign(key, &input);
            assert_eq!(expected_mac, actual_mac.as_ref());

            Ok(())
        })
    }
}
