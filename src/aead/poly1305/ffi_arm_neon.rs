// Copyright 2015-2025 Brian Smith.
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

#![cfg(all(target_arch = "arm", target_endian = "little"))]

use super::{poly1305_state, Key, Tag, KEY_LEN, OPAQUE_LEN, TAG_LEN};
use crate::{c, cpu::arm::Neon};
use core::num::NonZeroUsize;

// XXX/TODO(MSRV): change to `pub(super)`.
pub(in super::super) struct State {
    state: poly1305_state,
    neon: Neon,
}

impl State {
    pub(super) fn new_context(Key { key_and_nonce }: Key, neon: Neon) -> super::Context {
        prefixed_extern! {
            fn CRYPTO_poly1305_init_neon(state: &mut poly1305_state, key: &[u8; KEY_LEN]);
        }
        let mut r = Self {
            state: poly1305_state([0u8; OPAQUE_LEN]),
            neon,
        };
        unsafe { CRYPTO_poly1305_init_neon(&mut r.state, &key_and_nonce) }
        super::Context::ArmNeon(r)
    }

    pub(super) fn update(&mut self, input: &[u8]) {
        prefixed_extern! {
            fn CRYPTO_poly1305_update_neon(
                state: &mut poly1305_state,
                input: *const u8,
                in_len: c::NonZero_size_t);
        }
        if let Some(len) = NonZeroUsize::new(input.len()) {
            let _: Neon = self.neon;
            let input = input.as_ptr();
            unsafe { CRYPTO_poly1305_update_neon(&mut self.state, input, len) }
        }
    }

    pub(super) fn finish(mut self) -> Tag {
        prefixed_extern! {
            fn CRYPTO_poly1305_finish_neon(statep: &mut poly1305_state, mac: &mut [u8; TAG_LEN]);
        }
        let mut tag = Tag([0u8; TAG_LEN]);
        unsafe { CRYPTO_poly1305_finish_neon(&mut self.state, &mut tag.0) }
        tag
    }
}
