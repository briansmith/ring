// Copyright 2018 Brian Smith.
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

use super::{Block, BLOCK_LEN};
use crate::c;

#[repr(transparent)]
pub struct Key(GCM128_KEY);

impl Key {
    pub fn new(h_be: Block) -> Self {
        extern "C" {
            fn GFp_gcm128_init_htable(gcm_key: &mut GCM128_KEY, h_block: Block);
        }

        let mut r = Key(GCM128_KEY {
            Htable: [u128 { hi: 0, lo: 0 }; GCM128_HTABLE_LEN],
        });
        unsafe {
            GFp_gcm128_init_htable(&mut r.0, h_be);
        }
        r
    }
}

#[repr(transparent)]
pub struct Context(GCM128_CONTEXT);

impl Context {
    pub fn new(key: &Key, aad: &[u8]) -> Self {
        let mut ctx = Context(GCM128_CONTEXT {
            Xi: Block::zero(),
            H_unused: Block::zero(),
            key: key.0.clone(),
        });

        for ad in aad.chunks(BLOCK_LEN) {
            let mut block = Block::zero();
            block.partial_copy_from(ad);
            ctx.update_block(block);
        }

        ctx
    }

    pub fn update_blocks(&mut self, input: &[u8]) {
        debug_assert!(input.len() > 0);
        debug_assert_eq!(input.len() % BLOCK_LEN, 0);
        extern "C" {
            fn GFp_gcm128_ghash(ctx: &mut Context, input: *const u8, input_len: c::size_t);
        }
        unsafe {
            GFp_gcm128_ghash(self, input.as_ptr(), input.len());
        }
    }

    pub fn update_block(&mut self, a: Block) {
        extern "C" {
            fn GFp_gcm128_gmult(ctx: &mut Context);
        }

        self.0.Xi.bitxor_assign(a);
        unsafe {
            GFp_gcm128_gmult(self);
        }
    }

    pub(super) fn pre_finish<F>(self, f: F) -> super::Tag
    where
        F: FnOnce(Block) -> super::Tag,
    {
        f(self.0.Xi)
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn is_avx2(&self) -> bool {
        extern "C" {
            fn GFp_aesni_gcm_capable() -> c::int;
            fn GFp_gcm_clmul_enabled() -> c::int;
        }
        1 == unsafe { GFp_gcm_clmul_enabled() } && 1 == unsafe { GFp_aesni_gcm_capable() }
    }
}

// Keep in sync with `GCM128_KEY` in modes/internal.h.
#[derive(Clone)]
#[repr(C, align(16))]
struct GCM128_KEY {
    Htable: [u128; GCM128_HTABLE_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct u128 {
    hi: u64,
    lo: u64,
}

const GCM128_HTABLE_LEN: usize = 16;

// Keep in sync with `GCM128_CONTEXT` in modes/internal.h.
#[repr(C, align(16))]
struct GCM128_CONTEXT {
    Xi: Block,
    H_unused: Block,
    key: GCM128_KEY,
}
