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

use super::{Aad, Block, BLOCK_LEN};
use crate::cpu;
use libc::size_t;

#[repr(transparent)]
pub struct Key(GCM128_KEY);

impl Key {
    pub(super) fn new(mut h_be: Block, cpu_features: cpu::Features) -> Self {
        let h = h_be.u64s_be_to_native();

        let mut key = Key(GCM128_KEY {
            Htable: [u128 { hi: 0, lo: 0 }; GCM128_HTABLE_LEN],
        });

        match detect_implementation(cpu_features) {
            #[cfg(target_arch = "x86_64")]
            Implementation::CLMUL if has_avx_movbe(cpu_features) => {
                extern "C" {
                    fn GFp_gcm_init_avx(key: &mut Key, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_avx(&mut key, &h);
                }
            },

            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_init_clmul(key: &mut Key, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_clmul(&mut key, &h);
                }
            },

            #[cfg(any(target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_init_neon(key: &mut Key, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_neon(&mut key, &h);
                }
            },

            Implementation::Fallback => {
                extern "C" {
                    fn GFp_gcm_init_4bit(key: &mut Key, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_4bit(&mut key, &h);
                }
            },
        }

        key
    }
}

#[repr(transparent)]
pub struct Context {
    inner: GCM128_CONTEXT,
    cpu_features: cpu::Features,
}

impl Context {
    pub(crate) fn new(key: &Key, aad: Aad, cpu_features: cpu::Features) -> Self {
        let mut ctx = Context {
            inner: GCM128_CONTEXT {
                Xi: Block::zero(),
                H_unused: Block::zero(),
                key: key.0.clone(),
            },
            cpu_features,
        };

        for ad in aad.0.chunks(BLOCK_LEN) {
            let mut block = Block::zero();
            block.partial_copy_from(ad);
            ctx.update_block(block);
        }

        ctx
    }

    pub fn update_blocks(&mut self, input: &[u8]) {
        debug_assert!(input.len() > 0);
        debug_assert_eq!(input.len() % BLOCK_LEN, 0);

        let key_aliasing: *const GCM128_KEY = &self.inner.key;

        match detect_implementation(self.cpu_features) {
            #[cfg(target_arch = "x86_64")]
            Implementation::CLMUL if has_avx_movbe(self.cpu_features) => {
                extern "C" {
                    fn GFp_gcm_ghash_avx(
                        ctx: &mut Context, h_table: *const GCM128_KEY, inp: *const u8, len: size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_avx(self, key_aliasing, input.as_ptr(), input.len());
                }
            },

            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_ghash_clmul(
                        ctx: &mut Context, h_table: *const GCM128_KEY, inp: *const u8, len: size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_clmul(self, key_aliasing, input.as_ptr(), input.len());
                }
            },

            #[cfg(any(target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_ghash_neon(
                        ctx: &mut Context, h_table: *const GCM128_KEY, inp: *const u8, len: size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_neon(self, key_aliasing, input.as_ptr(), input.len());
                }
            },

            Implementation::Fallback => {
                extern "C" {
                    fn GFp_gcm_ghash_4bit(
                        ctx: &mut Context, h_table: *const GCM128_KEY, inp: *const u8, len: size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_4bit(self, key_aliasing, input.as_ptr(), input.len());
                }
            },
        }
    }

    pub fn update_block(&mut self, a: Block) {
        self.inner.Xi.bitxor_assign(a);

        let key_aliasing: *const GCM128_KEY = &self.inner.key;

        match detect_implementation(self.cpu_features) {
            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_gmult_clmul(ctx: &mut Context, Htable: *const GCM128_KEY);
                }
                unsafe {
                    GFp_gcm_gmult_clmul(self, key_aliasing);
                }
            },

            #[cfg(any(target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_gmult_neon(ctx: &mut Context, Htable: *const GCM128_KEY);
                }
                unsafe {
                    GFp_gcm_gmult_neon(self, key_aliasing);
                }
            },

            Implementation::Fallback => {
                extern "C" {
                    fn GFp_gcm_gmult_4bit(ctx: &mut Context, Htable: *const GCM128_KEY);
                }
                unsafe {
                    GFp_gcm_gmult_4bit(self, key_aliasing);
                }
            },
        }
    }

    pub(super) fn pre_finish<F>(self, f: F) -> super::Tag
    where
        F: FnOnce(Block) -> super::Tag,
    {
        f(self.inner.Xi)
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn is_avx2(&self, cpu_features: cpu::Features) -> bool {
        match detect_implementation(cpu_features) {
            Implementation::CLMUL => has_avx_movbe(self.cpu_features),
            _ => false,
        }
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

enum Implementation {
    CLMUL,

    #[cfg(target_arch = "arm")]
    NEON,

    Fallback,
}

#[inline]
fn detect_implementation(cpu: cpu::Features) -> Implementation {
    if (cpu::intel::FXSR.available(cpu) && cpu::intel::PCLMULQDQ.available(cpu))
        || cpu::arm::PMULL.available(cpu)
    {
        return Implementation::CLMUL;
    }

    #[cfg(target_arch = "arm")]
    {
        if cpu::arm::NEON.available(cpu) {
            return Implementation::NEON;
        }
    }

    Implementation::Fallback
}

#[cfg(target_arch = "x86_64")]
fn has_avx_movbe(cpu_features: cpu::Features) -> bool {
    return cpu::intel::AVX.available(cpu_features) && cpu::intel::MOVBE.available(cpu_features);
}
