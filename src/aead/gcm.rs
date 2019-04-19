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
    pub(crate) fn new(key: &Key, cpu_features: cpu::Features) -> Self {
        let ctx = Context {
            inner: GCM128_CONTEXT {
                Xi: Block::zero(),
                H_unused: Block::zero(),
                key: key.0.clone(),
            },
            cpu_features,
        };

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

    // This byte reverse is used by AES_GCM_SIV to do the final byte reverse during polyval calculation
    // polyval = ByteReverse(GHASH(...))
    pub(super) fn reverse(&mut self) {
        self.inner.Xi = self.inner.Xi.reverse();
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


#[repr(transparent)]
pub struct PolyValContext {
    gcm_ctx: Context,
}

impl PolyValContext {


    // POLYVAL(H, X_1, ..., X_n) =
    // ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ...,
    // ByteReverse(X_n))).
    //
    // See https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-02#appendix-A.
    pub(super) fn new(auth_key: &Block, cpu_features: cpu::Features) -> PolyValContext {
        let mut auth_key = auth_key.u64s_native();
        PolyValContext::reverse_and_mulX_ghash(&mut auth_key);

        let key = Key::new(Block::from_u64_native(auth_key[0], auth_key[1]), cpu_features);
        PolyValContext { gcm_ctx: Context::new(&key, cpu_features) }
    }

    // This function does ByteReverse(auth_key) * 'x'
    // reverse_and_mulX_ghash interprets the auth_key bytes as a reversed element of
    // the GHASH field, multiplies that by 'x' and serialises the result back into
    // auth_key, but with GHASH's backwards bit ordering.
    pub fn reverse_and_mulX_ghash(auth_key: &mut [u64; 2]) {

        let mut hi = auth_key[0];
        let mut lo = auth_key[1];

        let carry = 0_u64.wrapping_sub(hi & 1);

        // the lsb of lo is moved to the msb of hi
        hi >>= 1;
        hi |= lo << 63;
        // lo will be xored lsb of carry and the 8 bits are shifted to left to last byte fiele
        lo >>= 1;
        lo ^= (carry & 0xe1) << 56;

        // swap bytes and assign lo to 0th index and hi to 1st index to do swap at byte and u64 level
        auth_key[0] = lo.swap_bytes();
        auth_key[1] = hi.swap_bytes();
    }

    pub fn update_blocks(&mut self, input: &[u8]) {

        let mut in_len = input.len();
        // Allocate 32 * 16 bytes for reversed
        const REVERSED_SIZE: usize = 32 * 16;
        let mut reversed = [0u8; REVERSED_SIZE];

        let mut start = 0;
        while start < input.len() {
            let mut todo = in_len;
            todo = std::cmp::min(todo, REVERSED_SIZE);

            let reversed = &mut reversed[0..todo];
            reversed.copy_from_slice(&input[start..todo + start]);
            reversed.chunks_exact_mut(BLOCK_LEN)
                    .for_each(|chunk| chunk.reverse());

            self.gcm_ctx.update_blocks(&reversed[0..todo]);
            start += todo;
            in_len -= todo;
        }
    }

    pub fn pre_finish(&mut self) -> Block {
        self.gcm_ctx.reverse();
        self.gcm_ctx.inner.Xi
    }
}