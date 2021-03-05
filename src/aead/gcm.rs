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

use super::{
    block::{Block, BLOCK_LEN},
    Aad,
};
use crate::cpu;
use core::ops::BitXorAssign;

#[cfg(not(target_arch = "aarch64"))]
mod gcm_nohw;

pub struct Key {
    h_table: HTable,
    cpu_features: cpu::Features,
}

impl Key {
    pub(super) fn new(h_be: Block, cpu_features: cpu::Features) -> Self {
        let h: [u64; 2] = h_be.into();

        let mut key = Self {
            h_table: HTable {
                Htable: [u128 { hi: 0, lo: 0 }; HTABLE_LEN],
            },
            cpu_features,
        };
        let h_table = &mut key.h_table;

        match detect_implementation(cpu_features) {
            #[cfg(target_arch = "x86_64")]
            Implementation::CLMUL if has_avx_movbe(cpu_features) => {
                extern "C" {
                    fn GFp_gcm_init_avx(HTable: &mut HTable, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_avx(h_table, &h);
                }
            }

            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_init_clmul(Htable: &mut HTable, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_clmul(h_table, &h);
                }
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_init_neon(Htable: &mut HTable, h: &[u64; 2]);
                }
                unsafe {
                    GFp_gcm_init_neon(h_table, &h);
                }
            }

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::Fallback => {
                h_table.Htable[0] = gcm_nohw::init(h);
            }
        }

        key
    }
}

pub struct Context {
    inner: ContextInner,
    cpu_features: cpu::Features,
}

impl Context {
    pub(crate) fn new(key: &Key, aad: Aad<&[u8]>) -> Self {
        let mut ctx = Self {
            inner: ContextInner {
                Xi: Xi(Block::zero()),
                _unused: Block::zero(),
                Htable: key.h_table.clone(),
            },
            cpu_features: key.cpu_features,
        };

        for ad in aad.0.chunks(BLOCK_LEN) {
            let mut block = Block::zero();
            block.overwrite_part_at(0, ad);
            ctx.update_block(block);
        }

        ctx
    }

    /// Access to `inner` for the integrated AES-GCM implementations only.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(super) fn inner(&mut self) -> &mut ContextInner {
        &mut self.inner
    }

    pub fn update_blocks(&mut self, input: &[u8]) {
        // Th assembly functions take the input length in bytes, not blocks.
        let input_bytes = input.len();

        debug_assert_eq!(input_bytes % BLOCK_LEN, 0);
        debug_assert!(input_bytes > 0);

        let input = input.as_ptr() as *const [u8; BLOCK_LEN];
        let input = unsafe { core::slice::from_raw_parts(input, input_bytes / BLOCK_LEN) };

        // Although these functions take `Xi` and `h_table` as separate
        // parameters, one or more of them might assume that they are part of
        // the same `ContextInner` structure.
        let xi = &mut self.inner.Xi;
        let h_table = &self.inner.Htable;

        match detect_implementation(self.cpu_features) {
            #[cfg(target_arch = "x86_64")]
            Implementation::CLMUL if has_avx_movbe(self.cpu_features) => {
                extern "C" {
                    fn GFp_gcm_ghash_avx(
                        xi: &mut Xi,
                        Htable: &HTable,
                        inp: *const [u8; BLOCK_LEN],
                        len: crate::c::size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_avx(xi, h_table, input.as_ptr(), input_bytes);
                }
            }

            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_ghash_clmul(
                        xi: &mut Xi,
                        Htable: &HTable,
                        inp: *const [u8; BLOCK_LEN],
                        len: crate::c::size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_clmul(xi, h_table, input.as_ptr(), input_bytes);
                }
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_ghash_neon(
                        xi: &mut Xi,
                        Htable: &HTable,
                        inp: *const [u8; BLOCK_LEN],
                        len: crate::c::size_t,
                    );
                }
                unsafe {
                    GFp_gcm_ghash_neon(xi, h_table, input.as_ptr(), input_bytes);
                }
            }

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::Fallback => {
                gcm_nohw::ghash(xi, h_table.Htable[0], input);
            }
        }
    }

    pub fn update_block(&mut self, a: Block) {
        self.inner.Xi.bitxor_assign(a);

        // Although these functions take `Xi` and `h_table` as separate
        // parameters, one or more of them might assume that they are part of
        // the same `ContextInner` structure.
        let xi = &mut self.inner.Xi;
        let h_table = &self.inner.Htable;

        match detect_implementation(self.cpu_features) {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::CLMUL => {
                extern "C" {
                    fn GFp_gcm_gmult_clmul(xi: &mut Xi, Htable: &HTable);
                }
                unsafe {
                    GFp_gcm_gmult_clmul(xi, h_table);
                }
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            Implementation::NEON => {
                extern "C" {
                    fn GFp_gcm_gmult_neon(xi: &mut Xi, Htable: &HTable);
                }
                unsafe {
                    GFp_gcm_gmult_neon(xi, h_table);
                }
            }

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::Fallback => {
                gcm_nohw::gmult(xi, h_table.Htable[0]);
            }
        }
    }

    pub(super) fn pre_finish<F>(self, f: F) -> super::Tag
    where
        F: FnOnce(Block) -> super::Tag,
    {
        f(self.inner.Xi.0)
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn is_avx2(&self) -> bool {
        match detect_implementation(self.cpu_features) {
            Implementation::CLMUL => has_avx_movbe(self.cpu_features),
            _ => false,
        }
    }
}

// The alignment is required by non-Rust code that uses `GCM128_CONTEXT`.
#[derive(Clone)]
#[repr(C, align(16))]
struct HTable {
    Htable: [u128; HTABLE_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct u128 {
    hi: u64,
    lo: u64,
}

const HTABLE_LEN: usize = 16;

#[repr(transparent)]
pub struct Xi(Block);

impl BitXorAssign<Block> for Xi {
    #[inline]
    fn bitxor_assign(&mut self, a: Block) {
        self.0 ^= a;
    }
}

impl From<Xi> for Block {
    #[inline]
    fn from(Xi(block): Xi) -> Self {
        block
    }
}

// This corresponds roughly to the `GCM128_CONTEXT` structure in BoringSSL.
// Some assembly language code, in particular the MOVEBE+AVX2 X86-64
// implementation, requires this exact layout.
#[repr(C, align(16))]
pub(super) struct ContextInner {
    Xi: Xi,
    _unused: Block,
    Htable: HTable,
}

enum Implementation {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    CLMUL,

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    NEON,

    #[cfg(not(target_arch = "aarch64"))]
    Fallback,
}

#[inline]
fn detect_implementation(cpu_features: cpu::Features) -> Implementation {
    // `cpu_features` is only used for specific platforms.
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    let _cpu_features = cpu_features;

    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    {
        if (cpu::intel::FXSR.available(cpu_features)
            && cpu::intel::PCLMULQDQ.available(cpu_features))
            || cpu::arm::PMULL.available(cpu_features)
        {
            return Implementation::CLMUL;
        }
    }

    #[cfg(target_arch = "arm")]
    {
        if cpu::arm::NEON.available(cpu_features) {
            return Implementation::NEON;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        return Implementation::NEON;
    }

    #[cfg(not(target_arch = "aarch64"))]
    Implementation::Fallback
}

#[cfg(target_arch = "x86_64")]
fn has_avx_movbe(cpu_features: cpu::Features) -> bool {
    cpu::intel::AVX.available(cpu_features) && cpu::intel::MOVBE.available(cpu_features)
}
