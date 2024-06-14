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

use self::ffi::{Block, BLOCK_LEN, ZERO_BLOCK};
use super::{aes_gcm, Aad};
use crate::{
    bits::{BitLength, FromByteLen as _},
    cpu, error,
    polyfill::{sliceutil::overwrite_at_start, ArraySplitMap as _},
};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))] {
        pub(super) use self::ffi::{HTable, Xi};
    } else {
        use self::ffi::{HTable, Xi};
    }
}

#[macro_use]
mod ffi;
mod gcm_nohw;

#[derive(Clone)]
pub struct Key {
    h_table: HTable,
}

impl Key {
    pub(super) fn new(h_be: Block, cpu_features: cpu::Features) -> Self {
        let h: [u64; 2] = h_be.array_split_map(u64::from_be_bytes);
        let h_table = match detect_implementation(cpu_features) {
            #[cfg(target_arch = "x86_64")]
            Implementation::CLMUL if has_avx_movbe(cpu_features) => unsafe {
                htable_new!(gcm_init_avx, &h, cou_features)
            },

            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            Implementation::CLMUL => unsafe { htable_new!(gcm_init_clmul, &h, cpu_features) },

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            Implementation::NEON => unsafe { htable_new!(gcm_init_neon, &h, cpu_features) },

            Implementation::Fallback => HTable::new_single_entry(gcm_nohw::init(h)),
        };
        Self { h_table }
    }
}

pub struct Context<'key> {
    Xi: Xi,
    h_table: &'key HTable,
    aad_len: BitLength<u64>,
    in_out_len: BitLength<u64>,
    cpu_features: cpu::Features,
}

impl<'key> Context<'key> {
    pub(crate) fn new(
        key: &'key Key,
        aad: Aad<&[u8]>,
        in_out_len: usize,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        if in_out_len > aes_gcm::MAX_IN_OUT_LEN {
            return Err(error::Unspecified);
        }
        let in_out_len = BitLength::from_byte_len(in_out_len)?;
        let aad_len = BitLength::from_byte_len(aad.as_ref().len())?;

        // NIST SP800-38D Section 5.2.1.1 says that the maximum AAD length is
        // 2**64 - 1 bits, i.e. BitLength<u64>::MAX, so we don't need to do an
        // explicit check here.

        let mut ctx = Self {
            Xi: Xi(ZERO_BLOCK),
            h_table: &key.h_table,
            aad_len,
            in_out_len,
            cpu_features,
        };

        for ad in aad.0.chunks(BLOCK_LEN) {
            let mut block = ZERO_BLOCK;
            overwrite_at_start(&mut block, ad);
            ctx.update_block(block);
        }

        Ok(ctx)
    }

    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    pub(super) fn in_out_whole_block_bits(&self) -> BitLength<usize> {
        use crate::polyfill::usize_from_u64;
        const WHOLE_BLOCK_BITS_MASK: usize = !0b111_1111;
        #[allow(clippy::assertions_on_constants)]
        const _WHOLE_BLOCK_BITS_MASK_CORRECT: () =
            assert!(WHOLE_BLOCK_BITS_MASK == !((BLOCK_LEN * 8) - 1));
        BitLength::from_bits(usize_from_u64(self.in_out_len.as_bits()) & WHOLE_BLOCK_BITS_MASK)
    }

    /// Access to `inner` for the integrated AES-GCM implementations only.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[inline]
    pub(super) fn inner(&mut self) -> (&HTable, &mut Xi) {
        (self.h_table, &mut self.Xi)
    }

    pub fn update_blocks(&mut self, input: &[[u8; BLOCK_LEN]]) {
        let xi = &mut self.Xi;
        let h_table = self.h_table;

        match detect_implementation(self.cpu_features) {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: gcm_ghash_avx satisfies the ghash! contract.
            Implementation::CLMUL if has_avx_movbe(self.cpu_features) => unsafe {
                ghash!(gcm_ghash_avx, xi, h_table, input, self.cpu_features);
            },

            #[cfg(target_arch = "aarch64")]
            // If we have CLMUL then we probably have AES, so the integrated
            // implementation will take care of everything except any final
            // partial block. Thus, we avoid having an optimized implementation
            // here.
            Implementation::CLMUL => self.update_blocks_1x(input),

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            // SAFETY: gcm_ghash_clmul satisfies the ghash! contract on these
            // targets.
            Implementation::CLMUL => unsafe {
                ghash!(gcm_ghash_clmul, xi, h_table, input, self.cpu_features);
            },

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            // SAFETY: gcm_ghash_neon satisfies the ghash! contract on these
            // targets.
            Implementation::NEON => unsafe {
                ghash!(gcm_ghash_neon, xi, h_table, input, self.cpu_features);
            },

            Implementation::Fallback => {
                gcm_nohw::ghash(xi, h_table.first_entry(), input);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(never)]
    fn update_blocks_1x(&mut self, input: &[[u8; BLOCK_LEN]]) {
        for input in input {
            self.update_block(*input);
        }
    }

    pub fn update_block(&mut self, a: Block) {
        self.Xi.bitxor_assign(a);

        let xi = &mut self.Xi;
        let h_table = self.h_table;

        match detect_implementation(self.cpu_features) {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            Implementation::CLMUL => unsafe {
                gmult!(gcm_gmult_clmul, xi, h_table, self.cpu_features)
            },

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            Implementation::NEON => unsafe {
                gmult!(gcm_gmult_neon, xi, h_table, self.cpu_features)
            },

            Implementation::Fallback => {
                gcm_nohw::gmult(xi, h_table.first_entry());
            }
        }
    }

    pub(super) fn pre_finish<F>(mut self, f: F) -> super::Tag
    where
        F: FnOnce(Block, cpu::Features) -> super::Tag,
    {
        let mut block = [0u8; BLOCK_LEN];
        let (alen, clen) = block.split_at_mut(BLOCK_LEN / 2);
        alen.copy_from_slice(&BitLength::<u64>::to_be_bytes(self.aad_len));
        clen.copy_from_slice(&BitLength::<u64>::to_be_bytes(self.in_out_len));
        self.update_block(block);
        f(self.Xi.into_block(), self.cpu_features)
    }

    #[cfg(target_arch = "x86_64")]
    pub(super) fn is_avx(&self) -> bool {
        match detect_implementation(self.cpu_features) {
            Implementation::CLMUL => has_avx_movbe(self.cpu_features),
            _ => false,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(super) fn is_clmul(&self) -> bool {
        matches!(
            detect_implementation(self.cpu_features),
            Implementation::CLMUL
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
enum Implementation {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
    CLMUL,

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    NEON,

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

    #[cfg(target_arch = "aarch64")]
    {
        if cpu::arm::PMULL.available(cpu_features) {
            return Implementation::CLMUL;
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if cpu::intel::FXSR.available(cpu_features) && cpu::intel::PCLMULQDQ.available(cpu_features)
        {
            return Implementation::CLMUL;
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        if cpu::arm::NEON.available(cpu_features) {
            return Implementation::NEON;
        }
    }

    Implementation::Fallback
}

#[cfg(target_arch = "x86_64")]
fn has_avx_movbe(cpu_features: cpu::Features) -> bool {
    cpu::intel::AVX.available(cpu_features) && cpu::intel::MOVBE.available(cpu_features)
}
