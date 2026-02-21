// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
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

use super::{overlapping, quic::Sample, Nonce};
use crate::cpu;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(
                all(target_arch = "aarch64", target_endian = "little"),
                all(target_arch = "arm", target_endian = "little"),
                target_arch = "x86",
                target_arch = "x86_64"
            ))] {
        #[macro_use]
        mod ffi;
        #[cfg(test)]
        mod fallback;
    } else {
        mod fallback;
    }
}

use crate::polyfill::ArraySplitMap;

pub type Overlapping<'o> = overlapping::Overlapping<'o, u8>;

#[derive(Clone)]
pub struct Key {
    words: [u32; KEY_LEN / 4],
}

impl Key {
    pub(super) fn new(value: [u8; KEY_LEN]) -> Self {
        Self {
            words: value.array_split_map(u32::from_le_bytes),
        }
    }
}

impl Key {
    // Encrypts `in_out` with the counter 0 and returns counter 1,
    // where the counter is derived from the nonce `nonce`.
    #[inline]
    pub(super) fn encrypt_single_block_with_ctr_0<const N: usize>(
        &self,
        nonce: Nonce,
        in_out: &mut [u8; N],
        cpu: cpu::Features,
    ) -> Counter {
        assert!(N <= BLOCK_LEN);
        let (zero, one) = Counter::zero_one_less_safe(nonce);
        self.encrypt(zero, in_out.as_mut().into(), cpu);
        one
    }

    #[inline]
    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let cpu = cpu::features(); // TODO: Remove this.
        let (ctr, nonce) = sample.split_at(4);
        let ctr = u32::from_le_bytes(ctr.try_into().unwrap());
        let nonce = Nonce::assume_unique_for_key(nonce.try_into().unwrap());
        let ctr = Counter::from_nonce_and_ctr(nonce, ctr);

        let mut out: [u8; 5] = [0; 5];
        self.encrypt(ctr, out.as_mut().into(), cpu);
        out
    }

    #[inline(always)]
    pub(super) fn encrypt(&self, counter: Counter, in_out: Overlapping<'_>, cpu: cpu::Features) {
        cfg_if! {
            if #[cfg(all(target_arch = "aarch64", target_endian = "little"))] {
                use cpu::{GetFeature as _, aarch64::Neon};
                const NEON_MIN_LEN: usize = 192 + 1;
                if in_out.len() >= NEON_MIN_LEN {
                    if let Some(cpu) = cpu.get_feature() {
                        return chacha20_ctr32_ffi!(
                            unsafe { (NEON_MIN_LEN, Neon, Overlapping<'_>) => ChaCha20_ctr32_neon },
                            self, counter, in_out, cpu);
                    }
                }
                if in_out.len() >= 1 {
                    chacha20_ctr32_ffi!(
                        unsafe { (1, (), Overlapping<'_>) => ChaCha20_ctr32_nohw },
                        self, counter, in_out, ())
                }
            } else if #[cfg(all(target_arch = "arm", target_endian = "little"))] {
                use cpu::{GetFeature as _, arm::Neon};
                const NEON_MIN_LEN: usize = 192 + 1;
                if in_out.len() >= NEON_MIN_LEN {
                    if let Some(cpu) = cpu.get_feature() {
                        return chacha20_ctr32_ffi!(
                            unsafe { (NEON_MIN_LEN, Neon, &mut [u8]) => ChaCha20_ctr32_neon },
                            self, counter, in_out.copy_within(), cpu);
                    }
                }
                if in_out.len() >= 1 {
                    chacha20_ctr32_ffi!(
                        unsafe { (1, (), &mut [u8]) => ChaCha20_ctr32_nohw },
                        self, counter, in_out.copy_within(), ())
                }
            } else if #[cfg(target_arch = "x86")] {
                use cpu::{GetFeature as _, intel::Ssse3};
                if in_out.len() >= 1 {
                    if let Some(cpu) = cpu.get_feature() {
                        chacha20_ctr32_ffi!(
                            unsafe { (1, Ssse3, &mut [u8]) => ChaCha20_ctr32_ssse3 },
                            self, counter, in_out.copy_within(), cpu)
                    } else {
                        chacha20_ctr32_ffi!(
                            unsafe { (1, (), &mut [u8]) => ChaCha20_ctr32_nohw },
                            self, counter, in_out.copy_within(), ())
                    }
                }
            } else if #[cfg(target_arch = "x86_64")] {
                use cpu::{GetFeature, intel::{Avx2, Ssse3}};
                const SSE_MIN_LEN: usize = 128 + 1; // Also AVX2, SSSE3_4X, SSSE3
                if in_out.len() >= SSE_MIN_LEN {
                    let values = cpu.values();
                    if let Some(cpu) = values.get_feature() {
                        return chacha20_ctr32_ffi!(
                            unsafe { (SSE_MIN_LEN, Avx2, Overlapping<'_>) => ChaCha20_ctr32_avx2 },
                            self, counter, in_out, cpu);
                    }
                    if let Some(cpu) = values.get_feature() {
                        return chacha20_ctr32_ffi!(
                            unsafe { (SSE_MIN_LEN, Ssse3, Overlapping<'_>) =>
                                ChaCha20_ctr32_ssse3_4x },
                            self, counter, in_out, cpu);
                    }
                }
                if in_out.len() >= 1 {
                    chacha20_ctr32_ffi!(
                        unsafe { (1, (), Overlapping<'_>) => ChaCha20_ctr32_nohw },
                        self, counter, in_out, ())
                }
            } else {
                let _: cpu::Features = cpu;
                fallback::ChaCha20_ctr32(self, counter, in_out)
            }
        }
    }

    #[inline]
    pub(super) fn words_less_safe(&self) -> &[u32; KEY_LEN / 4] {
        &self.words
    }
}

/// Counter || Nonce, all native endian.
#[repr(transparent)]
pub struct Counter([u32; 4]);

impl Counter {
    // Nonce-reuse: the caller must only use the first counter (0) for at most
    // a single block.
    fn zero_one_less_safe(nonce: Nonce) -> (Self, Self) {
        let ctr0 @ Self([_, n0, n1, n2]) = Self::from_nonce_and_ctr(nonce, 0);
        let ctr1 = Self([1, n0, n1, n2]);
        (ctr0, ctr1)
    }

    fn from_nonce_and_ctr(nonce: Nonce, ctr: u32) -> Self {
        let [n0, n1, n2] = nonce.as_ref().array_split_map(u32::from_le_bytes);
        Self([ctr, n0, n1, n2])
    }

    /// This is "less safe" because it hands off management of the counter to
    /// the caller.
    #[cfg(any(
        test,
        not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))
    ))]
    fn into_words_less_safe(self) -> [u32; 4] {
        self.0
    }
}

pub const KEY_LEN: usize = 32;

const BLOCK_LEN: usize = 64;

#[cfg(test)]
mod tests;
