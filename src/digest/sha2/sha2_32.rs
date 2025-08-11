// Copyright 2024 Brian Smith.
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

use super::{BlockLen, CHAINING_WORDS};
use crate::cpu;
use crate::digest::sha2::k::K;
use cfg_if::cfg_if;
use core::num::Wrapping;

pub(in super::super) const SHA256_BLOCK_LEN: BlockLen = BlockLen::_512;

pub type State32 = [Wrapping<u32>; CHAINING_WORDS];

pub(crate) fn block_data_order_32(
    state: &mut State32,
    data: &[[u8; SHA256_BLOCK_LEN.into()]],
    cpu: cpu::Features,
) {
    cfg_if! {
        if #[cfg(all(target_arch = "aarch64", target_endian = "little"))] {
            use cpu::{GetFeature as _, aarch64::Sha256};
            if let Some(cpu)= cpu.get_feature() {
                sha2_32_k_ffi!(unsafe { Sha256 => sha256_block_data_order_hw }, state, data, &K_32, cpu)
            } else {
                sha2_32_k_ffi!(unsafe { () => sha256_block_data_order_nohw }, state, data, &K_32, ())
            }
        } else if #[cfg(all(target_arch = "arm", target_endian = "little"))] {
            use cpu::{GetFeature as _, arm::Neon};
            if let Some(cpu) = cpu.get_feature() {
                sha2_32_ffi!(unsafe { Neon => sha256_block_data_order_neon }, state, data, cpu)
            } else {
                sha2_32_ffi!(unsafe { () => sha256_block_data_order_nohw }, state, data, ())
            }
        } else if #[cfg(target_arch = "x86_64")] {
            use cpu::{GetFeature as _, intel::{Avx, IntelCpu, Sha, Ssse3 }};
            let cpu = cpu.values();
            if let Some(cpu) = cpu.get_feature() {
                sha2_32_ffi!(unsafe { (Sha, Ssse3) => sha256_block_data_order_hw }, state, data, cpu)
            } else if let Some(cpu) = cpu.get_feature() {
                // Pre-Zen AMD CPUs had slow SHLD/SHRD; Zen added the SHA
                // extension; see the discussion in upstream's sha1-586.pl.
                sha2_32_ffi!(unsafe { (Avx, IntelCpu) => sha256_block_data_order_avx }, state, data, cpu)
            } else if let Some(cpu) = cpu.get_feature() {
                sha2_32_ffi!(unsafe { Ssse3 => sha256_block_data_order_ssse3 }, state, data, cpu)
            } else {
                sha2_32_ffi!(unsafe { () => sha256_block_data_order_nohw }, state, data, ())
            }
        } else {
            let _ = cpu; // Unneeded.
            *state = super::fallback::block_data_order(*state, data)
        }
    }
}

pub(in super::super) const K_32: K<u32, { 64 + 1 }> = K::new_zero_terminated([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0,
]);
