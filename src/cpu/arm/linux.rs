// Copyright 2016-2024 Brian Smith.
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

use super::{AES, NEON, PMULL, SHA256};

pub const FORCE_DYNAMIC_DETECTION: u32 = 0;

// `uclibc` does not provide `getauxval` so just use static feature detection
// for it.
#[cfg(target_env = "uclibc")]
pub fn detect_features() -> u32 {
    0
}

#[cfg(not(target_env = "uclibc"))]
pub fn detect_features() -> u32 {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            use libc::{getauxval,AT_HWCAP, HWCAP_AES, HWCAP_PMULL, HWCAP_SHA2, HWCAP_SHA512};
        } else if #[cfg(target_arch = "arm")] {
            // The `libc` crate doesn't provide this functionality on all
            // 32-bit Linux targets, like Android or -musl. Use this polyfill
            // for all 32-bit ARM targets so that testing on one of them will
            // be more meaningful to the others.
            use libc::c_ulong;
            extern "C" {
                pub fn getauxval(type_: c_ulong) -> c_ulong;
            }
            const AT_HWCAP: c_ulong = 16;
            const AT_HWCAP2: c_ulong = 26;
            const HWCAP_NEON: c_ulong = 1 << 12;
            const HWCAP2_AES: c_ulong = 1 << 0;
            const HWCAP2_PMULL: c_ulong = 1 << 1;
            const HWCAP2_SHA2: c_ulong = 1 << 3;
        }
    }

    let caps = unsafe { getauxval(AT_HWCAP) };

    let mut features = 0;

    // We do not need to check for the presence of NEON, as Armv8-A always has it
    #[cfg(target_arch = "aarch64")]
    const _ASSERT_NEON_DETECTED: () = assert!((super::ARMCAP_STATIC & NEON.mask) == NEON.mask);

    // OpenSSL and BoringSSL don't enable any other features if NEON isn't
    // available.
    #[cfg(target_arch = "arm")]
    if caps & HWCAP_NEON == HWCAP_NEON {
        features |= NEON.mask;
    } else {
        return 0;
    }

    #[cfg(target_arch = "arm")]
    let caps = unsafe { getauxval(AT_HWCAP2) };

    #[cfg(target_arch = "arm")]
    use {HWCAP2_AES as HWCAP_AES, HWCAP2_PMULL as HWCAP_PMULL, HWCAP2_SHA2 as HWCAP_SHA2};

    if caps & HWCAP_AES == HWCAP_AES {
        features |= AES.mask;
    }
    if caps & HWCAP_PMULL == HWCAP_PMULL {
        features |= PMULL.mask;
    }
    if caps & HWCAP_SHA2 == HWCAP_SHA2 {
        features |= SHA256.mask;
    }

    #[cfg(target_arch = "aarch64")]
    if caps & HWCAP_SHA512 == HWCAP_SHA512 {
        features |= super::SHA512.mask;
    }

    features
}
