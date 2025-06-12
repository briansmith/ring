// Copyright 2016-2025 Brian Smith.
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

#![cfg(target_arch = "aarch64")]

use super::CAPS_STATIC;

mod abi_assumptions {
    use core::mem::size_of;

    // TODO: Support ARM64_32; see
    // https://github.com/briansmith/ring/issues/1832#issuecomment-1892928147. This also requires
    // replacing all `cfg(target_pointer_width)` logic for non-pointer/reference things
    // (`N0`, `Limb`, `LimbMask`, `crypto_word_t` etc.).
    const _ASSUMED_POINTER_SIZE: usize = 8;
    const _ASSUMED_USIZE_SIZE: () = assert!(size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () = assert!(size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

    // To support big-endian, we'd need to make several changes as described in
    // https://github.com/briansmith/ring/issues/1832.
    const _ASSUMED_ENDIANNESS: () = assert!(cfg!(target_endian = "little"));
}

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "ios", target_os = "macos", target_os = "tvos", target_os = "visionos", target_os = "watchos"))] {
        mod darwin;
        use darwin as detect;
    } else if #[cfg(target_os = "fuchsia")] {
        mod fuchsia;
        use fuchsia as detect;
    } else if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use linux as detect;
    } else if #[cfg(target_os = "windows")] {
        mod std_detect;
        use std_detect as detect;
    } else {
        mod detect {
            pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
            pub fn detect_features() -> u32 { 0 }
        }
    }
}

impl_get_feature! {
    features: [
        { ("aarch64") => Neon },

        // TODO(MSRV): There is no "pmull" feature listed from
        // `rustc --print cfg --target=aarch64-apple-darwin`. Originally ARMv8 tied
        // PMULL detection into AES detection, but later versions split it; see
        // https://developer.arm.com/downloads/-/exploration-tools/feature-names-for-a-profile
        // "Features introduced prior to 2020." Change this to use "pmull" when
        // that is supported.
        { ("aarch64") => PMull },

        { ("aarch64") => Aes },

        { ("aarch64") => Sha256 },

        // Keep in sync with `ARMV8_SHA512`.

        // "sha3" is overloaded for both SHA-3 and SHA-512.
        { ("aarch64") => Sha512 },
    ],
}

pub(super) mod featureflags {
    pub(in super::super) use super::detect::FORCE_DYNAMIC_DETECTION;
    use super::*;
    use crate::{
        cpu,
        polyfill::{once_cell::race, usize_from_u32},
    };
    use core::num::NonZeroUsize;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        fn init() -> NonZeroUsize {
            let detected = detect::detect_features();
            let filtered = (if cfg!(feature = "unstable-testing-arm-no-hw") {
                !Neon::mask()
            } else {
                0
            }) | (if cfg!(feature = "unstable-testing-arm-no-neon") {
                Neon::mask()
            } else {
                0
            });
            let detected = detected & !filtered;
            let merged = CAPS_STATIC | detected;
            let merged = usize_from_u32(merged) | (1 << (Shift::Initialized as u32));
            NonZeroUsize::new(merged).unwrap() // Can't fail because we just set a bit.
        }

        // SAFETY: This is the only caller. Any concurrent reading doesn't
        // affect the safety of the writing.
        let _: NonZeroUsize = FEATURES.get_or_init(init);

        // SAFETY: We initialized the CPU features as required.
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(in super::super) fn get(_cpu_features: cpu::Features) -> u32 {
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after `FEATURES.get_or_init()`,
        // we know we are reading from `FEATURES` after initializing it.
        // The `get_or_init()` also did the synchronization.
        let features = unsafe { FEATURES.get_unchecked() };

        // The truncation is lossless, as we set the value with a u32.
        #[allow(clippy::cast_possible_truncation)]
        let features = features.get() as u32;

        features
    }

    // On AArch64, we store all feature flags in `FEATURES`, so we dnn't need
    // Acquire/Release semantics.
    static FEATURES: race::OnceNonZeroUsize<race::Relaxed> = race::OnceNonZeroUsize::new();

    // TODO(MSRV): There is no "pmull" feature listed from
    // `rustc --print cfg --target=aarch64-apple-darwin`. Originally ARMv8 tied
    // PMULL detection into AES detection, but later versions split it; see
    // https://developer.arm.com/downloads/-/exploration-tools/feature-names-for-a-profile
    // "Features introduced prior to 2020." Change this to use "pmull" when
    // that is supported.
    //
    // "sha3" is overloaded for both SHA-3 and SHA-512.
    #[rustfmt::skip]
    pub(in super::super) const STATIC_DETECTED: u32 = 0
        | (if cfg!(target_feature = "neon") { Neon::mask() } else { 0 })
        | (if cfg!(target_feature = "aes") { Aes::mask() } else { 0 })
        | (if cfg!(target_feature = "aes") { PMull::mask() } else { 0 })
        | (if cfg!(target_feature = "sha2") { Sha256::mask() } else { 0 })
        | (if cfg!(target_feature = "sha3") { Sha512::mask() } else { 0 })
        ;
}

#[allow(clippy::assertions_on_constants)]
const _AARCH64_HAS_NEON: () = assert!((CAPS_STATIC & Neon::mask()) == Neon::mask());
