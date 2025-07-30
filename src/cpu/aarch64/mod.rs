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

    // arm64_32-apple-darwin code can call aarch64-apple-darwin assembly
    // functions, but aarch64-*_ilp32 functions CANNOT call
    // aarch64-* functions.
    //
    // In the arm64_32-apple-watchos "C" ABI, the caller zero-extends 32-bit
    // argument values to 64-bits and truncates return values to 32-bits. No
    // work needed to be done to adapt aarch64 to Apple's arm64_32.
    //
    // The standard AArch64-ILP32 ABI requires the callee to ignore garbage in
    // the upper half of 64-bit registers; i.e. the callee does the zero
    // extension instead of the caller. In order to support this, we'd need to
    // audit all the `prefixed_extern!`s for AArch64 and change every pointer
    // to a not-yet-existing 64-bit "zero-extended pointer" type, and change
    // every other <64-bit parameter type to the corresponding 64-bit type.
    const _ASSUMED_POINTER_SIZE: usize =
        if cfg!(all(target_os = "watchos", target_pointer_width = "32")) {
            todo!(); // Need to run tests for this ABI.
            #[allow(unreachable_code)]
            {
                4
            }
        } else {
            8
        };
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
        mod windows;
        use windows as detect;
    } else {
        mod detect {
            pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
            #[inline(always)]
            pub fn detect_features() -> u32 { 0 }
        }
    }
}

impl_get_feature! {
    Neon,

    // TODO(MSRV): There is no "pmull" feature listed from
    // `rustc --print cfg --target=aarch64-apple-darwin`. Originally ARMv8 tied
    // PMULL detection into AES detection, but later versions split it; see
    // https://developer.arm.com/downloads/-/exploration-tools/feature-names-for-a-profile
    // "Features introduced prior to 2020." Change this to use "pmull" when
    // that is supported.
    PMull,

    Aes,

    Sha256,

    // "sha3" is overloaded for both SHA-3 and SHA-512.
    Sha512,
}

pub(super) mod featureflags {
    pub(in super::super) use super::detect::FORCE_DYNAMIC_DETECTION;
    use super::*;
    use crate::{cpu, polyfill::once_cell::race};
    use core::num::NonZeroU32;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        fn init() -> NonZeroU32 {
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
            Shift::INITIALIZED_MASK | merged
        }

        // SAFETY: This is the only caller. Any concurrent reading doesn't
        // affect the safety of the writing.
        let _: NonZeroU32 = FEATURES.get_or_init(init);

        // SAFETY: We initialized the CPU features as required.
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(in super::super) fn get(_cpu_features: cpu::Features) -> u32 {
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after `FEATURES.get_or_init()`,
        // we know we are reading from `FEATURES` after initializing it.
        // The `get_or_init()` also did the synchronization.
        let features = unsafe { FEATURES.get_unchecked() };
        features.get()
    }

    // On AArch64, we store all feature flags in `FEATURES`, so we dnn't need
    // Acquire/Release semantics.
    static FEATURES: race::OnceNonZeroU32<race::Relaxed> = race::OnceNonZeroU32::new();

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
