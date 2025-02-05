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

mod abi_assumptions {
    use core::mem::size_of;

    // TODO: Support ARM64_32; see
    // https://github.com/briansmith/ring/issues/1832#issuecomment-1892928147. This also requires
    // replacing all `cfg(target_pointer_width)` logic for non-pointer/reference things
    // (`N0`, `Limb`, `LimbMask`, `crypto_word_t` etc.).
    #[cfg(target_arch = "aarch64")]
    const _ASSUMED_POINTER_SIZE: usize = 8;
    #[cfg(target_arch = "arm")]
    const _ASSUMED_POINTER_SIZE: usize = 4;
    const _ASSUMED_USIZE_SIZE: () = assert!(size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () = assert!(size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

    // To support big-endian, we'd need to make several changes as described in
    // https://github.com/briansmith/ring/issues/1832.
    const _ASSUMED_ENDIANNESS: () = assert!(cfg!(target_endian = "little"));
}

// uclibc: When linked statically, uclibc doesn't provide getauxval.
// When linked dynamically, recent versions do provide it, but we
// want to support older versions too. Assume that if uclibc is being
// used, this is an embedded target where the user cares a lot about
// minimizing code size and also that they know in advance exactly
// what target features are supported, so rely only on static feature
// detection.

cfg_if::cfg_if! {
    if #[cfg(all(all(target_arch = "aarch64", target_endian = "little"),
                 any(target_os = "ios", target_os = "macos", target_os = "tvos", target_os = "visionos", target_os = "watchos")))] {
        mod darwin;
        use darwin as detect;
    } else if #[cfg(all(all(target_arch = "aarch64", target_endian = "little"), target_os = "fuchsia"))] {
        mod fuchsia;
        use fuchsia as detect;
    } else if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use linux as detect;
    } else if #[cfg(all(all(target_arch = "aarch64", target_endian = "little"), target_os = "windows"))] {
        mod windows;
        use windows as detect;
    } else {
        mod detect {
            pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
            pub fn detect_features() -> u32 { 0 }
        }
    }
}

macro_rules! impl_get_feature_arm {
    { $feature:path => $T:ident } => {
        impl_get_feature!( $T );

        impl crate::cpu::GetFeature<$T> for super::Features {
            fn get_feature(&self) -> Option<$T> {
                if $feature.available(*self) {
                    Some($T(*self))
                } else {
                    None
                }
            }
        }
    }
}

macro_rules! features {
    {
        $(
            $target_feature_name:expr => $TyName:ident($name:ident) {
                mask: $mask:expr,
            }
        ),+
        , // trailing comma is required.
    } => {
        $(
            #[allow(dead_code)]
            pub(crate) const $name: Feature = Feature {
                mask: $mask,
            };
            impl_get_feature_arm!{ $name => $TyName }
        )+

        // See const assertions below.
        const ARMCAP_STATIC: u32 = ARMCAP_STATIC_DETECTED & !detect::FORCE_DYNAMIC_DETECTION;
        const ARMCAP_STATIC_DETECTED: u32 = 0
            $(
                | (
                    if cfg!(all(any(all(target_arch = "aarch64", target_endian = "little"), all(target_arch = "arm", target_endian = "little")),
                                target_feature = $target_feature_name)) {
                        $name.mask
                    } else {
                        0
                    }
                )
            )+;

        const ALL_FEATURES: &[Feature] = &[
            $(
                $name
            ),+
        ];
    }
}

pub(crate) struct Feature {
    mask: u32,
}

impl Feature {
    #[inline(always)]
    pub fn available(&self, cpu_features: super::Features) -> bool {
        if self.mask == self.mask & ARMCAP_STATIC {
            return true;
        }
        self.mask == self.mask & featureflags::get(cpu_features)
    }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
features! {
    // Keep in sync with `ARMV7_NEON`.
    "neon" => Neon(NEON) {
        mask: 1 << 0,
    },

    // Keep in sync with `ARMV8_AES`.
    "aes" => Aes(AES) {
        mask: 1 << 2,
    },

    // Keep in sync with `ARMV8_SHA256`.
    "sha2" => Sha256(SHA256) {
        mask: 1 << 4,
    },

    // Keep in sync with `ARMV8_PMULL`.
    //
    // TODO(MSRV): There is no "pmull" feature listed from
    // `rustc --print cfg --target=aarch64-apple-darwin`. Originally ARMv8 tied
    // PMULL detection into AES detection, but later versions split it; see
    // https://developer.arm.com/downloads/-/exploration-tools/feature-names-for-a-profile
    // "Features introduced prior to 2020." Change this to use "pmull" when
    // that is supported.
    "aes" => PMull(PMULL) {
        mask: 1 << 5,
    },

    // Keep in sync with `ARMV8_SHA512`.
    // "sha3" is overloaded for both SHA-3 and SHA512.
    "sha3" => Sha512(SHA512) {
        mask: 1 << 6,
    },
}

#[cfg(all(target_arch = "arm", target_endian = "little"))]
features! {
    // Keep in sync with `ARMV7_NEON`.
    "neon" => Neon(NEON) {
        mask: 1 << 0,
    },
}

pub(super) mod featureflags {
    use super::{detect, ALL_FEATURES, ARMCAP_STATIC, NEON};
    use crate::cpu;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        fn init() -> u32 {
            let detected = detect::detect_features();
            let filtered = (if cfg!(feature = "unstable-testing-arm-no-hw") {
                ALL_FEATURES
                    .iter()
                    .fold(0, |acc, feature| acc | feature.mask)
                    & !NEON.mask
            } else {
                0
            }) | (if cfg!(feature = "unstable-testing-arm-no-neon") {
                NEON.mask
            } else {
                0
            });
            let detected = detected & !filtered;
            let merged = ARMCAP_STATIC | detected;

            #[cfg(target_arch = "arm")]
            if (merged & NEON.mask) == NEON.mask {
                prefixed_extern! {
                    static mut neon_available: u32;
                }

                // TODO(MSRV 1.82.0): Remove `unsafe`.
                #[allow(unused_unsafe)]
                let p = unsafe { core::ptr::addr_of_mut!(neon_available) };

                // SAFETY: This is the only writer, and concurrent writing is
                // prevented as this is the `OnceLock`-like one-time
                // initialization provided by `spin::Once`. Any concurrent
                // reading doesn't affect the safety of this write. Any read
                // of `neon_available` before this initialization will be zero,
                // which is safe (no risk of illegal instructions) and correct
                // (the value computed will be the same regardless).
                //
                // The way we use `spin::Once` ensures the happens-before
                // relationship that is needed for readers to observe this
                // write.
                unsafe {
                    p.write(1);
                }
            }

            merged
        }

        // SAFETY: This is the only caller. Any concurrent reading doesn't
        // affect the safety of the writing.
        let _: &u32 = FEATURES.call_once(init);

        // SAFETY: We initialized the CPU features as required.
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(super) fn get(_cpu_features: cpu::Features) -> u32 {
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after `FEATURES.call_once()`,
        // we have met the prerequisites for calling `get_unchecked()`.
        let features: &u32 = unsafe { FEATURES.get_unchecked() };
        *features
    }

    static FEATURES: spin::Once<u32> = spin::Once::new();
}

#[allow(clippy::assertions_on_constants)]
const _AARCH64_HAS_NEON: () = assert!(
    ((ARMCAP_STATIC & NEON.mask) == NEON.mask)
        || !cfg!(all(target_arch = "aarch64", target_endian = "little"))
);

#[allow(clippy::assertions_on_constants)]
const _FORCE_DYNAMIC_DETECTION_HONORED: () =
    assert!((ARMCAP_STATIC & detect::FORCE_DYNAMIC_DETECTION) == 0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu;

    #[test]
    fn test_mask_abi() {
        assert_eq!(NEON.mask, 1);
    }

    #[cfg(not(all(target_arch = "arm", target_endian = "little")))]
    #[test]
    fn test_mask_abi_hw() {
        assert_eq!(AES.mask, 4);
        assert_eq!(SHA256.mask, 16);
        assert_eq!(PMULL.mask, 32);
        assert_eq!(SHA512.mask, 64);
    }

    #[test]
    fn test_armcap_static_is_subset_of_armcap_dynamic() {
        let cpu = cpu::features();
        let armcap_dynamic = featureflags::get(cpu);
        assert_eq!(armcap_dynamic & ARMCAP_STATIC, ARMCAP_STATIC);

        ALL_FEATURES.iter().for_each(|feature| {
            if (ARMCAP_STATIC & feature.mask) != 0 {
                assert!(feature.available(cpu));
            }
        })
    }
}
