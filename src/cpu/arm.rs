// Copyright 2016-2021 Brian Smith.
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

#![cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "arm")),
    allow(dead_code)
)]

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod abi_assumptions {
    // TODO: Support ARM64_32; see
    // https://github.com/briansmith/ring/issues/1832#issuecomment-1892928147. This also requires
    // replacing all `cfg(target_pointer_width)` logic for non-pointer/reference things
    // (`N0`, `Limb`, `LimbMask`, `crypto_word_t` etc.).
    #[cfg(target_arch = "aarch64")]
    const _ASSUMED_POINTER_SIZE: usize = 8;
    #[cfg(target_arch = "arm")]
    const _ASSUMED_POINTER_SIZE: usize = 4;
    const _ASSUMED_USIZE_SIZE: () = assert!(core::mem::size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () =
        assert!(core::mem::size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

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

#[cfg(all(
    any(target_os = "android", target_os = "linux"),
    any(target_arch = "aarch64", target_arch = "arm"),
    not(target_env = "uclibc")
))]
fn detect_features() -> u32 {
    use libc::c_ulong;

    // XXX: The `libc` crate doesn't provide `libc::getauxval` consistently
    // across all Android/Linux targets, e.g. musl.
    extern "C" {
        fn getauxval(type_: c_ulong) -> c_ulong;
    }

    const AT_HWCAP: c_ulong = 16;

    #[cfg(target_arch = "aarch64")]
    const HWCAP_NEON: c_ulong = 1 << 1;

    #[cfg(target_arch = "arm")]
    const HWCAP_NEON: c_ulong = 1 << 12;

    let caps = unsafe { getauxval(AT_HWCAP) };

    // We assume NEON is available on AARCH64 because it is a required
    // feature.
    #[cfg(target_arch = "aarch64")]
    debug_assert!(caps & HWCAP_NEON == HWCAP_NEON);

    let mut features = 0;

    // OpenSSL and BoringSSL don't enable any other features if NEON isn't
    // available.
    if caps & HWCAP_NEON == HWCAP_NEON {
        features = NEON.mask;

        #[cfg(target_arch = "aarch64")]
        const OFFSET: c_ulong = 3;

        #[cfg(target_arch = "arm")]
        const OFFSET: c_ulong = 0;

        #[cfg(target_arch = "arm")]
        let caps = {
            const AT_HWCAP2: c_ulong = 26;
            unsafe { getauxval(AT_HWCAP2) }
        };

        const HWCAP_AES: c_ulong = 1 << 0 + OFFSET;
        const HWCAP_PMULL: c_ulong = 1 << 1 + OFFSET;
        const HWCAP_SHA2: c_ulong = 1 << 3 + OFFSET;

        if caps & HWCAP_AES == HWCAP_AES {
            features |= AES.mask;
        }
        if caps & HWCAP_PMULL == HWCAP_PMULL {
            features |= PMULL.mask;
        }
        if caps & HWCAP_SHA2 == HWCAP_SHA2 {
            features |= SHA256.mask;
        }
    }

    features
}

#[cfg(all(target_os = "fuchsia", target_arch = "aarch64"))]
fn detect_features() -> u32 {
    type zx_status_t = i32;

    #[link(name = "zircon")]
    extern "C" {
        fn zx_system_get_features(kind: u32, features: *mut u32) -> zx_status_t;
    }

    const ZX_OK: i32 = 0;
    const ZX_FEATURE_KIND_CPU: u32 = 0;
    const ZX_ARM64_FEATURE_ISA_ASIMD: u32 = 1 << 2;
    const ZX_ARM64_FEATURE_ISA_AES: u32 = 1 << 3;
    const ZX_ARM64_FEATURE_ISA_PMULL: u32 = 1 << 4;
    const ZX_ARM64_FEATURE_ISA_SHA2: u32 = 1 << 6;

    let mut caps = 0;
    let rc = unsafe { zx_system_get_features(ZX_FEATURE_KIND_CPU, &mut caps) };

    let mut features = 0;

    // OpenSSL and BoringSSL don't enable any other features if NEON isn't
    // available.
    if rc == ZX_OK && (caps & ZX_ARM64_FEATURE_ISA_ASIMD == ZX_ARM64_FEATURE_ISA_ASIMD) {
        features = NEON.mask;

        if caps & ZX_ARM64_FEATURE_ISA_AES == ZX_ARM64_FEATURE_ISA_AES {
            features |= AES.mask;
        }
        if caps & ZX_ARM64_FEATURE_ISA_PMULL == ZX_ARM64_FEATURE_ISA_PMULL {
            features |= PMULL.mask;
        }
        if caps & ZX_ARM64_FEATURE_ISA_SHA2 == ZX_ARM64_FEATURE_ISA_SHA2 {
            features |= 1 << 4;
        }
    }

    features
}

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
fn detect_features() -> u32 {
    // We do not need to check for the presence of NEON, as Armv8-A always has it
    const _ASSERT_NEON_DETECTED: () = assert!((ARMCAP_STATIC & NEON.mask) == NEON.mask);
    let mut features = ARMCAP_STATIC;

    let result = unsafe {
        windows_sys::Win32::System::Threading::IsProcessorFeaturePresent(
            windows_sys::Win32::System::Threading::PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE,
        )
    };

    if result != 0 {
        // These are all covered by one call in Windows
        features |= AES.mask;
        features |= PMULL.mask;
        features |= SHA256.mask;
    }

    features
}

#[cfg(all(
    any(target_arch = "aarch64", target_arch = "arm"),
    not(any(
        target_os = "android",
        target_os = "fuchsia",
        all(target_os = "linux", not(target_env = "uclibc")),
        target_os = "windows"
    ))
))]
fn detect_features() -> u32 {
    0
}

macro_rules! features {
    {
        $(
            $target_feature_name:expr => $name:ident {
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
        )+

        const ARMCAP_STATIC: u32 = 0
            $(
                | (
                    if cfg!(all(any(target_arch = "aarch64", target_arch = "arm"),
                                target_feature = $target_feature_name)) {
                        $name.mask
                    } else {
                        0
                    }
                )
            )+;

        #[cfg(all(test, any(target_arch = "arm", target_arch = "aarch64")))]
        const ALL_FEATURES: [Feature; 4] = [
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
    pub fn available(&self, _: super::Features) -> bool {
        if self.mask == self.mask & ARMCAP_STATIC {
            return true;
        }

        #[cfg(all(
            any(
                target_os = "android",
                target_os = "fuchsia",
                all(target_os = "linux", not(target_env = "uclibc")),
                target_os = "windows"
            ),
            any(target_arch = "arm", target_arch = "aarch64")
        ))]
        {
            // SAFETY: See `OPENSSL_armcap_P`'s safety documentation.
            if self.mask == self.mask & unsafe { OPENSSL_armcap_P } {
                return true;
            }
        }

        false
    }
}

// Assumes all target feature names are the same for ARM and AAarch64.
features! {
    // Keep in sync with `ARMV7_NEON`.
    "neon" => NEON {
        mask: 1 << 0,
    },

    // Keep in sync with `ARMV8_AES`.
    "aes" => AES {
        mask: 1 << 2,
    },

    // Keep in sync with `ARMV8_SHA256`.
    "sha2" => SHA256 {
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
    "aes" => PMULL {
        mask: 1 << 5,
    },
}

// SAFETY:
// - This may only be called from within `cpu::features()` and only while it is initializing its
//   `INIT`.
// - See the safety invariants of `OPENSSL_armcap_P` below.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub unsafe fn init_global_shared_with_assembly() {
    let detected = detect_features();
    let filtered = (if cfg!(feature = "unstable-testing-arm-no-hw") {
        AES.mask | SHA256.mask | PMULL.mask
    } else {
        0
    }) | (if cfg!(feature = "unstable-testing-arm-no-neon") {
        NEON.mask
    } else {
        0
    });
    let detected = detected & !filtered;
    OPENSSL_armcap_P = ARMCAP_STATIC | detected;
}

// Some non-Rust code still checks this even when it is statically known
// the given feature is available, so we have to ensure that this is
// initialized properly. Keep this in sync with the initialization in
// BoringSSL's crypto.c.
//
// TODO: This should have "hidden" visibility but we don't have a way of
// controlling that yet: https://github.com/rust-lang/rust/issues/73958.
//
// SAFETY:
// - Rust code only accesses this through `cpu::Features`, which acts as a witness that
//   `cpu::features()` was called to initialize this.
// - Some assembly language functions access `OPENSSL_armcap_P` directly. Callers of those functions
//   must obtain a `cpu::Features` before calling them.
// - An instance of `cpu::Features` is a witness that this was initialized.
// - The initialization of the `INIT` in `cpu::features()` initializes this, and that `OnceCell`
//   implements acquire/release semantics that allow all the otherwise-apparently-unsynchronized
//   access.
// - `OPENSSL_armcap_P` must always be a superset of `ARMCAP_STATIC`.
// TODO: Remove all the direct accesses of this from assembly language code, and then replace this
// with a `OnceCell<u32>` that will provide all the necessary safety guarantees.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
prefixed_extern! {
    static mut OPENSSL_armcap_P: u32;
}

// MSRV: Enforce 1.61.0 on some aarch64-* targets (aarch64-apple-*, in particular) prior to. Earlier
// versions of Rust before did not report the AAarch64 CPU features correctly for these targets.
// Cargo.toml specifies `rust-version` but versions before Rust 1.56 don't know about it.
//
// ```
// $ rustc +1.61.0 --print cfg --target=aarch64-apple-ios | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// $ rustc +1.61.0 --print cfg --target=aarch64-apple-darwin | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// target_feature="sha3"
// ```
#[allow(clippy::assertions_on_constants)]
const _AARCH64_HAS_NEON: () =
    assert!(((ARMCAP_STATIC & NEON.mask) == NEON.mask) || !cfg!(target_arch = "aarch64"));
#[allow(clippy::assertions_on_constants)]
const _AARCH64_APPLE_FEATURES: u32 = NEON.mask | AES.mask | SHA256.mask | PMULL.mask;
#[allow(clippy::assertions_on_constants)]
const _AARCH64_APPLE_TARGETS_EXPECTED_FEATURES: () = assert!(
    ((ARMCAP_STATIC & _AARCH64_APPLE_FEATURES) == _AARCH64_APPLE_FEATURES)
        || !cfg!(all(target_arch = "aarch64", target_vendor = "apple"))
);

#[cfg(all(test, any(target_arch = "arm", target_arch = "aarch64")))]
mod tests {
    use super::*;

    #[test]
    fn test_mask_abi() {
        assert_eq!(NEON.mask, 1);
        assert_eq!(AES.mask, 4);
        assert_eq!(SHA256.mask, 16);
        assert_eq!(PMULL.mask, 32);
    }

    #[test]
    fn test_armcap_static_is_subset_of_armcap_dynamic() {
        // Ensure `OPENSSL_armcap_P` is initialized.
        let cpu = crate::cpu::features();

        let armcap_dynamic = unsafe { OPENSSL_armcap_P };
        assert_eq!(armcap_dynamic & ARMCAP_STATIC, ARMCAP_STATIC);

        ALL_FEATURES.iter().for_each(|feature| {
            if (ARMCAP_STATIC & feature.mask) != 0 {
                assert!(feature.available(cpu));
            }
        })
    }
}
