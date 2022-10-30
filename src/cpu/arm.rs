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

// TODO(MSRV): Replace this with use of `std::arch::is_arm_feature_detected!()`.
#[cfg(all(target_arch = "arm", any(target_os = "android", target_os = "linux")))]
pub fn setup() {
    use libc::{c_ulong, getauxval, AT_HWCAP};

    const HWCAP_NEON: c_ulong = 1 << 12;

    let caps = unsafe { getauxval(AT_HWCAP) };

    // OpenSSL and BoringSSL don't enable any other features if NEON isn't
    // available.
    if caps & HWCAP_NEON == HWCAP_NEON {
        let mut features = NEON.mask;

        #[cfg(target_arch = "arm")]
        let caps = {
            const AT_HWCAP2: c_ulong = 26;
            unsafe { getauxval(AT_HWCAP2) }
        };

        const HWCAP2_AES: c_ulong = 1 << 0;
        const HWCAP2_PMULL: c_ulong = 1 << 1;
        const HWCAP2_SHA2: c_ulong = 1 << 3;

        if caps & HWCAP2_AES == HWCAP2_AES {
            features |= AES.mask;
        }
        if caps & HWCAP2_PMULL == HWCAP2_PMULL {
            features |= PMULL.mask;
        }
        if caps & HWCAP2_SHA2 == HWCAP2_SHA2 {
            features |= SHA256.mask;
        }

        unsafe { OPENSSL_armcap_P = features };
    }
}

macro_rules! features {
    {   // Use `:tt` instead of `:literal` to work around
        // https://github.com/rust-lang/rust/issues/72726.
        $(
            $static_target_feature_name:literal then $dynamic_target_feature_name:tt => $name:ident {
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

        #[cfg(all(target_arch = "aarch64", any(target_family = "unix", target_family = "windows")))]
        pub fn setup() {
            extern crate std;
            use std::arch::is_aarch64_feature_detected;

            let features = 0
            $(
                | (if is_aarch64_feature_detected!($dynamic_target_feature_name) { $name.mask } else { 0 })
            )+;
            debug_assert_eq!(features & ARMCAP_STATIC, ARMCAP_STATIC);
            unsafe { OPENSSL_armcap_P = features };
        }

        const ARMCAP_STATIC: u32 = 0
            $(
                | ( if cfg!(target_feature = $static_target_feature_name) { $name.mask } else { 0 } )
            )+;

        const _ALL_FEATURES_MASK: u32 = 0
            $(  | $name.mask
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
                target_os = "linux",
                target_os = "windows"
            ),
            any(target_arch = "arm", target_arch = "aarch64")
        ))]
        {
            if self.mask == self.mask & unsafe { OPENSSL_armcap_P } {
                return true;
            }
        }

        false
    }
}

// Assumes all target feature names are the same for ARM and AAarch64.
features! {
    "neon" then "neon" => NEON {
        mask: 1 << 0,
    },

    "aes" then "aes" => AES {
        mask: 1 << 2,
    },

    "sha2" then "sha2" => SHA256 {
        mask: 1 << 4,
    },

    // TODO(MSRV): There is no "pmull" feature listed from
    // `rustc --print cfg --target=aarch64-apple-darwin`. Originally ARMv8 tied
    // PMULL detection into AES detection, but later versions split it; see
    // https://developer.arm.com/downloads/-/exploration-tools/feature-names-for-a-profile
    // "Features introduced prior to 2020." Change this to use "pmull" when
    // that is supported.
    "aes" then "pmull" => PMULL {
        mask: 1 << 5,
    },
}

// Some non-Rust code still checks this even when it is statically known
// the given feature is available, so we have to ensure that this is
// initialized properly. Keep this in sync with the initialization in
// BoringSSL's crypto.c.
//
// TODO: This should have "hidden" visibility but we don't have a way of
// controlling that yet: https://github.com/rust-lang/rust/issues/73958.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
prefixed_export! {
    #[allow(non_upper_case_globals)]
    static mut OPENSSL_armcap_P: u32 = ARMCAP_STATIC;
}

const _APPLE_TARGETS_HAVE_ALL_FEATURES: () = assert!(
    (ARMCAP_STATIC == _ALL_FEATURES_MASK)
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

    #[cfg(target_vendor = "apple")]
    #[test]
    fn test_apple_minimum_features() {
        ALL_FEATURES.iter().for_each(|feature| {
            assert_eq!(ARMCAP_STATIC & feature.mask, feature.mask);
        });
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
