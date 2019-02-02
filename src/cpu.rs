// Copyright 2016 Brian Smith.
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

/// A witness indicating that CPU features have been detected and cached.
///
/// TODO: Eventually all feature detection logic should be done through
/// functions that accept a `Features` parameter, to guarantee that nothing
/// tries to read the cached values before they are written.
///
/// This is a zero-sized type so that it can be "stored" wherever convenient.
#[derive(Copy, Clone)]
pub(crate) struct Features(());

#[inline(always)]
pub(crate) fn features() -> Features {
    // We don't do runtime feature detection on iOS. instead some features are
    // assumed to be present; see `arm::Feature`.
    #[cfg(not(target_os = "ios"))]
    {
        static INIT: spin::Once<()> = spin::Once::new();
        let () = INIT.call_once(|| {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                extern "C" {
                    fn GFp_cpuid_setup();
                }
                unsafe {
                    GFp_cpuid_setup();
                }
            }

            #[cfg(all(
                any(target_os = "android", target_os = "linux"),
                any(target_arch = "aarch64", target_arch = "arm")
            ))]
            {
                arm::linux_setup();
            }

            #[cfg(all(target_os = "fuchsia", any(target_arch = "aarch64")))]
            {
                arm::fuchsia_setup();
            }
        });
    }

    Features(())
}

pub(crate) mod arm {
    #[cfg(all(
        any(target_os = "android", target_os = "linux"),
        any(target_arch = "aarch64", target_arch = "arm")
    ))]
    pub fn linux_setup() {
        // XXX: The `libc` crate doesn't provide `libc::getauxval` consistently
        // across all Android/Linux targets, e.g. musl.
        extern "C" {
            fn getauxval(type_: libc::c_ulong) -> libc::c_ulong;
        }

        const AT_HWCAP: libc::c_ulong = 16;

        #[cfg(target_arch = "aarch64")]
        const HWCAP_NEON: libc::c_ulong = 1 << 1;

        #[cfg(target_arch = "arm")]
        const HWCAP_NEON: libc::c_ulong = 1 << 12;

        let caps = unsafe { getauxval(AT_HWCAP) };

        // OpenSSL and BoringSSL don't enable any other features if NEON isn't
        // available.
        if caps & HWCAP_NEON == HWCAP_NEON {
            let mut features = NEON.mask;

            #[cfg(target_arch = "aarch64")]
            const OFFSET: libc::c_ulong = 3;

            #[cfg(target_arch = "arm")]
            const OFFSET: libc::c_ulong = 0;

            #[cfg(target_arch = "arm")]
            let caps = {
                const AT_HWCAP2: libc::c_ulong = 26;
                unsafe { getauxval(AT_HWCAP2) }
            };

            const HWCAP_AES: libc::c_ulong = 1 << 0 + OFFSET;
            const HWCAP_PMULL: libc::c_ulong = 1 << 1 + OFFSET;
            const HWCAP_SHA2: libc::c_ulong = 1 << 3 + OFFSET;

            if caps & HWCAP_AES == HWCAP_AES {
                features |= AES.mask;
            }
            if caps & HWCAP_PMULL == HWCAP_PMULL {
                features |= PMULL.mask;
            }
            if caps & HWCAP_SHA2 == HWCAP_SHA2 {
                features |= 1 << 4;
            }

            unsafe { GFp_armcap_P = features };
        }
    }

    #[cfg(all(target_os = "fuchsia", any(target_arch = "aarch64")))]
    pub fn fuchsia_setup() {
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

        // OpenSSL and BoringSSL don't enable any other features if NEON isn't
        // available.
        if rc == ZX_OK && (caps & ZX_ARM64_FEATURE_ISA_ASIMD == ZX_ARM64_FEATURE_ISA_ASIMD) {
            let mut features = NEON.mask;

            if caps & ZX_ARM64_FEATURE_ISA_AES == ZX_ARM64_FEATURE_ISA_AES {
                features |= AES.mask;
            }
            if caps & ZX_ARM64_FEATURE_ISA_PMULL == ZX_ARM64_FEATURE_ISA_PMULL {
                features |= PMULL.mask;
            }
            if caps & ZX_ARM64_FEATURE_ISA_SHA2 == ZX_ARM64_FEATURE_ISA_SHA2 {
                features |= 1 << 4;
            }

            unsafe { GFp_armcap_P = features };
        }
    }

    pub(crate) struct Feature {
        #[cfg_attr(
            any(
                target_os = "ios",
                not(any(target_arch = "arm", target_arch = "aarch64"))
            ),
            allow(dead_code)
        )]
        mask: u32,

        #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
        ios: bool,
    }

    impl Feature {
        #[inline(always)]
        pub fn available(&self, _: super::Features) -> bool {
            #[cfg(all(target_os = "ios", any(target_arch = "arm", target_arch = "aarch64")))]
            {
                return self.ios;
            }

            #[cfg(all(
                any(target_os = "android", target_os = "linux", target_os = "fuchsia"),
                any(target_arch = "arm", target_arch = "aarch64")
            ))]
            {
                return self.mask == self.mask & unsafe { GFp_armcap_P };
            }

            #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
            {
                return false;
            }
        }
    }

    // Keep in sync with `ARMV7_NEON`.
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    pub(crate) const NEON: Feature = Feature {
        mask: 1 << 0,
        ios: true,
    };

    // Keep in sync with `ARMV8_AES`.
    pub(crate) const AES: Feature = Feature {
        mask: 1 << 2,
        ios: true,
    };

    // Keep in sync with `ARMV8_PMULL`.
    pub(crate) const PMULL: Feature = Feature {
        mask: 1 << 5,
        ios: true,
    };

    #[cfg(all(
        any(target_os = "android", target_os = "linux", target_os = "fuchsia"),
        any(target_arch = "arm", target_arch = "aarch64")
    ))]
    extern "C" {
        static mut GFp_armcap_P: u32;
    }
}

#[cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(dead_code)
)]
pub(crate) mod intel {
    pub(crate) struct Feature {
        word: usize,
        mask: u32,
    }

    impl Feature {
        #[inline(always)]
        pub fn available(&self, _: super::Features) -> bool {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                extern "C" {
                    static mut GFp_ia32cap_P: [u32; 4];
                }
                return self.mask == self.mask & unsafe { GFp_ia32cap_P[self.word] };
            }

            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            {
                return false;
            }
        }
    }

    pub(crate) const FXSR: Feature = Feature {
        word: 0,
        mask: 1 << 24,
    };

    pub(crate) const PCLMULQDQ: Feature = Feature {
        word: 1,
        mask: 1 << 1,
    };

    pub(crate) const SSSE3: Feature = Feature {
        word: 1,
        mask: 1 << 9,
    };

    #[cfg(target_arch = "x86_64")]
    pub(crate) const MOVBE: Feature = Feature {
        word: 1,
        mask: 1 << 22,
    };

    pub(crate) const AES: Feature = Feature {
        word: 1,
        mask: 1 << 25,
    };

    #[cfg(target_arch = "x86_64")]
    pub(crate) const AVX: Feature = Feature {
        word: 1,
        mask: 1 << 28,
    };

    #[cfg(all(target_arch = "x86_64", test))]
    mod x86_64_tests {
        use super::*;

        #[test]
        fn test_avx_movbe_mask() {
            // This is the OpenSSL style of testing these bits.
            assert_eq!((AVX.mask | MOVBE.mask) >> 22, 0x41);
        }
    }
}
