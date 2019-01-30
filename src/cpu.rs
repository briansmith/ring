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
                #[cfg(any(feature = "force_std_detection", all(target_env = "sgx" /*, target_vendor = "fortanix"*/)))]
                {
                    extern "C" {
                        static mut GFp_ia32cap_P: [u32; 4];
                    }
                    let [l1edx, l1ecx, l7ebx, l7ecx] = unsafe { &mut GFp_ia32cap_P };

                    if is_x86_feature_detected!("aes") {
                        *l1ecx |= 1<<25;
                    }
                    if is_x86_feature_detected!("pclmulqdq") {
                        *l1ecx |= 1<<1;
                    }
                    if is_x86_feature_detected!("rdrand") {
                        *l1ecx |= 1<<30;
                    }
                    if is_x86_feature_detected!("rdseed") {
                        *l7ebx |= 1<<18;
                    }
                    if is_x86_feature_detected!("tsc") {
                        *l1edx |= 1<<4;
                    }
                    if is_x86_feature_detected!("mmx") {
                        *l1edx |= 1<<23;
                    }
                    if is_x86_feature_detected!("sse") {
                        *l1edx |= 1<<25;
                    }
                    if is_x86_feature_detected!("sse2") {
                        *l1edx |= 1<<26;
                    }
                    if is_x86_feature_detected!("sse3") {
                        *l1ecx |= 1<<0;
                    }
                    if is_x86_feature_detected!("ssse3") {
                        *l1ecx |= 1<<9;
                    }
                    if is_x86_feature_detected!("sse4.1") {
                        *l1ecx |= 1<<19;
                    }
                    if is_x86_feature_detected!("sse4.2") {
                        *l1ecx |= 1<<20;
                    }
                    if is_x86_feature_detected!("sha") {
                        *l7ebx |= 1<<29;
                    }
                    if is_x86_feature_detected!("avx") {
                        *l1ecx |= 1<<28;
                    }
                    if is_x86_feature_detected!("avx2") {
                        *l7ebx |= 1<<5;
                    }
                    if is_x86_feature_detected!("avx512f") {
                        *l7ebx |= 1<<16;
                    }
                    if is_x86_feature_detected!("avx512cd") {
                        *l7ebx |= 1<<28;
                    }
                    if is_x86_feature_detected!("avx512er") {
                        *l7ebx |= 1<<27;
                    }
                    if is_x86_feature_detected!("avx512pf") {
                        *l7ebx |= 1<<26;
                    }
                    if is_x86_feature_detected!("avx512bw") {
                        *l7ebx |= 1<<30;
                    }
                    if is_x86_feature_detected!("avx512dq") {
                        *l7ebx |= 1<<17;
                    }
                    if is_x86_feature_detected!("avx512vl") {
                        *l7ebx |= 1<<31;
                    }
                    if is_x86_feature_detected!("avx512ifma") {
                        *l7ebx |= 1<<21;
                    }
                    if is_x86_feature_detected!("avx512vbmi") {
                        *l7ecx |= 1<<1;
                    }
                    if is_x86_feature_detected!("avx512vpopcntdq") {
                        *l7ecx |= 1<<14;
                    }
                    if is_x86_feature_detected!("fma") {
                        *l1ecx |= 1<<12;
                    }
                    if is_x86_feature_detected!("bmi1") {
                        *l7ebx |= 1<<3;
                    }
                    if is_x86_feature_detected!("bmi2") {
                        *l7ebx |= 1<<8;
                    }
                    if is_x86_feature_detected!("popcnt") {
                        *l1ecx |= 1<<23;
                    }
                    if is_x86_feature_detected!("fxsr") {
                        *l1edx |= 1<<24;
                    }
                    if is_x86_feature_detected!("xsave") {
                        *l1ecx |= 1<<26;
                    }
                    /* will be stable on 1.33.0
                    if is_x86_feature_detected!("cmpxchg16b") {
                        *l1ecx |= 1<<13;
                    }
                    if is_x86_feature_detected!("adx") {
                        *l7ebx |= 1<<19;
                    }
                    */

                    // Rust can't detect the MOVBE feature yet, but it's widely
                    // available.
                    *l1ecx |= 1<<22;

                    // This bit is reserved in the CPUID specification, but the
                    // BoringSSL detection code uses it to represent that this
                    // is an Intel CPU. However, this bit is only used in
                    // conjunction with the AVX bit to test for presence of
                    // AVX, thus serving no purpose. Always set it.
                    *l1edx |= 1<<30;

                    // Features that don't map to leaf 1 or leaf 7:
                    //   Leaf 0xd:
                    //   * xsaveopt
                    //   * xsaves
                    //   * xsavec
                    //   Leaf 0x8000_0001:
                    //   * sse4a
                    //   * abm
                    //   * lzcnt
                    //   * tbm
                }
                #[cfg(not(any(feature = "force_std_detection", all(target_env = "sgx" /*, target_vendor = "fortanix"*/))))]
                {
                    extern "C" {
                        fn GFp_cpuid_setup();
                    }
                    unsafe {
                        GFp_cpuid_setup();
                    }
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
