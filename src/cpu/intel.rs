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

use cfg_if::cfg_if;

mod abi_assumptions {
    use core::mem::size_of;

    // TOOD: Support targets that do not have SSE and SSE2 enabled, such as
    // x86_64-unknown-linux-none. See
    // https://github.com/briansmith/ring/issues/1793#issuecomment-1793243725,
    // https://github.com/briansmith/ring/issues/1832,
    // https://github.com/briansmith/ring/issues/1833.
    const _ASSUMES_SSE2: () =
        assert!(cfg!(target_feature = "sse") && cfg!(target_feature = "sse2"));

    #[cfg(target_arch = "x86_64")]
    const _ASSUMED_POINTER_SIZE: usize = 8;
    #[cfg(target_arch = "x86")]
    const _ASSUMED_POINTER_SIZE: usize = 4;
    const _ASSUMED_USIZE_SIZE: () = assert!(size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () = assert!(size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

    const _ASSUMED_ENDIANNESS: () = assert!(cfg!(target_endian = "little"));
}

pub(super) mod featureflags {
    use crate::{
        cpu,
        polyfill::{once_cell::race, usize_from_u32},
    };
    use core::num::NonZeroUsize;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        // SAFETY: `OPENSSL_cpuid_setup` must be called only in
        // `INIT.call_once()` below.
        prefixed_extern! {
            fn OPENSSL_cpuid_setup(out: &mut [u32; 4]);
        }

        let _: NonZeroUsize = FEATURES.get_or_init(|| {
            let mut cpuid = [0; 4];
            // SAFETY: We assume that it is safe to execute CPUID and XGETBV.
            unsafe {
                OPENSSL_cpuid_setup(&mut cpuid);
            }
            let caps = super::cpuid_to_caps_and_set_c_flags(&cpuid);
            let caps = usize_from_u32(caps) | (1 << (super::Shift::Initialized as u32));
            NonZeroUsize::new(caps).unwrap() // Can't fail because we just set a bit of `caps`.
        });

        // SAFETY: We initialized the CPU features as required.
        // `INIT.call_once` has `happens-before` semantics.
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(in super::super) fn get(_cpu_features: cpu::Features) -> u32 {
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after `FEATURES.get_or_init()`,
        // we know we are reading from `FEATURES` after initializing it.
        //
        // Also, 0 means "no features detected" to users, which is designed to
        // be a safe configuration.
        let features = FEATURES.get().map(NonZeroUsize::get).unwrap_or(0);

        // The truncation is lossless, as we set the value with a u32.
        #[allow(clippy::cast_possible_truncation)]
        let features = features as u32;

        features
    }

    static FEATURES: race::OnceNonZeroUsize = race::OnceNonZeroUsize::new();

    pub const STATIC_DETECTED: u32 = 0;
    pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
}

fn cpuid_to_caps_and_set_c_flags(cpuid: &[u32; 4]) -> u32 {
    // "Intel" citations are for "Intel 64 and IA-32 Architectures Software
    // Developer’s Manual", Combined Volumes, December 2024.
    // "AMD" citations are for "AMD64 Technology AMD64 Architecture
    // Programmer’s Manual, Volumes 1-5" Revision 4.08 April 2024.

    // The `prefixed_extern!` uses below assume this
    #[cfg(target_arch = "x86_64")]
    use core::{mem::align_of, sync::atomic::AtomicU32};
    #[cfg(target_arch = "x86_64")]
    const _ATOMIC32_ALIGNMENT_EQUALS_U32_ALIGNMENT: () =
        assert!(align_of::<AtomicU32>() == align_of::<u32>());

    fn check(leaf: u32, bit: u32) -> bool {
        let shifted = 1 << bit;
        (leaf & shifted) == shifted
    }
    fn set(out: &mut u32, shift: Shift) {
        let shifted = 1 << (shift as u32);
        debug_assert_eq!(*out & shifted, 0);
        *out |= shifted;
        debug_assert_eq!(*out & shifted, shifted);
    }

    // CPUID leaf 1.
    let leaf1_ecx = cpuid[1];

    // Intel: "Structured Extended Feature Flags Enumeration Leaf"
    #[cfg(target_arch = "x86_64")]
    let extended_features_ebx = cpuid[2];

    // We don't need anything from cpuid[3] presently.

    let mut caps = 0;

    #[cfg(target_arch = "x86_64")]
    {
        // Synthesized.
        if check(cpuid[0], 30) {
            set(&mut caps, Shift::IntelCpu);
        }

        if check(leaf1_ecx, 22) {
            set(&mut caps, Shift::Movbe);
        }

        if check(extended_features_ebx, 3) {
            set(&mut caps, Shift::Bmi1);
        }

        let bmi2_available = check(extended_features_ebx, 8);
        if bmi2_available {
            set(&mut caps, Shift::Bmi2);
        };

        if check(extended_features_ebx, 19) {
            set(&mut caps, Shift::Adx);

            if bmi2_available {
                // Declared as `uint32_t` in the C code.
                prefixed_extern! {
                    static adx_bmi2_available: AtomicU32;
                }
                // SAFETY: The C code only reads `adx_bmi2_available`, and its
                // reads are synchronized through the `OnceNonZeroUsize`
                // Acquire/Release semantics as we ensure we have a
                // `cpu::Features` instance before calling into the C code.
                let flag = unsafe { &adx_bmi2_available };
                flag.store(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    // The preceding do not require (or denote) the ability to access any SIMD
    // registers.

    // AMD: "Collectively the SSE1, [...] are referred to as the legacy SSE
    // instructions. All legacy SSE instructions support 128-bit vector
    // operands."

    // Intel: "11.6.2 Checking for Intel SSE and SSE2 Support"
    // We have to assume the prerequisites for SSE/SSE2 are met since we're
    // already almost deifnitely using SSE registers if these target features
    // are enabled.
    const _SSE_REQUIRED: () = assert!(cfg!(target_feature = "sse"));
    const _SSE2_REQUIRED: () = assert!(cfg!(target_feature = "sse2"));

    // Intel: "12.7.2 Checking for SSSE3 Support"
    // If/when we support dynamic detection of SSE/SSE2, make this conditional
    // on SSE/SSE2.
    if check(leaf1_ecx, 9) {
        set(&mut caps, Shift::Ssse3);
    }

    // Intel: "12.12.2 Checking for Intel SSE4.1 Support"
    // If/when we support dynamic detection of SSE/SSE2, make this conditional
    // on SSE/SSE2.
    // XXX: We don't check for SSE3 and we're not sure if it is compatible for
    //      us to do so; does AMD advertise SSE3? TODO: address this.
    // XXX: We don't condition this on SSSE3 being available. TODO: address
    //      this.
    #[cfg(target_arch = "x86_64")]
    if check(leaf1_ecx, 19) {
        set(&mut caps, Shift::Sse41);
    }

    // AMD: "The extended SSE instructions include [...]."

    // Intel: "14.3 DETECTION OF INTEL AVX INSTRUCTIONS"
    // `OPENSSL_cpuid_setup` clears this bit when it detects the OS doesn't
    // support AVX state.
    if check(leaf1_ecx, 28) {
        set(&mut caps, Shift::Avx);
    }

    // "14.7.1 Detection of Intel AVX2 Hardware support"
    // XXX: We don't condition AVX2 on AVX. TODO: Address this.
    // `OPENSSL_cpuid_setup` clears this bit when it detects the OS doesn't
    // support AVX state.
    #[cfg(target_arch = "x86_64")]
    if check(extended_features_ebx, 5) {
        set(&mut caps, Shift::Avx2);

        // Declared as `uint32_t` in the C code.
        prefixed_extern! {
            static avx2_available: AtomicU32;
        }
        // SAFETY: The C code only reads `avx2_available`, and its reads are
        // synchronized through the `OnceNonZeroUsize` Acquire/Release
        // semantics as we ensure we have a `cpu::Features` instance before
        // calling into the C code.
        let flag = unsafe { &avx2_available };
        flag.store(1, core::sync::atomic::Ordering::Relaxed);
    }

    // Intel: "12.13.4 Checking for Intel AES-NI Support"
    // If/when we support dynamic detection of SSE/SSE2, revisit this.
    // TODO: Clarify "interesting" states like (!SSE && AVX && AES-NI)
    // and AES-NI & !AVX.
    // Each check of `ClMul`, `Aes`, and `Sha` must be paired with a check for
    // an AVX feature (e.g. `Avx`) or an SSE feature (e.g. `Ssse3`), as every
    // use will either be supported by SSE* or AVX* instructions. We then
    // assume that those supporting instructions' prerequisites (e.g. OS
    // support for AVX or SSE state, respectively) are the only prerequisites
    // for these features.
    if check(leaf1_ecx, 1) {
        set(&mut caps, Shift::ClMul);
    }
    if check(leaf1_ecx, 25) {
        set(&mut caps, Shift::Aes);
    }
    // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
    // static feature detection for this.
    #[cfg(target_arch = "x86_64")]
    if check(extended_features_ebx, 29) {
        set(&mut caps, Shift::Sha);
    }

    caps
}

impl_get_feature! {
    features: [
        { ("x86", "x86_64") => ClMul },
        { ("x86", "x86_64") => Ssse3 },
        { ("x86_64") => Sse41 },
        { ("x86_64") => Movbe },
        { ("x86", "x86_64") => Aes },
        { ("x86", "x86_64") => Avx },
        { ("x86_64") => Bmi1 },
        { ("x86_64") => Avx2 },
        { ("x86_64") => Bmi2 },
        { ("x86_64") => Adx },
        // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
        // static feature detection for this.
        { ("x86_64") => Sha },
    ],
}

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        #[derive(Clone, Copy)]
        pub(crate) struct IntelCpu(super::Features);

        impl super::GetFeature<IntelCpu> for super::features::Values {
            fn get_feature(&self) -> Option<IntelCpu> {
                const MASK: u32 = 1 << (Shift::IntelCpu as u32);
                if (self.values() & MASK) == MASK {
                    Some(IntelCpu(self.cpu()))
                } else {
                    None
                }
            }
        }

        #[derive(Clone, Copy)]
        pub(crate) struct NotPreZenAmd(super::Features);

        impl super::GetFeature<NotPreZenAmd> for super::features::Values {
            fn get_feature(&self) -> Option<NotPreZenAmd> {
                let sha2: Option<Avx2> = self.get_feature();
                // Pre-Zen AMD CPUs didn't implement SHA. (One Pre-Zen AMD CPU
                // did support AVX2.) If we're building for a CPU that requires
                // SHA instructions then we want to avoid the runtime check for
                // an Intel/AND CPU.
                if sha2.is_some() {
                    return Some(NotPreZenAmd(self.cpu()));
                }
                // Perhaps we should do !AMD instead of Intel.
                let intel: Option<IntelCpu> = self.get_feature();
                if intel.is_some() {
                    return Some(NotPreZenAmd(self.cpu()))
                }
                None
            }
        }
    }
}
