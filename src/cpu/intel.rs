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
use core::{mem::align_of, sync::atomic::AtomicU32};

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
    use crate::cpu;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        // SAFETY: `OPENSSL_cpuid_setup` must be called only in
        // `INIT.call_once()` below.
        prefixed_extern! {
            fn OPENSSL_cpuid_setup(out: &mut [u32; 4]);
        }

        let _: &u32 = FEATURES.call_once(|| {
            let mut cpuid = [0; 4];
            // SAFETY: We assume that it is safe to execute CPUID and XGETBV.
            unsafe {
                OPENSSL_cpuid_setup(&mut cpuid);
            }
            super::cpuid_to_caps_and_set_c_flags(&cpuid)
        });

        // SAFETY: We initialized the CPU features as required.
        // `INIT.call_once` has `happens-before` semantics.
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(in super::super) fn get(_cpu_features: cpu::Features) -> u32 {
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after `FEATURES.call_once()`,
        // we have met the prerequisites for calling `get_unchecked()`.
        let features: &u32 = unsafe { FEATURES.get_unchecked() };
        *features
    }

    static FEATURES: spin::Once<u32> = spin::Once::new();

    pub const STATIC_DETECTED: u32 = 0;
    pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
}

fn cpuid_to_caps_and_set_c_flags(cpuid: &[u32; 4]) -> u32 {
    // The `prefixed_extern!` uses below assume this
    const _ATOMIC32_ALIGNMENT_EQUSLS_U32_ALIGNMENT: () =
        assert!(align_of::<AtomicU32>() == align_of::<u32>());

    fn check(cpuid: &[u32; 4], idx: usize, bit: u32) -> bool {
        let shifted = 1 << bit;
        (cpuid[idx] & shifted) == shifted
    }
    fn set(out: &mut u32, shift: Shift) {
        let shifted = 1 << (shift as u32);
        debug_assert_eq!(*out & shifted, 0);
        *out |= shifted;
        debug_assert_eq!(*out & shifted, shifted);
    }

    let mut caps = 0;

    if check(cpuid, 0, 24) {
        set(&mut caps, Shift::Fxsr);
    }

    // Synthesized.
    #[cfg(target_arch = "x86_64")]
    if check(cpuid, 0, 30) {
        set(&mut caps, Shift::IntelCpu);
    }

    if check(cpuid, 1, 1) {
        set(&mut caps, Shift::ClMul);
    }

    if check(cpuid, 1, 9) {
        set(&mut caps, Shift::Ssse3);
    }

    if check(cpuid, 1, 19) {
        set(&mut caps, Shift::Sse41);
    }

    #[cfg(target_arch = "x86_64")]
    if check(cpuid, 1, 22) {
        set(&mut caps, Shift::Movbe);
    }

    if check(cpuid, 1, 25) {
        set(&mut caps, Shift::Aes);
    }

    if check(cpuid, 1, 28) {
        set(&mut caps, Shift::Avx);
    }

    #[cfg(target_arch = "x86_64")]
    if check(cpuid, 2, 3) {
        set(&mut caps, Shift::Bmi1);
    }

    #[cfg(target_arch = "x86_64")]
    if check(cpuid, 2, 5) {
        set(&mut caps, Shift::Avx2);

        prefixed_extern! {
            static avx2_available: AtomicU32;
        }
        let flag = unsafe { &avx2_available };
        flag.store(1, core::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let bmi2_available = check(cpuid, 2, 8);
        if bmi2_available {
            set(&mut caps, Shift::Bmi2);
        };

        if check(cpuid, 2, 19) {
            set(&mut caps, Shift::Adx);

            if bmi2_available {
                prefixed_extern! {
                    static adx_bmi2_available: AtomicU32;
                }
                let flag = unsafe { &adx_bmi2_available };
                flag.store(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
    // static feature detection for this.
    #[cfg(target_arch = "x86_64")]
    if check(cpuid, 2, 29) {
        set(&mut caps, Shift::Sha);
    }

    caps
}

impl_get_feature! {
    features: [
        { ("x86", "x86_64") => Fxsr },
        { ("x86", "x86_64") => ClMul },
        { ("x86", "x86_64") => Ssse3 },
        { ("x86", "x86_64") => Sse41 },
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
