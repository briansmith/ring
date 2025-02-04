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

struct Feature {
    word: usize,
    mask: u32,
}

pub(super) mod featureflags {
    use crate::cpu;
    use core::ptr;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        // SAFETY: `OPENSSL_cpuid_setup` must be called only in
        // `INIT.call_once()` below.
        prefixed_extern! {
            fn OPENSSL_cpuid_setup();
        }
        static INIT: spin::Once<()> = spin::Once::new();
        // SAFETY: This is the only caller. Any concurrent reading doesn't
        // affect the safety of the writing.
        let () = INIT.call_once(|| unsafe { OPENSSL_cpuid_setup() });

        // SAFETY: We initialized the CPU features as required.
        // `INIT.call_once` has `happens-before` semantics.
        let cpu = unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() };

        #[cfg(target_arch = "x86_64")]
        {
            use super::{super::GetFeature as _, Adx, Avx2, Bmi2};
            use core::{
                mem::align_of,
                sync::atomic::{AtomicU32, Ordering},
            };

            // These are declared as `uint32_t` on the C side.
            const _ATOMIC32_ALIGNMENT_EQUSLS_U32_ALIGNMENT: () =
                assert!(align_of::<AtomicU32>() == align_of::<u32>());

            if matches!(cpu.get_feature(), Some((Adx { .. }, Bmi2 { .. }))) {
                prefixed_extern! {
                    static adx_bmi2_available: AtomicU32;
                }
                // SAFETY: This is the only writer, and concurrent writing is
                // prevented as this is the `OnceLock`-like one-time
                // initialization provided by `spin::Once`. Any concurrent
                // reading doesn't affect the safety of this write.
                //
                // Any read of `adx_bmi2_available` before this will be zero,
                // which is safe (no risk of illegal instructions) and correct
                // (the value computed will be the same regardless).
                let flag = unsafe { &adx_bmi2_available };
                flag.store(1, Ordering::Relaxed);
            }
            if matches!(cpu.get_feature(), Some(Avx2 { .. })) {
                prefixed_extern! {
                    static avx2_available: AtomicU32;
                }
                // SAFETY: This is the only writer, and concurrent writing is
                // prevented as this is the `OnceLock`-like one-time
                // initialization provided by `spin::Once`.
                //
                // Any read of `avx2_available` before this will be zero, which
                // is safe (no risk of illegal instructions) and correct (the
                // value computed will be the same regardless).
                let flag = unsafe { &avx2_available };
                flag.store(1, Ordering::Relaxed);
            }
        }

        cpu
    }

    pub(super) fn get(_cpu_features: cpu::Features) -> &'static [u32; 4] {
        prefixed_extern! {
            static mut OPENSSL_ia32cap_P: [u32; 4];
        }
        // TODO(MSRV 1.82.0): Remove `unsafe`.
        #[allow(unused_unsafe)]
        let p = unsafe { ptr::addr_of!(OPENSSL_ia32cap_P) };
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after the `INIT.call_once()`
        // (which guarantees `happens-before` semantics), or during the
        // `INIT.call_once()` after writing to `OPENSSL_ia32cap_P`, we can
        // safely read from `OPENSSL_ia32cap_P` without further
        // synchronization.
        unsafe { &*p }
    }
}

impl Feature {
    #[allow(clippy::needless_return)]
    #[inline(always)]
    pub fn available(&self, cpu_features: super::Features) -> bool {
        let flags = featureflags::get(cpu_features);
        self.mask == self.mask & flags[self.word]
    }
}

macro_rules! impl_get_feature_cpuid {
    { $( { ( $( $arch:expr ),+ ) => ($word:expr, $bit:expr) => $NAME:ident => $Name:ident }, )+ } => {
      $(
        #[cfg(any( $( target_arch = $arch ),+ ))]
        const $NAME: Feature = Feature {
            word: $word,
            mask: 1 << $bit,
        };

        #[cfg(any( $( target_arch = $arch ),+ ))]
        impl_get_feature! { $NAME => $Name }
      )+
    }
}

impl_get_feature_cpuid! {
    // Synthesized
    { ("x86_64") => (0, 30) => INTEL_CPU => IntelCpu },
    { ("x86", "x86_64") => (0, 24) => FXSR => Fxsr },
    { ("x86", "x86_64") => (1, 1) => PCLMULQDQ => ClMul },
    { ("x86", "x86_64") => (1, 9) => SSSE3 => Ssse3 },
    { ("x86", "x86_64") => (1, 19) => SSE41 => Sse41 },
    { ("x86_64") => (1, 22) => MOVBE => Movbe },
    { ("x86", "x86_64") => (1, 25) => AES => Aes },
    { ("x86", "x86_64") => (1, 28) => AVX => Avx },
    { ("x86_64") => (2, 3) => BMI1 => Bmi1 },
    { ("x86_64") => (2, 5) => AVX2 => Avx2 },
    { ("x86_64") => (2, 8) => BMI2 => Bmi2 },
    { ("x86_64") => (2, 19) => ADX => Adx },
    // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
    // static feature detection for this.
    { ("x86_64") => (2, 29) => SHA => Sha },
}

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {


        #[derive(Clone, Copy)]
        pub(crate) struct NotPreZenAmd(super::Features);

        impl super::GetFeature<NotPreZenAmd> for super::Features {
            fn get_feature(&self) -> Option<NotPreZenAmd> {
                let sha2: Option<Avx2> = self.get_feature();
                // Pre-Zen AMD CPUs didn't implement SHA. (One Pre-Zen AMD CPU
                // did support AVX2.) If we're building for a CPU that requires
                // SHA instructions then we want to avoid the runtime check for
                // an Intel/AND CPU.
                if sha2.is_some() {
                    return Some(NotPreZenAmd(*self));
                }
                // Perhaps we should do !AMD instead of Intel.
                let intel: Option<IntelCpu> = self.get_feature();
                if intel.is_some() {
                    return Some(NotPreZenAmd(*self))
                }
                None
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", test))]
mod x86_64_tests {
    use super::*;

    #[test]
    fn test_avx_movbe_mask() {
        // This is the OpenSSL style of testing these bits.
        assert_eq!((AVX.mask | MOVBE.mask) >> 22, 0x41);
    }
}
