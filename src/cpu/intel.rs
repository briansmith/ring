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

pub(crate) struct Feature {
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
        unsafe { cpu::Features::new_after_feature_flags_written_and_synced_unchecked() }
    }

    pub(super) fn get(_cpu_features: cpu::Features) -> &'static [u32; 4] {
        prefixed_extern! {
            static mut OPENSSL_ia32cap_P: [u32; 4];
        }
        // TODO(MSRV 1.82.0): Remove `unsafe`.
        #[allow(unused_unsafe)]
        let p = unsafe { ptr::addr_of!(OPENSSL_ia32cap_P) };
        // SAFETY: Since only `get_or_init()` could have created
        // `_cpu_features`, and it only does so after the `INIT.call_once()`,
        // which guarantees `happens-before` semantics, we can read from
        // `OPENSSL_ia32cap_P` without further synchronization.
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

#[allow(dead_code)]
pub(crate) const ADX: Feature = Feature {
    word: 2,
    mask: 1 << 19,
};

#[allow(dead_code)]
pub(crate) const BMI1: Feature = Feature {
    word: 2,
    mask: 1 << 3,
};

#[allow(dead_code)]
pub(crate) const BMI2: Feature = Feature {
    word: 2,
    mask: 1 << 8,
};

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

#[allow(dead_code)]
const SSE41: Feature = Feature {
    word: 1,
    mask: 1 << 19,
};

pub(crate) const AES: Feature = Feature {
    word: 1,
    mask: 1 << 25,
};

impl_get_feature! { AES => Aes }
impl_get_feature! { FXSR => Fxsr }
impl_get_feature! { PCLMULQDQ => ClMul }
impl_get_feature! { SSSE3 => Ssse3 }

cfg_if! {
    if #[cfg(any(target_arch = "x86_64"))] {
        //
        const INTEL_CPU: Feature = Feature {
            word: 0,
            mask: 1 << 30,
        };
        impl_get_feature!{ INTEL_CPU => IntelCpu }

        pub(crate) const MOVBE: Feature = Feature {
            word: 1,
            mask: 1 << 22,
        };

        pub(crate) const AVX: Feature = Feature {
            word: 1,
            mask: 1 << 28,
        };

        const SHA: Feature = Feature {
            word: 2,
            mask: 1 << 29,
        };

        impl_get_feature!{ SSE41 => Sse41 }
        impl_get_feature!{ MOVBE => Movbe }
        impl_get_feature!{ AVX => Avx }
        impl_get_feature!{ SHA => Sha }
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
