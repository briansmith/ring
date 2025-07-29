// Copyright 2016-2021 Brian Smith.
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

// "Intel" citations are for "Intel 64 and IA-32 Architectures Software
// Developer’s Manual", Combined Volumes, December 2024.
// "AMD" citations are for "AMD64 Technology AMD64 Architecture
// Programmer’s Manual, Volumes 1-5" Revision 4.08 April 2024.

use core::ops::{BitAnd, Shl};

mod abi_assumptions {
    use core::mem::size_of;

    // TOOD: Support targets that do not have SSE and SSE2 enabled, such as
    // x86_64-unknown-linux-none. See
    // https://github.com/briansmith/ring/issues/1793#issuecomment-1793243725,
    // https://github.com/briansmith/ring/issues/1832,
    // https://github.com/briansmith/ring/issues/1833.
    const _ASSUMES_SSE2: () =
        assert!(cfg!(target_feature = "sse") && cfg!(target_feature = "sse2"));

    const _ASSUMED_POINTER_SIZE: usize = 8;
    const _ASSUMED_USIZE_SIZE: () = assert!(size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () = assert!(size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

    const _ASSUMED_ENDIANNESS: () = assert!(cfg!(target_endian = "little"));
}

pub(super) mod featureflags {
    use super::{super::CAPS_STATIC, *};
    use crate::{cpu, polyfill::once_cell::race};
    use core::num::NonZeroU32;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        let _: NonZeroU32 = FEATURES.get_or_init(|| {
            // SAFETY: `cpuid_all` assumes CPUID is available and that it is
            // compatible with Intel.
            let cpuid_results = unsafe { cpuid_all() };
            let detected = cpuid_to_caps_and_set_c_flags(cpuid_results);
            let merged = CAPS_STATIC | detected;
            Shift::INITIALIZED_MASK | merged
        });

        // SAFETY: We initialized the CPU features as required.
        // `INIT.call_once` has `happens-before` semantics.
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

    static FEATURES: race::OnceNonZeroU32<race::AcquireRelease> = race::OnceNonZeroU32::new();

    // Limited to x86_64-v2 features.
    // TODO: Add missing x86-64-v3 features if we find real-world use of x86-64-v3.
    // TODO: Add all features we use.
    #[rustfmt::skip]
    pub const STATIC_DETECTED: u32 = 0
        | if cfg!(target_feature = "sse4.1") { Sse41::mask() } else { 0 }
        | if cfg!(target_feature = "ssse3") { Ssse3::mask() } else { 0 }
        ;

    pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
}

struct CpuidSummary {
    is_intel: bool,
    leaf1_ecx: u32,
    extended_features_ecx: u32,
    extended_features_ebx: u32,
    xcr0: u64,
}

// SAFETY: This unconditionally uses CPUID because we don't have a good
// way to detect CPUID and because we don't know of a CPU that supports
// SSE2 (that we currently statically require) but doesn't support
// CPUID. SGX is one environment where CPUID isn't allowed but where
// SSE2 is statically supported. Ideally there would be a
// `cfg!(target_feature = "cpuid")` we could use.
unsafe fn cpuid_all() -> CpuidSummary {
    use core::arch::x86_64 as arch;

    // MSRV(1.66) avoids miscompilations when calling `__cpuid`;
    // see https://github.com/rust-lang/rust/pull/101861.

    // Intel: "21.1.1 Notes on Where to Start".
    let leaf0 = unsafe { arch::__cpuid(0) };

    let is_intel =
        (leaf0.ebx == 0x756e6547) && (leaf0.edx == 0x49656e69) && (leaf0.ecx == 0x6c65746e);

    let leaf1_ecx = if leaf0.eax >= 1 {
        // SAFETY: `leaf0.eax >= 1` indicates leaf 1 is available.
        let leaf1 = unsafe { arch::__cpuid(1) };
        leaf1.ecx
    } else {
        // Expected to be unreachable on any environment we currently
        // support.
        0
    };

    let (extended_features_ecx, extended_features_ebx) = if leaf0.eax >= 7 {
        // SAFETY: `leaf0.eax >= 7` indicates leaf 7 is available.
        let leaf7 = unsafe { arch::__cpuid(7) };
        (leaf7.ecx, leaf7.ebx)
    } else {
        (0, 0)
    };

    let xcr0 = if check(leaf1_ecx, 27) {
        unsafe { arch::_xgetbv(0) }
    } else {
        0
    };

    CpuidSummary {
        is_intel,
        leaf1_ecx,
        extended_features_ecx,
        extended_features_ebx,
        xcr0,
    }
}

fn cpuid_to_caps_and_set_c_flags(r: CpuidSummary) -> u32 {
    use core::{mem::align_of, sync::atomic::AtomicU32};

    let CpuidSummary {
        is_intel,
        leaf1_ecx,
        extended_features_ecx,
        extended_features_ebx,
        xcr0,
    } = r;

    // The `prefixed_extern!` uses below assume this
    const _ATOMIC32_ALIGNMENT_EQUALS_U32_ALIGNMENT: () =
        assert!(align_of::<AtomicU32>() == align_of::<u32>());

    fn set(out: &mut u32, shift: Shift) {
        let shifted = 1 << (shift as u32);
        debug_assert_eq!(*out & shifted, 0);
        *out |= shifted;
        debug_assert_eq!(*out & shifted, shifted);
    }

    let mut caps = 0;

    // AMD: "Collectively the SSE1, [...] are referred to as the legacy SSE
    // instructions. All legacy SSE instructions support 128-bit vector
    // operands."

    // Intel: "11.6.2 Checking for Intel SSE and SSE2 Support"
    // We have to assume the prerequisites for SSE/SSE2 are met since we're
    // already almost definitely using SSE registers if these target features
    // are enabled.
    //
    // These also seem to help ensure CMOV support; There doesn't seem to be
    // a `cfg!(target_feature = "cmov")`. It is likely that removing these
    // assertions will remove the requirement for CMOV. With our without
    // CMOV, it is likely that some of our timing side channel prevention does
    // not work. Presumably the people who delete these are verifying that it
    // all works fine.
    const _SSE_REQUIRED: () = assert!(cfg!(target_feature = "sse"));
    const _SSE2_REQUIRED: () = assert!(cfg!(target_feature = "sse2"));

    // Intel: "12.7.2 Checking for SSSE3 Support"
    // If/when we support dynamic detection of SSE/SSE2, make this conditional
    // on SSE/SSE2.
    // TODO: Make this conditional on SSE3.
    if check(leaf1_ecx, 9) {
        set(&mut caps, Shift::Ssse3);

        // Intel: "12.12.2 Checking for Intel SSE4.1 Support"
        if check(leaf1_ecx, 19) {
            set(&mut caps, Shift::Sse41);
        }
    }

    // AMD: "The extended SSE instructions include [...]."

    // Intel: "14.3 DETECTION OF INTEL AVX INSTRUCTIONS"
    let os_supports_ymm_xmm = check(xcr0, 2) && check(xcr0, 1);
    let cpu_supports_avx = check(leaf1_ecx, 28);
    let avx_available = os_supports_ymm_xmm && cpu_supports_avx;
    if avx_available {
        set(&mut caps, Shift::Avx);
    }

    // "14.7.1 Detection of Intel AVX2 Hardware support"
    if avx_available && check(extended_features_ebx, 5) {
        set(&mut caps, Shift::Avx2);

        // Declared as `uint32_t` in the C code.
        prefixed_extern! {
            static avx2_available: AtomicU32;
        }
        // SAFETY: The C code only reads `avx2_available`, and its reads are
        // synchronized through the `OnceNonZeroU32` Acquire/Release
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
    let clmul_available = check(leaf1_ecx, 1);
    if clmul_available {
        set(&mut caps, Shift::ClMul);
    }
    let aesni_available = check(leaf1_ecx, 25);
    if aesni_available {
        set(&mut caps, Shift::Aes);
    }

    // 14.3.1 Detection of VEX-Encoded AES and VPCLMULQDQ.
    // vaesenc/vaesenclast with XMM registers is NOT using the VAES feature.
    // vpclmulqdq with XMM registers is NOT using the VPCLMULQDQ feature.
    let vex_aesni_clmul_available = avx_available && clmul_available && aesni_available;

    // The Intel docs don't seem to document the detection. The instruction
    // definitions of the VEX.256 instructions reference the
    // VAES/VPCLMULQDQ features and the documentation for the extended
    // features gives the values. We combine these into one feature because
    // we never use them independently.
    let vaes_available = check(extended_features_ecx, 9);
    let vclmul_available = check(extended_features_ecx, 10);

    // Our code that uses the VAES and VPCLMULQDQ features also uses the XMM
    // form, so make this feature conditional on it being available. Combine
    // this all into one feature since we never use the features separately.
    if vex_aesni_clmul_available && vaes_available && vclmul_available {
        set(&mut caps, Shift::VAesClmul);
    }

    // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
    // static feature detection for this.
    if check(extended_features_ebx, 29) {
        set(&mut caps, Shift::Sha);
    }

    if is_intel {
        set(&mut caps, Shift::IntelCpu);
    }

    if check(leaf1_ecx, 22) {
        set(&mut caps, Shift::Movbe);
    }

    let adx_available = check(extended_features_ebx, 19);
    if adx_available {
        set(&mut caps, Shift::Adx);
    }

    // Some 6th Generation (Skylake) CPUs claim to support BMI1 and BMI2
    // when they don't; see erratum "SKD052". The Intel document at
    // https://www.intel.com/content/dam/www/public/us/en/documents/specification-updates/6th-gen-core-u-y-spec-update.pdf
    // contains the footnote "Affects 6th Generation Intel Pentium processor
    // family and Intel Celeron processor family". Further research indicates
    // that Skylake Pentium/Celeron do not implement AVX or ADX. It turns
    // out that we only use BMI1 and BMI2 in combination with ADX and/or
    // AVX.
    //
    // rust `std::arch::is_x86_feature_detected` does a very similar thing
    // but only looks at AVX, not ADX. Note that they reference an older
    // version of the erratum labeled SKL052.
    let believe_bmi_bits = !is_intel || (adx_available || cpu_supports_avx);

    if check(extended_features_ebx, 3) && believe_bmi_bits {
        set(&mut caps, Shift::Bmi1);
    }

    let bmi2_available = check(extended_features_ebx, 8) && believe_bmi_bits;
    if bmi2_available {
        set(&mut caps, Shift::Bmi2);
    }

    if adx_available && bmi2_available {
        // Declared as `uint32_t` in the C code.
        prefixed_extern! {
            static adx_bmi2_available: AtomicU32;
        }
        // SAFETY: The C code only reads `adx_bmi2_available`, and its
        // reads are synchronized through the `OnceNonZeroU32`
        // Acquire/Release semantics as we ensure we have a
        // `cpu::Features` instance before calling into the C code.
        let flag = unsafe { &adx_bmi2_available };
        flag.store(1, core::sync::atomic::Ordering::Relaxed);
    }

    caps
}

fn check<T: BitAnd<Output = T> + Copy + Eq + From<u8> + Shl<u32, Output = T>>(
    leaf: T,
    index: u32,
) -> bool {
    let shifted: T = T::from(1u8) << index;
    (leaf & shifted) == shifted
}

impl_get_feature! {
    VAesClmul,

    ClMul,

    Ssse3,

    Sse41,

    Movbe,

    Aes,

    Avx,

    Bmi1,

    Avx2,

    Bmi2,

    Adx,

    // See BoringSSL 69c26de93c82ad98daecaec6e0c8644cdf74b03f before enabling
    // static feature detection for this.
    Sha,

    // x86_64 can just assume SSE2 is available.
    // Sse2,
}

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
