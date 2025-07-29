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

    const _ASSUMED_POINTER_SIZE: usize = 4;
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

    #[rustfmt::skip]
    pub const STATIC_DETECTED: u32 = 0
        | (if cfg!(target_feature = "sse2") { super::Sse2::mask() } else { 0 })
        ;

    pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
}

struct CpuidSummary {
    leaf1_edx: u32,
    leaf1_ecx: u32,
}

// SAFETY: This unconditionally uses CPUID because we don't have a good
// way to detect CPUID and because we don't know of a CPU that supports
// SSE2 (that we currently statically require) but doesn't support
// CPUID. SGX is one environment where CPUID isn't allowed but where
// SSE2 is statically supported. Ideally there would be a
// `cfg!(target_feature = "cpuid")` we could use.
unsafe fn cpuid_all() -> CpuidSummary {
    use core::arch::x86 as arch;

    // MSRV(1.66) avoids miscompilations when calling `__cpuid`;
    // see https://github.com/rust-lang/rust/pull/101861.

    // Intel: "21.1.1 Notes on Where to Start".
    let leaf0 = unsafe { arch::__cpuid(0) };

    let (leaf1_edx, leaf1_ecx) = if leaf0.eax >= 1 {
        // SAFETY: `leaf0.eax >= 1` indicates leaf 1 is available.
        let leaf1 = unsafe { arch::__cpuid(1) };
        (leaf1.edx, leaf1.ecx)
    } else {
        // Expected to be unreachable on any environment we currently
        // support.
        (0, 0)
    };

    CpuidSummary {
        leaf1_edx,
        leaf1_ecx,
    }
}

fn cpuid_to_caps_and_set_c_flags(r: CpuidSummary) -> u32 {
    let CpuidSummary {
        leaf1_edx,
        leaf1_ecx,
    } = r;

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

    #[cfg(not(target_feature = "sse2"))]
    {
        // If somebody is trying to compile for an x86 target without SSE2
        // and they deleted the `_SSE2_REQUIRED` const assertion above then
        // they're probably trying to support a Linux/BSD/etc. distro that
        // tries to support ancient x86 systems without SSE/SSE2. Try to
        // reduce the harm caused, by implementing dynamic feature detection
        // for them so that most systems will work like normal.
        //
        // Note that usually an x86-64 target with SSE2 disabled by default,
        // usually `-none-` targets, will not support dynamically-detected use
        // of SIMD registers via CPUID. A whole different mechanism is needed
        // to support them. Same for i*86-*-none targets.
        let leaf1_edx = cpuid[0];
        let sse1_available = check(leaf1_edx, 25);
        let sse2_available = check(leaf1_edx, 26);
        if sse1_available && sse2_available {
            set(&mut caps, Shift::Sse2);
        }
    }
    let _ = leaf1_edx;

    // Intel: "12.7.2 Checking for SSSE3 Support"
    // If/when we support dynamic detection of SSE/SSE2, make this conditional
    // on SSE/SSE2.
    // TODO: Make this conditional on SSE3.
    if check(leaf1_ecx, 9) {
        set(&mut caps, Shift::Ssse3);
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
    ClMul,
    Ssse3,
    Aes,
    Avx,
    Sse2,
}

#[cfg(test)]
mod tests {
    // This should always pass on any x86 system except very, very, old ones.
    #[test]
    fn x86_has_sse2() {
        use super::*;
        use crate::cpu::{self, GetFeature as _};
        assert!(matches!(cpu::features().get_feature(), Some(Sse2 { .. })))
    }
}
