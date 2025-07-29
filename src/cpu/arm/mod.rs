// Copyright 2016-2025 Brian Smith.
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

#![cfg(target_arch = "arm")]

use super::CAPS_STATIC;

mod abi_assumptions {
    use core::mem::size_of;

    const _ASSUMED_POINTER_SIZE: usize = 4;
    const _ASSUMED_USIZE_SIZE: () = assert!(size_of::<usize>() == _ASSUMED_POINTER_SIZE);
    const _ASSUMED_REF_SIZE: () = assert!(size_of::<&'static u8>() == _ASSUMED_POINTER_SIZE);

    // To support big-endian, we'd need to make several changes as described in
    // https://github.com/briansmith/ring/issues/1832.
    const _ASSUMED_ENDIANNESS: () = assert!(cfg!(target_endian = "little"));
}

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use linux as detect;
    } else {
        mod detect {
            pub const FORCE_DYNAMIC_DETECTION: u32 = 0;
            pub fn detect_features() -> u32 { 0 }
        }
    }
}

impl_get_feature! {
    // TODO(MSRV): 32-bit ARM doesn't have `target_feature = "neon"` yet.
    Neon,
}

pub(super) mod featureflags {
    pub(in super::super) use super::detect::FORCE_DYNAMIC_DETECTION;
    use super::*;
    use crate::{cpu, polyfill::once_cell::race};
    use core::num::NonZeroU32;

    pub(in super::super) fn get_or_init() -> cpu::Features {
        fn init() -> NonZeroU32 {
            let detected = detect::detect_features();
            let filtered = (if cfg!(feature = "unstable-testing-arm-no-hw") {
                !Neon::mask()
            } else {
                0
            }) | (if cfg!(feature = "unstable-testing-arm-no-neon") {
                Neon::mask()
            } else {
                0
            });
            let detected = detected & !filtered;
            let merged = CAPS_STATIC | detected;

            #[cfg(target_has_atomic = "32")]
            if (merged & Neon::mask()) == Neon::mask() {
                use core::sync::atomic::{AtomicU32, Ordering};

                // `neon_available` is declared as `alignas(4) uint32_t` in the C code.
                // AtomicU32 is `#[repr(C, align(4))]`.
                prefixed_extern! {
                    static neon_available: AtomicU32;
                }
                // SAFETY: The C code only reads `neon_available`, and its
                // reads are synchronized through the `OnceNonZeroU32`
                // Acquire/Release semantics as we ensure we have a
                // `cpu::Features` instance before calling into the C code.
                let p = unsafe { &neon_available };
                p.store(1, Ordering::Relaxed);
            }

            Shift::INITIALIZED_MASK | merged
        }

        // SAFETY: This is the only caller. Any concurrent reading doesn't
        // affect the safety of the writing.
        let _: NonZeroU32 = FEATURES.get_or_init(init);

        // SAFETY: We initialized the CPU features as required.
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

    // We have a separate flag for NEON, so we need Acquire/Release ordering.
    static FEATURES: race::OnceNonZeroU32<race::AcquireRelease> = race::OnceNonZeroU32::new();

    // TODO(MSRV): 32-bit ARM doesn't support any static feature detection yet.
    pub(in super::super) const STATIC_DETECTED: u32 = 0;
}
