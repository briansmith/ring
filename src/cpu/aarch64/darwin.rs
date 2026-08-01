// Copyright 2016-2024 Brian Smith.
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

use super::{Aes, CAPS_STATIC, Neon, PMull, Sha256};
#[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
use {super::Sha512, core::ffi::CStr};

// ```
// $ rustc --print cfg --target=aarch64-apple-ios | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// $ rustc --print cfg --target=aarch64-apple-darwin | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// target_feature="sha3"
// ```
//
// Every aarch64-apple-* device has AES, PMULL and SHA-256, and by default the
// compiler tells us so. However, we cannot *rely* on being told, because
// `-Ctarget-cpu` can leave the target feature set *smaller* than the target's
// default:
//
// ```
// $ rustc --print cfg --target=aarch64-apple-darwin -Ctarget-cpu=generic | grep -E "neon|aes|sha"
// target_feature="neon"
// ```
//
// On Apple Silicon, `-Ctarget-cpu=native` makes LLVM pick an older CPU than
// the default one (`cyclone`, or `generic` on hosts whose CPU LLVM does not
// recognize, e.g. virtualized CI runners); see
// https://github.com/rust-lang/rust/issues/93889. Users also disable target
// features explicitly. Formerly such a configuration was a hard compile error
// here; instead, detect at runtime whatever the compiler didn't promise us,
// like we do for the other operating systems.
//
// This is the mirror image of the workaround in `linux.rs`: there
// `-Ctarget-cpu` reports *more* features than the CPU actually has, so the
// static feature set cannot be trusted to be correct; here it reports *fewer*,
// so it cannot be trusted to be complete.
//
// XXX/TODO(coverage)/TODO(size): aarch64-apple-darwin is statically guaranteed to have "sha3" but
// other aarch64-apple-* targets require dynamic detection. Since we don't have test coverage for
// the other targets yet, we wouldn't have a way of testing the dynamic detection if we statically
// enabled `Sha512` for -darwin. So instead, temporarily, we statically ignore the static
// availability of the feature on -darwin so that it runs the dynamic detection.
//
// This is particularly important because we haven't tested the ABI validity of any
// fallback implementations, especially for ARM64_32.
pub const FORCE_DYNAMIC_DETECTION: u32 =
    !(Neon::mask() | Aes::mask() | Sha256::mask() | PMull::mask());

pub fn detect_features() -> u32 {
    #[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
    fn detect_feature(name: &CStr) -> bool {
        use core::{mem::size_of_val, ptr};
        use libc::{c_int, c_void};

        let mut value: c_int = 0;
        let mut len = size_of_val(&value);
        let value_ptr = ptr::from_mut(&mut value).cast::<c_void>();
        // SAFETY: `value_ptr` is a valid pointer to `value` and `len` is the size of `value`.
        let rc =
            unsafe { libc::sysctlbyname(name.as_ptr(), value_ptr, &mut len, ptr::null_mut(), 0) };
        // All the conditions are separated so we can observe them in code coverage.
        if rc != 0 {
            return false;
        }
        debug_assert_eq!(len, size_of_val(&value));
        if len != size_of_val(&value) {
            return false;
        }
        value != 0
    }

    // We do not need to check for the presence of NEON, as Armv8-A always has it
    const _ASSERT_NEON_DETECTED: () = assert!((CAPS_STATIC & Neon::mask()) == Neon::mask());

    #[cfg_attr(
        any(not(target_pointer_width = "64"), target_os = "watchos"),
        allow(unused_mut)
    )]
    let mut features = 0;

    #[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
    {
        // Only ask the OS about the features the compiler didn't already
        // promise us. The `cfg!`s are constant-folded, so a
        // default-configured build makes no additional `sysctl` calls.
        //
        // The `hw.optional.arm.FEAT_*` names require macOS 12 / iOS 15 or
        // later. On earlier versions the lookup fails and we fall back to the
        // implementations that don't require the feature; slower, but correct.
        if !cfg!(target_feature = "aes") {
            // `STATIC_DETECTED` derives `PMull` from "aes" since there is no
            // "pmull" target feature, but the OS reports them separately.
            if detect_feature(c"hw.optional.arm.FEAT_AES") {
                features |= Aes::mask();
            }
            if detect_feature(c"hw.optional.arm.FEAT_PMULL") {
                features |= PMull::mask();
            }
        }
        if !cfg!(target_feature = "sha2") && detect_feature(c"hw.optional.arm.FEAT_SHA256") {
            features |= Sha256::mask();
        }
        if detect_feature(c"hw.optional.armv8_2_sha512") {
            features |= Sha512::mask();
        }
    }

    features
}

#[cfg(test)]
mod tests {
    use super::super::Sha512;
    use super::*;
    use crate::cpu::{self, GetFeature};

    #[test]
    fn sha512_detection() {
        // We intentionally disable static feature detection for SHA-512.
        const _SHA512_NOT_STATICALLY_DETECTED: () = assert!((CAPS_STATIC & Sha512::mask()) == 0);

        let maybe_sha512: Option<Sha512> = cpu::features().get_feature();
        let has_sha512 = maybe_sha512.is_some();

        // Intentionally defer the assertion to runtime instead of compile time.
        #[cfg(all(target_os = "macos", target_pointer_width = "64"))]
        {
            // Whether "sha3" is enabled statically depends on `-Ctarget-cpu`,
            // but every aarch64-apple-darwin device has SHA-512 regardless, so
            // we must detect it either way.
            assert_eq!(has_sha512, cfg!(target_pointer_width = "64"));
        }

        #[cfg(any(not(target_pointer_width = "64"), target_os = "watchos"))]
        {
            assert!(!has_sha512);
        }
    }

    // Every aarch64-apple-* device has these, so we must find them whether or
    // not the compiler enabled them statically; see the comment on
    // `FORCE_DYNAMIC_DETECTION` above.
    #[test]
    #[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
    #[cfg(not(feature = "unstable-testing-arm-no-hw"))]
    fn aes_pmull_sha256_detection() {
        let cpu = cpu::features();
        let aes: Option<Aes> = cpu.get_feature();
        let pmull: Option<PMull> = cpu.get_feature();
        let sha256: Option<Sha256> = cpu.get_feature();
        assert!(aes.is_some());
        assert!(pmull.is_some());
        assert!(sha256.is_some());
    }
}
