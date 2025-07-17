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

use super::{Aes, Neon, PMull, Sha256, CAPS_STATIC};
#[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
use {super::Sha512, core::ffi::CStr};

// ```
// $ rustc +1.61.0 --print cfg --target=aarch64-apple-ios | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// $ rustc +1.61.0 --print cfg --target=aarch64-apple-darwin | grep -E "neon|aes|sha|pmull"
// target_feature="aes"
// target_feature="neon"
// target_feature="sha2"
// target_feature="sha3"
// ```
//
// XXX/TODO(coverage)/TODO(size): aarch64-apple-darwin is statically guaranteed to have "sha3" but
// other aarch64-apple-* targets require dynamic detection. Since we don't have test coverage for
// the other targets yet, we wouldn't have a way of testing the dynamic detection if we statically
// enabled `Sha512` for -darwin. So instead, temporarily, we statically ignore the static
// availability of the feature on -darwin so that it runs the dynamic detection.
//
// This is particularly important because we haven't tested the ABI validity of any
// fallback implementations, especially for ARM64_32.
pub const MIN_STATIC_FEATURES: u32 = Neon::mask() | Aes::mask() | Sha256::mask() | PMull::mask();
pub const FORCE_DYNAMIC_DETECTION: u32 = !MIN_STATIC_FEATURES;

// MSRV: Enforce 1.61.0 onaarch64-apple-*, in particular) prior to. Earlier
// versions of Rust before did not report the AAarch64 CPU features correctly
// for these targets. Cargo.toml specifies `rust-version` but versions before
// Rust 1.56 don't know about it.
#[allow(clippy::assertions_on_constants)]
const _AARCH64_APPLE_TARGETS_EXPECTED_FEATURES: () =
    assert!((CAPS_STATIC & MIN_STATIC_FEATURES) == MIN_STATIC_FEATURES);

// Ensure we don't accidentally allow features statically beyond
// `MIN_STATIC_FEATURES` so that dynamic detection is done uniformly for
// all of these targets.
#[allow(clippy::assertions_on_constants)]
const _AARCH64_APPLE_DARWIN_TARGETS_EXPECTED_FEATURES: () =
    assert!(CAPS_STATIC == MIN_STATIC_FEATURES);

pub fn detect_features() -> u32 {
    #[cfg(all(target_pointer_width = "64", not(target_os = "watchos")))]
    fn detect_feature(name: &CStr) -> bool {
        use crate::polyfill;
        use core::mem::size_of_val;
        use libc::{c_int, c_void};

        let mut value: c_int = 0;
        let mut len = size_of_val(&value);
        let value_ptr = polyfill::ptr::from_mut(&mut value).cast::<c_void>();
        // SAFETY: `value_ptr` is a valid pointer to `value` and `len` is the size of `value`.
        let rc = unsafe {
            libc::sysctlbyname(name.as_ptr(), value_ptr, &mut len, core::ptr::null_mut(), 0)
        };
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
        // TODO(MSRV-1.77): Use c"..." literal.
        // TODO(MSRV-1.72): Use `CStr::from_bytes_with_nul`.
        // TODO(MSRV-1.69): Use `CStr::from_bytes_until_nul`.
        const SHA512_NAME: &CStr =
            unsafe { CStr::from_bytes_with_nul_unchecked(b"hw.optional.armv8_2_sha512\0") };

        if detect_feature(SHA512_NAME) {
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

        if cfg!(all(target_os = "macos", target_pointer_width = "64")) {
            // All aarch64-apple-darwin targets have SHA3 enabled statically...
            assert!(cfg!(target_feature = "sha3"));
            assert_eq!(has_sha512, cfg!(target_pointer_width = "64"));
        }
        if cfg!(any(not(target_pointer_width = "64"), target_os = "watchos")) {
            assert!(!has_sha512);
        }
    }
}
