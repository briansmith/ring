// Copyright 2024 Brian Smith.
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

//! Work around lack of `const fn` support for `CStr`.

#![cfg(all(target_arch = "aarch64", target_vendor = "apple"))]

use core::ffi::CStr;

pub const fn unwrap_const_from_bytes_with_nul(value: &'static [u8]) -> &'static CStr {
    // XXX: We cannot use `unwrap_const` since `CStr` is not `Copy`.
    match const_from_bytes_with_nul(value) {
        Some(r) => r,
        None => panic!("const_from_bytes_with_nul failed"),
    }
}

// TODO(MSRV 1.72): Replace with `CStr::from_bytes_with_nul`.
#[inline(always)]
const fn const_from_bytes_with_nul(value: &'static [u8]) -> Option<&'static CStr> {
    const fn const_contains(mut value: &[u8], needle: &u8) -> bool {
        while let [head, tail @ ..] = value {
            if *head == *needle {
                return true;
            }
            value = tail;
        }
        false
    }

    // TODO(MSRV 1.69): Use `core::ffi::CStr::from_bytes_until_nul`
    match value {
        [before_nul @ .., 0] if !const_contains(before_nul, &0) => {
            // SAFETY:
            //   * `value` is nul-terminated according to the slice pattern.
            //   * `value` doesn't contain any interior null, by the guard.
            Some(unsafe { CStr::from_bytes_with_nul_unchecked(value) })
        }
        _ => None,
    }
}

mod tests {
    use super::const_from_bytes_with_nul;

    // Bad.
    const _EMPTY_UNTERMINATED: () = assert!(const_from_bytes_with_nul(b"").is_none());
    const _EMPTY_DOUBLE_TERMINATED: () = assert!(const_from_bytes_with_nul(b"\0\0").is_none());
    const _DOUBLE_NUL: () = assert!(const_from_bytes_with_nul(b"\0\0").is_none());
    const _LEADINGL_NUL: () = assert!(const_from_bytes_with_nul(b"\0a\0").is_none());
    const _INTERNAL_NUL_UNTERMINATED: () = assert!(const_from_bytes_with_nul(b"\0a").is_none());

    // Good.
    const EMPTY_TERMINATED: () = assert!(const_from_bytes_with_nul(b"\0").is_some());
    const _NONEMPTY: () = assert!(const_from_bytes_with_nul(b"asdf\0").is_some());
    const _1_CHAR: () = assert!(const_from_bytes_with_nul(b"a\0").is_some());
}
