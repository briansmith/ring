// Copyright 2015 Brian Smith.
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

use libc;

pub fn map_bssl_result(bssl_result: libc::c_int) -> Result<(), ()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(())
    }
}

pub fn map_bssl_ptr_result<T>(bssl_result: *mut T) -> Result<*mut T, ()> {
    if bssl_result.is_null() {
        return Err(());
    }
    Ok(bssl_result)
}


/// Returns `Ok(())` of `a == b` and `Err(())` otherwise. The comparison of
/// `a` and `b` is done in constant time with respect to the contents of each,
/// but NOT in constant time with respect to the lengths of `a` and `b`.
pub fn verify_slices_are_equal_ct(a: &[u8], b: &[u8]) -> Result<(), ()> {
    if a.len() != b.len() {
        return Err(());
    }
    let result = unsafe {
        CRYPTO_memcmp(a.as_ptr(), b.as_ptr(), a.len() as libc::size_t)
    };
    match result {
        0 => Ok(()),
        _ => Err(())
    }
}

// XXX: As of Rust 1.4, the compiler will no longer warn about the use of
// `usize` and `isize` in FFI declarations. Remove the `allow(improper_ctypes)`
// when Rust 1.4 is released.
#[allow(improper_ctypes)]
extern {
    fn CRYPTO_memcmp(a: *const libc::uint8_t, b: *const libc::uint8_t,
                     len: libc::size_t) -> libc::c_int;
}
