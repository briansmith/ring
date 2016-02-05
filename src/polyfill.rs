// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Polyfills for functionality that will (hopefully) be added to Rust's
//! standard library soon.

#![allow(unsafe_code)]

pub mod slice {
    use core;

    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill(dest: &mut [u8], value: u8) {
        for d in dest {
            *d = value;
        }
    }

    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill_from_slice(dest: &mut [u8], src: &[u8]) {
        assert_eq!(dest.len(), src.len());
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), dest.as_mut_ptr(),
                                           src.len())
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u8<'a>(src: &'a [u64]) -> &'a [u8] {
        unsafe {
            core::slice::from_raw_parts(src.as_ptr() as *const u8, src.len() * 8)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u32<'a>(src: &'a [u64]) -> &'a [u32] {
        unsafe {
            core::slice::from_raw_parts(src.as_ptr() as *const u32, src.len() * 2)
        }
    }
}
