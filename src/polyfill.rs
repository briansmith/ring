// Copyright 2015-2016 Brian Smith.
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

//! Polyfills for functionality that will (hopefully) be added to Rust's
//! standard library soon.

use core;

#[macro_use]
pub mod convert;

#[inline(always)]
pub const fn u64_from_usize(x: usize) -> u64 { x as u64 }

#[inline(always)]
pub fn usize_from_u32(x: u32) -> usize { x as usize }

/// `core::num::Wrapping` doesn't support `rotate_left`.
/// There is no usable trait for `rotate_left`, so this polyfill just
/// hard-codes u32. https://github.com/rust-lang/rust/issues/32463
#[inline(always)]
pub fn wrapping_rotate_left_u32(x: core::num::Wrapping<u32>, n: u32) -> core::num::Wrapping<u32> {
    core::num::Wrapping(x.0.rotate_left(n))
}

pub mod slice {
    #[inline(always)]
    pub fn u32_from_be_u8(buffer: [u8; 4]) -> u32 {
        u32::from(buffer[0]) << 24
            | u32::from(buffer[1]) << 16
            | u32::from(buffer[2]) << 8
            | u32::from(buffer[3])
    }

    #[inline(always)]
    pub fn be_u8_from_u32(value: u32) -> [u8; 4] {
        [
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]
    }

    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill(dest: &mut [u8], value: u8) {
        for d in dest {
            *d = value;
        }
    }
}
