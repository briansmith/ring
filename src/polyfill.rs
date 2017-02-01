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

// A better name for the `&*` idiom for removing the mutability from a
// reference.
#[cfg(feature = "use_heap")]
#[inline(always)]
pub fn ref_from_mut_ref<'a, T: ?Sized>(x: &'a mut T) -> &'a T { x }

#[inline(always)]
pub fn u64_from_usize(x: usize) -> u64 { x as u64 }

/// `core::num::Wrapping` doesn't support `rotate_left`.
/// There is no usable trait for `rotate_left`, so this polyfill just
/// hard-codes u32. https://github.com/rust-lang/rust/issues/32463
#[inline(always)]
pub fn wrapping_rotate_left_u32(x: core::num::Wrapping<u32>, n: u32)
                                -> core::num::Wrapping<u32> {
    core::num::Wrapping(x.0.rotate_left(n))
}


pub mod slice {
    use core;

    #[inline(always)]
    pub fn u32_from_be_u8(buffer: &[u8; 4]) -> u32 {
        u32::from(buffer[0]) << 24 |
        u32::from(buffer[1]) << 16 |
        u32::from(buffer[2]) << 8 |
        u32::from(buffer[3])
    }

    #[inline(always)]
    pub fn u32_from_le_u8(buffer: &[u8; 4]) -> u32 {
        u32::from(buffer[0]) |
        u32::from(buffer[1]) << 8 |
        u32::from(buffer[2]) << 16 |
        u32::from(buffer[3]) << 24
    }

    #[inline(always)]
    pub fn be_u8_from_u32(value: u32) -> [u8; 4] {
        [((value >> 24) & 0xff) as u8,
         ((value >> 16) & 0xff) as u8,
         ((value >> 8) & 0xff) as u8,
         (value & 0xff) as u8]
    }

    #[inline(always)]
    #[allow(dead_code)] // Only used for RSA currently
    pub fn be_u8_from_u64(value: u64) -> [u8; 8] {
        [((value >> 56) & 0xff) as u8,
         ((value >> 48) & 0xff) as u8,
         ((value >> 40) & 0xff) as u8,
         ((value >> 32) & 0xff) as u8,
         ((value >> 24) & 0xff) as u8,
         ((value >> 16) & 0xff) as u8,
         ((value >> 8) & 0xff) as u8,
         (value & 0xff) as u8]
    }

    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill(dest: &mut [u8], value: u8) {
        for d in dest {
            *d = value;
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u8(src: &[u64]) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(src.as_ptr() as *const u8,
                                        src.len() * 8)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u8_mut(src: &mut [u64]) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(src.as_mut_ptr() as *mut u8,
                                            src.len() * 8)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    #[allow(dead_code)] // Only used on 32-bit builds currently
    pub fn u32_as_u8<'a>(src: &'a [u32]) -> &'a [u8] {
        unsafe {
            core::slice::from_raw_parts(src.as_ptr() as *mut u8, src.len() * 4)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    #[allow(dead_code)] // Only used on 32-bit builds currently
    pub fn u32_as_u8_mut<'a>(src: &'a mut [u32]) -> &'a mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(src.as_mut_ptr() as *mut u8,
                                            src.len() * 4)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u32(src: &[u64]) -> &[u32] {
        unsafe {
            core::slice::from_raw_parts(src.as_ptr() as *const u32,
                                        src.len() * 2)
        }
    }

    // https://internals.rust-lang.org/t/safe-trasnsmute-for-slices-e-g-u64-u32-particularly-simd-types/2871
    #[inline(always)]
    pub fn u64_as_u32_mut(src: &mut [u64]) -> &mut [u32] {
        unsafe {
            core::slice::from_raw_parts_mut(src.as_mut_ptr() as *mut u32,
                                            src.len() * 2)
        }
    }

    #[inline(always)]
    pub fn as_wrapping_mut<T>(src: &mut [T]) -> &mut [core::num::Wrapping<T>] {
        unsafe {
            core::slice::from_raw_parts_mut(
                src.as_mut_ptr() as *mut core::num::Wrapping<T>, src.len())
        }
    }
}

/// Returns a reference to the elements of `$slice` as an array, verifying that
/// the slice is of length `$len`.
macro_rules! slice_as_array_ref {
    ($slice:expr, $len:expr) => {
        {
            use error;

            fn slice_as_array_ref<T>(slice: &[T])
                                     -> Result<&[T; $len], error::Unspecified> {
                if slice.len() != $len {
                    return Err(error::Unspecified);
                }
                Ok(unsafe {
                    &*(slice.as_ptr() as *const [T; $len])
                })
            }
            slice_as_array_ref($slice)
        }
    }
}

/// Returns a reference to elements of `$slice` as a mutable array, verifying
/// that the slice is of length `$len`.
macro_rules! slice_as_array_ref_mut {
    ($slice:expr, $len:expr) => {
        {
            use error;

            fn slice_as_array_ref<T>(slice: &mut [T])
                                     -> Result<&mut [T; $len],
                                               error::Unspecified> {
                if slice.len() != $len {
                    return Err(error::Unspecified);
                }
                Ok(unsafe {
                    &mut *(slice.as_mut_ptr() as *mut [T; $len])
                })
            }
            slice_as_array_ref($slice)
        }
    }
}
