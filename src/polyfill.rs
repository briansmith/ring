// Copyright 2015-2016 Brian Smith.
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

//! Polyfills for functionality that will (hopefully) be added to Rust's
//! standard library soon.

#[inline(always)]
pub const fn u64_from_usize(x: usize) -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    const _LOSSLESS: () = assert!(usize::MAX == ((usize::MAX) as u64) as usize);
    x as u64
}

pub const fn usize_from_u32(x: u32) -> usize {
    #[allow(clippy::cast_possible_truncation)]
    const _LOSSLESS: () = assert!(u32::MAX == ((u32::MAX) as usize) as u32);
    x as usize
}

/// const-capable `x.try_into().unwrap_or(usize::MAX)`
#[allow(clippy::cast_possible_truncation)]
#[inline(always)]
pub const fn usize_from_u64_saturated(x: u64) -> usize {
    const USIZE_MAX: u64 = u64_from_usize(usize::MAX);
    if x < USIZE_MAX {
        x as usize
    } else {
        usize::MAX
    }
}

#[macro_use]
mod cold_error;

mod array_flat_map;
mod array_split_map;

mod atomic;

pub mod partial_buffer;
pub mod sliceutil;

#[cfg(feature = "alloc")]
mod leading_zeros_skipped;

#[cfg(any(
    all(target_arch = "aarch64", target_endian = "little"),
    all(target_arch = "arm", target_endian = "little"),
    target_arch = "x86",
    target_arch = "x86_64"
))]
pub mod once_cell {
    pub mod race;
}

#[allow(unused_imports)]
pub mod prelude {
    // If a polyfill is for an **already-stable** API, and it has the same
    // API and semantics as that stable API, then give it the same name so that
    // the standard library implementation will be used except for old versions
    // of Rust.
    //
    // If the polyfill is for a not-yet-stable API, or if its API isn't exactly
    // the same, or if its semantics differ, implement it in a trait outside
    // these modules and always use it with fully-qualified syntax. This is
    // particularly important to do since code coverage testing is done on
    // using Rust Nightly.
    pub(crate) use super::{
        atomic::AtomicPolyfills,
        ptr::PointerPolyfills,
        slice::{SliceOfArraysPolyfills, SlicePolyfills},
    };
}

mod notsend;
pub mod ptr;

pub(crate) mod slice;

mod smaller_chunks;

mod start_ptr;

#[cfg(test)]
mod test;

mod unwrap_const;

pub use self::{
    array_flat_map::ArrayFlatMap, array_split_map::ArraySplitMap, notsend::NotSend,
    unwrap_const::unwrap_const,
};

#[allow(unused_imports)]
pub use self::{
    smaller_chunks::SmallerChunks,
    start_ptr::{StartMutPtr, StartPtr},
};

#[cfg(feature = "alloc")]
pub use leading_zeros_skipped::LeadingZerosStripped;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_usize_from_u64_saturated() {
        const USIZE_MAX: u64 = u64_from_usize(usize::MAX);
        assert_eq!(usize_from_u64_saturated(u64::MIN), usize::MIN);
        assert_eq!(usize_from_u64_saturated(USIZE_MAX), usize::MAX);
        assert_eq!(usize_from_u64_saturated(USIZE_MAX - 1), usize::MAX - 1);

        #[cfg(not(target_pointer_width = "64"))]
        {
            assert_eq!(usize_from_u64_saturated(USIZE_MAX + 1), usize::MAX);
        }
    }
}
