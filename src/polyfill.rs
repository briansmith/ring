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

#[inline(always)]
pub const fn u64_from_usize(x: usize) -> u64 {
    x as u64
}

pub fn usize_from_u32(x: u32) -> usize {
    x as usize
}

#[macro_use]
mod chunks_fixed;

mod array_flat_map;

#[cfg(feature = "alloc")]
mod leading_zeros_skipped;

#[cfg(test)]
mod test;

mod unwrap_const;

pub use self::{array_flat_map::ArrayFlatMap, chunks_fixed::*, unwrap_const::unwrap_const};

#[cfg(feature = "alloc")]
pub use leading_zeros_skipped::LeadingZerosStripped;
