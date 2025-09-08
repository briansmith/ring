// This file, and all code in `rand/getrandom`, are vendored from
// the `getrandom` project:
// https://github.com/rust-random/getrandom/tree/78ef61a0e7a5dc876da0b496998464630a4c0bf0
//
// Copyright (c) 2018-2025 The rust-random Project Developers
// Copyright (c) 2014 The Rust Project Developers
// 
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

// Overwrite links to crate items with intra-crate links
//! [`Error::UNEXPECTED`]: Error::UNEXPECTED
//! [`fill_uninit`]: fill_uninit

#![warn(rust_2018_idioms, unused_lifetimes, missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(getrandom_backend = "efi_rng", feature(uefi_std))]
#![deny(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::fn_to_numeric_cast,
    clippy::fn_to_numeric_cast_with_truncation,
    clippy::ptr_as_ptr,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]

use core::mem::MaybeUninit;

mod backends;
mod error;
mod util;

#[cfg(feature = "std")]
mod error_std_impls;

pub use error::Error;

/// Fill `dest` with random bytes from the system's preferred random number source.
///
/// This function returns an error on any failure, including partial reads. We
/// make no guarantees regarding the contents of `dest` on error. If `dest` is
/// empty, `getrandom` immediately returns success, making no calls to the
/// underlying operating system.
///
/// Blocking is possible, at least during early boot; see module documentation.
///
/// In general, `getrandom` will be fast enough for interactive usage, though
/// significantly slower than a user-space CSPRNG; for the latter consider
/// [`rand::thread_rng`](https://docs.rs/rand/*/rand/fn.thread_rng.html).
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), getrandom::Error> {
/// let mut buf = [0u8; 32];
/// getrandom::fill(&mut buf)?;
/// # Ok(()) }
/// ```
#[inline]
pub fn fill(dest: &mut [u8]) -> Result<(), Error> {
    // SAFETY: The `&mut MaybeUninit<_>` reference doesn't escape,
    // and `fill_uninit` guarantees it will never de-initialize
    // any part of `dest`.
    let _ = fill_uninit(unsafe { util::slice_as_uninit_mut(dest) })?;
    Ok(())
}

/// Fill potentially uninitialized buffer `dest` with random bytes from
/// the system's preferred random number source and return a mutable
/// reference to those bytes.
///
/// On successful completion this function is guaranteed to return a slice
/// which points to the same memory as `dest` and has the same length.
/// In other words, it's safe to assume that `dest` is initialized after
/// this function has returned `Ok`.
///
/// No part of `dest` will ever be de-initialized at any point, regardless
/// of what is returned.
///
/// # Examples
///
/// ```ignore
/// # // We ignore this test since `uninit_array` is unstable.
/// #![feature(maybe_uninit_uninit_array)]
/// # fn main() -> Result<(), getrandom::Error> {
/// let mut buf = core::mem::MaybeUninit::uninit_array::<1024>();
/// let buf: &mut [u8] = getrandom::fill_uninit(&mut buf)?;
/// # Ok(()) }
/// ```
#[inline]
pub fn fill_uninit(dest: &mut [MaybeUninit<u8>]) -> Result<&mut [u8], Error> {
    if !dest.is_empty() {
        backends::fill_inner(dest)?;
    }

    #[cfg(getrandom_msan)]
    extern "C" {
        fn __msan_unpoison(a: *mut core::ffi::c_void, size: usize);
    }

    // SAFETY: `dest` has been fully initialized by `imp::fill_inner`
    // since it returned `Ok`.
    Ok(unsafe { util::slice_assume_init_mut(dest) })
}
