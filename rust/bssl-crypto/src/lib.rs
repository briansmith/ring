/* Copyright (c) 2023, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#![deny(
    missing_docs,
    unsafe_op_in_unsafe_fn,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

//! Rust BoringSSL bindings
extern crate alloc;

extern crate core;

use core::ffi::c_void;

#[macro_use]
mod macros;

/// Authenticated Encryption with Additional Data algorithms.
pub mod aead;

/// AES block operations.
pub mod aes;

/// Ciphers.
pub mod cipher;

pub mod digest;

/// Ed25519, a signature scheme.
pub mod ed25519;

pub mod hkdf;

pub mod hmac;

/// Random number generation.
pub mod rand;

pub mod x25519;

/// Memory-manipulation operations.
pub mod mem;

/// Elliptic curve diffie-hellman operations.
pub mod ecdh;

pub(crate) mod bn;
pub(crate) mod ec;
pub(crate) mod pkey;

#[cfg(test)]
mod test_helpers;

/// Error type for when a "signature" (either a public-key signature or a MAC)
/// is incorrect.
#[derive(Debug)]
pub struct InvalidSignatureError;

/// FfiSlice exists to provide `as_ffi_ptr` on slices. Calling `as_ptr` on an
/// empty Rust slice may return the alignment of the type, rather than NULL, as
/// the pointer. When passing pointers into C/C++ code, that is not a valid
/// pointer. Thus this method should be used whenever passing a pointer to a
/// slice into BoringSSL code.
trait FfiSlice {
    fn as_ffi_ptr(&self) -> *const u8;
    fn as_ffi_void_ptr(&self) -> *const c_void {
        self.as_ffi_ptr() as *const c_void
    }
}

impl FfiSlice for [u8] {
    fn as_ffi_ptr(&self) -> *const u8 {
        if self.is_empty() {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

impl<const N: usize> FfiSlice for [u8; N] {
    fn as_ffi_ptr(&self) -> *const u8 {
        if N == 0 {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

/// See the comment [`FfiSlice`].
trait FfiMutSlice {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8;
    fn as_ffi_void_ptr(&mut self) -> *mut c_void {
        self.as_mut_ffi_ptr() as *mut c_void
    }
}

impl FfiMutSlice for [u8] {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8 {
        if self.is_empty() {
            core::ptr::null_mut()
        } else {
            self.as_mut_ptr()
        }
    }
}

impl<const N: usize> FfiMutSlice for [u8; N] {
    fn as_mut_ffi_ptr(&mut self) -> *mut u8 {
        if N == 0 {
            core::ptr::null_mut()
        } else {
            self.as_mut_ptr()
        }
    }
}

/// This is a helper struct which provides functions for passing slices over FFI.
///
/// Deprecated: use `FfiSlice` which adds less noise and lets one grep for `as_ptr`
/// as a sign of something to check.
struct CSlice<'a>(&'a [u8]);

impl<'a> From<&'a [u8]> for CSlice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

impl CSlice<'_> {
    /// Returns a raw pointer to the value, which is safe to pass over FFI.
    pub fn as_ptr<T>(&self) -> *const T {
        if self.0.is_empty() {
            core::ptr::null()
        } else {
            self.0.as_ptr() as *const T
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// This is a helper struct which provides functions for passing mutable slices over FFI.
///
/// Deprecated: use `FfiMutSlice` which adds less noise and lets one grep for
/// `as_ptr` as a sign of something to check.
struct CSliceMut<'a>(&'a mut [u8]);

impl CSliceMut<'_> {
    /// Returns a raw pointer to the value, which is safe to pass over FFI.
    pub fn as_mut_ptr<T>(&mut self) -> *mut T {
        if self.0.is_empty() {
            core::ptr::null_mut()
        } else {
            self.0.as_mut_ptr() as *mut T
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> From<&'a mut [u8]> for CSliceMut<'a> {
    fn from(value: &'a mut [u8]) -> Self {
        Self(value)
    }
}

/// A helper trait implemented by types which reference borrowed foreign types.
///
/// # Safety
///
/// Implementations of `ForeignTypeRef` must guarantee the following:
///
/// - `Self::from_ptr(x).as_ptr() == x`
/// - `Self::from_ptr_mut(x).as_ptr() == x`
unsafe trait ForeignTypeRef: Sized {
    /// The raw C type.
    type CType;

    /// Constructs a shared instance of this type from its raw type.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid, immutable, instance of the type for the `'a` lifetime.
    #[inline]
    unsafe fn from_ptr<'a>(ptr: *mut Self::CType) -> &'a Self {
        debug_assert!(!ptr.is_null());
        unsafe { &*(ptr as *mut _) }
    }

    /// Constructs a mutable reference of this type from its raw type.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid, unique, instance of the type for the `'a` lifetime.
    #[inline]
    unsafe fn from_ptr_mut<'a>(ptr: *mut Self::CType) -> &'a mut Self {
        debug_assert!(!ptr.is_null());
        unsafe { &mut *(ptr as *mut _) }
    }

    /// Returns a raw pointer to the wrapped value.
    #[inline]
    fn as_ptr(&self) -> *mut Self::CType {
        self as *const _ as *mut _
    }
}

/// A helper trait implemented by types which has an owned reference to foreign types.
///
/// # Safety
///
/// Implementations of `ForeignType` must guarantee the following:
///
/// - `Self::from_ptr(x).as_ptr() == x`
unsafe trait ForeignType {
    /// The raw C type.
    type CType;

    /// Constructs an instance of this type from its raw type.
    ///
    /// # Safety
    ///
    /// - `ptr` must be a valid, immutable, instance of `CType`.
    /// - Ownership of `ptr` is passed to the implementation, and will free `ptr` when dropped.
    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self;

    /// Returns a raw pointer to the wrapped value.
    fn as_ptr(&self) -> *mut Self::CType;
}

/// Returns a BoringSSL structure that is initialized by some function.
/// Requires that the given function completely initializes the value.
///
/// (Tagged `unsafe` because a no-op argument would otherwise expose
/// uninitialized memory.)
unsafe fn initialized_struct<T, F>(init: F) -> T
where
    F: FnOnce(*mut T),
{
    let mut out_uninit = core::mem::MaybeUninit::<T>::uninit();
    init(out_uninit.as_mut_ptr());
    unsafe { out_uninit.assume_init() }
}

/// Wrap a closure that initializes an output buffer and return that buffer as
/// an array. Requires that the closure fully initialize the given buffer.
///
/// Safety: the closure must fully initialize the array.
unsafe fn with_output_array<const N: usize, F>(func: F) -> [u8; N]
where
    F: FnOnce(*mut u8, usize),
{
    let mut out_uninit = core::mem::MaybeUninit::<[u8; N]>::uninit();
    let out_ptr = if N != 0 {
        out_uninit.as_mut_ptr() as *mut u8
    } else {
        core::ptr::null_mut()
    };
    func(out_ptr, N);
    // Safety: `func` promises to fill all of `out_uninit`.
    unsafe { out_uninit.assume_init() }
}

/// Wrap a closure that initializes an output buffer and return that buffer as
/// an array. The closure returns a [`core::ffi::c_int`] and, if the return value
/// is not one, then the initialization is assumed to have failed and [None] is
/// returned. Otherwise, this function requires that the closure fully
/// initialize the given buffer.
///
/// Safety: the closure must fully initialize the array if it returns one.
unsafe fn with_output_array_fallible<const N: usize, F>(func: F) -> Option<[u8; N]>
where
    F: FnOnce(*mut u8, usize) -> core::ffi::c_int,
{
    let mut out_uninit = core::mem::MaybeUninit::<[u8; N]>::uninit();
    let out_ptr = if N != 0 {
        out_uninit.as_mut_ptr() as *mut u8
    } else {
        core::ptr::null_mut()
    };
    if func(out_ptr, N) == 1 {
        // Safety: `func` promises to fill all of `out_uninit` if it returns one.
        unsafe { Some(out_uninit.assume_init()) }
    } else {
        None
    }
}

/// Used to prevent external implementations of internal traits.
mod sealed {
    pub struct Sealed;
}
