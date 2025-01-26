// Copyright 2025 Brian Smith.
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

pub(crate) use crate::error::LenMismatchError;

pub(crate) trait AliasingSlices3<T> {
    /// The pointers passed to `f` will all be non-null and properly aligned,
    /// but may be dangling.
    ///
    /// The first pointer, `r` points to potentially-uninitialized writable
    /// space for `expected_len` elements of type `T`. Accordingly, `f` must
    /// not read from `r` before writing to it.
    ///
    /// The second & third pointers, `a` and `b`, point to `expected_len`
    /// initialized values of type `T`.
    ///
    /// `r`, `a`, and/or `b` may alias each other, but only in the following
    /// ways: `ptr::eq(r, a)`, `ptr::eq(r, b)`, and/or `ptr::eq(a, b)`; they
    /// will not be "overlapping."
    fn with_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError>;
}

impl<T> AliasingSlices3<T> for &mut [T] {
    fn with_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let r = self;
        if r.len() != expected_len {
            return Err(LenMismatchError::new(r.len()));
        }
        Ok(f(r.as_mut_ptr(), r.as_ptr(), r.as_ptr()))
    }
}

impl<T> AliasingSlices3<T> for (&mut [T], &[T]) {
    fn with_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let (r, a) = self;
        if r.len() != expected_len {
            return Err(LenMismatchError::new(r.len()));
        }
        if a.len() != expected_len {
            return Err(LenMismatchError::new(a.len()));
        }
        Ok(f(r.as_mut_ptr(), r.as_ptr(), a.as_ptr()))
    }
}

impl<T> AliasingSlices3<T> for (&mut [T], &[T], &[T]) {
    fn with_pointers<R>(
        self,
        expected_len: usize,
        f: impl FnOnce(*mut T, *const T, *const T) -> R,
    ) -> Result<R, LenMismatchError> {
        let (r, a, b) = self;
        if r.len() != expected_len {
            return Err(LenMismatchError::new(r.len()));
        }
        if a.len() != expected_len {
            return Err(LenMismatchError::new(a.len()));
        }
        if b.len() != expected_len {
            return Err(LenMismatchError::new(b.len()));
        }
        Ok(f(r.as_mut_ptr(), a.as_ptr(), b.as_ptr()))
    }
}
