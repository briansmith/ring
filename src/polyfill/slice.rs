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

// TODO(MSRV feature(slice_as_chunks)): Use `slice::as_chunks` instead.
// This is copied from the libcore implementation of `slice::as_chunks`.
#[inline(always)]
pub fn as_chunks<T, const N: usize>(slice: &[T]) -> (&[[T; N]], &[T]) {
    assert!(N != 0, "chunk size must be non-zero");
    let len = slice.len() / N;
    let (multiple_of_n, remainder) = slice.split_at(len * N);
    // SAFETY: We already panicked for zero, and ensured by construction
    // that the length of the subslice is a multiple of N.
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let chunked = unsafe { core::slice::from_raw_parts(multiple_of_n.as_ptr().cast(), len) };
    (chunked, remainder)
}

// TODO(MSRV feature(slice_as_chunks)): Use `slice::as_chunks_mut` instead.
// This is adapted from above implementation of `slice::as_chunks`, as the
// libcore implementation uses other unstable APIs.
pub fn as_chunks_mut<T, const N: usize>(slice: &mut [T]) -> (&mut [[T; N]], &mut [T]) {
    assert!(N != 0, "chunk size must be non-zero");
    let len = slice.len() / N;
    let (multiple_of_n, remainder) = slice.split_at_mut(len * N);
    // SAFETY: We already panicked for zero, and ensured by construction
    // that the length of the subslice is a multiple of N.
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let chunked =
        unsafe { core::slice::from_raw_parts_mut(multiple_of_n.as_mut_ptr().cast(), len) };
    (chunked, remainder)
}

// TODO(MSRV feature(slice_flatten)): Use `slice::flatten` instead.
// This is derived from the libcore implementation, using only stable APIs.
pub fn flatten<T, const N: usize>(slice: &[[T; N]]) -> &[T] {
    let len = if core::mem::size_of::<T>() == 0 {
        slice.len().checked_mul(N).expect("slice len overflow")
    } else {
        // SAFETY: `slice.len() * N` cannot overflow because `slice` is
        // already in the address space.
        slice.len() * N
    };
    // SAFETY: `[T]` is layout-identical to `[T; N]`
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast(), len) }
}

// TODO(MSRV feature(slice_flatten)): Use `slice::flatten_mut` instead.
// This is derived from the libcore implementation, using only stable APIs.
pub fn flatten_mut<T, const N: usize>(slice: &mut [[T; N]]) -> &mut [T] {
    let len = if core::mem::size_of::<T>() == 0 {
        slice.len().checked_mul(N).expect("slice len overflow")
    } else {
        // SAFETY: `slice.len() * N` cannot overflow because `slice` is
        // already in the address space.
        slice.len() * N
    };
    // SAFETY: `[T]` is layout-identical to `[T; N]`
    unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), len) }
}

// TODO(MSRV feature(split_at_checked)): Use `slice::split_at_checked`.
//
// Note that the libcore version is implemented in terms of
// `slice::split_at_unchecked()`, and `slice::split_at()` was changed to be
// implemented in terms of `split_at_checked`. For now, we implement this in
// terms of `split_at` and rely on the optimizer to eliminate the panic.
#[inline(always)]
pub fn split_at_checked<T>(slice: &[T], i: usize) -> Option<(&[T], &[T])> {
    if slice.len() >= i {
        Some(slice.split_at(i))
    } else {
        None
    }
}
