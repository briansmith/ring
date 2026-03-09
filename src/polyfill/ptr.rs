// Copyright 2024 Brian Smith.
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

use core::mem::MaybeUninit;

#[allow(dead_code)]
pub(crate) trait PointerPolyfills {
    type ArrayPointer<const N: usize>;

    // TODO(MSRV feature(ptr_cast_array)): Drop this.
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N>;
}

impl<T> PointerPolyfills for *const T {
    type ArrayPointer<const N: usize> = *const [T; N];

    #[inline(always)]
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N> {
        self.cast::<[T; N]>()
    }
}

impl<T> PointerPolyfills for *mut T {
    type ArrayPointer<const N: usize> = *mut [T; N];

    #[inline(always)]
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N> {
        self.cast::<[T; N]>()
    }
}

#[allow(dead_code)]
#[inline(always)]
pub const fn cast_init_slice_of_array<T, const N: usize>(
    p: *const [[MaybeUninit<T>; N]],
) -> *const [[T; N]] {
    p as *const [[T; N]]
}
