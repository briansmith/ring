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

#[allow(dead_code)]
pub(crate) trait PointerPolyfills {
    type ArrayPointer<const N: usize>;

    // TODO(MSRV feature(ptr_cast_array)): Drop this.
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N>;
}

#[allow(dead_code)]
pub(crate) trait ConstPointerPolyfills {
    fn addr(self) -> usize;
}

impl<T> ConstPointerPolyfills for *const T {
    #[inline(always)]
    fn addr(self) -> usize {
        self as usize
    }
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

#[inline(always)]
pub fn addr_eq<T>(p: *const T, q: *const T) -> bool {
    p.cast::<()>() == q.cast::<()>()
}
