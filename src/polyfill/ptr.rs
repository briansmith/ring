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
pub(crate) trait PointerPolyfills<T> {
    type ArrayPointer<const N: usize>;

    // TODO(MSRV feature(ptr_cast_array)): Drop this.
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N>;
}

impl<T> PointerPolyfills<T> for *const T {
    type ArrayPointer<const N: usize> = *const [T; N];

    #[inline(always)]
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N> {
        self.cast::<[T; N]>()
    }
}

impl<T> PointerPolyfills<T> for *mut T {
    type ArrayPointer<const N: usize> = *mut [T; N];

    #[inline(always)]
    fn cast_array_<const N: usize>(self) -> Self::ArrayPointer<N> {
        self.cast::<[T; N]>()
    }
}

// TODO(MSRV feature(array_ptr_get)): Considering dropping this, depending on
// how https://github.com/rust-lang/rust/issues/119834#issuecomment-3137563829
// is resolved.
#[allow(dead_code)]
pub(crate) trait StartPtr {
    type Elem;
    fn start_ptr_(self) -> *const Self::Elem;
}

impl<T, const N: usize> StartPtr for *const [T; N] {
    type Elem = T;
    #[inline(always)]
    fn start_ptr_(self) -> *const Self::Elem {
        self.cast::<Self::Elem>()
    }
}

// TODO(MSRV feature(array_ptr_get)): Considering dropping this, depending on
// how https://github.com/rust-lang/rust/issues/119834#issuecomment-3137563829
// is resolved.
#[allow(dead_code)]
pub(crate) trait StartPtrMut {
    type Elem;
    fn start_mut_ptr_(self) -> *mut Self::Elem;
}

impl<T, const N: usize> StartPtrMut for *mut [T; N] {
    type Elem = T;
    #[inline(always)]
    fn start_mut_ptr_(self) -> *mut Self::Elem {
        self.cast::<Self::Elem>()
    }
}

// TODO(MSRV 1.76): Replace with `core::ptr::from_mut`.
#[allow(dead_code)]
#[inline(always)]
pub fn from_mut<T: ?Sized>(r: &mut T) -> *mut T {
    r
}

// TODO(MSRV 1.76): Replace with `core::ptr::from_ref`.
#[allow(dead_code)]
#[inline(always)]
pub const fn from_ref<T: ?Sized>(r: &T) -> *const T {
    r
}
