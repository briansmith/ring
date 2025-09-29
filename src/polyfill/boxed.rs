// Copyright 2025 Brian Smith.
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

use alloc::{boxed::Box, vec::Vec};
use core::mem::MaybeUninit;

#[allow(dead_code)]
pub(crate) trait BoxSlicePolyfills<E> {
    fn new_uninit_slice(len: usize) -> Box<[MaybeUninit<E>]>;
}

#[allow(dead_code)]
pub(crate) trait BoxMaybeUninitSlicePolyfills<E> {
    unsafe fn assume_init(self) -> Box<[E]>;
}

impl<E> BoxSlicePolyfills<E> for Box<[E]> {
    fn new_uninit_slice(len: usize) -> Box<[MaybeUninit<E>]> {
        let mut b = Vec::with_capacity(len);
        // SAFETY: Every element of the spare capacity `_uninit` is already
        // `MaybeUninit::uninit()`, so we don't need to write anything.
        unsafe {
            b.set_len(len);
        }
        b.into_boxed_slice()
    }
}

impl<E> BoxMaybeUninitSlicePolyfills<E> for Box<[MaybeUninit<E>]> {
    unsafe fn assume_init(self) -> Box<[E]> {
        let r: Box<[MaybeUninit<E>]> = self;
        let r: *mut [MaybeUninit<E>] = Box::into_raw(r);
        let r: *mut [E] = r as *mut [E]; // cast_init
        unsafe { Box::from_raw(r) }
    }
}
