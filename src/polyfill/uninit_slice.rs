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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    start_ptr::{StartMutPtr, StartPtr},
    uninit_slice_cursor::Cursor,
};
use crate::{error::LenMismatchError, polyfill};
use core::{
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::RangeTo,
    ptr,
};

pub struct Uninit<'target, E> {
    target: &'target mut [MaybeUninit<E>],
}

impl<'target, E> Default for Uninit<'target, E> {
    fn default() -> Self {
        Self {
            target: Default::default(),
        }
    }
}

impl<E> StartPtr for &Uninit<'_, E> {
    type Elem = E;

    fn start_ptr(self) -> *const Self::Elem {
        <*const MaybeUninit<E>>::cast::<E>(self.target.as_ptr()) // cast_init
    }
}

impl<E> StartMutPtr for &mut Uninit<'_, E> {
    type Elem = E;

    fn start_mut_ptr(self) -> *mut Self::Elem {
        <*mut MaybeUninit<E>>::cast::<E>(self.target.as_mut_ptr()) // cast_init
    }
}

impl<'target, E> Uninit<'target, E> {
    pub fn into_cursor(self) -> Cursor<'target, E> {
        Cursor::from(self)
    }

    pub fn len(&self) -> usize {
        self.target.len()
    }

    #[allow(dead_code)]
    pub fn reborrow_mut(&mut self) -> Uninit<'_, E> {
        Uninit {
            target: self.target,
        }
    }

    pub(super) fn split_off_mut<'s>(
        &'s mut self,
        range: RangeTo<usize>,
    ) -> Option<Uninit<'target, E>> {
        if self.target.len() < range.end {
            return None;
        }
        let (front, back) = mem::take(self).target.split_at_mut(range.end);
        self.target = back;
        Some(Uninit { target: front })
    }
}

// `E: Copy` to avoid `Drop` issues.
impl<'target, E: Copy> Uninit<'target, E> {
    #[allow(dead_code)]
    pub fn write_copy_of_slice(
        mut self,
        src: &[E],
    ) -> Result<WriteResult<'target, E, Self, ()>, LenMismatchError> {
        let Some(mut dst) = self.split_off_mut(..src.len()) else {
            return Err(LenMismatchError::new(self.len()));
        };
        let written = unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst.start_mut_ptr(), src.len());
            dst.assume_init()
        };
        Ok(WriteResult {
            written,
            dst_leftover: self,
            src_leftover: (),
        })
    }

    pub fn write_iter<Src: IntoIterator<Item = E>>(
        mut self,
        src: Src,
    ) -> WriteResult<'target, E, Self, Src::IntoIter> {
        let mut init_len = 0;
        let mut src = src.into_iter();
        self.target
            .iter_mut()
            .zip(src.by_ref())
            .for_each(|(dst, src)| {
                let _: &mut E = dst.write(src);
                init_len += 1;
            });
        let written = self
            .split_off_mut(..init_len)
            .unwrap_or_else(|| unreachable!());
        let written = unsafe { written.assume_init() };

        WriteResult {
            written,
            dst_leftover: self,
            src_leftover: src,
        }
    }

    // If the result of `u.write_fully_with(f)` is `Ok(r)` then:
    //    * `r.len() == u.len()`
    //    * `r` has overwritten any elements of `self`.
    //    * Either `r.as_ptr()` equals `u.as_ptr()` or `u.len() == 0` and `r.len() == 0`.
    pub fn write_fully_with<EI>(
        self,
        f: impl for<'a> FnOnce(Uninit<'a, E>) -> Result<&'a mut [E], EI>,
    ) -> Result<&'target mut [E], LenMismatchError>
    where
        LenMismatchError: From<EI>,
    {
        let (len, ptr) = (self.len(), self.start_ptr());
        let written = f(self)?;
        if written.len() != len {
            Err(LenMismatchError::new(written.len()))?;
        }
        // Verify the returned slice is actually `self` overwritten, but also
        // allow any empty slice for usability.
        if !polyfill::ptr::addr_eq(ptr, written.as_ptr()) && len != 0 {
            // Abuse `LenMismatchError` for convenience; this is never going to
            // happen anyway.
            return Err(LenMismatchError::new(ptr.addr()));
        }
        Ok(written)
    }

    pub unsafe fn assume_init(self) -> &'target mut [E] {
        let r: &'target mut [MaybeUninit<E>] = self.target;
        let r: *mut [MaybeUninit<E>] = ptr::from_mut(r);
        let r: *mut [E] = r as *mut [E];
        let r: &'target mut [E] = unsafe { &mut *r };
        r
    }
}

// Generally it isn't safe to cast `mut T` to `mut MaybeUninit<T>` because
// somebody might then unsoundly write `uninit` into it without using `unsafe`.
// We avoid that problem here because `Uninit` never writes `uninit` and it
// never exposes a `MaybeUninit<T>` (mutable) reference externally.
impl<'target, E> AliasedUninit<'target, E> {
    pub fn from_mut(target: &'target mut [E]) -> Self {
        let target: &'target mut [E] = target;
        let target: *mut [E] = target;
        let target: *mut [MaybeUninit<E>] = target as *mut [MaybeUninit<E>];
        let _target: &'target mut [MaybeUninit<E>] = unsafe { &mut *target };
        Self {
            target,
            _a: PhantomData,
        }
    }
}

impl<'target, E> From<&'target mut [MaybeUninit<E>]> for Uninit<'target, E> {
    fn from(target: &'target mut [MaybeUninit<E>]) -> Self {
        Self { target }
    }
}

// A pointer to an `Uninit` that remembers the `Uninit`'s lifetime.
pub struct AliasedUninit<'target, E> {
    target: *mut [MaybeUninit<E>],
    _a: PhantomData<&'target mut [MaybeUninit<E>]>,
}

impl<E> StartPtr for &AliasedUninit<'_, E> {
    type Elem = E;

    fn start_ptr(self) -> *const Self::Elem {
        let r: *const MaybeUninit<E> =
            <*const [MaybeUninit<E>]>::cast::<MaybeUninit<E>>(self.target);
        let r: *const E = <*const MaybeUninit<E>>::cast::<E>(r); // cast_init
        r
    }
}

impl<E> StartMutPtr for &mut AliasedUninit<'_, E> {
    type Elem = E;

    fn start_mut_ptr(self) -> *mut Self::Elem {
        let r: *mut MaybeUninit<E> = <*mut [MaybeUninit<E>]>::cast::<MaybeUninit<E>>(self.target);
        let r: *mut E = <*mut MaybeUninit<E>>::cast::<E>(r); // cast_init
        r
    }
}

impl<'target, E> From<Uninit<'target, E>> for AliasedUninit<'target, E> {
    fn from(uninit: Uninit<'target, E>) -> Self {
        Self {
            target: ptr::from_mut(uninit.target),
            _a: PhantomData,
        }
    }
}

impl<'target, E> AliasedUninit<'target, E> {
    pub unsafe fn from_raw_parts_mut(start_ptr: *mut E, len: usize) -> Self {
        let start_ptr: *mut MaybeUninit<E> = <*mut E>::cast::<MaybeUninit<E>>(start_ptr);
        Self {
            target: ptr::slice_from_raw_parts_mut(start_ptr, len),
            _a: PhantomData,
        }
    }

    pub unsafe fn deref_unchecked(self) -> Uninit<'target, E> {
        let target: *mut [MaybeUninit<E>] = self.target;
        let target = unsafe { &mut *target };
        Uninit { target }
    }
}

pub struct WriteResult<'written, E, Dst, Src> {
    written: &'written mut [E],
    dst_leftover: Dst,
    src_leftover: Src,
}

impl<'written, E, Dst, Src> WriteResult<'written, E, Dst, Src> {
    #[cfg(test)]
    pub fn ignore_uninit(self) -> WriteResult<'written, E, (), Src> {
        self.take_uninit().0
    }

    #[inline(always)]
    pub fn take_uninit(self) -> (WriteResult<'written, E, (), Src>, Dst) {
        let WriteResult {
            written,
            dst_leftover,
            src_leftover,
        } = self;
        (
            WriteResult {
                written,
                dst_leftover: (),
                src_leftover,
            },
            dst_leftover,
        )
    }

    #[inline(always)]
    pub fn src_empty(self) -> Result<WriteResult<'written, E, Dst, ()>, LenMismatchError>
    where
        Src: IntoIterator,
    {
        let WriteResult {
            written,
            dst_leftover,
            src_leftover,
        } = self;
        let mut src_leftover = src_leftover.into_iter().peekable();
        if src_leftover.next().is_some() {
            return Err(LenMismatchError::new(src_leftover.size_hint().0));
        }
        Ok(WriteResult {
            written,
            dst_leftover,
            src_leftover: (),
        })
    }
}

impl<'written, E, Src> WriteResult<'written, E, Uninit<'written, E>, Src> {
    #[allow(dead_code)]
    #[inline(always)]
    pub fn uninit_empty(self) -> Result<WriteResult<'written, E, (), Src>, LenMismatchError> {
        let (res, dst_leftover) = self.take_uninit();
        if dst_leftover.len() != 0 {
            return Err(LenMismatchError::new(dst_leftover.len()));
        }
        Ok(res)
    }
}

impl<'written, E> WriteResult<'written, E, (), ()> {
    #[inline(always)]
    pub fn into_written(self) -> &'written mut [E] {
        self.written
    }
}
