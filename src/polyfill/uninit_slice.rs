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

use super::start_ptr::{StartMutPtr, StartPtr};
use crate::error::LenMismatchError;
use core::{
    iter,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ops::RangeTo,
    ptr,
    slice::SliceIndex,
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
    pub fn len(&self) -> usize {
        self.target.len()
    }

    #[allow(dead_code)]
    pub fn reborrow_mut(&mut self) -> Uninit<'_, E> {
        Uninit {
            target: self.target,
        }
    }

    fn get_internal<I>(&self, range: I) -> Option<&[MaybeUninit<E>]>
    where
        I: SliceIndex<[MaybeUninit<E>], Output = [MaybeUninit<E>]>,
    {
        self.target.get(range)
    }

    pub fn get_mut<I>(&mut self, range: I) -> Option<Uninit<'_, E>>
    where
        I: SliceIndex<[MaybeUninit<E>], Output = [MaybeUninit<E>]>,
    {
        let target = self.target.get_mut(range)?;
        Some(Uninit { target })
    }

    pub fn split_at_mut_checked(
        self,
        mid: usize,
    ) -> Option<(Uninit<'target, E>, Uninit<'target, E>)> {
        let (before, after) = self.target.split_at_mut_checked(mid)?;
        Some((Self { target: before }, Self { target: after }))
    }

    pub fn split_off_mut<'s>(&'s mut self, range: RangeTo<usize>) -> Option<Uninit<'target, E>> {
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
        self,
        src: &[E],
    ) -> Result<WriteResult<'target, E, Self, ()>, LenMismatchError> {
        let mut buf = Buf::from(self);
        buf.unfilled().write_copy_of_slice(src)?;
        let (written, dst_leftover) = buf.split_filled_mut();
        Ok(WriteResult {
            written,
            dst_leftover,
            src_leftover: (),
        })
    }

    pub fn write_copy_of_slice_padded(
        self,
        src: &[E],
        padding: E,
    ) -> Result<&'target mut [E], LenMismatchError> {
        let mut buf = Buf::from(self);
        buf.unfilled().write_copy_of_slice(src)?;
        let num_zeros = buf.unfilled().capacity();
        buf.unfilled().write_repeat(padding, num_zeros)?;
        Ok(buf.into_filled_mut())
    }

    pub fn write_filled_copy(self, value: E) -> &'target mut [E]
    where
        E: Copy, // To avoid concerns about `value.clone()` panicking
    {
        self.write_iter(iter::repeat(value)).written
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
// never exposes a `MaybeUninit<T>` (mutable) reference externally (with a
// non-`unsafe` API).
impl<'target, E> From<&'target mut [E]> for Uninit<'target, E> {
    fn from(target: &'target mut [E]) -> Self {
        let target: &'target mut [E] = target;
        let target: *mut [E] = target;
        let target: *mut [MaybeUninit<E>] = target as *mut [MaybeUninit<E>];
        let target: &'target mut [MaybeUninit<E>] = unsafe { &mut *target };
        Self { target }
    }
}

// Generally it isn't safe to cast `mut T` to `mut MaybeUninit<T>` because
// somebody might then unsoundly write `uninit` into it without using `unsafe`.
// We avoid that problem here because `AliasedUninit` never writes `uninit` and
// it never exposes a `MaybeUninit<T>` (mutable) reference externally (with a
// non-`unsafe` API).
impl<'target, E> AliasedUninit<'target, E> {
    pub fn from_mut(target: &'target mut [E]) -> Self {
        let target = Uninit::from(target);
        Self {
            target: target.target,
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
    // `()` is a zero-sized type, whereas `[MaybeUninit<E>]` isn't. From
    // https://rust-lang.github.io/unsafe-code-guidelines/glossary.html#aliasing,
    // "One interesting side effect of these rules is that references and
    // pointers to Zero Sized Types never alias each other, because their span
    // length is always 0 bytes." So this allows us to mention `'target`
    // basically without any other effect, or even alluding to any other
    // effect.
    _a: PhantomData<&'target mut ()>,
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

/// A writable (and readable) buffer analogous to `core::io::BorrowedBuf`.
pub struct Buf<'target, E> {
    storage: Uninit<'target, E>,
    filled: usize,
}

impl<'target, E: Copy> From<Uninit<'target, E>> for Buf<'target, E> {
    fn from(storage: Uninit<'target, E>) -> Self {
        Self { storage, filled: 0 }
    }
}

impl<'target, E: Copy> Buf<'target, E> {
    pub fn filled<'s>(&'s self) -> &'s [E] {
        let filled = self
            .storage
            .get_internal(..self.filled)
            .unwrap_or_else(|| unreachable!()); // due to invariant

        // TODO(MSRV-1.93: Use `unsafe { filled.assume_init_ref() }`):
        let filled: &'s [MaybeUninit<E>] = filled;
        let filled: *const [MaybeUninit<E>] = filled;
        let filled: *const [E] = filled as *const [E];
        let filled: &'s [E] = unsafe { &*filled };
        filled
    }

    pub fn filled_mut(&mut self) -> &mut [E] {
        let filled = self
            .storage
            .get_mut(..self.filled)
            .unwrap_or_else(|| unreachable!()); // By invariant
        unsafe { filled.assume_init() }
    }

    pub fn into_filled_mut(self) -> &'target mut [E] {
        let (filled, _unfilled) = self.split_filled_mut();
        filled
    }

    pub fn unfilled(&mut self) -> Cursor<'target, '_, E> {
        Cursor { buf: self }
    }

    fn unfilled_uninit(&mut self) -> Uninit<'_, E> {
        let unfilled = self
            .storage
            .target
            .get_mut(self.filled..)
            .unwrap_or_else(|| {
                unreachable!() // due to invariant
            });
        Uninit::from(unfilled)
    }

    fn split_filled_mut(self) -> (&'target mut [E], Uninit<'target, E>) {
        let (filled, unfilled) = self
            .storage
            .split_at_mut_checked(self.filled)
            .unwrap_or_else(|| unreachable!()); // by invariant.
        // SAFETY: by invariant.
        let filled = unsafe { filled.assume_init() };
        (filled, unfilled)
    }
}

/// A writable cursor analogous to `core::io::BorrowedCursor`.
///
/// We don't attempt to implement the collapsing of `target` and ``buf` into
/// a single lifetime.
pub struct Cursor<'target, 'buf, E> {
    buf: &'buf mut Buf<'target, E>,
}

impl<E: Copy> Cursor<'_, '_, E> {
    pub fn capacity(&self) -> usize {
        // Can't overflow due to invariant
        self.buf.storage.target.len() - self.buf.filled
    }

    pub fn write(&mut self, value: E) -> Result<(), LenMismatchError> {
        self.write_repeat(value, 1)
    }

    pub fn write_repeat(&mut self, value: E, repeat: usize) -> Result<(), LenMismatchError> {
        let mut unfilled = self.buf.unfilled_uninit();
        let capacity = unfilled.len();
        let to_fill = unfilled
            .split_off_mut(..repeat)
            .ok_or_else(|| LenMismatchError::new(capacity))?;
        // Can't overflow since `written` is a subslice of `self.buf.storage`.
        self.buf.filled += to_fill.write_filled_copy(value).len();
        Ok(())
    }

    pub fn write_copy_of_slice(&mut self, src: &[E]) -> Result<(), LenMismatchError> {
        let mut dst = self.buf.unfilled_uninit();
        if dst.len() < src.len() {
            return Err(LenMismatchError::new(dst.len()));
        }
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst.start_mut_ptr(), src.len());
        };
        self.buf.filled += src.len();
        Ok(())
    }

    pub fn write_iter<Src: IntoIterator<Item = E>>(
        &mut self,
        src: Src,
    ) -> (&mut [E], Src::IntoIter) {
        // TODO: Deal with panics.
        let start = self.buf.filled;
        let WriteResult {
            written,
            dst_leftover: _,
            src_leftover,
        } = self.buf.unfilled_uninit().write_iter(src);
        let written_len = written.len();
        // Can't overflow because `wr.written` is a slice of `self.buf.storage`.
        self.buf.filled += written_len;
        let (_existing, written) = self
            .buf
            .filled_mut()
            .split_at_mut_checked(start)
            .unwrap_or_else(|| unreachable!());
        (written, src_leftover)
    }

    /// See `core::io::BorrowedCursor::with_unfilled_buf`.
    ///
    /// # Panics
    ///
    /// Panics if `f` replaces `Buf` with a different one.
    pub fn with_unfilled_buf<R>(&mut self, f: impl FnOnce(&mut Buf<'_, E>) -> R) -> R {
        let mut buf = Buf::from(self.buf.unfilled_uninit());
        let ptr = buf.storage.start_ptr();
        let len = buf.storage.target.len();
        let res = f(&mut buf);
        assert!(ptr::addr_eq(buf.storage.start_ptr(), ptr));
        assert!(buf.storage.len() <= len);
        self.buf.filled += buf.filled;
        // The above assertions ensure our invariant is maintained.
        debug_assert!(self.buf.filled <= self.buf.storage.len());
        res
    }
}

pub struct WriteResult<'written, E, Dst, Src> {
    written: &'written mut [E],
    dst_leftover: Dst,
    src_leftover: Src,
}

impl<'written, E, Dst, Src> WriteResult<'written, E, Dst, Src> {
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
