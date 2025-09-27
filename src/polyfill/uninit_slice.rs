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

use super::start_ptr::{StartMutPtr, StartPtr};
use crate::{error::LenMismatchError, polyfill};
use core::{marker::PhantomData, mem::MaybeUninit, ptr};

pub struct Uninit<'a, E> {
    target: &'a mut [MaybeUninit<E>],
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

impl<E> Uninit<'_, E> {
    pub fn len(&self) -> usize {
        self.target.len()
    }
}

// `E: Copy` to avoid `Drop` issues.
impl<'s, E: Copy> Uninit<'s, E> {
    #[allow(dead_code)]
    pub fn write_copy_of_slice_checked(self, src: &[E]) -> Result<&'s mut [E], LenMismatchError> {
        self.write_iter_checked(src.iter().copied())
    }

    pub fn write_iter_checked(
        self,
        mut iter: impl ExactSizeIterator<Item = E>,
    ) -> Result<&'s mut [E], LenMismatchError>
    where
        E: Clone + Copy,
    {
        if iter.len() != self.len() {
            return Err(LenMismatchError::new(iter.len()));
        }
        self.target.iter_mut().enumerate().try_for_each(|(i, d)| {
            let _: &mut E = d.write(iter.next().ok_or_else(|| LenMismatchError::new(i))?);
            Ok(())
        })?;
        Ok(unsafe { self.assume_init() })
    }

    // `FnOnce(&'a mut MaybeUninit<[E]>)`.
    //
    // If `f` returns a slice with lifetime `a` and the same length as `self`, then
    // it must have fully initialized every element of `self` or else it has done
    // something unsound.
    pub fn write_fully_with<EI>(
        self,
        f: impl for<'a> FnOnce(Uninit<'a, E>) -> Result<&'a mut [E], EI>,
    ) -> Result<&'s mut [E], LenMismatchError>
    where
        LenMismatchError: From<EI>,
    {
        let (len, ptr) = (self.len(), self.start_ptr());
        let written = f(self)?;
        if written.len() != len {
            Err(LenMismatchError::new(written.len()))?;
        }
        debug_assert!(len == 0 || (written.as_ptr() == ptr));
        Ok(written)
    }

    pub unsafe fn assume_init(self) -> &'s mut [E] {
        let r: &'s mut [MaybeUninit<E>] = self.target;
        let r: *mut [MaybeUninit<E>] = polyfill::ptr::from_mut(r);
        let r: *mut [E] = r as *mut [E];
        let r: &'s mut [E] = unsafe { &mut *r };
        r
    }
}

// Generally it isn't safe to cast `mut T` to `mut MaybeUninit<T>` because
// somebody might then unsoundly write `uninit` into it without using `unsafe`.
// We avoid that problem here because `Uninit` never writes `uninit` and it
// never exposes a `MaybeUninit<T>` (mutable) reference externally.
impl<'a, E> AliasedUninit<'a, E> {
    pub fn from_mut(target: &'a mut [E]) -> Self {
        let target: &'a mut [E] = target;
        let target: *mut [E] = target;
        let target: *mut [MaybeUninit<E>] = target as *mut [MaybeUninit<E>];
        let _target: &'a mut [MaybeUninit<E>] = unsafe { &mut *target };
        Self {
            target,
            _a: PhantomData,
        }
    }
}

impl<'a, E> From<&'a mut [MaybeUninit<E>]> for Uninit<'a, E> {
    fn from(target: &'a mut [MaybeUninit<E>]) -> Self {
        Self { target }
    }
}

// A pointer to an `Uninit` that remembers the `Uninit`'s lifetime.
pub struct AliasedUninit<'a, E> {
    target: *mut [MaybeUninit<E>],
    _a: PhantomData<&'a mut [MaybeUninit<E>]>,
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

impl<'a, E> From<Uninit<'a, E>> for AliasedUninit<'a, E> {
    fn from(uninit: Uninit<'a, E>) -> Self {
        Self {
            target: polyfill::ptr::from_mut(uninit.target),
            _a: PhantomData,
        }
    }
}

impl<'a, E> AliasedUninit<'a, E> {
    pub unsafe fn from_raw_parts_mut(start_ptr: *mut E, len: usize) -> Self {
        let start_ptr: *mut MaybeUninit<E> = <*mut E>::cast::<MaybeUninit<E>>(start_ptr);
        Self {
            target: ptr::slice_from_raw_parts_mut(start_ptr, len),
            _a: PhantomData,
        }
    }

    pub unsafe fn deref_unchecked(self) -> Uninit<'a, E> {
        let target: *mut [MaybeUninit<E>] = self.target;
        let target = unsafe { &mut *target };
        Uninit { target }
    }
}
