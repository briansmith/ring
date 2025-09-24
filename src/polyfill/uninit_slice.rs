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

use crate::error::LenMismatchError;

pub struct Uninit<'a, E> {
    target: &'a mut [E],
}

impl<E> Uninit<'_, E> {
    fn as_ptr(&self) -> *const E {
        self.target.as_ptr() // cast_uninit
    }

    pub fn len(&self) -> usize {
        self.target.len()
    }
}

// `E: Copy` to avoid `Drop` issues.
impl<'s, E: Copy> Uninit<'s, E> {
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
            *d = iter.next().ok_or_else(|| LenMismatchError::new(i))?;
            Ok(())
        })?;
        // Ok(unsafe { self.assume_init() })
        Ok(self.target)
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
        let (len, ptr) = (self.len(), self.as_ptr());
        let written = f(self)?;
        if written.len() != len {
            Err(LenMismatchError::new(written.len()))?;
        }
        debug_assert!(len == 0 || (written.as_ptr() == ptr));
        Ok(written)
    }
}

// TODO: From<&'a mut [MaybeUninit<E>]>
impl<'a, E> Uninit<'a, E> {
    pub fn from_mut(target: &'a mut [E]) -> Self {
        Self { target }
    }
}
