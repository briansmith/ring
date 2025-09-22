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

#![cfg(not(target_arch = "x86_64"))]

//! Arrays of fixed-length slices, where the length is chosen at runtime,
//! and where the backing store is provided by the user.

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::slice;
use crate::{error::LenMismatchError, polyfill};
use core::{mem::MaybeUninit, num::NonZeroUsize};

/// An uninitialized array of slices.
///
/// E: Copy to avoid drop issues.
pub struct Uninit<'e, E> {
    storage: &'e mut [MaybeUninit<E>],
    elems_per_item: NonZeroUsize,
    len: usize,
}

/// An uninitialized array.
///
/// `E: Copy` to avoid having to implement any `Drop` logic.
impl<E: Copy> Uninit<'_, E> {
    /// Create an uninitialized array of `num_elems` slices of length
    ///`elems_per_item`, backed by `storage`.
    ///
    pub fn new(
        storage: &'_ mut [MaybeUninit<E>],
        num_elems: usize,
        elems_per_item: NonZeroUsize,
    ) -> Result<Uninit<'_, E>, LenMismatchError> {
        let total_elems = num_elems
            .checked_mul(elems_per_item.get())
            .ok_or_else(|| LenMismatchError::new(elems_per_item.get()))?;
        // TODO: Should we split `storage` from the end instead?
        //let mid = overallocated_storage.len().checked_sub(total_elems)?;
        //let storage = overallocated_storage.get_mut(mid..)?;
        let storage = storage
            .get_mut(..total_elems)
            .ok_or_else(|| LenMismatchError::new(num_elems))?;
        Ok(Uninit {
            storage,
            elems_per_item,
            len: num_elems,
        })
    }

    /// Initialize the array by calling the function `f` once for each entry.
    ///
    /// The first argument to `f`, `init`, references the already-initialized
    /// contents of the array; it's length indicates how many entries have been
    /// initialized previously, which is `i` for the `i`th item.
    ///
    /// The second argument to `f`, `uninit`, is the entry to initialize. `f`
    /// must return a reference to `uninit` after fully initializing it.
    pub fn init_fold<'r, Error: Into<LenMismatchError>>(
        self,
        mut f: impl for<'i, 'u> FnMut(
            &'i mut Array<'_, E>,
            slice::Uninit<'u, E>,
        ) -> Result<&'u mut [E], Error>,
    ) -> Result<Array<'r, E>, LenMismatchError>
    where
        Self: 'r,
        LenMismatchError: From<Error>,
    {
        for (init_len, mid) in (self.elems_per_item.get()..)
            .step_by(self.elems_per_item.get())
            .enumerate()
        {
            let Some(init_and_current) = self.storage.get_mut(..mid) else {
                break;
            };
            let (init, current) = init_and_current
                .split_at_mut_checked(mid - self.elems_per_item.get())
                .unwrap_or_else(|| unreachable!());
            let init = polyfill::slice::Uninit::from(init);
            let mut init = Array {
                storage: unsafe { init.assume_init() },
                len: init_len,
                elems_per_item: self.elems_per_item,
            };
            let _: &mut [E] =
                slice::Uninit::from(current).write_fully_with(|current| f(&mut init, current))?;
        }
        let init = polyfill::slice::Uninit::from(self.storage);
        Ok(Array {
            storage: unsafe { init.assume_init() },
            elems_per_item: self.elems_per_item,
            len: self.len,
        })
    }
}

pub struct Array<'e, E> {
    storage: &'e mut [E],
    elems_per_item: NonZeroUsize,
    len: usize,
}

impl<E> Array<'_, E> {
    pub fn len(&self) -> usize {
        assert_eq!(self.len, self.storage.len() / self.elems_per_item.get());
        self.len
    }

    pub fn last(&self) -> Option<&[E]> {
        let before = self.storage.len().checked_sub(self.elems_per_item.get())?;
        self.get_(before)
    }

    // `self.mid()` is equivalent to `self.get(self.len() / 2)`.
    //
    // Potentially this is easier to optimize since it avoids multiplication.
    pub fn mid(&self) -> Option<&[E]> {
        let adjust = if self.len % 2 == 0 {
            0
        } else {
            self.elems_per_item.get()
        };
        self.get_((self.storage.len() - adjust) / 2)
    }

    // Inline so that the compiler can do strength reduction on the
    // multiplication.
    #[inline(always)]
    pub fn get(&self, i: usize) -> Option<&[E]> {
        let before = i.checked_mul(self.elems_per_item.get())?;
        self.get_(before)
    }

    fn get_(&self, before: usize) -> Option<&[E]> {
        let after = before.checked_add(self.elems_per_item.get())?;
        self.storage.get(before..after)
    }

    pub fn as_flattened(&self) -> &[E] {
        self.storage
    }
}
