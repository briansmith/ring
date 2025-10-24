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

use super::uninit_slice::{Uninit, WriteResult};
use core::mem;

pub struct Cursor<'buf, E> {
    uninit: Uninit<'buf, E>,
}

impl<'buf, E> Cursor<'buf, E> {
    pub fn write_iter<'s, Src: IntoIterator<Item = E>>(
        &'s mut self,
        src: Src,
    ) -> WriteResult<'buf, E, (), Src::IntoIter>
    where
        E: Copy,
    {
        // TODO: Deal with panics.
        let uninit = mem::replace(&mut self.uninit, Uninit::from([].as_mut_slice()));
        let (res, uninit) = uninit.write_iter(src).take_uninit();
        self.uninit = uninit;
        res
    }
}

impl<'buf, E> From<Uninit<'buf, E>> for Cursor<'buf, E> {
    fn from(uninit: Uninit<'buf, E>) -> Self {
        Self { uninit }
    }
}
