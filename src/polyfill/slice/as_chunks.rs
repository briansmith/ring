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

use super::AsChunksMut;
use core::ops;

#[inline(always)]
pub fn as_chunks<T, const N: usize>(slice: &[T]) -> (AsChunks<'_, T, N>, &[T]) {
    assert!(N != 0, "chunk size must be non-zero");
    let len = slice.len() / N;
    let (multiple_of_n, remainder) = slice.split_at(len * N);
    (AsChunks(multiple_of_n), remainder)
}

#[derive(Clone, Copy)]
pub struct AsChunks<'a, T, const N: usize>(&'a [T]);

impl<'a, T, const N: usize> AsChunks<'a, T, N> {
    #[inline(always)]
    pub fn from_ref(value: &'a [T; N]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn as_flattened(&self) -> &[T] {
        self.0
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const [T; N] {
        self.0.as_ptr().cast_array_::<N>()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len() / N
    }
}

impl<T, const N: usize> ops::Index<usize> for AsChunks<'_, T, N>
where
    [T]: ops::Index<ops::Range<usize>, Output = [T]>,
{
    type Output = [T; N];

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        let start = N * index;
        let slice = &self.0[start..(start + N)];
        slice.try_into().unwrap()
    }
}

impl<'a, T, const N: usize> IntoIterator for AsChunks<'a, T, N> {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = AsChunksIter<'a, T, N>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        AsChunksIter(self.0.chunks_exact(N))
    }
}

pub struct AsChunksIter<'a, T, const N: usize>(core::slice::ChunksExact<'a, T>);

impl<'a, T, const N: usize> Iterator for AsChunksIter<'a, T, N> {
    type Item = &'a [T; N];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| x.try_into().unwrap())
    }
}

// `&mut [[T; N]]` is implicitly convertible to `&[[T; N]]` but our types can't
// do that.
impl<'a, T, const N: usize> From<&'a AsChunksMut<'_, T, N>> for AsChunks<'a, T, N> {
    #[inline(always)]
    fn from(as_mut: &'a AsChunksMut<'_, T, N>) -> Self {
        Self(as_mut.as_flattened())
    }
}

impl<'a, T, const N: usize> From<&'a [T; N]> for AsChunks<'a, T, N> {
    #[inline(always)]
    fn from(array: &'a [T; N]) -> Self {
        Self(array)
    }
}

// TODO: `impl From<AsChunks<'a, T, {2*N}> for AsChunks<'a, T, N>`.
impl<'a, T> From<AsChunks<'a, T, 8>> for AsChunks<'a, T, 4> {
    #[inline(always)]
    fn from(as_2x: AsChunks<'a, T, 8>) -> Self {
        Self(as_2x.0)
    }
}
