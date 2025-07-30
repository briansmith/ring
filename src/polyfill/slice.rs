// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

mod as_chunks;
mod as_chunks_mut;

pub use as_chunks::{as_chunks, AsChunks};
pub use as_chunks_mut::{as_chunks_mut, AsChunksMut};

#[allow(dead_code)]
pub trait SlicePolyfills<T> {
    fn split_at_checked(&self, mid: usize) -> Option<(&[T], &[T])>;
    fn split_at_mut_checked(&mut self, mid: usize) -> Option<(&mut [T], &mut [T])>;
    fn split_first_chunk_mut<const N: usize>(&mut self) -> Option<(&mut [T; N], &mut [T])>;
}

impl<T> SlicePolyfills<T> for [T] {
    //
    // Note that the libcore version is implemented in terms of
    // `slice::split_at_unchecked()`, and `slice::split_at()` was changed to be
    // implemented in terms of `split_at_checked`. For now, we implement this in
    // terms of `split_at` and rely on the optimizer to eliminate the panic.
    // TODO(MSRV-1.80): Use `slice::split_at_checked`.
    #[inline]
    fn split_at_checked(&self, mid: usize) -> Option<(&[T], &[T])> {
        if self.len() >= mid {
            Some(self.split_at(mid))
        } else {
            None
        }
    }

    // TODO(MSRV-1.80): Use `slice::split_at_checked`.
    #[inline]
    fn split_at_mut_checked(&mut self, mid: usize) -> Option<(&mut [T], &mut [T])> {
        if self.len() >= mid {
            Some(self.split_at_mut(mid))
        } else {
            None
        }
    }

    // TODO(MSRV-1.77): Use `slice::split_first_chunk_mut`.
    #[inline]
    fn split_first_chunk_mut<const N: usize>(&mut self) -> Option<(&mut [T; N], &mut [T])> {
        let (head, tail) = self.split_at_mut_checked(N)?;
        head.try_into().ok().map(|head| (head, tail))
    }
}
