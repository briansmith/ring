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

pub(crate) use super::{
    aliasing_slices::{AliasSrc, AliasingSlices, InOut},
    uninit_slice::{AliasedUninit, Uninit, WriteResult},
    uninit_slice_cursor::Cursor,
};

#[allow(dead_code)]
pub(crate) trait SlicePolyfills {
    type Elem;

    // TODO(MSRV-1.88): Use `slice::as_chunks`.
    fn as_chunks<const N: usize>(&self) -> (&[[Self::Elem; N]], &[Self::Elem]);

    // TODO(MSRV-1.88): Use `slice::as_chunks_mut`.
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]);
}

impl<T> SlicePolyfills for [T] {
    type Elem = T;

    #[inline]
    fn as_chunks<const N: usize>(&self) -> (&[[Self::Elem; N]], &[Self::Elem]) {
        const { assert!(N != 0) };
        let len = self.len();
        let remainder_len = len % N;
        let (chunks, remainder) = self.split_at(len - remainder_len);
        let chunks = <*const Self::Elem>::cast::<[Self::Elem; N]>(chunks.as_ptr());
        let chunks = unsafe { core::slice::from_raw_parts(chunks, len / N) };
        (chunks, remainder)
    }

    #[inline]
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]) {
        const { assert!(N != 0) };
        let len = self.len();
        let remainder_len = len % N;
        let (chunks, remainder) = self.split_at_mut(len - remainder_len);
        let chunks = <*mut Self::Elem>::cast::<[Self::Elem; N]>(chunks.as_mut_ptr());
        let chunks = unsafe { core::slice::from_raw_parts_mut(chunks, len / N) };
        (chunks, remainder)
    }
}
