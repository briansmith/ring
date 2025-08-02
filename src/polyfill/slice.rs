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

use crate::polyfill::{StartMutPtr, StartPtr};

#[allow(dead_code)]
pub(crate) trait SlicePolyfills {
    type Elem;
    fn as_chunks<const N: usize>(&self) -> (&[[Self::Elem; N]], &[Self::Elem]);
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]);
    fn split_at_checked(&self, mid: usize) -> Option<(&[Self::Elem], &[Self::Elem])>;
    fn split_at_mut_checked(
        &mut self,
        mid: usize,
    ) -> Option<(&mut [Self::Elem], &mut [Self::Elem])>;
    fn split_first_chunk_mut<const N: usize>(
        &mut self,
    ) -> Option<(&mut [Self::Elem; N], &mut [Self::Elem])>;
}

impl<T> SlicePolyfills for [T] {
    type Elem = T;

    // TODO(MSRV-1.88): Use `slice::as_chunks`.
    #[inline]
    fn as_chunks<const N: usize>(&self) -> (&[[Self::Elem; N]], &[Self::Elem]) {
        assert!(N != 0);
        let len = self.len();
        let remainder_len = len % N;
        let (chunks, remainder) = self.split_at(len - remainder_len);
        let chunks = <*const Self::Elem>::cast::<[Self::Elem; N]>(chunks.as_ptr());
        let chunks = unsafe { core::slice::from_raw_parts(chunks, len / N) };
        (chunks, remainder)
    }

    // TODO(MSRV-1.88): Use `slice::as_chunks_mut`.
    #[inline]
    fn as_chunks_mut<const N: usize>(&mut self) -> (&mut [[Self::Elem; N]], &mut [Self::Elem]) {
        assert!(N != 0);
        let len = self.len();
        let remainder_len = len % N;
        let (chunks, remainder) = self.split_at_mut(len - remainder_len);
        let chunks = <*mut Self::Elem>::cast::<[Self::Elem; N]>(chunks.as_mut_ptr());
        let chunks = unsafe { core::slice::from_raw_parts_mut(chunks, len / N) };
        (chunks, remainder)
    }

    // Note that the libcore version is implemented in terms of
    // `slice::split_at_unchecked()`, and `slice::split_at()` was changed to be
    // implemented in terms of `split_at_checked`. For now, we implement this in
    // terms of `split_at` and rely on the optimizer to eliminate the panic.
    // TODO(MSRV-1.80): Use `slice::split_at_checked`.
    #[inline]
    fn split_at_checked(&self, mid: usize) -> Option<(&[Self::Elem], &[Self::Elem])> {
        if self.len() >= mid {
            Some(self.split_at(mid))
        } else {
            None
        }
    }

    // TODO(MSRV-1.80): Use `slice::split_at_checked`.
    #[inline]
    fn split_at_mut_checked(
        &mut self,
        mid: usize,
    ) -> Option<(&mut [Self::Elem], &mut [Self::Elem])> {
        if self.len() >= mid {
            Some(self.split_at_mut(mid))
        } else {
            None
        }
    }

    // TODO(MSRV-1.77): Use `slice::split_first_chunk_mut`.
    #[inline]
    fn split_first_chunk_mut<const N: usize>(
        &mut self,
    ) -> Option<(&mut [Self::Elem; N], &mut [Self::Elem])> {
        let (head, tail) = self.split_at_mut_checked(N)?;
        head.try_into().ok().map(|head| (head, tail))
    }
}

#[allow(dead_code)]
pub(crate) trait SliceOfArraysPolyfills: SlicePolyfills {
    type ElemElem;

    fn as_flattened(&self) -> &[Self::ElemElem];
    fn as_flattened_mut(&mut self) -> &mut [Self::ElemElem];
}

impl<T, const N: usize> SliceOfArraysPolyfills for [[T; N]] {
    type ElemElem = T;

    #[inline]
    fn as_flattened(&self) -> &[Self::ElemElem] {
        let total_len = self.len() * N;
        let p: *const Self::Elem = self.as_ptr();
        let p: *const Self::ElemElem = StartPtr::start_ptr(p);
        unsafe { core::slice::from_raw_parts(p, total_len) }
    }

    #[inline]
    fn as_flattened_mut(&mut self) -> &mut [Self::ElemElem] {
        let total_len = self.len() * N;
        let p: *mut Self::Elem = self.as_mut_ptr();
        let p: *mut Self::ElemElem = StartMutPtr::start_mut_ptr(p);
        unsafe { core::slice::from_raw_parts_mut(p, total_len) }
    }
}
