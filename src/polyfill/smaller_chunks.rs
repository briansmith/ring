#[allow(unused_imports)]
use crate::polyfill::prelude::*;

#[allow(dead_code)]
pub trait SmallerChunks<const N: usize> {
    type Elem;
    fn as_smaller_chunks(&self) -> &[[Self::Elem; N]];
}

impl<T> SmallerChunks<4> for [[T; 8]] {
    type Elem = T;
    #[inline(always)]
    fn as_smaller_chunks(&self) -> &[[Self::Elem; 4]] {
        let (chunks, _) = self.as_flattened().as_chunks::<4>();
        chunks
    }
}
