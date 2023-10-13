/// Allows splitting a reference to an array type into fixed-length chunks.
pub trait ChunksFixed<'a, Chunks>
where
    Chunks: 'a,
{
    fn chunks_fixed(self) -> Chunks;
}

/// `$unchuncked_len` must be divisible by `$chunk_len`.
macro_rules! define_chunks_fixed {
    ( $unchuncked_len:expr, $chunk_len:expr ) => {
        define_chunks_fixed!($unchuncked_len, $chunk_len, $unchuncked_len / $chunk_len);
    };

    ( $unchuncked_len:expr, $chunk_len:expr, $chunked_len:expr ) => {
        impl<'a, T> ChunksFixed<'a, &'a [[T; $chunk_len]; $chunked_len]>
            for &'a [T; $unchuncked_len]
        {
            #[inline(always)]
            fn chunks_fixed(self) -> &'a [[T; $chunk_len]; $chunked_len] {
                let as_ptr: *const [T; $chunk_len] = self.as_ptr() as *const [T; $chunk_len];
                let as_ptr = as_ptr as *const [[T; $chunk_len]; $chunked_len];
                unsafe { &*as_ptr }
            }
        }
    };
}

// Sorted by the first value, then the second value.
define_chunks_fixed!(64, 32);
define_chunks_fixed!(80, 20);
