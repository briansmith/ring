use core::{mem::align_of, sync::atomic::AtomicUsize};

pub trait AtomicPolyfills {
    type NonAtomic: Sized + Copy;

    #[allow(dead_code)]
    fn as_ptr(&self) -> *mut Self::NonAtomic;
}

impl AtomicPolyfills for AtomicUsize {
    type NonAtomic = usize;

    #[inline(always)]
    fn as_ptr(&self) -> *mut Self::NonAtomic {
        // SAFETY: "This type has the same size and bit validity as
        // the underlying integer type, usize. However, the alignment of
        // this type is always equal to its size, even on targets where
        // usize has a lesser alignment."
        const _ALIGNMENT_COMPATIBLE: () =
            assert!(align_of::<AtomicUsize>() % align_of::<usize>() == 0);
        super::ptr::from_ref(self).cast_mut().cast::<usize>()
    }
}
