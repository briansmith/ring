use core::{mem::align_of, sync::atomic::AtomicU32};

pub trait AtomicPolyfills {
    type NonAtomic: Sized + Copy;

    #[allow(dead_code)]
    fn as_ptr(&self) -> *mut Self::NonAtomic;
}

impl AtomicPolyfills for AtomicU32 {
    type NonAtomic = u32;

    // TODO(MSRV-1.70): drop this in favor of `AtomicU32::as_ptr()`.
    #[inline(always)]
    fn as_ptr(&self) -> *mut Self::NonAtomic {
        // SAFETY: "This type has the same size and bit validity as
        // the underlying integer type, usize. However, the alignment of
        // this type is always equal to its size, even on targets where
        // usize has a lesser alignment."
        const _ALIGNMENT_COMPATIBLE: () = assert!(align_of::<AtomicU32>() % align_of::<u32>() == 0);
        super::ptr::from_ref(self)
            .cast::<Self::NonAtomic>()
            .cast_mut()
    }
}
