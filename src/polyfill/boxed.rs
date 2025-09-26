use alloc::{boxed::Box, vec};
use core::mem::MaybeUninit;

// `E: Copy` to avoid having to deal with `Drop`.
#[allow(dead_code)]
pub(crate) trait BoxUninitPolyfills<E: Copy> {
    fn new_uninit_slice(len: usize) -> Self
    where
        E: Default;
    unsafe fn assume_init(self) -> Box<[E]>;
}

impl<E: Copy> BoxUninitPolyfills<E> for Box<[MaybeUninit<E>]> {
    fn new_uninit_slice(len: usize) -> Self
    where
        E: Default,
    {
        let r: Box<[E]> = vec![E::default(); len].into_boxed_slice();
        let r: *mut [E] = Box::into_raw(r);
        let r: *mut [MaybeUninit<E>] = r as *mut [MaybeUninit<E>]; // cast_uninit
        unsafe { Box::from_raw(r) }
    }

    unsafe fn assume_init(self) -> Box<[E]> {
        let r: Box<[MaybeUninit<E>]> = self;
        let r: *mut [MaybeUninit<E>] = Box::into_raw(r);
        let r: *mut [E] = r as *mut [E]; // cast_init
        unsafe { Box::from_raw(r) }
    }
}
