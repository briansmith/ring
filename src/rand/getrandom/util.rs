use core::mem::MaybeUninit;

/// Polyfill for `maybe_uninit_slice` feature's
/// `MaybeUninit::slice_assume_init_mut`. Every element of `slice` must have
/// been initialized.
#[inline(always)]
#[allow(unused_unsafe)] // TODO(MSRV 1.65): Remove this.
pub unsafe fn slice_assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    let ptr = ptr_from_mut::<[MaybeUninit<T>]>(slice) as *mut [T];
    // SAFETY: `MaybeUninit<T>` is guaranteed to be layout-compatible with `T`.
    unsafe { &mut *ptr }
}

/// View an mutable initialized array as potentially-uninitialized.
///
/// This is unsafe because it allows assigning uninitialized values into
/// `slice`, which would be undefined behavior.
#[inline(always)]
#[allow(unused_unsafe)] // TODO(MSRV 1.65): Remove this.
pub unsafe fn slice_as_uninit_mut<T>(slice: &mut [T]) -> &mut [MaybeUninit<T>] {
    let ptr = ptr_from_mut::<[T]>(slice) as *mut [MaybeUninit<T>];
    // SAFETY: `MaybeUninit<T>` is guaranteed to be layout-compatible with `T`.
    unsafe { &mut *ptr }
}

// TODO: MSRV(1.76.0): Replace with `core::ptr::from_mut`.
fn ptr_from_mut<T: ?Sized>(r: &mut T) -> *mut T {
    r
}
