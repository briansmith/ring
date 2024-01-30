// TODO: header

use core::mem::MaybeUninit;

// impl MaybeUninit<T> {
// ...
// #[unstable(feature = "maybe_uninit_slice", issue = "63569")]
// #[rustc_const_unstable(feature = "const_maybe_uninit_assume_init", issue = "none")]
// #[inline(always)]
#[allow(clippy::needless_lifetimes)]
pub unsafe fn slice_assume_init_mut<'s, T>(slice: &'s mut [MaybeUninit<T>]) -> &'s mut [T] {
    // SAFETY: casting `slice` to a `*mut [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // mut reference and thus guaranteed to be valid for writes.
    unsafe { &mut *(slice as *mut [MaybeUninit<T>] as *mut [T]) }
}
