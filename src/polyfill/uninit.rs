use core::mem::MaybeUninit;

/// Like `&'target mut MaybeUninit<T>` without a non-`unsafe` way to write
/// `MaybeUninit::uninit()` into the value. This allows one to safely abstract
/// a function `f` across an output buffer `out` of types `&mut T` or
/// since the caller can now assume that `f` won't write `MaybeUninit::uninit()`
/// to `out`.
pub struct Uninit<'target, T> {
    target: &'target mut MaybeUninit<T>,
}

impl<'target, T> From<&'target mut T> for Uninit<'target, T> {
    fn from(target: &'target mut T) -> Self {
        let target: &'target mut T = target;
        let target: *mut MaybeUninit<T> = <*mut T>::cast::<MaybeUninit<T>>(target); // cast_uninit
        // SAFETY: We never write `MaybeUninit::uninit()` to `target` and never
        // expose it from a non-`unsafe` function.
        let target: &'target mut MaybeUninit<T> = unsafe { &mut *target };
        Self { target }
    }
}

impl<'target, T: Copy> Uninit<'target, T> {
    pub fn write(self, value: T) -> &'target mut T {
        self.target.write(value)
    }
}
