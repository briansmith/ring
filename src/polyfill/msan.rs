/// Allocate an uninitialized buffer on the stack and then initialize it
/// with `f`, where `f` must be implemented in assembly language.
///
/// If the `msan` feature is enabled, the initialized buffer is unpoisoned
/// after `f` is called and before it is returned.
///
#[inline]
pub unsafe fn assume_init_asm<T>(f: impl FnOnce(&mut core::mem::MaybeUninit<T>)) -> T {
    assume_init_not_asm(|buffer| {
        f(buffer);

        #[cfg(feature = "msan")]
        {
            extern "C" {
                // `a` is `volatile`.
                fn __msan_unpoison(a: *const core::ffi::c_void, size: usize);
            }
            __msan_unpoison(
                buffer.as_ptr() as *const core::ffi::c_void,
                core::mem::size_of::<T>(),
            );
        }
    })
}

/// Allocate an uninitialized buffer on the stack and then initialize it
/// with `f`, where `f` is not implemented in assembly language.
#[inline]
pub unsafe fn assume_init_not_asm<T>(f: impl FnOnce(&mut core::mem::MaybeUninit<T>)) -> T {
    let mut buffer = core::mem::MaybeUninit::uninit();
    f(&mut buffer);
    buffer.assume_init()
}
