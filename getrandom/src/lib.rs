#![no_std]
use sgx_trts::trts::rsgx_read_rand;
#[inline]
pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    // SAFETY: The `&mut MaybeUninit<_>` reference doesn't escape, and
    // `getrandom_uninit` guarantees it will never de-initialize any part of
    // `dest`.
    // getrandom_uninit(unsafe { slice_as_uninit_mut(dest) })?;
    rsgx_read_rand(dest).expect("getrandom::rsgx_read_rand failed!");
    Ok(())
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error();