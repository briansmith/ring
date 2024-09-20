#![no_std]
use mc_sgx_types::{sgx_read_rand, sgx_status_t};

#[inline]
pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    match unsafe { sgx_read_rand(dest.as_mut_ptr(), dest.len()) } {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(Error),
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error;
