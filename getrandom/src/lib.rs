#![no_std]
mod error;

pub use error::Error;

use mc_sgx_types::{sgx_read_rand, sgx_status_t};

#[inline]
pub fn getrandom(dest: &mut [u8]) -> Result<(), Error> {
    use sgx_status_t::{SGX_ERROR_FEATURE_NOT_SUPPORTED, SGX_SUCCESS};

    let status = unsafe { sgx_read_rand(dest.as_mut_ptr(), dest.len()) };

    match status {
        SGX_SUCCESS => Ok(()),
        SGX_ERROR_FEATURE_NOT_SUPPORTED => Err(Error::UNSUPPORTED),
        _ => Err(Error::UNEXPECTED),
    }
}
