#[cfg(any(all(target_pointer_width = "32", test),
    all(target_pointer_width = "32", target_os = "linux")))]
pub type AuxvUnsignedLong = u32;
#[cfg(any(all(target_pointer_width = "64", test),
    all(target_pointer_width = "64", target_os = "linux")))]
pub type AuxvUnsignedLong = u64;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, sets success to false and returns 0.
    #[cfg(target_os="linux")]
    pub fn getauxval_wrapper(auxv_type: AuxvUnsignedLong,
                             success: *mut AuxvUnsignedLong) -> i32;
}

#[derive(Debug, PartialEq)]
pub enum GetauxvalError {
    /// getauxval() is not available at runtime
    #[cfg(target_os="linux")]
    FunctionNotAvailable,
    /// getauxval() could not find the requested type
    NotFound,
    /// getauxval() encountered a different error
    #[cfg(target_os="linux")]
    UnknownError
}

pub trait GetauxvalProvider {
    /// Look up an entry in the auxiliary vector. See getauxval(3) in glibc.
    /// Unfortunately, prior to glibc 2.19, getauxval() returns 0 without
    /// setting `errno` if the type is not found, so on such old systems
    /// this will return `Ok(0)` rather than `Err(GetauxvalError::NotFound)`.
    fn getauxval(&self, auxv_type: AuxvUnsignedLong)
        -> Result<AuxvUnsignedLong, GetauxvalError>;
}

#[cfg(target_os="linux")]
pub struct NativeGetauxvalProvider {}

#[cfg(target_os="linux")]
impl GetauxvalProvider for NativeGetauxvalProvider {
    /// Returns Some if the native invocation succeeds and the requested type was
    /// found, otherwise None.
    fn getauxval(&self, auxv_type: AuxvUnsignedLong)
            -> Result<AuxvUnsignedLong, GetauxvalError> {

        let mut result = 0;
        unsafe {
            return match getauxval_wrapper(auxv_type, &mut result) {
                1 => Ok(result),
                0 => Err(GetauxvalError::NotFound),
                -1 => Err(GetauxvalError::FunctionNotAvailable),
                -2 => Err(GetauxvalError::UnknownError),
                x => panic!("getauxval_wrapper returned an unexpected value: {}", x)
            }
        }
    }
}

// from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP
// even on platforms where unsigned long is 64 bits.
pub const AT_HWCAP: AuxvUnsignedLong = 16;
// currently only used by powerpc and arm64 AFAICT
pub const AT_HWCAP2: AuxvUnsignedLong = 26;

#[cfg(test)]
mod tests {
    #[cfg(target_os="linux")]
    use super::{AT_HWCAP, GetauxvalError, GetauxvalProvider,
        NativeGetauxvalProvider};

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_finds_hwcap() {
        let native_getauxval = NativeGetauxvalProvider{};
        let result = native_getauxval.getauxval(AT_HWCAP);
        // there should be SOMETHING in the value
        assert!(result.unwrap() > 0);
    }

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_doesnt_find_bogus_type() {
        let native_getauxval = NativeGetauxvalProvider{};

        // AT_NULL aka 0 is effectively the EOF for auxv, so it's never a valid type
        assert_eq!(GetauxvalError::NotFound, native_getauxval.getauxval(0).unwrap_err());
    }

}
