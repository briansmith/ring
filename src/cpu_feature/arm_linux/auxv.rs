#[cfg(any(all(target_pointer_width = "32", test),
    all(target_pointer_width = "32", target_os = "linux")))]
pub type Type = u32;
#[cfg(any(all(target_pointer_width = "64", test),
    all(target_pointer_width = "64", target_os = "linux")))]
pub type Type = u64;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, sets success to false and returns 0.
    #[cfg(target_os="linux")]
    pub fn getauxval_wrapper(auxv_type: Type, success: *mut Type) -> i32;
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

pub trait Provider {
    /// Look up an entry in the auxiliary vector. See getauxval(3) in glibc.
    /// Unfortunately, prior to glibc 2.19, getauxval() returns 0 without
    /// setting `errno` if the type is not found, so on such old systems
    /// this will return `Ok(0)` rather than `Err(GetauxvalError::NotFound)`.
    fn getauxval(&self, auxv_type: Type) -> Result<Type, GetauxvalError>;
}

#[cfg(target_os="linux")]
pub struct NativeProvider {}

#[cfg(target_os="linux")]
impl Provider for NativeProvider {
    /// Returns Some if the native invocation succeeds and the requested type was
    /// found, otherwise None.
    fn getauxval(&self, auxv_type: Type)
            -> Result<Type, GetauxvalError> {

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
pub const AT_HWCAP: Type = 16;
// currently only used by powerpc and arm64 AFAICT
pub const AT_HWCAP2: Type = 26;
