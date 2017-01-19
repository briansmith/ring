use c;

pub type Type = c::unsigned_long;
pub type Value = c::unsigned_long;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, returns 0.
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "android")))]
    pub fn getauxval_wrapper(auxv_type: Type) -> Value;
}

pub trait Provider {
    /// Look up an entry in the auxiliary vector. See getauxval(3) in glibc.
    /// If the requested type is not found, 0 will be returned.
    fn getauxval(&self, auxv_type: Type) -> Value;
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android")))]
pub struct NativeProvider;

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "android")))]
impl Provider for NativeProvider {
    fn getauxval(&self, auxv_type: Type) -> Value {
        unsafe { getauxval_wrapper(auxv_type) }
    }
}

// From [linux]/include/uapi/linux/auxvec.h.
// Only the first 32 bits of HWCAP are set even on platforms
// where unsigned long is 64 bits so that the expressible features
// remain consistent between the two platforms.
pub const AT_HWCAP: Type = 16;
pub const AT_HWCAP2: Type = 26;
