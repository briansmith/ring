#[cfg(any(all(target_pointer_width = "32", test),
    all(target_pointer_width = "32", target_os = "linux")))]
pub type Type = u32;
#[cfg(any(all(target_pointer_width = "64", test),
    all(target_pointer_width = "64", target_os = "linux")))]
pub type Type = u64;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, returns 0.
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
        target_os = "linux"))]
    pub fn getauxval_wrapper(auxv_type: Type) -> Type;
}

pub trait Provider {
    /// Look up an entry in the auxiliary vector. See getauxval(3) in glibc.
    /// If the requested type is not found, 0 will be returned.
    fn getauxval(&self, auxv_type: Type) -> Type;
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os = "linux"))]
pub struct NativeProvider {}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os = "linux"))]
impl Provider for NativeProvider {
    fn getauxval(&self, auxv_type: Type) -> Type {
        unsafe {
            return getauxval_wrapper(auxv_type);
        }
    }
}

// from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP
// even on platforms where unsigned long is 64 bits.
pub const AT_HWCAP: Type = 16;
// currently only used by powerpc and arm64 AFAICT
pub const AT_HWCAP2: Type = 26;
