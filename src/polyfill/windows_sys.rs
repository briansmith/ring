pub type DWORD = u32;
pub type BOOL = i32;

/// This Arm processor implements the Arm v8 extra cryptographic instructions (for example, AES, SHA1 and SHA2).
pub const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: DWORD = 30;

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    /// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent>
    fn IsProcessorFeaturePresent(processor_feature: DWORD) -> BOOL;
}
