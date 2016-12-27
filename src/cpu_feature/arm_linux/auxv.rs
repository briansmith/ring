extern crate byteorder;

use std;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;
use std::vec::Vec;
use std::ops::{BitAnd, BitAndAssign, BitOrAssign, Not};
use std::hash::Hash;

use self::byteorder::{ByteOrder, ReadBytesExt};

// /proc/self/auxv is defined to be pairs of `unsigned long`-width bits, and
// getauxval() also is defined to take an `unsigned long` param and return the same.
// Adding further complexity, we want to always run tests against auxv files that are
// from systems with 64-bit unsigned longs, so we can't just always use the native
// size.
pub trait AuxvUnsignedLong : BitAndAssign<Self> + BitAnd<Self, Output=Self>
        + BitOrAssign<Self> + Not<Output=Self> + Eq + Ord + Hash + Sized + Copy
        + From<u32> {
    fn read<B: ByteOrder>(&mut Read) -> std::io::Result<Self>;
}

impl AuxvUnsignedLong for u32 {
    fn read<B: ByteOrder> (reader: &mut Read) -> std::io::Result<u32>{
        reader.read_u32::<B>()
    }
}

impl AuxvUnsignedLong for u64 {
    fn read<B: ByteOrder> (reader: &mut Read) -> std::io::Result<u64>{
        reader.read_u64::<B>()
    }
}

#[cfg(any(all(target_pointer_width = "32", test),
    all(target_pointer_width = "32", target_os = "linux")))]
pub type AuxvUnsignedLongNative = u32;
#[cfg(any(all(target_pointer_width = "64", test),
    all(target_pointer_width = "64", target_os = "linux")))]
pub type AuxvUnsignedLongNative = u64;

extern "C" {
    /// Invoke getauxval(3) if available. If it's not linked, or if invocation
    /// fails or the type is not found, sets success to false and returns 0.
    #[cfg(target_os="linux")]
    pub fn getauxval_wrapper(auxv_type: AuxvUnsignedLongNative,
                             success: *mut u8)
         -> AuxvUnsignedLongNative;
}

pub trait GetauxvalProvider {
    fn getauxval(&self, auxv_type: AuxvUnsignedLongNative)
        -> Option<AuxvUnsignedLongNative>;
}

#[cfg(target_os="linux")]
pub struct NativeGetauxvalProvider {}

#[cfg(target_os="linux")]
impl GetauxvalProvider for NativeGetauxvalProvider {
    /// Returns Some if the native invocation succeeds and the requested type was
    /// found, otherwise None.
    fn getauxval(&self, auxv_type: AuxvUnsignedLongNative)
            -> Option<AuxvUnsignedLongNative> {
        let mut success = 0;
        unsafe {
            let result = getauxval_wrapper(auxv_type, &mut success);
            if success == 1 {
                return Some(result);
            }
        }

        None
    }
}

/// auxv "types": the argument to getauxv, or the first of each pair in
/// /proc/self/auxv.
/// This structure allows us to bind these constants in a way that allows
/// 64-bit testing on all platforms but also can express the native
/// underlying type.
/// Don't modify the fields; they're meant to be read only.
#[allow(non_snake_case, non_camel_case_types)]
pub struct AuxvTypes<T: AuxvUnsignedLong> {
    pub AT_HWCAP: T,
    pub AT_HWCAP2: T
}

impl <T: AuxvUnsignedLong> AuxvTypes<T> {
    pub fn new() -> AuxvTypes<T> {
        AuxvTypes {
            // from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP
            // even on platforms where unsigned long is 64 bits.
            AT_HWCAP: T::from(16),
            // currently only used by powerpc and arm64 AFAICT
            AT_HWCAP2: T::from(26)
        }
    }
}

pub type AuxVals<T> = HashMap<T, T>;

#[derive(Debug, PartialEq)]
pub enum AuxValError {
    IoError,
    InvalidFormat
}

/// Read an entry from the procfs auxv file.
///
/// input: pairs of unsigned longs, as in /proc/self/auxv. The first of each
/// pair is the 'type' and the second is the 'value'.
///
/// aux_types: the types to look for
/// returns a map of types to values, only including entries for types that were
/// requested that also had values in the aux vector
pub fn search_procfs_auxv<T: AuxvUnsignedLong, B: ByteOrder>(path: &Path,
                                                             aux_types: &[T])
        -> Result<AuxVals<T>, AuxValError> {
    let mut input = File::open(path)
        .map_err(|_| AuxValError::IoError)
        .map(|f| BufReader::new(f))?;

    let ulong_size = std::mem::size_of::<T>();
    let mut buf: Vec<u8> = Vec::with_capacity(2 * ulong_size);
    let mut result = HashMap::<T, T>::new();

    loop {
        buf.clear();
        // fill vec so we can slice into it
        for _ in 0 .. 2 * ulong_size {
            buf.push(0);
        }

        let mut read_bytes: usize = 0;
        while read_bytes < 2 * ulong_size {
            // read exactly buf's len of bytes.
            match input.read(&mut buf[read_bytes..]) {
                Ok(n) => {
                    if n == 0 {
                        // should not hit EOF before AT_NULL
                        return Err(AuxValError::InvalidFormat)
                    }

                    read_bytes += n;
                }
                Err(_) => return Err(AuxValError::IoError)
            }
        }

        let mut reader = &buf[..];
        let found_aux_type = T::read::<B>(&mut reader)
            .map_err(|_| AuxValError::InvalidFormat)?;
        let aux_val = T::read::<B>(&mut reader)
            .map_err(|_| AuxValError::InvalidFormat)?;

        if aux_types.contains(&found_aux_type) {
            let _ = result.insert(found_aux_type, aux_val);
        }

        // AT_NULL (0) signals the end of auxv
        if found_aux_type == T::from(0) {
            return Ok(result);
        }
    }
}


#[cfg(test)]
mod tests {
    extern crate byteorder;

    use std::path::Path;
    use super::{AuxValError, AuxvTypes, search_procfs_auxv};
    #[cfg(target_os="linux")]
    use super::{AuxvUnsignedLongNative, GetauxvalProvider,
        NativeGetauxvalProvider};

    use self::byteorder::LittleEndian;

    // uid of program that read /proc/self/auxv
    const AT_UID: u64 = 11;

    // x86 hwcap bits from [linux]/arch/x86/include/asm/cpufeature.h
    const X86_FPU: u32 = 0 * 32 + 0;
    const X86_ACPI: u32 = 0 * 32 + 22;

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_finds_hwcap() {
        let native_getauxval = NativeGetauxvalProvider{};
        let result = native_getauxval.getauxval(AuxvTypes::new().AT_HWCAP);
        assert!(result.is_some());
        // there should be SOMETHING in the value
        assert!(result.unwrap() > 0);
    }

    #[test]
    #[cfg(target_os="linux")]
    fn test_getauxv_hwcap_linux_doesnt_find_bogus_type() {
        let native_getauxval = NativeGetauxvalProvider{};

        assert!(native_getauxval.getauxval(
            AuxvUnsignedLongNative::from(555555555_u32)).is_none());
    }

    #[test]
    fn test_parse_auxv_virtualbox_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x64-4850HQ.auxv");
        let vals = search_procfs_auxv::<u64, LittleEndian>(path,
                                                           &[test_auxv_types().AT_HWCAP,
                                                               test_auxv_types().AT_HWCAP2,
                                                               AT_UID])
            .unwrap();
        let hwcap = vals.get(&test_auxv_types().AT_HWCAP).unwrap();
        assert_eq!(&395049983_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        // virtualized, no acpi via msr I guess
        assert_eq!(0, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&test_auxv_types().AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxv_real_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.auxv");
        let vals = search_procfs_auxv::<u64, LittleEndian>(path,
                                                           &[test_auxv_types().AT_HWCAP,
                                                               test_auxv_types().AT_HWCAP2,
                                                               AT_UID])
            .unwrap();
        let hwcap = vals.get(&test_auxv_types().AT_HWCAP).unwrap();

        assert_eq!(&3219913727_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        assert_eq!(1 << X86_ACPI, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&test_auxv_types().AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxv_real_linux_half_of_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-value-in-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<u64, LittleEndian>(path,
                                                    &[555555555]).unwrap_err());
    }

    #[test]
    fn test_parse_auxv_real_linux_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<u64, LittleEndian>(path,
                                                    &[555555555]).unwrap_err());
    }

    #[test]
    fn test_parse_auxv_real_linux_truncated_entry_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-truncated-entry.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_procfs_auxv::<u64, LittleEndian>(path,
                                                    &[555555555]).unwrap_err());
    }

    fn test_auxv_types() -> AuxvTypes<u64> {
        AuxvTypes::new()
    }
}
