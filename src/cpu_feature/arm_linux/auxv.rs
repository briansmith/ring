extern crate byteorder;

use std;
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;
use std::vec::Vec;

use self::byteorder::{NativeEndian, ReadBytesExt};
use c::ulong;

// from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP bits.
pub const AT_HWCAP: ulong = 16;
// currently only used by powerpc and arm64 AFAICT
pub const AT_HWCAP2: ulong = 26;

pub type AuxVals = HashMap<ulong, ulong>;

#[derive(Debug, PartialEq)]
pub enum AuxValError {
    IoError,
    InvalidFormat
}

/// Read an entry from the aux vector.
///
/// input: pairs of unsigned longs, as in /proc/self/auxv. The first of each
/// pair is the 'type' and the second is the 'value'.
///
/// aux_types: the types to look for
/// returns a map of types to values, only including entries for types that were
/// requested that also had values in the aux vector
#[allow(dead_code)] // TODO
pub fn search_auxv(path: &Path, aux_types: &[ulong]) ->
Result<AuxVals, AuxValError> {
    let mut input = File::open(path)
        .map_err(|_| AuxValError::IoError)
        .map(|f| BufReader::new(f))?;

    let ulong_size = std::mem::size_of::<ulong>();
    let mut buf: Vec<u8> = Vec::with_capacity(2 * ulong_size);
    let mut result = HashMap::<ulong, ulong>::new();

    loop {
        buf.clear();
        // fill vec so we can slice into it
        for _ in 0 .. 2 * ulong_size {
            buf.push(0);
        }

        let mut read_bytes = 0;
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
        // TODO determine length to read
        let found_aux_type = reader.read_u64::<NativeEndian>()
            .map_err(|_| AuxValError::InvalidFormat)?;
        let aux_val = reader.read_u64::<NativeEndian>()
            .map_err(|_| AuxValError::InvalidFormat)?;

        if aux_types.contains(&found_aux_type) {
            let _ = result.insert(found_aux_type, aux_val);
        }

        // AT_NULL (0) signals the end of auxv
        if found_aux_type == 0 {
            return Ok(result);
        }
    }
}


#[cfg(test)]
mod tests {
    use std::path::Path;
    use super::{AuxValError, AT_HWCAP, AT_HWCAP2, search_auxv};
    use c::ulong;

    // uid of program that read /proc/self/auxv
    const AT_UID: ulong = 11;

    // x86 hwcap bits from [linux]/arch/x86/include/asm/cpufeature.h
    const X86_FPU: u32 = 0 * 32 + 0;
    const X86_ACPI: u32 = 0 * 32 + 22;

    #[test]
    fn test_parse_auxv_virtualbox_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x64-4850HQ.auxv");
        let vals = search_auxv(path, &[AT_HWCAP, AT_HWCAP2, AT_UID]).unwrap();
        let hwcap = vals.get(&AT_HWCAP).unwrap();
        assert_eq!(&395049983_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        // virtualized, no acpi via msr I guess
        assert_eq!(0, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxv_real_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.auxv");
        let vals = search_auxv(path, &[AT_HWCAP, AT_HWCAP2, AT_UID]).unwrap();
        let hwcap = vals.get(&AT_HWCAP).unwrap();

        assert_eq!(&3219913727_u64, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        assert_eq!(1 << X86_ACPI, 1 << X86_ACPI & hwcap);

        assert!(!vals.contains_key(&AT_HWCAP2));

        assert_eq!(&1000_u64, vals.get(&AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxv_real_linux_half_of_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-value-in-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_auxv(path, &[555555555]).unwrap_err());
    }

    #[test]
    fn test_parse_auxv_real_linux_trailing_null_missing_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-no-trailing-null.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_auxv(path, &[555555555]).unwrap_err());
    }

    #[test]
    fn test_parse_auxv_real_linux_truncated_entry_error() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k-mangled-truncated-entry.auxv");
        assert_eq!(AuxValError::InvalidFormat,
            search_auxv(path, &[555555555]).unwrap_err());
    }
}
