extern crate byteorder;
extern crate libc;

use std;
use std::collections::HashMap;
use std::string::{String, ToString};
use std::io::BufRead;
use std::vec::Vec;
use self::byteorder::{NativeEndian, ReadBytesExt};
// TODO represent unsigned long without libc
use self::libc::c_ulong;

#[derive(Debug, PartialEq)]
enum AuxvalError {
    IoError,
    InvalidFormat,
    NotFound
}

/// Read an entry from the aux vector.
///
/// input: pairs of unsigned longs, as in /proc/self/auxv. The first of each
/// pair is the 'type' and the second is the 'value'.
///
/// aux_type: the type to look for
/// returns the value found for the given type, or an error
#[allow(dead_code)] // TODO
fn search_auxv(input: &mut BufRead, aux_type: c_ulong) ->
        Result<c_ulong, AuxvalError> {
    let size_len = std::mem::size_of::<c_ulong>();
    let mut buf: Vec<u8> = Vec::with_capacity(2 * size_len); // two ulongs


    loop {
        buf.clear();
        for _ in 0 .. 2 * size_len {
            buf.push(0);
        }

        let mut read_bytes = 0;
        while read_bytes < 2 * size_len {
            // read exactly buf's len of bytes.
            match input.read(&mut buf[read_bytes..]) {
                Ok(n) => {
                    if n == 0 {
                        // should not hit EOF before AT_NULL
                        return Err(AuxvalError::InvalidFormat)
                    }

                    read_bytes += n;
                }
                Err(_) => return Err(AuxvalError::IoError)
            }
        }

        let mut reader = &buf[..];
        let found_aux_type = reader.read_u64::<NativeEndian>()
            .map_err(|_| AuxvalError::InvalidFormat)?;
        let aux_val = reader.read_u64::<NativeEndian>()
            .map_err(|_| AuxvalError::InvalidFormat)?;

        if found_aux_type == aux_type {
            return Ok(aux_val);
        }

         // AT_NULL (0) signals the end of auxv
        if found_aux_type == 0 {
            return Err(AuxvalError::NotFound);
        }
    }
}

#[derive(Debug, PartialEq)]
enum CpuInfoError {
    IoError,
    InvalidFormat
}

/// parse the contents of /proc/cpuinfo into a map of field names to values.
/// Only uses the first core, assuming all are the same.
#[allow(dead_code)] // TODO
fn parse_cpuinfo(input: &mut BufRead)
        -> Result<HashMap<String,String>, CpuInfoError> {
    // cpu flags can be quite long
    let mut line_buf = String::with_capacity(300);
    let mut fields = HashMap::new();

    loop {
        line_buf.clear();

        let bytes_read = input.read_line(&mut line_buf)
            .map_err(|_| CpuInfoError::IoError)?;
        let trimmed_line = line_buf.trim_right_matches('\n');
        if trimmed_line.is_empty() || bytes_read == 1 {
            // empty line is the per-core delimiter; we just look at the first
            // core.. Or, if there is only 1, we will hit EOF after last newline
            // without a separate blank line.
            return Ok(fields);
        }

        let mut chunks = trimmed_line.splitn(2, ":");
        let name = chunks.next().ok_or(CpuInfoError::InvalidFormat)?
            .trim_right_matches('\t')
            .to_string();
        let value = chunks.next().ok_or(CpuInfoError::InvalidFormat)?
            .trim_left_matches(' ')
            .to_string();

        let _ = fields.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Read;
    use std::fs::File;
    use std::path::Path;
    use std::string::String;
    use std::vec::Vec;
    use super::AuxvalError;
    use super::CpuInfoError;
    use super::libc::c_ulong;

    // from [linux]/include/uapi/linux/auxvec.h. First 32 bits of HWCAP bits.
    const AT_HWCAP: c_ulong = 16;
    // currently only used by powerpc and arm64 AFAICT, so not found on x86
    const AT_HWCAP2: c_ulong = 26;
    // uid of program that read /proc/self/auxv
    const AT_UID: c_ulong = 11;

    // x86 hwcap bits from [linux]/arch/x86/include/asm/cpufeature.h
    const X86_FPU: u64 = 0 * 32 + 0;
    const X86_ACPI: u64 = 0 * 32 + 22;

    #[test]
    fn test_parse_auxval_virtualbox_linux() {
        let path = Path::new("src/cpu-feature-test-data/macos-virtualbox-linux-x64-4850HQ.auxv");
        let hwcap = search_auxval_file(path, AT_HWCAP).unwrap();
        assert_eq!(395049983, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        // virtualized, no acpi via msr I guess
        assert_eq!(0, 1 << X86_ACPI & hwcap);

        assert_eq!(AuxvalError::NotFound,
            search_auxval_file(path, AT_HWCAP2).unwrap_err());

        assert_eq!(1000, search_auxval_file(path, AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxval_real_linux() {
        let path = Path::new("src/cpu-feature-test-data/linux-x64-i7-6850k.auxv");
        let hwcap = search_auxval_file(path, AT_HWCAP).unwrap();
        assert_eq!(3219913727, hwcap);

        assert_eq!(1, 1 << X86_FPU & hwcap);
        assert_eq!(1 << X86_ACPI, 1 << X86_ACPI & hwcap);

        assert_eq!(AuxvalError::NotFound,
            search_auxval_file(path, AT_HWCAP2).unwrap_err());

        assert_eq!(1000, search_auxval_file(path, AT_UID).unwrap());
    }

    #[test]
    fn test_parse_auxval_real_linux_half_of_trailing_null_missing_error() {
        let path = Path::new("src/cpu-feature-test-data/linux-x64-i7-6850k-mangled-no-value-in-trailing-null.auxv");
        assert_eq!(AuxvalError::InvalidFormat,
            search_auxval_file(path, 555555555).unwrap_err());
    }

    #[test]
    fn test_parse_auxval_real_linux_trailing_null_missing_error() {
        let path = Path::new("src/cpu-feature-test-data/linux-x64-i7-6850k-mangled-no-trailing-null.auxv");
        assert_eq!(AuxvalError::InvalidFormat,
            search_auxval_file(path, 555555555).unwrap_err());
    }

    #[test]
    fn test_parse_auxval_real_linux_truncated_entry_error() {
        let path = Path::new("src/cpu-feature-test-data/linux-x64-i7-6850k-mangled-truncated-entry.auxv");
        assert_eq!(AuxvalError::InvalidFormat,
            search_auxval_file(path, 555555555).unwrap_err());
    }

    #[test]
    fn test_parse_cpuinfo_virtualbox_linux() {
        let path = Path::new("src/cpu-feature-test-data/macos-virtualbox-linux-x64-4850HQ.cpuinfo");
        let cpuinfo = parse_cpuinfo_file(path).unwrap();

        // 1 tab
        assert_eq!("0", cpuinfo.get("processor").unwrap());
        // 2 tabs of spacing
        assert_eq!("70", cpuinfo.get("model").unwrap());
        // 0 tabs of spacing
        assert_eq!("", cpuinfo.get("power management").unwrap());
    }

    #[test]
    fn test_parse_cpuinfo_real_linux() {
        let path = Path::new("src/cpu-feature-test-data/linux-x64-i7-6850k.cpuinfo");
        let cpuinfo = parse_cpuinfo_file(path).unwrap();

        // 1 tab
        assert_eq!("0", cpuinfo.get("processor").unwrap());
        // 2 tabs of spacing
        assert_eq!("79", cpuinfo.get("model").unwrap());
        // 0 tabs of spacing
        assert_eq!("", cpuinfo.get("power management").unwrap());
    }

    #[test]
    fn test_parse_cpuinfo_no_colon_delimiter_error() {
        let mut input = "foobar\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo(&mut input);
        assert_eq!(CpuInfoError::InvalidFormat, cpuinfo.unwrap_err());
    }

    #[test]
    fn test_parse_cpuinfo_no_trailing_blank_line_ok() {
        // this is how it would be if there was only 1 core
        let mut input = "wp		: yes\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo(&mut input).unwrap();
        assert_eq!(1, cpuinfo.len());
    }

    #[test]
    fn test_parse_cpuinfo_empty_line_ok() {
        let mut input = "\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo(&mut input).unwrap();
        assert_eq!(0, cpuinfo.len());
    }

    #[test]
    fn test_parse_cpuinfo_empty_input_ok() {
        let mut input = "".as_bytes();
        let cpuinfo = super::parse_cpuinfo(&mut input).unwrap();
        assert_eq!(0, cpuinfo.len());
    }

    fn parse_cpuinfo_file(path: &Path)
            -> Result<HashMap<String,String>, CpuInfoError> {
        let mut buf = Vec::new();
        let mut f = File::open(path).unwrap();
        let _ = f.read_to_end(&mut buf).unwrap();

        let mut buffer = &buf[..];
        super::parse_cpuinfo(&mut buffer)
    }

    fn search_auxval_file(path: &Path, aux_type: u64) -> Result<u64, AuxvalError> {
        let mut buf = Vec::new();
        let mut f = File::open(path).unwrap();
        let _ = f.read_to_end(&mut buf).unwrap();

        let mut buffer = &buf[..];

        super::search_auxv(&mut buffer, aux_type)
    }
}
