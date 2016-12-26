use std::collections::HashMap;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use std::fs::File;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use std::io::BufReader;
use std::io::BufRead;
use std::string::{String, ToString};

#[derive(Debug, PartialEq)]
pub enum CpuInfoError {
    IoError,
    InvalidFormat
}

pub type CpuInfo = HashMap<String, String>;

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
pub fn parse_cpuinfo() -> Result<CpuInfo, CpuInfoError> {
    match File::open("/proc/cpuinfo").map(|f| BufReader::new(f)) {
        Ok(mut r) => parse_cpuinfo_reader(&mut r),
        Err(_) => Err(CpuInfoError::IoError)
    }
}

/// parse the contents of /proc/cpuinfo into a map of field names to values.
/// Keeps the first encountered value for each name.
#[cfg(any(test, target_os="linux"))]
pub fn parse_cpuinfo_reader(input: &mut BufRead) -> Result<CpuInfo, CpuInfoError> {
    // cpu flags can be quite long
    let mut line_buf = String::with_capacity(300);
    let mut fields = HashMap::new();

    loop {
        line_buf.clear();

        let bytes_read = input.read_line(&mut line_buf)
            .map_err(|_| CpuInfoError::IoError)?;
        if bytes_read == 0 {
            // eof
            return Ok(fields);
        }

        let trimmed_line = line_buf.trim_right_matches('\n');
        if trimmed_line.is_empty() {
            // skip blank lines
            continue;
        }

        let mut chunks = trimmed_line.splitn(2, ":");
        let name = chunks.next().ok_or(CpuInfoError::InvalidFormat)?
            .trim_right_matches('\t')
            .to_string();
        let value = chunks.next().ok_or(CpuInfoError::InvalidFormat)?
            .trim_left_matches(' ')
            .to_string();

        let _ = fields.entry(name).or_insert(value);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::fs::File;
    use std::path::Path;
    use std::vec::Vec;
    use super::{CpuInfo, CpuInfoError};

    #[test]
    fn test_parse_cpuinfo_virtualbox_linux() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/macos-virtualbox-linux-x64-4850HQ.cpuinfo");
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
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo");
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
        let cpuinfo = super::parse_cpuinfo_reader(&mut input);
        assert_eq!(CpuInfoError::InvalidFormat, cpuinfo.unwrap_err());
    }

    #[test]
    fn test_parse_cpuinfo_no_trailing_blank_line_ok() {
        // this is how it would be if there was only 1 core
        let mut input = "wp		: yes\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo_reader(&mut input).unwrap();
        assert_eq!(1, cpuinfo.len());
    }

    #[test]
    fn test_parse_cpuinfo_empty_line_ok() {
        let mut input = "\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo_reader(&mut input).unwrap();
        assert_eq!(0, cpuinfo.len());
    }

    #[test]
    fn test_parse_cpuinfo_empty_input_ok() {
        let mut input = "".as_bytes();
        let cpuinfo = super::parse_cpuinfo_reader(&mut input).unwrap();
        assert_eq!(0, cpuinfo.len());
    }

    #[test]
    fn test_parse_cpuinfo_skips_blank_line() {
        let mut input = "foo\t: bar\n\nbaz\t: quux\n".as_bytes();
        let cpuinfo = super::parse_cpuinfo_reader(&mut input).unwrap();
        assert_eq!(2, cpuinfo.len());
        assert_eq!("bar", cpuinfo.get("foo").unwrap());
        assert_eq!("quux", cpuinfo.get("baz").unwrap());
    }

    #[test]
    fn test_parse_cpuinfo_broken_arm() {
        let path = Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo");
        let cpuinfo = parse_cpuinfo_file(path).unwrap();

        // kept the first 'processor'
        assert_eq!("0", cpuinfo.get("processor").unwrap());
        // found things after several blank lines
        assert_eq!("0x51", cpuinfo.get("CPU implementer").unwrap());
    }

    fn parse_cpuinfo_file(path: &Path) -> Result<CpuInfo, CpuInfoError> {
        let mut buf = Vec::new();
        let mut f = File::open(path).unwrap();
        let _ = f.read_to_end(&mut buf).unwrap();

        let mut buffer = &buf[..];
        super::parse_cpuinfo_reader(&mut buffer)
    }
}
