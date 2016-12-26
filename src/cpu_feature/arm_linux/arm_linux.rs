use std::collections::HashSet;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use std::fs::File;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use std::io::BufReader;
use std::string::{String, ToString};
// TODO represent unsigned long without libc
use c::ulong;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use self::auxv::AuxValError;
use self::auxv::AuxVals;
use self::cpuinfo::CpuInfo;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use self::cpuinfo::parse_cpuinfo;

// Bits exposed in HWCAP and HWCAP2
// See /usr/include/asm/hwcap.h on an ARM installation for the source of
// these values.
const ARM_HWCAP2_AES: ulong = 1 << 0;
const ARM_HWCAP2_PMULL: ulong = 1 << 1;
const ARM_HWCAP2_SHA1: ulong = 1 << 2;
const ARM_HWCAP2_SHA2: ulong = 1 << 3;

const ARM_HWCAP_NEON: ulong = 1 << 12;

// Constants used in GFp_armcap_P
// from include/openssl/arm_arch.h
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
const ARMV7_NEON: u32 = 1 << 0;
// not a typo; there is no constant for 1 << 1
const ARMV8_AES: u32 = 1 << 2;
const ARMV8_SHA1: u32 = 1 << 3;
const ARMV8_SHA256: u32 = 1 << 4;
const ARMV8_PMULL: u32 = 1 << 5;

extern "C" {
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
    #[allow(non_upper_case_globals)]
    pub static mut GFp_armcap_P: u32;
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
#[allow(non_snake_case)]
extern "C" fn GFp_cpuid_setup() {
    if let Ok(mut r) = File::open("/proc/cpuinfo").map(|f| BufReader::new(f)) {
        if let Ok(c) = parse_cpuinfo(&mut r) {
            // TODO handle failures to read from procfs auxv
            if let Ok(auxvals) = auxv::search_auxv(&Path::from("/proc/self/auxv"),
                       &[auxv::AT_HWCAP, auxv::AT_HWCAP2]) {
                let armcap = arm_cpuid_setup(&c, &auxvals);
                unsafe {
                    GFp_armcap_P |= armcap;
                }
            }
        }
    }
}

/// returns the GFp_armcap_P bitstring
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
#[allow(dead_code)] // TODO
fn arm_cpuid_setup(cpuinfo: &CpuInfo, procfs_auxv: &AuxVals) -> u32 {
    let mut hwcap: ulong = 0;

    // |getauxval| is not available on Android until API level 20. If it is
    // unavailable, read from /proc/self/auxv as a fallback. This is unreadable
    // on some versions of Android, so further fall back to /proc/cpuinfo.
    // See
    // https://android.googlesource.com/platform/ndk/+/882ac8f3392858991a0e1af33b4b7387ec856bd2
    // and b/13679666 (Google-internal) for details. */

    // TODO link to getauxval weakly and use that if available. In particular,
    // this is needed by the assumption in hwcap_from_cpuinfo that future architectures
    // will have a working getauxval.

    if let Some(v) = procfs_auxv.get(&auxv::AT_HWCAP) {
        hwcap = *v;
    } else {
        // fall back to cpuinfo
        if let Some(v) = hwcap_from_cpuinfo(&cpuinfo) {
            hwcap = v;
        }
    }

    // Clear NEON support if known broken
    if cpu_has_broken_neon(&cpuinfo) {
        hwcap &= !ARM_HWCAP_NEON;
    }

    // Matching OpenSSL, only report other features if NEON is present
    let mut armcap: u32 = 0;
    if hwcap & ARM_HWCAP_NEON > 0 {
        armcap |= ARMV7_NEON;

        // Some ARMv8 Android devices don't expose AT_HWCAP2. Fall back to
        // /proc/cpuinfo. See https://crbug.com/596156

        // TODO use getauxval if available for AT_HWCAP2

        let mut hwcap2: ulong = 0;
        if let Some(v) = procfs_auxv.get(&auxv::AT_HWCAP2) {
            hwcap2 = *v;
        } else {
            if let Some(v) = hwcap2_from_cpuinfo(&cpuinfo) {
                hwcap2 = v;
            }
            // otherwise, leave at 0
        }

        armcap |= armcap_for_hwcap2(hwcap2);
    }

    return armcap;
}


#[allow(dead_code)] // TODO
fn armcap_for_hwcap2(hwcap2: ulong) -> u32 {
    let mut ret: u32 = 0;
    if hwcap2 & ARM_HWCAP2_AES > 0 {
        ret |= ARMV8_AES;
    }
    if hwcap2 & ARM_HWCAP2_PMULL > 0 {
        ret |= ARMV8_PMULL;
    }
    if hwcap2 & ARM_HWCAP2_SHA1 > 0 {
        ret |= ARMV8_SHA1;
    }
    if hwcap2 & ARM_HWCAP2_SHA2 > 0 {
        ret |= ARMV8_SHA256;
    }

    return ret;
}

#[allow(dead_code)] // TODO
fn hwcap_from_cpuinfo(cpuinfo: &CpuInfo) -> Option<ulong> {
    if let Some(v) = cpuinfo.get("CPU architecture") {
        if v == "8" {
            // This is a 32-bit ARM binary running on a 64-bit kernel. NEON is
            // always available on ARMv8. Linux omits required features, so
            // reading the "Features" line does not work. (For simplicity,
            // use strict equality. We assume everything running on future
            // ARM architectures will have a working |getauxval|.)
            return Some(ARM_HWCAP_NEON);
        }
    }

    if let Some(v) = cpuinfo.get("Features") {
        if parse_arm_cpuinfo_features(v).contains("neon") {
            return Some(ARM_HWCAP_NEON);
        }
    }

    return None;
}

#[allow(dead_code)] // TODO
fn hwcap2_from_cpuinfo(cpuinfo: &CpuInfo) -> Option<ulong> {
    if let Some(v) = cpuinfo.get("Features") {
        let mut ret: ulong = 0;
        let features = parse_arm_cpuinfo_features(v);

        if features.contains("aes") {
            ret |= ARM_HWCAP2_AES;
        }
        if features.contains("pmull") {
            ret |= ARM_HWCAP2_PMULL;
        }
        if features.contains("sha1") {
            ret |= ARM_HWCAP2_SHA1;
        }
        if features.contains("sha2") {
            ret |= ARM_HWCAP2_SHA2;
        }

        return Some(ret);
    } else {
        return None;
    }
}

#[allow(dead_code)] // TODO
fn cpu_has_broken_neon(cpuinfo: &CpuInfo) -> bool {
    return cpuinfo.get("CPU implementer").map_or(false, |s| s == "0x51") &&
        cpuinfo.get("CPU architecture").map_or( false, |s| s == "7") &&
        cpuinfo.get("CPU variant").map_or(false, |s| s == "0x1") &&
        cpuinfo.get("CPU part").map_or(false, |s| s == "0x04d") &&
        cpuinfo.get("CPU revision").map_or(false, |s| s == "0")
}

#[allow(dead_code)] // TODO
fn parse_arm_cpuinfo_features(features_val: &str) -> HashSet<String> {
    return features_val.trim_right_matches(' ')
        .split(' ')
        .map(|s| s.to_string())
        .collect();
}

mod auxv;
mod cpuinfo;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{ARMV8_AES, ARMV8_PMULL, ARMV8_SHA1, ARMV8_SHA256,
        ARM_HWCAP2_AES, ARM_HWCAP2_PMULL, ARM_HWCAP2_SHA1, ARM_HWCAP2_SHA2};
    use super::cpuinfo::{parse_cpuinfo, CpuInfo, CpuInfoError};

    #[test]
    fn armcap_for_hwcap2_zero_returns_zero() {
        assert_eq!(0, super::armcap_for_hwcap2(0));
    }

    #[test]
    fn armcap_for_hwcap2_all_hwcap2_returns_all_armcap() {
        assert_eq!(ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256,
        super::armcap_for_hwcap2(
            ARM_HWCAP2_AES| ARM_HWCAP2_PMULL| ARM_HWCAP2_SHA1| ARM_HWCAP2_SHA2));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_8_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "8".to_string());

        assert_eq!(Some(super::ARM_HWCAP_NEON), super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_with_feature_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());
        let _ = cpuinfo.insert("Features".to_string(), "foo neon bar ".to_string());

        assert_eq!(Some(super::ARM_HWCAP_NEON), super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_without_feature_returns_none() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());

        assert_eq!(None, super::hwcap_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_missing_features_returns_none() {
        // x86 doesn't have "Features", it has "flags"
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo")).unwrap();

        assert_eq!(None, super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_sad_features_returns_zero() {
        // the broken cpu has weaksauce features
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        assert_eq!(Some(0), super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_fancy_features_returns_all() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("Features".to_string(), "quux aes pmull sha1 sha2 foo ".to_string());

        assert_eq!(Some(super::ARM_HWCAP2_AES
                | super::ARM_HWCAP2_PMULL
                | super::ARM_HWCAP2_SHA1
                | super::ARM_HWCAP2_SHA2),
            super::hwcap2_from_cpuinfo(&cpuinfo));
    }

    #[test]
    fn arm_broken_neon_cpuinfo_detects_broken_arm() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        assert!(super::cpu_has_broken_neon(&cpuinfo));
    }

    #[test]
    fn arm_broken_neon_cpuinfo_ignores_x86() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo")).unwrap();

        assert!(!super::cpu_has_broken_neon(&cpuinfo));
    }

    #[test]
    fn parse_arm_features_handles_trailing_space() {
        let set = super::parse_arm_cpuinfo_features("foo bar baz ");
        assert_eq!(3, set.len());
        assert!(set.contains("baz"));
    }

    fn parse_cpuinfo_file(path: &Path) -> Result<CpuInfo, CpuInfoError> {
        let mut buf = Vec::new();
        let mut f = File::open(path).unwrap();
        let _ = f.read_to_end(&mut buf).unwrap();

        let mut buffer = &buf[..];
        parse_cpuinfo(&mut buffer)
    }
}
