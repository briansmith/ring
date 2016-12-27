use std::collections::HashSet;
use std::string::{String, ToString};
use self::auxv::AuxvUnsignedLong;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use self::auxv::NativeGetauxvalProvider;
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux")))]
use self::auxv::{AuxVals, AuxvTypes, AuxvUnsignedLongNative, GetauxvalProvider};
use self::cpuinfo::CpuInfo;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use self::cpuinfo::parse_cpuinfo;

// Bits exposed in HWCAP and HWCAP2 auxv values
#[derive(Clone, Copy)]
#[allow(non_snake_case)]
struct ArmHwcapFeatures<T: AuxvUnsignedLong> {
    ARM_HWCAP2_AES: T,
    ARM_HWCAP2_PMULL: T,
    ARM_HWCAP2_SHA1: T,
    ARM_HWCAP2_SHA2: T,
    ARM_HWCAP_NEON: T,
}

impl <T: AuxvUnsignedLong> ArmHwcapFeatures<T> {
    fn new() -> ArmHwcapFeatures<T> {
        ArmHwcapFeatures {
            // See /usr/include/asm/hwcap.h on an ARM installation for the
            // source of these values.
            ARM_HWCAP2_AES: T::from(1 << 0),
            ARM_HWCAP2_PMULL: T::from(1 << 1),
            ARM_HWCAP2_SHA1: T::from(1 << 2),
            ARM_HWCAP2_SHA2: T::from(1 << 3),

            ARM_HWCAP_NEON: T::from(1 << 12),
        }
    }
}

// Constants used in GFp_armcap_P
// from include/openssl/arm_arch.h
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os="linux")))]
const ARMV7_NEON: u32 = 1 << 0;
// not a typo; there is no constant for 1 << 1
const ARMV8_AES: u32 = 1 << 2;
const ARMV8_SHA1: u32 = 1 << 3;
const ARMV8_SHA256: u32 = 1 << 4;
const ARMV8_PMULL: u32 = 1 << 5;

extern "C" {
    #[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
        target_os="linux"))]
    #[allow(non_upper_case_globals)]
    pub static mut GFp_armcap_P: u32;
}

#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os="linux"))]
#[allow(non_snake_case)]
extern "C" fn GFp_cpuid_setup() {
    let auxv_types: AuxvTypes<AuxvUnsignedLongNative> = AuxvTypes::new();
    let hwcap_features: ArmHwcapFeatures<AuxvUnsignedLongNative>
        = ArmHwcapFeatures::new();
    if let Ok(c) = parse_cpuinfo() {
        // TODO handle failures to read from procfs auxv
        if let Ok(auxvals) =
                auxv::search_auxv::<AuxvUnsignedLongNative, NativeEndian>(
                    &Path::from("/proc/self/auxv"),
                    &[auxv_types.AT_HWCAP, auxv_types.AT_HWCAP2]) {
            let armcap =
                armcap_bits::<NativeGetauxvalProvider>(&c, &auxvals, auxv_types,
                                                       hwcap_features);
            unsafe {
                GFp_armcap_P |= armcap;
            }
        }
    }
}

/// returns the GFp_armcap_P bitstring
#[cfg(any(test, all(any(target_arch = "arm", target_arch = "aarch64"),
    target_os="linux")))]
fn armcap_bits<G: GetauxvalProvider> (cpuinfo: &CpuInfo,
                                      procfs_auxv: &AuxVals<AuxvUnsignedLongNative>,
                                      auxval_types: AuxvTypes<AuxvUnsignedLongNative>,
                                      hwcap_features: ArmHwcapFeatures<AuxvUnsignedLongNative>,
                                      getauxval_provider: G)
        -> u32 {
    let mut hwcap = AuxvUnsignedLongNative::from(0_u32);

    // |getauxval| is not available on Android until API level 20. If it is
    // unavailable, read from /proc/self/auxv as a fallback. This is unreadable
    // on some versions of Android, so further fall back to /proc/cpuinfo.
    // See
    // https://android.googlesource.com/platform/ndk/+/882ac8f3392858991a0e1af33b4b7387ec856bd2
    // and b/13679666 (Google-internal) for details. */

    if let Some(v) = getauxval_provider.getauxval(auxval_types.AT_HWCAP) {
        hwcap = v;
    } else if let Some(v) = procfs_auxv.get(&auxval_types.AT_HWCAP) {
        hwcap = *v;
    } else if let Some(v) = hwcap_from_cpuinfo(&cpuinfo, hwcap_features) {
        hwcap = v;
    }

    // Clear NEON support if known broken
    if cpu_has_broken_neon(&cpuinfo) {
        hwcap &= !hwcap_features.ARM_HWCAP_NEON;
    }

    // Matching OpenSSL, only report other features if NEON is present
    let mut armcap: u32 = 0;
    if hwcap & hwcap_features.ARM_HWCAP_NEON > AuxvUnsignedLongNative::from(0_u32) {
        armcap |= ARMV7_NEON;

        // Some ARMv8 Android devices don't expose AT_HWCAP2. Fall back to
        // /proc/cpuinfo. See https://crbug.com/596156

        let mut hwcap2 = AuxvUnsignedLongNative::from(0_u32);
        if let Some(v) = getauxval_provider.getauxval(auxval_types.AT_HWCAP2) {
            hwcap2 = v;
        } else if let Some(v) = procfs_auxv.get(&auxval_types.AT_HWCAP2) {
            hwcap2 = *v;
        } else if let Some(v) = hwcap2_from_cpuinfo(&cpuinfo, hwcap_features) {
            hwcap2 = v;
        }

        armcap |= armcap_for_hwcap2(hwcap2, hwcap_features);
    }

    return armcap;
}

fn armcap_for_hwcap2<T: AuxvUnsignedLong>(hwcap2: T,
                                          hwcap_features: ArmHwcapFeatures<T>)
                                          -> u32 {
    let mut ret: u32 = 0;
    if hwcap2 & hwcap_features.ARM_HWCAP2_AES > T::from(0) {
        ret |= ARMV8_AES;
    }
    if hwcap2 & hwcap_features.ARM_HWCAP2_PMULL > T::from(0) {
        ret |= ARMV8_PMULL;
    }
    if hwcap2 & hwcap_features.ARM_HWCAP2_SHA1 > T::from(0) {
        ret |= ARMV8_SHA1;
    }
    if hwcap2 & hwcap_features.ARM_HWCAP2_SHA2 > T::from(0) {
        ret |= ARMV8_SHA256;
    }

    return ret;
}

fn hwcap_from_cpuinfo<T: AuxvUnsignedLong>(cpuinfo: &CpuInfo,
                                           hwcap_features: ArmHwcapFeatures<T>)
                                           -> Option<T> {
    if let Some(v) = cpuinfo.get("CPU architecture") {
        if v == "8" {
            // This is a 32-bit ARM binary running on a 64-bit kernel. NEON is
            // always available on ARMv8. Linux omits required features, so
            // reading the "Features" line does not work. (For simplicity,
            // use strict equality. We assume everything running on future
            // ARM architectures will have a working |getauxval|.)
            return Some(hwcap_features.ARM_HWCAP_NEON);
        }
    }

    if let Some(v) = cpuinfo.get("Features") {
        if parse_arm_cpuinfo_features(v).contains("neon") {
            return Some(hwcap_features.ARM_HWCAP_NEON);
        }
    }

    return None;
}

fn hwcap2_from_cpuinfo<T: AuxvUnsignedLong>(cpuinfo: &CpuInfo,
                                            hwcap_features: ArmHwcapFeatures<T>)
                                            -> Option<T> {
    if let Some(v) = cpuinfo.get("Features") {
        let mut ret: T = T::from(0);
        let features = parse_arm_cpuinfo_features(v);

        if features.contains("aes") {
            ret |= hwcap_features.ARM_HWCAP2_AES;
        }
        if features.contains("pmull") {
            ret |= hwcap_features.ARM_HWCAP2_PMULL;
        }
        if features.contains("sha1") {
            ret |= hwcap_features.ARM_HWCAP2_SHA1;
        }
        if features.contains("sha2") {
            ret |= hwcap_features.ARM_HWCAP2_SHA2;
        }

        return Some(ret);
    } else {
        return None;
    }
}

fn cpu_has_broken_neon(cpuinfo: &CpuInfo) -> bool {
    return cpuinfo.get("CPU implementer").map_or(false, |s| s == "0x51") &&
        cpuinfo.get("CPU architecture").map_or( false, |s| s == "7") &&
        cpuinfo.get("CPU variant").map_or(false, |s| s == "0x1") &&
        cpuinfo.get("CPU part").map_or(false, |s| s == "0x04d") &&
        cpuinfo.get("CPU revision").map_or(false, |s| s == "0")
}

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
    extern crate byteorder;

    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{armcap_bits, ArmHwcapFeatures, ARMV7_NEON, ARMV8_AES,
        ARMV8_PMULL, ARMV8_SHA1, ARMV8_SHA256};
    use super::cpuinfo::{parse_cpuinfo_reader, CpuInfo, CpuInfoError};
    use super::auxv::{AuxvTypes, AuxVals, AuxvUnsignedLongNative,
        GetauxvalProvider};

    struct StubGetauxvalProvider {
        auxv: AuxVals<AuxvUnsignedLongNative>
    }

    impl GetauxvalProvider for StubGetauxvalProvider {
        fn getauxval(&self, auxv_type: AuxvUnsignedLongNative)
                -> Option<AuxvUnsignedLongNative> {
            self.auxv.get(&auxv_type).map(|v| *v)
        }
    }

    #[test]
    fn armcap_bits_broken_neon_without_auxv_yields_zero_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(0,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_broken_neon_with_neon_getauxv_yields_zero_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        let getauxv = hwcap_neon_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(0,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_broken_neon_with_neon_procfs_yields_zero_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = hwcap_neon_procfs_auxv();

        assert_eq!(0,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_getauxv_yields_neon_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo")).unwrap();

        // we don't have an arm cpuinfo test file but we're testing an empty-auxv case anyway
        let getauxv = hwcap_neon_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(ARMV7_NEON,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_procfs_auxv_yields_neon_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo")).unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = hwcap_neon_procfs_auxv();

        assert_eq!(ARMV7_NEON,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_ok_neon_without_auxv_yields_neon_only_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-C1904.cpuinfo")).unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(ARMV7_NEON,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_without_auxv_yields_fully_populated_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo"))
                .unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                    | ARMV8_SHA256,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_getauxv_hwcap_yields_fully_populated_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo"))
            .unwrap();

        let getauxv = hwcap_neon_getauxv();
        let proc_auxv = empty_procfs_auxv();

        assert_eq!(ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                    | ARMV8_SHA256,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_procfs_auxv_hwcap_yields_fully_populated_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo"))
            .unwrap();

        let getauxv = not_found_getauxv();
        let proc_auxv = hwcap_neon_procfs_auxv();

        assert_eq!(ARMV7_NEON | ARMV8_PMULL | ARMV8_AES | ARMV8_SHA1
                    | ARMV8_SHA256,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_getauxv_hwcap_and_aes_getauxv_hwcap2_yields_only_neon_aes_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo"))
            .unwrap();

        let proc_auxv = empty_procfs_auxv();

        let mut auxv = AuxVals::new();
        let _ = auxv.insert(native_auxv_types().AT_HWCAP,
                            native_hwcap_features().ARM_HWCAP_NEON);
        let _ = auxv.insert(native_auxv_types().AT_HWCAP2,
                            native_hwcap_features().ARM_HWCAP2_AES);
        let getauxv = StubGetauxvalProvider {
            auxv: auxv
        };

        assert_eq!(ARMV7_NEON | ARMV8_AES,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_bits_arm_8_with_cpuinfo_features_with_neon_only_procfs_hwcap_and_pmull_procfs_hwcap2_yields_only_neon_aes_armcap() {
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-cavium-thunderx.cpuinfo"))
            .unwrap();

        let mut proc_auxv = AuxVals::new();
        let _ = proc_auxv.insert(native_auxv_types().AT_HWCAP,
                                 native_hwcap_features().ARM_HWCAP_NEON);
        let _ = proc_auxv.insert(native_auxv_types().AT_HWCAP2,
                                 native_hwcap_features().ARM_HWCAP2_PMULL);
        let getauxv = not_found_getauxv();

        assert_eq!(ARMV7_NEON | ARMV8_PMULL,
            armcap_bits::<StubGetauxvalProvider>(&cpuinfo, &proc_auxv,
                                                 native_auxv_types(),
                                                 native_hwcap_features(),
                                                 getauxv));
    }

    #[test]
    fn armcap_for_hwcap2_zero_returns_zero() {
        assert_eq!(0, super::armcap_for_hwcap2(0, test_hwcap_features()));
    }

    #[test]
    fn armcap_for_hwcap2_all_hwcap2_returns_all_armcap() {
        assert_eq!(ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256,
        super::armcap_for_hwcap2(test_hwcap_features().ARM_HWCAP2_AES
                                    | test_hwcap_features().ARM_HWCAP2_PMULL
                                    | test_hwcap_features().ARM_HWCAP2_SHA1
                                    | test_hwcap_features().ARM_HWCAP2_SHA2,
                                 test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_8_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "8".to_string());

        assert_eq!(Some(test_hwcap_features().ARM_HWCAP_NEON),
            super::hwcap_from_cpuinfo(&cpuinfo, test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_with_feature_returns_neon() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());
        let _ = cpuinfo.insert("Features".to_string(),
                               "foo neon bar ".to_string());

        assert_eq!(Some(test_hwcap_features().ARM_HWCAP_NEON),
            super::hwcap_from_cpuinfo(&cpuinfo, test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap_cpuinfo_arch_7_without_feature_returns_none() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("CPU architecture".to_string(), "7".to_string());

        assert_eq!(None, super::hwcap_from_cpuinfo(&cpuinfo,
                                                   test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_missing_features_returns_none() {
        // x86 doesn't have "Features", it has "flags"
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-x64-i7-6850k.cpuinfo")).unwrap();

        assert_eq!(None, super::hwcap2_from_cpuinfo(&cpuinfo,
                                                    test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_sad_features_returns_zero() {
        // the broken cpu has weaksauce features
        let cpuinfo = parse_cpuinfo_file(
            Path::new("src/cpu_feature/arm_linux/test-data/linux-arm-broken.cpuinfo")).unwrap();

        assert_eq!(Some(0), super::hwcap2_from_cpuinfo(&cpuinfo,
                                                       test_hwcap_features()));
    }

    #[test]
    fn arm_hwcap2_cpuinfo_fancy_features_returns_all() {
        let mut cpuinfo = HashMap::<String, String>::new();
        let _ = cpuinfo.insert("Features".to_string(),
                               "quux aes pmull sha1 sha2 foo ".to_string());

        assert_eq!(Some(test_hwcap_features().ARM_HWCAP2_AES
                | test_hwcap_features().ARM_HWCAP2_PMULL
                | test_hwcap_features().ARM_HWCAP2_SHA1
                | test_hwcap_features().ARM_HWCAP2_SHA2),
            super::hwcap2_from_cpuinfo(&cpuinfo, test_hwcap_features()));
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
        parse_cpuinfo_reader(&mut buffer)
    }

    fn test_hwcap_features() -> ArmHwcapFeatures<u64> {
        ArmHwcapFeatures::new()
    }

    fn native_auxv_types() -> AuxvTypes<AuxvUnsignedLongNative> {
        AuxvTypes::new()
    }

    fn native_hwcap_features() -> ArmHwcapFeatures<AuxvUnsignedLongNative> {
        ArmHwcapFeatures::new()
    }

    fn empty_procfs_auxv() -> AuxVals<AuxvUnsignedLongNative> {
        AuxVals::new()
    }

    fn hwcap_neon_procfs_auxv() ->  AuxVals<AuxvUnsignedLongNative> {
        let mut proc_auxv = AuxVals::<AuxvUnsignedLongNative>::new();
        let _ = proc_auxv.insert(native_auxv_types().AT_HWCAP,
                                 native_hwcap_features().ARM_HWCAP_NEON);

        proc_auxv
    }

    fn not_found_getauxv() -> StubGetauxvalProvider {
        StubGetauxvalProvider { auxv: AuxVals::<AuxvUnsignedLongNative>::new() }
    }

    fn hwcap_neon_getauxv() -> StubGetauxvalProvider {
        let mut auxv = AuxVals::new();
        let _ = auxv.insert(native_auxv_types().AT_HWCAP,
                            native_hwcap_features().ARM_HWCAP_NEON);

        StubGetauxvalProvider {
            auxv: auxv
        }
    }
}
