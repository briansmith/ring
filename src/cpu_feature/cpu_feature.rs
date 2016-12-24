extern crate libc;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
use std::fs::File;
#[cfg(all(target_os = "linux", target_arch = "arm"))]
use std::io::BufReader;
// TODO represent unsigned long without libc
#[cfg(all(target_os = "linux", target_arch = "arm"))]
use self::libc::c_ulong;
#[cfg(all(target_os = "linux", target_arch = "arm"))]
use self::auxv::{AuxValError, AuxVals};
#[cfg(all(target_os = "linux", target_arch = "arm"))]
use self::cpuinfo::CpuInfo;
#[cfg(all(target_os = "linux", target_arch = "arm"))]
use self::arm::arm_cpuid_setup;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
static HAS_BROKEN_NEON: bool = false;

// TODO is this used in practice? Its C equivalent is the only user of the
// global, and the function name has no uses
#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[allow(non_snake_case)]
extern "C" fn GFp_has_broken_NEON() -> bool {
    return HAS_BROKEN_NEON;
}

extern "C" {
    #[cfg(all(target_os = "linux", target_arch = "arm"))]
    #[allow(non_upper_case_globals)]
    pub static mut GFp_armcap_P: u32;
}

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[allow(non_snake_case)]
extern "C" fn GFp_cpuid_setup() {
    if let Ok(r) = File::open("/proc/cpuinfo").map(|f| BufReader::new(f)) {
        if let Ok(c) = parse_cpuinfo(cpuinfo_reader) {
            // TODO handle failures to read from procfs auxv
            if let Ok(auxvals) = search_procfs_auxv(&[auxv::AT_HWCAP, auxv::AT_HWCAP2]) {
                let (armcap, broken_neon) = arm_cpuid_setup(&c, &auxvals);
                GFp_armcap_P |= armcap;
                HAS_BROKEN_NEON = broken_neon;
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[allow(dead_code)] // TODO
fn search_procfs_auxv(auxv_types: &[c_ulong]) -> Result<AuxVals, AuxValError> {
    let mut auxv = File::open("/proc/self/auxv")
        .map_err(|_| AuxValError::IoError)
        .map(|f| BufReader::new(f))?;

    auxv::search_auxv(&mut auxv, auxv_types)
}

mod auxv;
mod cpuinfo;
mod arm;
