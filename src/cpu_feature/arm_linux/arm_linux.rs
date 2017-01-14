use self::auxv::Type;
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), target_os="linux"))]
use self::auxv::NativeProvider;
use self::auxv::{AT_HWCAP, AT_HWCAP2, Provider};

// See /usr/include/asm/hwcap.h on an ARM installation for the source of these values
const ARM_HWCAP2_AES: Type = 1 << 0;
const ARM_HWCAP2_PMULL: Type = 1 << 1;
const ARM_HWCAP2_SHA1: Type = 1 << 2;
const ARM_HWCAP2_SHA2: Type = 1 << 3;

const ARM_HWCAP_NEON: Type = 1 << 12;

// Constants used in GFp_armcap_P
// Keep in sync with include/openssl/arm_arch.h
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
pub fn arm_linux_set_cpu_features() {
    let getauxval = NativeProvider {};

    unsafe {
        GFp_armcap_P |= armcap_from_features(getauxval);
    }
}

/// returns a u32 with bits set for use in GFp_armcap_P
fn armcap_from_features<G: Provider> (getauxval: G) -> u32 {
    let hwcap = getauxval.getauxval(AT_HWCAP).unwrap_or(0);
    
    // Matching OpenSSL, only report other features if NEON is present.
    let mut armcap: u32 = 0;
    if hwcap & ARM_HWCAP_NEON != 0 {
        armcap |= ARMV7_NEON;

        let hwcap2 = getauxval.getauxval(AT_HWCAP2).unwrap_or(0);

        armcap |= armcap_for_hwcap2(hwcap2);
    }

    return armcap;
}

fn armcap_for_hwcap2(hwcap2: Type) -> u32 {
    let mut ret: u32 = 0;
    if hwcap2 & ARM_HWCAP2_AES != 0 {
        ret |= ARMV8_AES;
    }
    if hwcap2 & ARM_HWCAP2_PMULL != 0 {
        ret |= ARMV8_PMULL;
    }
    if hwcap2 & ARM_HWCAP2_SHA1 != 0 {
        ret |= ARMV8_SHA1;
    }
    if hwcap2 & ARM_HWCAP2_SHA2 != 0 {
        ret |= ARMV8_SHA256;
    }

    return ret;
}

mod auxv;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{armcap_from_features, ARMV7_NEON,
        ARMV8_AES, ARMV8_PMULL, ARMV8_SHA1, ARMV8_SHA256, ARM_HWCAP2_AES,
        ARM_HWCAP2_PMULL, ARM_HWCAP2_SHA1, ARM_HWCAP2_SHA2,
        ARM_HWCAP_NEON};
    use super::auxv::{Type, GetauxvalError,
        Provider, AT_HWCAP, AT_HWCAP2};

    struct StubGetauxval {
        auxv: HashMap<Type, Type>
    }

    impl Provider for StubGetauxval {
        fn getauxval(&self, auxv_type: Type)
                -> Result<Type, GetauxvalError> {
            self.auxv.get(&auxv_type).map(|v| *v).ok_or(GetauxvalError::NotFound)
        }
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_getauxv_yields_neon_armcap() {
        do_armcap_bits_test(hwcap_neon_getauxv(), ARMV7_NEON);
    }

    #[test]
    fn armcap_bits_arm_8_with_neon_only_getauxv_hwcap_and_all_getauxv_hwcap2_yields_all_features_armcap() {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(AT_HWCAP, ARM_HWCAP_NEON);
        let _ = auxv.insert(AT_HWCAP2, ARM_HWCAP2_AES | ARM_HWCAP2_PMULL | ARM_HWCAP2_SHA1 | ARM_HWCAP2_SHA2);
        let getauxv = StubGetauxval {
            auxv: auxv
        };

        do_armcap_bits_test(getauxv, ARMV7_NEON | ARMV8_AES | ARMV8_SHA1 | ARMV8_SHA256 | ARMV8_PMULL);
    }


    #[test]
    fn armcap_bits_arm_8_with_neon_only_getauxv_hwcap_and_aes_getauxv_hwcap2_yields_only_neon_aes_armcap() {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(AT_HWCAP, ARM_HWCAP_NEON);
        let _ = auxv.insert(AT_HWCAP2, ARM_HWCAP2_AES);
        let getauxv = StubGetauxval {
            auxv: auxv
        };

        do_armcap_bits_test(getauxv, ARMV7_NEON | ARMV8_AES);
    }

    #[test]
    fn armcap_for_hwcap2_all_hwcap2_returns_all_armcap() {
        assert_eq!(ARMV8_AES | ARMV8_PMULL | ARMV8_SHA1 | ARMV8_SHA256,
            super::armcap_for_hwcap2(ARM_HWCAP2_AES
                                        | ARM_HWCAP2_PMULL
                                        | ARM_HWCAP2_SHA1
                                        | ARM_HWCAP2_SHA2));
    }

    fn do_armcap_bits_test(getauxval: StubGetauxval,
                           expected_armcap: u32) {
        assert_eq!(expected_armcap,
            armcap_from_features::<StubGetauxval>(getauxval));
    }

    fn hwcap_neon_getauxv() -> StubGetauxval {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(AT_HWCAP,
                            ARM_HWCAP_NEON);

        StubGetauxval {
            auxv: auxv
        }
    }
}
