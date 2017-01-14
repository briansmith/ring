// See /usr/include/asm/hwcap.h on an ARM installation for the source of these values
const ARM_HWCAP2_AES: auxv::Type = 1 << 0;
const ARM_HWCAP2_PMULL: auxv::Type = 1 << 1;
const ARM_HWCAP2_SHA1: auxv::Type = 1 << 2;
const ARM_HWCAP2_SHA2: auxv::Type = 1 << 3;

const ARM_HWCAP_NEON: auxv::Type = 1 << 12;

// Constants used in GFp_armcap_P
// Keep in sync with include/openssl/arm_arch.h
const ARMV7_NEON: u32 = 1 << 0;
// not a typo; there is no constant for 1 << 1
const ARMV8_AES: u32 = 1 << 2;
const ARMV8_SHA1: u32 = 1 << 3;
const ARMV8_SHA256: u32 = 1 << 4;
const ARMV8_PMULL: u32 = 1 << 5;

/// returns a u32 with bits set for use in GFp_armcap_P
pub fn armcap_from_features<G: auxv::Provider> (getauxval: G) -> u32 {
    let hwcap = getauxval.getauxval(auxv::AT_HWCAP);
    
    // Matching OpenSSL, only report other features if NEON is present.
    let mut armcap: u32 = 0;
    if hwcap & ARM_HWCAP_NEON != 0 {
        armcap |= ARMV7_NEON;

        let hwcap2 = getauxval.getauxval(auxv::AT_HWCAP2);

        armcap |= armcap_for_hwcap2(hwcap2);
    }

    return armcap;
}

fn armcap_for_hwcap2(hwcap2: auxv::Type) -> u32 {
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
    use super::auxv;

    struct StubGetauxval {
        auxv: HashMap<auxv::Type, auxv::Type>
    }

    impl auxv::Provider for StubGetauxval {
        fn getauxval(&self, auxv_type: auxv::Type) -> auxv::Type {
            self.auxv.get(&auxv_type).map(|v| *v).unwrap_or(0)
        }
    }

    #[test]
    fn armcap_bits_ok_neon_with_neon_getauxv_yields_neon_armcap() {
        do_armcap_bits_test(hwcap_neon_getauxv(), ARMV7_NEON);
    }

    #[test]
    fn armcap_bits_arm_8_with_neon_only_getauxv_hwcap_and_all_getauxv_hwcap2_yields_all_features_armcap() {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(auxv::AT_HWCAP, ARM_HWCAP_NEON);
        let _ = auxv.insert(auxv::AT_HWCAP2, ARM_HWCAP2_AES | ARM_HWCAP2_PMULL | ARM_HWCAP2_SHA1 | ARM_HWCAP2_SHA2);
        let getauxv = StubGetauxval {
            auxv: auxv
        };

        do_armcap_bits_test(getauxv, ARMV7_NEON | ARMV8_AES | ARMV8_SHA1 | ARMV8_SHA256 | ARMV8_PMULL);
    }


    #[test]
    fn armcap_bits_arm_8_with_neon_only_getauxv_hwcap_and_aes_getauxv_hwcap2_yields_only_neon_aes_armcap() {
        let mut auxv = HashMap::new();
        let _ = auxv.insert(auxv::AT_HWCAP, ARM_HWCAP_NEON);
        let _ = auxv.insert(auxv::AT_HWCAP2, ARM_HWCAP2_AES);
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
        let _ = auxv.insert(auxv::AT_HWCAP,
                            ARM_HWCAP_NEON);

        StubGetauxval {
            auxv: auxv
        }
    }
}
