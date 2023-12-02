macro_rules! mul_mont {
    { $visibility:vis $name:ident(n0: $n0:expr; modulus: $modulus:expr) } => {
        $visibility unsafe extern "C" fn $name(
            r: *mut crate::limb::Limb,   // [COMMON_OPS.num_limbs]
            a: *const crate::limb::Limb, // [COMMON_OPS.num_limbs]
            b: *const crate::limb::Limb, // [COMMON_OPS.num_limbs]
        ) {
            use crate::arithmetic::montgomery::{bn_mul_mont, N0};
            static N_N0: N0 = N0::precalculated($n0);
            bn_mul_mont(
                r,
                a,
                b,
                $modulus.limbs.as_ptr(),
                &N_N0,
                COMMON_OPS.num_limbs,
            )
        }
    }
}
