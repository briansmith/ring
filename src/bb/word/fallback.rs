use super::{super::BoolMask, Word, WordOps};

impl WordOps for Word {
    #[inline]
    fn is_zero(self) -> BoolMask {
        use crate::limb::{Limb, LimbMask}; // XXX: Backwards dependency.
        prefixed_extern! {
            fn LIMB_is_zero(limb: Limb) -> LimbMask;
        }
        unsafe { LIMB_is_zero(self) }
    }
}
