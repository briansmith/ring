use super::{super::BoolMask, Word, WordOps};
use crate::polyfill;
use core::{arch::asm, mem};

impl WordOps for Word {
    fn from_u8(a: &u8) -> Self {
        let mut r: Self;
        unsafe {
            asm!(
                "ldrb {r:w}, [{a_ptr}]", // zero-extended to 32-bits, then 64-bits.
                a_ptr = in(reg) polyfill::ptr::from_ref(a),
                r = lateout(reg) r,
                options(nostack, readonly)
            );
        }
        r
    }

    fn is_zero(self) -> BoolMask {
        let r: u64;
        unsafe {
            asm!(
                "subs {r}, {a}, #1",
                "sbc  {r}, {r}, {r}", // r - r - carry = 0 - carry = -carry.
                a = in(reg) self,
                r = lateout(reg) r,
                options(nomem, nostack, pure)
            );
        }
        unsafe { mem::transmute::<u64, BoolMask>(r) }
    }
}
