use super::{super::BoolMask, Word, WordOps};
use core::{arch::asm, mem};

impl WordOps for Word {
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
