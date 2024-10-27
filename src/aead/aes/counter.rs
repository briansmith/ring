// Copyright 2018-2024 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    super::nonce::{Nonce, NONCE_LEN},
    ffi::Counter,
    Block, BLOCK_LEN,
};
use crate::polyfill::{nonzerousize_from_nonzerou32, unwrap_const};
use core::num::{NonZeroU32, NonZeroUsize};

// `Counter` is `ffi::Counter` as its representation is dictated by its use in
// the FFI.
impl Counter {
    pub fn one_two(nonce: Nonce) -> (Iv, Self) {
        let mut value = [0u8; BLOCK_LEN];
        value[..NONCE_LEN].copy_from_slice(nonce.as_ref());
        value[BLOCK_LEN - 1] = 1;
        let iv = Iv::new_less_safe(value);
        value[BLOCK_LEN - 1] = 2;
        (iv, Self(value))
    }

    pub fn try_into_iv(self) -> Result<Iv, CounterOverflowError> {
        let iv = Iv(self.0);
        let [.., c0, c1, c2, c3] = &self.0;
        let old_value: u32 = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        if old_value == 0 {
            return Err(CounterOverflowError::new());
        }
        Ok(iv)
    }

    pub fn increment_by(
        &mut self,
        increment_by: NonZeroUsize,
    ) -> Result<IvBlock, CounterOverflowError> {
        #[cold]
        #[inline(never)]
        fn overflowed(sum: u32) -> Result<u32, CounterOverflowError> {
            match sum {
                0 => Ok(0),
                _ => Err(CounterOverflowError::new()),
            }
        }

        let iv = Iv(self.0);

        let increment_by = match NonZeroU32::try_from(increment_by) {
            Ok(value) => value,
            _ => return Err(CounterOverflowError::new()),
        };

        let [.., c0, c1, c2, c3] = &mut self.0;
        let old_value: u32 = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        if old_value == 0 {
            return Err(CounterOverflowError::new());
        }
        let new_value = match old_value.overflowing_add(increment_by.get()) {
            (sum, false) => sum,
            (sum, true) => overflowed(sum)?,
        };
        [*c0, *c1, *c2, *c3] = u32::to_be_bytes(new_value);

        Ok(IvBlock {
            initial_iv: iv,
            len: increment_by,
        })
    }

    #[cfg(target_arch = "x86")]
    pub(super) fn increment_unchecked_less_safe(&mut self) -> Iv {
        let iv = Iv(self.0);

        let [.., c0, c1, c2, c3] = &mut self.0;
        let old_value: u32 = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        debug_assert_ne!(old_value, 0);
        // TODO: unchecked_add?
        let new_value = old_value.wrapping_add(1);
        // Note that it *is* valid for new_value to be zero!
        [*c0, *c1, *c2, *c3] = u32::to_be_bytes(new_value);

        iv
    }
}

pub(in super::super) struct CounterOverflowError(());

impl CounterOverflowError {
    #[cold]
    fn new() -> Self {
        Self(())
    }
}

pub(in super::super) struct IvBlock {
    initial_iv: Iv,
    // invariant: 0 < len && len <= u32::MAX
    len: NonZeroU32,
}

impl IvBlock {
    pub(super) fn from_iv(iv: Iv) -> Self {
        const _1: NonZeroU32 = unwrap_const(NonZeroU32::new(1));
        Self {
            initial_iv: iv,
            len: _1,
        }
    }

    // This conversion cannot fail.
    pub fn len(&self) -> NonZeroUsize {
        nonzerousize_from_nonzerou32(self.len)
    }

    // "Less safe" because this subverts the IV reuse prevention machinery. The
    // caller must ensure the IV is used only once.
    pub(super) fn into_initial_iv(self) -> Iv {
        self.initial_iv
    }

    #[cfg(any(target_arch = "arm", test))]
    pub(super) fn split_at(
        self,
        num_blocks: usize,
    ) -> Result<(Option<IvBlock>, Option<IvBlock>), super::InOutLenInconsistentWithIvBlockLenError>
    {
        use super::InOutLenInconsistentWithIvBlockLenError;
        let num_before = u32::try_from(num_blocks)
            .map_err(|_| InOutLenInconsistentWithIvBlockLenError::new())?;
        let num_after = self
            .len
            .get()
            .checked_sub(num_before)
            .ok_or_else(InOutLenInconsistentWithIvBlockLenError::new)?;

        let num_before = match NonZeroU32::new(num_before) {
            Some(num_blocks) => num_blocks,
            None => return Ok((None, Some(self))),
        };
        let num_after = match NonZeroU32::new(num_after) {
            Some(num_after) => num_after,
            None => return Ok((Some(self), None)),
        };
        let mut ctr = Counter(self.initial_iv.0);
        let before = ctr
            .increment_by(nonzerousize_from_nonzerou32(num_before))
            .map_err(|_: CounterOverflowError| InOutLenInconsistentWithIvBlockLenError::new())?;
        let after = Self {
            initial_iv: Iv::new_less_safe(ctr.0),
            len: num_after,
        };
        Ok((Some(before), Some(after)))
    }

    #[cfg(target_arch = "x86")]
    pub(super) fn into_counter_less_safe(
        self,
        input_blocks: usize,
    ) -> Result<Counter, super::InOutLenInconsistentWithIvBlockLenError> {
        if input_blocks != self.len().get() {
            return Err(super::InOutLenInconsistentWithIvBlockLenError::new());
        }
        Ok(Counter(self.initial_iv.0))
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub(in super::super) struct Iv(Block);

impl Iv {
    // This is "less safe" because it subverts the counter reuse protection.
    // The caller needs to ensure that the IV isn't reused.
    pub(super) fn new_less_safe(value: Block) -> Self {
        Self(value)
    }

    /// "Less safe" because it defeats attempts to use the type system to prevent reuse of the IV.
    #[inline]
    pub(super) fn into_block_less_safe(self) -> Block {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polyfill::usize_from_u32;

    const DUMMY_ONCE_VALUE: [u8; NONCE_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
    ];
    fn dummy_nonce() -> Nonce {
        Nonce::assume_unique_for_key(DUMMY_ONCE_VALUE)
    }

    fn dummy_value(counter: [u8; 4]) -> [u8; BLOCK_LEN] {
        let mut value = [0u8; BLOCK_LEN];
        value[..NONCE_LEN].copy_from_slice(&DUMMY_ONCE_VALUE);
        value[NONCE_LEN..].copy_from_slice(&counter);
        value
    }

    const _1: NonZeroUsize = unwrap_const(NonZeroUsize::new(1));
    const _2: NonZeroUsize = unwrap_const(NonZeroUsize::new(2));
    const MAX: NonZeroUsize = unwrap_const(NonZeroUsize::new(usize_from_u32(u32::MAX)));
    const MAX_MINUS_1: NonZeroUsize = unwrap_const(NonZeroUsize::new(MAX.get() - 1));
    const MAX_MINUS_2: NonZeroUsize = unwrap_const(NonZeroUsize::new(MAX.get() - 2));

    const USIZE_MAX: NonZeroUsize = unwrap_const(NonZeroUsize::new(usize::MAX));

    #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
    const MAX_PLUS_1: NonZeroUsize = unwrap_const(NonZeroUsize::new(MAX.get() + 1));

    #[test]
    fn one_is_one() {
        let (one, _two) = Counter::one_two(dummy_nonce());
        let as_block = one.into_block_less_safe();
        assert_eq!(as_block, dummy_value([0, 0, 0, 1]));
    }

    #[test]
    fn two_is_two() {
        let (_one, two) = Counter::one_two(dummy_nonce());
        let as_block = two.try_into_iv().ok().unwrap().into_block_less_safe();
        assert_eq!(as_block, dummy_value([0, 0, 0, 2]));
    }

    #[test]
    fn smallest_increment() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let _: IvBlock = ctr.increment_by(_1).ok().unwrap();
        assert_eq!(
            ctr.try_into_iv().ok().unwrap().into_block_less_safe(),
            dummy_value([0, 0, 0, 3])
        );
    }

    #[test]
    fn carries() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block: IvBlock = ctr
            .increment_by(NonZeroUsize::new(0xfe).unwrap())
            .ok()
            .unwrap();
        assert_eq!(
            iv_block.into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 0, 2])
        );
        let iv_block = ctr
            .increment_by(NonZeroUsize::new(0xff_00).unwrap())
            .ok()
            .unwrap();
        assert_eq!(
            iv_block.into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 1, 0])
        );
        let iv_block = ctr
            .increment_by(NonZeroUsize::new(0xff_00_00).unwrap())
            .ok()
            .unwrap();
        assert_eq!(
            iv_block.into_initial_iv().into_block_less_safe(),
            dummy_value([0, 1, 0, 0])
        );
        let iv_block = ctr
            .increment_by(NonZeroUsize::new(0xff_00_00_00).unwrap())
            .ok()
            .unwrap();
        assert_eq!(
            iv_block.into_initial_iv().into_block_less_safe(),
            dummy_value([1, 0, 0, 0])
        );
        assert_eq!(&ctr.0[..], dummy_value([0, 0, 0, 0]));
        assert!(ctr.try_into_iv().is_err()); // Because it is zero
    }

    #[test]
    fn large_increment() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let _: IvBlock = ctr.increment_by(MAX_MINUS_2).ok().unwrap();
        let iv_block = ctr.increment_by(_1).ok().unwrap();
        assert_eq!(
            iv_block.into_initial_iv().into_block_less_safe(),
            dummy_value([0xff, 0xff, 0xff, 0xff])
        );
        assert!(ctr.increment_by(_1).is_err());
    }

    #[test]
    fn larger_increment_then_increment() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let _: IvBlock = ctr.increment_by(MAX_MINUS_1).ok().unwrap();
        assert_eq!(&ctr.0[..], dummy_value([0, 0, 0, 0]));
        assert!(ctr.increment_by(MAX_MINUS_1).is_err());
    }

    #[test]
    fn larger_increment_then_into_iv() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let _: IvBlock = ctr.increment_by(MAX_MINUS_1).ok().unwrap();
        assert_eq!(&ctr.0[..], dummy_value([0, 0, 0, 0]));
        assert!(ctr.try_into_iv().is_err());
    }

    #[test]
    fn even_larger_increment() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        assert!(ctr.increment_by(MAX).is_err());
    }

    #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
    #[test]
    fn even_larger_still_increment() {
        const MAX_PLUS_1: NonZeroUsize = unwrap_const(NonZeroUsize::new(MAX.get() + 1));
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        assert!(ctr.increment_by(MAX_PLUS_1).is_err());
    }

    #[test]
    fn way_too_large_increment() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        assert!(ctr.increment_by(USIZE_MAX).is_err());
    }

    #[test]
    fn split_at_start() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block = ctr.increment_by(_1).ok().unwrap();
        let (a, b) = iv_block.split_at(0).ok().unwrap();
        assert!(a.is_none());
        assert_eq!(
            b.unwrap().into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 0, 2])
        );
    }

    #[test]
    fn split_at_end() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block = ctr.increment_by(_1).ok().unwrap();
        let (a, b) = iv_block.split_at(1).ok().unwrap();
        assert_eq!(
            a.unwrap().into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 0, 2])
        );
        assert!(b.is_none());
    }

    #[test]
    fn split_at_middle() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block = ctr.increment_by(_2).ok().unwrap();
        let (a, b) = iv_block.split_at(1).ok().unwrap();
        assert_eq!(
            a.unwrap().into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 0, 2])
        );
        assert_eq!(
            b.unwrap().into_initial_iv().into_block_less_safe(),
            dummy_value([0, 0, 0, 3])
        );
    }

    #[test]
    fn split_at_overflow() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block = ctr.increment_by(_1).ok().unwrap();
        assert!(iv_block.split_at(2).is_err());
    }

    #[cfg(not(any(target_pointer_width = "16", target_pointer_width = "32")))]
    #[test]
    fn split_at_u32_max_plus_1() {
        let (_, mut ctr) = Counter::one_two(dummy_nonce());
        let iv_block = ctr.increment_by(MAX_MINUS_2).ok().unwrap();
        assert!(iv_block.split_at(MAX_PLUS_1.get()).is_err());
    }
}
