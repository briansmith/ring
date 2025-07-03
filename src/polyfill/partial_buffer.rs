use crate::{error::InputTooLongError, polyfill::sliceutil};

/// A buffer that is *almost* never full, but which can transiently be full.
///
/// Invariant: `LEN_MAX_PLUS_1` == `LEN_MAX + 1`. (We use `LEN_MAX_PLUS_1`
/// instead of `LEN_MAX` as a const parameter due to current limitations of
/// const generics.)
///
/// Invariant: `LEN_MAX <= 255` so that the length can fit in a byte.
#[derive(Clone)]
#[repr(transparent)]
// TODO(MSRV): `const LEN_MAX: u8` instead of `const LEN_MAX_PLUS_1: usize`.
pub struct PartialBuffer<const LEN_MAX_PLUS_1: usize> {
    // `len` is stored in the last byte.
    buffer_and_len: [u8; LEN_MAX_PLUS_1],
}

impl<const LEN_MAX_PLUS_1: usize> PartialBuffer<LEN_MAX_PLUS_1> {
    #[inline]
    pub fn new_zeroed() -> Self {
        // TODO(MSRV): const { assert!(...) };
        assert!(u8::try_from(LEN_MAX_PLUS_1 - 1).is_ok());
        Self {
            // Zero the buffer and set `len = 0`. It's safety-critical that we
            // initialize the whole buffer so that the case where we're not
            // panic-safe don't cause memory unsafety.
            buffer_and_len: [0; LEN_MAX_PLUS_1],
        }
    }

    #[inline]
    pub fn len(&self) -> PurportedLen<LEN_MAX_PLUS_1> {
        // TODO(MSRV): `const LEN_INDEX: usize = usize_from_u8(LEN_MAX);`
        // TODO(MSRV): `const LEN_INDEX` and make an associated const.
        let LEN_INDEX: usize = LEN_MAX_PLUS_1 - 1;
        PurportedLen(self.buffer_and_len[LEN_INDEX])
    }

    #[inline]
    fn set_purported_len(&mut self, PurportedLen(len): PurportedLen<LEN_MAX_PLUS_1>) {
        // TODO(MSRV): `const LEN_INDEX: usize = usize_from_u8(LEN_MAX);`
        // TODO(MSRV): `const LEN_INDEX` and make an associated const.
        let LEN_INDEX: usize = LEN_MAX_PLUS_1 - 1;
        self.buffer_and_len[LEN_INDEX] = len;
    }

    #[inline]
    pub fn overwrite_at_start_partial(
        &mut self,
        buffer: &[u8],
    ) -> Result<(), InputTooLongError<usize>> {
        let len = buffer.len().try_into()?;
        sliceutil::overwrite_at_start(&mut self.buffer_and_len, buffer);
        self.set_purported_len(len);
        Ok(())
    }

    #[inline]
    pub fn temporarily_use_whole_buffer_less_safe_not_panic_safe(
        &mut self,
        f: impl FnOnce(&mut [u8; LEN_MAX_PLUS_1]) -> PurportedLen<LEN_MAX_PLUS_1>,
    ) {
        // XXX: If `f` writes to the last byte of the buffer and then panics,
        // then things go pretty badly as we'll interpret that byte as the
        // length going forward.
        let new_purported_len = f(&mut self.buffer_and_len);
        // If `f` doesn't panic then the invariant is restored here. We don't
        // care whether `f` actually wrote anything to the buffer to ensure
        // that `new_purported_len` makes sense, as we've ensured in the
        // constructor that at least every byte was written once.
        self.set_purported_len(new_purported_len);
    }
}

pub struct PurportedLen<const LEN_MAX_PLUS_1: usize>(u8);

impl<const LEN_MAX_PLUS_1: usize> PurportedLen<LEN_MAX_PLUS_1> {
    pub const ZERO: Self = Self(0);
}

impl<const LEN_MAX_PLUS_1: usize> From<PurportedLen<LEN_MAX_PLUS_1>> for usize {
    #[inline]
    fn from(PurportedLen(value): PurportedLen<LEN_MAX_PLUS_1>) -> Self {
        usize::from(value)
    }
}

impl<const LEN_MAX_PLUS_1: usize> TryFrom<usize> for PurportedLen<LEN_MAX_PLUS_1> {
    type Error = InputTooLongError;

    #[inline]
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        assert!(u8::try_from(LEN_MAX_PLUS_1 - 1).is_ok());
        if value >= LEN_MAX_PLUS_1 {
            return Err(InputTooLongError::new(value));
        }
        #[allow(clippy::cast_possible_truncation)]
        Ok(Self(value as u8))
    }
}
