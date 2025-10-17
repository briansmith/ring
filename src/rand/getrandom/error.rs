use core::fmt;

// This private alias mirrors `std::io::RawOsError`:
// https://doc.rust-lang.org/std/io/type.RawOsError.html)
cfg_if::cfg_if!(
    if #[cfg(target_os = "uefi")] {
        // See the UEFI spec for more information:
        // https://uefi.org/specs/UEFI/2.10/Apx_D_Status_Codes.html
        type RawOsError = usize;
        type NonZeroRawOsError = core::num::NonZeroUsize;
        const UEFI_ERROR_FLAG: RawOsError = 1 << (RawOsError::BITS - 1);
    } else {
        type RawOsError = i32;
        type NonZeroRawOsError = core::num::NonZeroI32;
    }
);

/// A small and `no_std` compatible error type
///
/// The [`Error::raw_os_error()`] will indicate if the error is from the OS, and
/// if so, which error code the OS gave the application. If such an error is
/// encountered, please consult with your system documentation.
///
/// *If this crate's `"std"` Cargo feature is enabled*, then:
/// - [`getrandom::Error`][Error] implements
///   [`std::error::Error`](https://doc.rust-lang.org/std/error/trait.Error.html)
/// - [`std::io::Error`](https://doc.rust-lang.org/std/io/struct.Error.html) implements
///   [`From<getrandom::Error>`](https://doc.rust-lang.org/std/convert/trait.From.html).

// note: on non-UEFI targets OS errors are represented as negative integers,
// while on UEFI targets OS errors have the highest bit set to 1.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error(NonZeroRawOsError);

impl Error {
    /// Internal errors can be in the range of 2^16..2^17
    const INTERNAL_START: RawOsError = 1 << 16;

    /// Creates a new instance of an `Error` from a particular internal error code.
    pub(crate) const fn new_internal(n: u16) -> Error {
        // SAFETY: code > 0 as INTERNAL_START > 0 and adding `n` won't overflow `RawOsError`.
        let code = Error::INTERNAL_START + (n as RawOsError);
        Error(unsafe { NonZeroRawOsError::new_unchecked(code) })
    }
}
