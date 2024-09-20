use core::{fmt, num::NonZeroU32};

/// A small and `no_std` compatible error type
///
/// The [`Error::raw_os_error()`] will indicate if the error is from the OS, and
/// if so, which error code the OS gave the application. If such an error is
/// encountered, please consult with your system documentation.
///
/// Internally this type is a NonZeroU32, with certain values reserved for
/// certain purposes, see [`Error::INTERNAL_START`] and [`Error::CUSTOM_START`].
///
/// *If this crate's `"std"` Cargo feature is enabled*, then:
/// - [`getrandom::Error`][Error] implements
///   [`std::error::Error`](https://doc.rust-lang.org/std/error/trait.Error.html)
/// - [`std::io::Error`](https://doc.rust-lang.org/std/io/struct.Error.html) implements
///   [`From<getrandom::Error>`](https://doc.rust-lang.org/std/convert/trait.From.html).
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error(NonZeroU32);

const fn internal_error(n: u16) -> Error {
    // SAFETY: code > 0 as INTERNAL_START > 0 and adding n won't overflow a u32.
    let code = Error::INTERNAL_START + (n as u32);
    Error(unsafe { NonZeroU32::new_unchecked(code) })
}

impl Error {
    /// This target/platform is not supported by `getrandom`.
    pub const UNSUPPORTED: Error = internal_error(0);
    /// The platform-specific `errno` returned a non-positive value.
    pub const ERRNO_NOT_POSITIVE: Error = internal_error(1);
    /// Encountered an unexpected situation which should not happen in practice.
    pub const UNEXPECTED: Error = internal_error(2);
    /// Call to [`CCRandomGenerateBytes`](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonRandom.h.auto.html) failed
    /// on iOS, tvOS, or waatchOS.
    // TODO: Update this constant name in the next breaking release.
    pub const IOS_SEC_RANDOM: Error = internal_error(3);
    /// Call to Windows [`RtlGenRandom`](https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom) failed.
    pub const WINDOWS_RTL_GEN_RANDOM: Error = internal_error(4);
    /// RDRAND instruction failed due to a hardware issue.
    pub const FAILED_RDRAND: Error = internal_error(5);
    /// RDRAND instruction unsupported on this target.
    pub const NO_RDRAND: Error = internal_error(6);
    /// The environment does not support the Web Crypto API.
    pub const WEB_CRYPTO: Error = internal_error(7);
    /// Calling Web Crypto API `crypto.getRandomValues` failed.
    pub const WEB_GET_RANDOM_VALUES: Error = internal_error(8);
    /// On VxWorks, call to `randSecure` failed (random number generator is not yet initialized).
    pub const VXWORKS_RAND_SECURE: Error = internal_error(11);
    /// Node.js does not have the `crypto` CommonJS module.
    pub const NODE_CRYPTO: Error = internal_error(12);
    /// Calling Node.js function `crypto.randomFillSync` failed.
    pub const NODE_RANDOM_FILL_SYNC: Error = internal_error(13);
    /// Called from an ES module on Node.js. This is unsupported, see:
    /// <https://docs.rs/getrandom#nodejs-es-module-support>.
    pub const NODE_ES_MODULE: Error = internal_error(14);
    /// Calling Windows ProcessPrng failed.
    pub const WINDOWS_PROCESS_PRNG: Error = internal_error(15);

    /// Codes below this point represent OS Errors (i.e. positive i32 values).
    /// Codes at or above this point, but below [`Error::CUSTOM_START`] are
    /// reserved for use by the `rand` and `getrandom` crates.
    pub const INTERNAL_START: u32 = 1 << 31;

    /// Codes at or above this point can be used by users to define their own
    /// custom errors.
    pub const CUSTOM_START: u32 = (1 << 31) + (1 << 30);

    /// Creates a new instance of an `Error` from a particular OS error code.
    ///
    /// This method is analogous to [`std::io::Error::from_raw_os_error()`][1],
    /// except that it works in `no_std` contexts and `code` will be
    /// replaced with `Error::UNEXPECTED` if it isn't in the range
    /// `1..Error::INTERNAL_START`. Thus, for the result `r`,
    /// `r == Self::UNEXPECTED || r.raw_os_error().unsigned_abs() == code`.
    ///
    /// [1]: https://doc.rust-lang.org/std/io/struct.Error.html#method.from_raw_os_error
    #[allow(dead_code)]
    pub(super) fn from_os_error(code: u32) -> Self {
        match NonZeroU32::new(code) {
            Some(code) if code.get() < Self::INTERNAL_START => Self(code),
            _ => Self::UNEXPECTED,
        }
    }

    /// Extract the raw OS error code (if this error came from the OS)
    ///
    /// This method is identical to [`std::io::Error::raw_os_error()`][1], except
    /// that it works in `no_std` contexts. If this method returns `None`, the
    /// error value can still be formatted via the `Display` implementation.
    ///
    /// [1]: https://doc.rust-lang.org/std/io/struct.Error.html#method.raw_os_error
    #[inline]
    pub fn raw_os_error(self) -> Option<i32> {
        if self.0.get() < Self::INTERNAL_START {
            match () {
                #[cfg(target_os = "solid_asp3")]
                // On SOLID, negate the error code again to obtain the original
                // error code.
                () => Some(-(self.0.get() as i32)),
                #[cfg(not(target_os = "solid_asp3"))]
                () => Some(self.0.get() as i32),
            }
        } else {
            None
        }
    }

    /// Extract the bare error code.
    ///
    /// This code can either come from the underlying OS, or be a custom error.
    /// Use [`Error::raw_os_error()`] to disambiguate.
    #[inline]
    pub const fn code(self) -> NonZeroU32 {
        self.0
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("Error");
        if let Some(errno) = self.raw_os_error() {
            dbg.field("os_error", &errno);
        } else if let Some(desc) = internal_desc(*self) {
            dbg.field("internal_code", &self.0.get());
            dbg.field("description", &desc);
        } else {
            dbg.field("unknown_code", &self.0.get());
        }
        dbg.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(errno) = self.raw_os_error() {
            write!(f, "OS Error: {}", errno)
        } else if let Some(desc) = internal_desc(*self) {
            f.write_str(desc)
        } else {
            write!(f, "Unknown Error: {}", self.0.get())
        }
    }
}

impl From<NonZeroU32> for Error {
    fn from(code: NonZeroU32) -> Self {
        Self(code)
    }
}

fn internal_desc(error: Error) -> Option<&'static str> {
    match error {
        Error::UNSUPPORTED => Some("getrandom: this target is not supported"),
        Error::ERRNO_NOT_POSITIVE => Some("errno: did not return a positive value"),
        Error::UNEXPECTED => Some("unexpected situation"),
        Error::IOS_SEC_RANDOM => Some("SecRandomCopyBytes: iOS Security framework failure"),
        Error::WINDOWS_RTL_GEN_RANDOM => Some("RtlGenRandom: Windows system function failure"),
        Error::FAILED_RDRAND => Some("RDRAND: failed multiple times: CPU issue likely"),
        Error::NO_RDRAND => Some("RDRAND: instruction not supported"),
        Error::WEB_CRYPTO => Some("Web Crypto API is unavailable"),
        Error::WEB_GET_RANDOM_VALUES => Some("Calling Web API crypto.getRandomValues failed"),
        Error::VXWORKS_RAND_SECURE => Some("randSecure: VxWorks RNG module is not initialized"),
        Error::NODE_CRYPTO => Some("Node.js crypto CommonJS module is unavailable"),
        Error::NODE_RANDOM_FILL_SYNC => Some("Calling Node.js API crypto.randomFillSync failed"),
        Error::NODE_ES_MODULE => Some("Node.js ES modules are not directly supported, see https://docs.rs/getrandom#nodejs-es-module-support"),
        Error::WINDOWS_PROCESS_PRNG => Some("ProcessPrng: Windows system function failure"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use core::mem::size_of;

    #[test]
    fn test_size() {
        assert_eq!(size_of::<Error>(), 4);
        assert_eq!(size_of::<Result<(), Error>>(), 4);
    }
}
