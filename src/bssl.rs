// Copyright 2015 Brian Smith.
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

use crate::{c, error};

/// An `int` returned from a foreign function containing **1** if the function
/// was successful or **0** if an error occurred. This is the convention used by
/// C code in `ring`.
#[must_use]
#[repr(transparent)]
pub struct Result(c::int);

impl Result {
    #[cfg(not(any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86",
        target_arch = "x86_64"
    )))]
    pub fn ok() -> Self {
        Self(1)
    }
}

impl From<Result> for core::result::Result<(), error::Unspecified> {
    fn from(Result(ret): Result) -> Self {
        // BoringSSL functions are supposed to return 1 on success but some,
        // such as bn_mul_mont* on 32-bit ARM at least, return other non-zero
        // values on success instead.
        if ret == 0 {
            Err(error::Unspecified)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    mod result {
        use crate::{bssl, c};
        use core::mem::{align_of, size_of};

        #[test]
        fn size_and_alignment() {
            type Underlying = c::int;
            assert_eq!(size_of::<bssl::Result>(), size_of::<Underlying>());
            assert_eq!(align_of::<bssl::Result>(), align_of::<Underlying>());
        }

        #[test]
        fn semantics() {
            assert!(Result::from(bssl::Result(0)).is_err());
            assert!(Result::from(bssl::Result(1)).is_ok());
        }
    }
}
