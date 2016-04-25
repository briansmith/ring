// Copyright 2015-2016 Brian Smith.
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

//! Cryptographic psuedo-random number generation.

#![allow(unsafe_code)]

#[cfg(unix)]
extern crate std;

use c;
use core;

/// A secure random number generator.
pub trait SecureRandom {
    /// Fills `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()>;
}

/// A secure random number generator where the random values come directly
/// from the operating system.
///
/// On "unix"-ish platforms, this is currently done by reading from
/// `/dev/urandom`. A new file handle for `/dev/urandom/` is opened each time a
/// `SystemRandom` is constructed and the file handle is closed each time.
///
/// On other platforms, this is done using the platform's API for secure random
/// number generation.
///
/// For efficiency's sake, it is recommend to create a single SystemRandom and
/// then use it for all randomness generation, especially if the
/// /dev/urandom-based `SystemRandom` implementation may be used.
pub struct SystemRandom {
    impl_: Impl,
}

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> Result<SystemRandom, ()> {
        Ok(SystemRandom { impl_: try!(Impl::new()) })
    }
}

impl SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
        self.impl_.fill(dest)
    }
}

#[cfg(unix)]
type Impl = self::urandom::DevURandom;

#[cfg(windows)]
type Impl = self::sysrand::Sysrand;

#[cfg(unix)]
mod urandom {
    extern crate std;

    pub struct DevURandom {
        file: std::fs::File,
    }

    impl DevURandom {
        pub fn new() -> Result<DevURandom, ()> {
            // std::fs::File::open opens the file with close-on-exec semantics
            // whenever possible.
            Ok(DevURandom {
                file: try!(std::fs::File::open("/dev/urandom").map_err(|_| ())),
            })
        }
    }

    impl super::SecureRandom for DevURandom {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
            use self::std::io::Read;
            self.file.read_exact(dest).map_err(|_| ())
        }
    }
}

#[cfg(windows)]
mod sysrand {
    use {bssl, c};

    pub struct Sysrand;

    impl Sysrand {
        pub fn new() -> Result<Sysrand, ()> {
            Ok(Sysrand)
        }
    }

    impl super::SecureRandom for Sysrand {
        #[allow(unsafe_code)]
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
            bssl::map_result(unsafe {
                CRYPTO_sysrand(dest.as_mut_ptr(), dest.len())
            })
        }
    }

    extern {
        fn CRYPTO_sysrand(buf: *mut u8, len: c::size_t) -> c::int;
    }
}


/// An adapter that lets the C code use `SecureRandom`.
#[allow(non_snake_case)]
#[doc(hidden)]
pub struct RAND<'a> {
    pub rng: &'a mut SecureRandom,
}

#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn RAND_bytes(rng: *mut RAND, dest: *mut u8,
                                dest_len: c::size_t) -> c::int {
    let dest: &mut [u8] = core::slice::from_raw_parts_mut(dest, dest_len);

    match (*(*rng).rng).fill(dest) {
        Ok(()) => 1,
        _ => 0
    }
}
