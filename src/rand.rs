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

//! Cryptographic pseudo-random number generation.
//!
//! An application should create a single `SystemRandom` and then use it for
//! all randomness generation. Functions that generate random bytes should take
//! a `&SecureRandom` parameter instead of instantiating their own. Besides
//! being more efficient, this also helps document where non-deterministic
//! (random) outputs occur. Taking a reference to a `SecureRandom` also helps
//! with testing techniques like fuzzing, where it is useful to use a
//! (non-secure) deterministic implementation of `SecureRandom` so that results
//! can be replayed. Following this pattern also may help with sandboxing
//! (seccomp filters on Linux in particular). See `SystemRandom`'s
//! documentation for more details.

#[cfg(any(target_os = "linux",
          target_os = "ios",
          windows,
          test))]
use c;

#[cfg(test)]
use core;

use error;


/// A secure random number generator.
pub trait SecureRandom {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified>;
}

/// A secure random number generator where the random values come directly
/// from the operating system.
///
/// A single `SystemRandom` may be shared across multiple threads safely.
///
/// `new()` is guaranteed to always succeed and to have low latency; it won't
/// try to open or read from a file or do similar things. The first call to
/// `fill()` may block a substantial amount of time since any and all
/// initialization is deferred to it. Therefore, it may be a good idea to call
/// `fill()` once at a non-latency-sensitive time to minimize latency for
/// future calls.
///
/// On non-Linux Unix-/Posix-ish platforms, `fill()` is currently always
/// implemented by reading from `/dev/urandom`. (This is something that should
/// be improved, at least for platforms that offer something better.)
///
/// On Redox, `fill()` is implemented by reading from `rand:`.
///
/// On Linux, `fill()` will use the [`getrandom`] syscall. If the kernel is too
/// old to support `getrandom` then by default `fill()` falls back to reading
/// from `/dev/urandom`. This decision is made the first time `fill`
/// *succeeds*. The fallback to `/dev/urandom` can be disabled by disabling the
/// `dev_urandom_fallback` default feature; this should be done whenever the
/// target system is known to support `getrandom`. Library crates should avoid
/// explicitly enabling the `dev_urandom_fallback` feature.
///
/// On Windows, `fill` is implemented using the platform's API for secure
/// random number generation.
///
/// When `/dev/urandom` is used, a file handle for `/dev/urandom` won't be
/// opened until `fill` is called. In particular, `SystemRandom::new()` will
/// not open `/dev/urandom` or do other potentially-high-latency things. The
/// file handle will never be closed, until the operating system closes it at
/// process shutdown. All instance of `SystemRandom` will share a single file
/// handle.
///
/// On Linux, to properly implement seccomp filtering when the
/// `dev_urandom_fallback` default feature is disabled, allow `getrandom`
/// through. When the fallback is enabled, allow file opening, `getrandom`,
/// and `read` up until the first call to `fill()` succeeds. After that, allow
/// `getrandom` and `read`.
///
/// [`getrandom`]: http://man7.org/linux/man-pages/man2/getrandom.2.html
pub struct SystemRandom;

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> SystemRandom { SystemRandom }
}

impl SystemRandom {
    /// This is the same as calling `fill` through the `SecureRandom` trait,
    /// but allows callers to avoid the annoying step of needing to
    /// `use rand::SecureRandom` just to call `fill` on a `SystemRandom`.
    #[inline(always)]
    pub fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        fill_impl(dest)
    }
}

impl SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        fill_impl(dest)
    }
}

#[cfg(not(any(target_os = "linux",
              target_os = "macos",
              target_os = "ios",
              windows)))]
use self::urandom::fill as fill_impl;

#[cfg(any(all(target_os = "linux", not(feature = "dev_urandom_fallback")),
          windows))]
use self::sysrand::fill as fill_impl;

#[cfg(all(target_os = "linux", feature = "dev_urandom_fallback"))]
use self::sysrand_or_urandom::fill as fill_impl;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use self::darwin::fill as fill_impl;

#[cfg(any(target_os = "linux", windows))]
mod sysrand {
    use error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        let mut read_len = 0;
        while read_len < dest.len() {
            let r = unsafe {
                super::GFp_sysrand_chunk(dest[read_len..].as_mut_ptr(),
                                         dest.len() - read_len)
            };
            if r < 0 {
                return Err(error::Unspecified);
            }
            // XXX: If r == 0 then this is a busy wait loop waiting for the
            // kernel entropy pool to be initialized.
            read_len += r as usize;
        }
        Ok(())
    }
}

// Keep the `cfg` conditions in sync with the conditions in lib.rs.
#[cfg(all(any(target_os = "redox", unix),
          not(any(target_os = "macos", target_os = "ios")),
          not(all(target_os = "linux",
                  not(feature = "dev_urandom_fallback")))))]
mod urandom {
    extern crate std;
    use error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        #[cfg(target_os = "redox")]
        static RANDOM_PATH: &'static str = "rand:";
        #[cfg(unix)]
        static RANDOM_PATH: &'static str = "/dev/urandom";

        lazy_static! {
            static ref FILE: Result<std::fs::File, std::io::Error> =
                std::fs::File::open(RANDOM_PATH);
        }

        match *FILE {
            Ok(ref file) => {
                use self::std::io::Read;
                (&*file).read_exact(dest).map_err(|_| error::Unspecified)
            },
            Err(_) => Err(error::Unspecified),
        }
    }
}

// Keep the `cfg` conditions in sync with the conditions in lib.rs.
#[cfg(all(target_os = "linux", feature = "dev_urandom_fallback"))]
mod sysrand_or_urandom {
    extern crate std;
    use error;

    enum Mechanism {
        Sysrand,
        DevURandom,
    }

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        lazy_static! {
            static ref MECHANISM: Mechanism = {
                let mut dummy = [0u8; 1];
                if unsafe {
                    super::GFp_sysrand_chunk(dummy.as_mut_ptr(),
                                               dummy.len()) } == -1 {
                    Mechanism::DevURandom
                } else {
                    Mechanism::Sysrand
                }
            };
        }

        match *MECHANISM {
            Mechanism::Sysrand => super::sysrand::fill(dest),
            Mechanism::DevURandom => super::urandom::fill(dest),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod darwin {
    use c;
    use error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        let r = unsafe {
            SecRandomCopyBytes(kSecRandomDefault, dest.len(),
                               dest.as_mut_ptr())
        };
        match r {
            0 => Ok(()),
            _ => Err(error::Unspecified),
        }
    }

    enum SecRandomRef {}

    #[link(name = "Security", kind = "framework")]
    extern {
        static kSecRandomDefault: &'static SecRandomRef;

        // For now `rnd` must be `kSecRandomDefault`.
        fn SecRandomCopyBytes(rnd: &'static SecRandomRef, count: c::size_t,
                              bytes: *mut u8) -> c::int;
    }
}

/// An adapter that lets the C code use `SecureRandom`.
#[allow(non_snake_case)]
#[doc(hidden)]
pub struct RAND<'a> {
    pub rng: &'a SecureRandom,
}

impl<'a> RAND<'a> {
    /// Wraps `rng` in a `RAND` so it can be passed to non-Rust code.
    pub fn new(rng: &'a SecureRandom) -> RAND<'a> { RAND { rng: rng } }
}

#[cfg(test)]
#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn RAND_bytes(rng: *mut RAND, dest: *mut u8,
                                dest_len: c::size_t) -> c::int {
    let dest: &mut [u8] = core::slice::from_raw_parts_mut(dest, dest_len);

    match (*(*rng).rng).fill(dest) {
        Ok(()) => 1,
        _ => 0,
    }
}


#[cfg(any(target_os = "linux", windows))]
extern {
    fn GFp_sysrand_chunk(buf: *mut u8, len: c::size_t) -> c::long;
}


#[cfg(test)]
mod tests {
    use rand;
    extern crate std;

    #[test]
    fn test_system_random_lengths() {
        // Test that `fill` succeeds for various interesting lengths. `256` and
        // multiples thereof are interesting because that's an edge case for
        // `getrandom` on Linux.
        let lengths = [0, 1, 2, 3, 96, 255, 256, 257, 511, 512, 513, 4096];

        for len in lengths.iter() {
            let mut buf = vec![0; *len];

            let rng = rand::SystemRandom::new();
            assert!(rng.fill(&mut buf).is_ok());

            // If `len` < 96 then there's a big chance of false positives, but
            // otherwise the likelihood of a false positive is so too low to
            // worry about.
            if *len >= 96 {
                assert!(buf.iter().any(|x| *x != 0));
            }
        }
    }
}
