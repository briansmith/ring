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
//!
//! An application should create a single SystemRandom and then use it for all
//! randomness generation. Functions that generate random bytes should take a
//! `&mut SecureRandom` parameter instead of instantiating their own. Besides
//! being more efficient, this also helps document where non-deterministic
//! (random) outputs occur. Taking a reference to a `SecureRandom` also helps
//! with testing techniques like fuzzing, where it is useful to use a
//! (non-secure) deterministic implementation of `SecureRandom` so that results
//! can be replayed. Following this pattern also may help with sandboxing
//! (seccomp filters on Linux in particular). See `SystemRandom`'s
//! documentation for more details.


#![allow(unsafe_code)]

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
/// On Linux, `fill()` will use the
/// [`getrandom`](man7.org/linux/man-pages/man2/getrandom.2.html) syscall. If
/// the kernel is too old to support `getrandom` then by default `fill()` falls
/// back to reading from `/dev/urandom`. This decision is made the first time
/// `fill` *succeeds*. The fallback to `/dev/urandom` can be disabled by
/// disabling by enabling the *ring* crate's `disable_dev_urandom_fallback`
/// feature; this should be done whenever the target system is known to support
/// `getrandom`. Note that only application (binary) crates, and not library
/// crates, should enable the `disable_dev_urandom_fallback` feature.
///
/// On Windows, `fill` is implemented done using the platform's API for secure
/// random number generation.
///
/// When `/dev/urandom` is used, a file handle for `/dev/urandom` won't be
/// opened until `fill` is called. In particular, `SystemRandom::new()` will
/// not open `/dev/urandom` or do other potentially-high-latency things. Once
/// the file handle is opened by `fill()`, it won't be closed until the
/// `SystemRandom` is destroyed. Each instance of `SystemRandom` will have its
/// own file handle.
///
/// On Linux, to properly implement seccomp filtering when the
/// `disable_dev_urandom_fallback` feature is enabled, allow `getrandom`
/// through. Otherwise, allow file opening, `getrandom`, and `read` up until
/// `fill()` succeeds. After that, allow `getrandom` and `read`.
pub struct SystemRandom {
    impl_: Impl,
}

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> SystemRandom {
        SystemRandom { impl_: Impl::new() }
    }
}

impl SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
        self.impl_.fill(dest)
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
type Impl = self::urandom::DevURandom;

#[cfg(any(all(target_os = "linux", feature = "disable_dev_urandom_fallback"),
          windows))]
type Impl = self::sysrand::Sysrand;

#[cfg(all(target_os = "linux", not(feature = "disable_dev_urandom_fallback")))]
type Impl = self::sysrand_or_urandom::SysRandOrDevURandom;

#[cfg(all(unix,
          not(all(target_os = "linux",
                  feature = "disable_dev_urandom_fallback"))))]
mod urandom {
    use core;
    extern crate std;

    pub enum DevURandom {
        Unopened,
        Opened(std::fs::File),
    }

    impl DevURandom {
        pub fn new() -> DevURandom { DevURandom::Unopened }
    }

    impl super::SecureRandom for DevURandom {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
            use self::std::io::Read;
            match self {
                &mut DevURandom::Opened(ref mut file) =>
                    file.read_exact(dest).map_err(|_| ()),
                &mut DevURandom::Unopened => {
                    let _ = core::mem::replace(self,
                        DevURandom::Opened(
                            try!(std::fs::File::open("/dev/urandom")
                                    .map_err(|_| ()))));
                    self.fill(dest)
                }
            }
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
mod sysrand {
    use bssl;

    pub struct Sysrand;

    impl Sysrand {
        pub fn new() -> Sysrand {
            Sysrand
        }
    }

    impl super::SecureRandom for Sysrand {
        #[allow(unsafe_code)]
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
            for mut chunk in
                    dest.chunks_mut(super::CRYPTO_sysrand_chunk_max_len) {
                try!(bssl::map_result(unsafe {
                    super::CRYPTO_sysrand_chunk(chunk.as_mut_ptr(), chunk.len())
                }));
            }
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", not(feature = "disable_dev_urandom_fallback")))]
mod sysrand_or_urandom {
    use core;
    use super::{sysrand, urandom};

    pub enum SysRandOrDevURandom {
        Undecided,
        Sysrand(sysrand::Sysrand),
        DevURandom(urandom::DevURandom),
    }

    impl SysRandOrDevURandom {
        pub fn new() -> SysRandOrDevURandom {
            SysRandOrDevURandom::Undecided
        }
    }

    impl super::SecureRandom for SysRandOrDevURandom {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
            match self {
                &mut SysRandOrDevURandom::Sysrand(ref mut i) => i.fill(dest),
                &mut SysRandOrDevURandom::DevURandom(ref mut i) => i.fill(dest),
                &mut SysRandOrDevURandom::Undecided => {
                    let first_chunk_len =
                        core::cmp::min(dest.len(),
                                       super::CRYPTO_sysrand_chunk_max_len);
                    match unsafe {
                        super::CRYPTO_sysrand_chunk(dest.as_mut_ptr(),
                                                    first_chunk_len)
                    } {
                        1 => {
                            let _ = core::mem::replace(self,
                                SysRandOrDevURandom::Sysrand(
                                    sysrand::Sysrand::new()));
                            if first_chunk_len < dest.len() {
                                self.fill(&mut dest[first_chunk_len..])
                            } else {
                                Ok(())
                            }
                        },
                        -1 => {
                            let _ = core::mem::replace(self,
                                SysRandOrDevURandom::DevURandom(
                                    urandom::DevURandom::new()));
                            self.fill(dest)
                        },
                        _ => {
                            Err(())
                        }
                    }
                }
            }
        }
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


#[cfg(any(target_os = "linux", windows))]
extern {
    pub static CRYPTO_sysrand_chunk_max_len: c::size_t;
    pub fn CRYPTO_sysrand_chunk(buf: *mut u8, len: c::size_t) -> c::int;
}

#[cfg(test)]
mod tests {
    use rand;
    use rand::SecureRandom;
    extern crate std;

    #[test]
    fn test_system_random_lengths() {
        // Test that `fill` succeeds for various interesting lengths. `256` and
        // multiples thereof are interesting because that's an edge case for
        // `getrandom` on Linux.
        let lengths = [0, 1, 2, 3, 96, 255, 256, 257, 511, 512, 513, 4096];

        for len in lengths.iter() {
            let mut buf = std::vec::Vec::with_capacity(*len);
            for _ in 0..*len {
                buf.push(0);
            }

            let mut rng = rand::SystemRandom::new();
            assert!(rng.fill(&mut buf).is_ok());

            // If `len` < 96 then there's a big chance of false positives, but
            // otherwise the likelihood of a false positive is so too low to
            // worry about.
            if *len >= 96 {
                assert!(buf.iter().any(|x| *x != 0));
            }

            // Make sure we didn't forget to finish filling in the rest of the
            // buffer after we filled in the first chunk, especially in the
            // case in the `SysRandOrDevURandom::Undecided` case.
            if *len > max_chunk_len() {
                assert!(buf[max_chunk_len()..].iter().any(|x| *x != 0));
            }
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    fn max_chunk_len() -> usize { super::CRYPTO_sysrand_chunk_max_len }

    #[cfg(not(any(target_os = "linux", windows)))]
    fn max_chunk_len() -> usize {
        use core;
        core::usize::MAX
    }
}
