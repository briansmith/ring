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

use crate::{error, sealed};

/// A secure random number generator.
pub trait SecureRandom: sealed::Sealed {
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
/// On Android and Linux, `fill()` will use the [`getrandom`] syscall. If the
/// kernel is too old to support `getrandom(2)` then, by default, `fill()`
/// falls back reading from certain files in `/dev`. First, it reads a single
/// byte from `/dev/random` to make sure the kernel's entropy pool is
/// initialized. Then it fills the buffer with data from `/dev/urandom`.
///
/// On macOS and iOS, `fill()` is implemented using `SecRandomCopyBytes`.
///
/// On NetBSD, the Linux file-based fallback approch is used.
///
/// On Redox, `fill()` is implemented by reading from `rand:`.
///
/// On Fuchsia, `fill` is implemented using `zx_cprng_draw`.
///
/// On Windows, `fill` is implemented using `RtlGenRandom`.
///
/// When a file-based fallback is used, a file won't be opened until `fill` is
/// called. In particular, `SystemRandom::new()` will not open any files or do
/// other potentially-high-latency things. The file handle will only be closed
/// when the operating system closes it at process shutdown. All instances of
/// `SystemRandom` will share a single file handle.
///
/// All file-based methods require the `use_heap` feature. If this feature is
/// not enabled, only syscalls will be used to obain randomness.
///
/// [`getrandom`]: http://man7.org/linux/man-pages/man2/getrandom.2.html
pub struct SystemRandom;

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        fill_impl(dest)
    }
}

impl sealed::Sealed for SystemRandom {}

#[cfg(all(feature = "use_heap", any(target_os = "android", target_os = "linux")))]
fn fill_impl(dest: &mut [u8]) -> Result<(), error::Unspecified> {
    use lazy_static::lazy_static;
    lazy_static! {
        static ref SYSRAND_SUPPORTED: bool = sysrand::is_supported();
    }
    match *SYSRAND_SUPPORTED {
        true => sysrand::fill(dest),
        false => file::fill(dest),
    }
}

#[cfg(any(
    not(feature = "use_heap"),
    target_os = "macos",
    target_os = "ios",
    target_os = "fuchsia",
    windows
))]
use sysrand::fill as fill_impl;

#[cfg(any(target_os = "netbsd", target_os = "redox"))]
use file::fill as fill_impl;

#[cfg(feature = "use_heap")]
mod file {
    use crate::error;
    use std::{fs::File, io::Read};

    #[allow(dead_code)]
    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        #[cfg(target_os = "redox")]
        static RANDOM_PATH: &str = "rand:";
        #[cfg(not(target_os = "redox"))]
        static RANDOM_PATH: &str = "/dev/urandom";

        use lazy_static::lazy_static;
        lazy_static! {
            static ref FILE: Result<File, error::Unspecified> = {
                if cfg!(not(target_os = "redox")) {
                    File::open("/dev/random")?.read_exact(&mut [0u8; 1])?;
                }
                let file = File::open(RANDOM_PATH)?;
                Ok(file)
            };
        }
        let mut file: &File = FILE.as_ref()?;
        file.read_exact(dest)?;
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod sysrand {
    use crate::error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        let mut start = 0;
        while start < dest.len() {
            start += getrandom(&mut dest[start..], true)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_supported() -> bool {
        getrandom(&mut [], false).is_ok()
    }

    fn getrandom(dest: &mut [u8], block: bool) -> Result<usize, error::Unspecified> {
        let flags = if block { 0 } else { libc::GRND_NONBLOCK };
        let r = unsafe { libc::syscall(libc::SYS_getrandom, dest.as_mut_ptr(), dest.len(), flags) };
        if r < 0 {
            #[cfg(target_os = "android")]
            use libc::__errno as errno;
            #[cfg(target_os = "linux")]
            use libc::__errno_location as errno;

            // If an interrupt occurs while getrandom() is blocking to wait
            // for the entropy pool, then EINTR is returned. Returning 0
            // will cause the caller to try again.
            match unsafe { *errno() } {
                libc::EINTR | libc::EAGAIN => Ok(0),
                _ => Err(error::Unspecified),
            }
        } else {
            Ok(r as usize)
        }
    }
}

#[cfg(windows)]
mod sysrand {
    use crate::error;

    #[inline]
    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        use winapi::shared::wtypesbase::ULONG;
        use winapi::um::ntsecapi::RtlGenRandom;

        // Prevent overflow of ULONG
        for chunk in dest.chunks_mut(ULONG::max_value() as usize) {
            let ret = unsafe { RtlGenRandom(chunk.as_mut_ptr() as PVOID, chunk.len() as ULONG) };
            if ret == 0 {
                return Err(error::Unspecified);
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod sysrand {
    use crate::error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        match unsafe { SecRandomCopyBytes(kSecRandomDefault, dest.len(), dest.as_mut_ptr()) } {
            0 => Ok(()),
            _ => Err(error::Unspecified),
        }
    }

    // XXX: Replace with extern type when #![feature(extern_types)] is stable
    #[repr(C)]
    struct SecRandom([u8; 0]);

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecRandomDefault: &'static SecRandom;

        // For now `rnd` must be `kSecRandomDefault`.
        #[must_use]
        fn SecRandomCopyBytes(rnd: &'static SecRandom, count: c::size_t, bytes: *mut u8) -> c::int;
    }
}

#[cfg(target_os = "fuchsia")]
mod sysrand {
    use crate::error;

    pub fn fill(dest: &mut [u8]) -> Result<(), error::Unspecified> {
        unsafe { zx_cprng_draw(dest.as_mut_ptr(), dest.len()) };
        Ok(())
    }

    #[link(name = "zircon")]
    extern "C" {
        fn zx_cprng_draw(buffer: *mut u8, length: usize);
    }
}
