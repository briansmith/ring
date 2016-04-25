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

use {bssl, c};
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
/// `/dev/urandom`. On other platforms, this is done using the platform's
/// API for secure random number generation.
pub struct SystemRandom {
    _dummy: u8,
}

impl SystemRandom {
    /// Constructs a new `SystemRandom`.
    #[inline(always)]
    pub fn new() -> Result<SystemRandom, ()> {
        init_once();
        Ok(SystemRandom { _dummy: 1 })
    }
}

impl SecureRandom for SystemRandom {
    #[inline(always)]
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), ()> {
        bssl::map_result(unsafe {
            CRYPTO_sysrand(dest.as_mut_ptr(), dest.len())
        })
    }
}

extern {
    fn CRYPTO_sysrand(buf: *mut u8, len: c::size_t) -> c::int;
}

#[cfg(unix)]
extern {
    fn CRYPTO_sysrand_init_once();
}

#[cfg(not(unix))]
fn init_once() { }

#[cfg(unix)]
fn init_once() {
    INIT.call_once(|| {
        unsafe {
            CRYPTO_sysrand_init_once();
        }
    });
}

#[cfg(unix)]
static INIT: std::sync::Once = std::sync::ONCE_INIT;


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
