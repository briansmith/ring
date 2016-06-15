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

use c;

pub fn map_result(bssl_result: c::int) -> Result<(), ()> {
    match bssl_result {
        1 => Ok(()),
        _ => Err(())
    }
}

// Adapt a BoringSSL test suite to a Rust test.
//
// The BoringSSL test suite is broken up into multiple files. Originally, they
// were all executables with their own `main` functions. Those main functions
// have been replaced with uniquely-named functions so that they can all be
// linked into the same executable.
#[cfg(test)]
macro_rules! bssl_test {
    ( $fn_name:ident, $bssl_test_main_fn_name:ident ) => {
        #[test]
        #[allow(unsafe_code)]
        fn $fn_name() {
            use $crate::{c, init};
            extern {
                fn $bssl_test_main_fn_name() -> c::int;
            }

            init::init_once();

            let result = unsafe {
                $bssl_test_main_fn_name()
            };
            assert_eq!(result, 0);
        }
    }
}

// Adapt a BoringSSL test suite to a Rust test like `bssl_test`, passing the
// test suite function a `rand::SecureRandom`.
#[cfg(test)]
macro_rules! bssl_test_rng {
    ( $fn_name:ident, $bssl_test_main_fn_name:ident ) => {
        #[test]
        #[allow(improper_ctypes, unsafe_code)]
        fn $fn_name() {
            use $crate::{c, init, rand};
            extern {
                fn $bssl_test_main_fn_name(rng: *mut rand::RAND) -> c::int;
            }

            init::init_once();

            let rng = rand::SystemRandom::new();
            let mut rng = rand::RAND { rng: &rng };
            let result = unsafe {
                $bssl_test_main_fn_name(&mut rng)
            };
            assert_eq!(result, 0);
        }
    }
}
