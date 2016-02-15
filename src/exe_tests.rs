// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// These tests are ones that were written for OpenSSL or BoringSSL, each of
// which is compiled into its own executable. The tests have been modified to
// not print anything when they succeed.

use std;

macro_rules! exe_test {
    ( $name:ident, $relative_path_to_exe:expr, $args:expr ) => {
        #[test]
        fn $name() {
            let args: &[&'static str] = &$args;
            const RELATIVE_PATH_TO_EXE: &'static str =
                concat!(env!("OUT_DIR"), "/test/ring/", $relative_path_to_exe);
            assert!(std::process::Command::new(RELATIVE_PATH_TO_EXE)
                                              .args(args)
                                              .status()
                                              .unwrap()
                                              .success());
        }
    }
}

exe_test!(aes_test, "crypto/aes/aes_test", []);

#[cfg(not(feature = "no_heap"))]
exe_test!(bn_test, "crypto/bn/bn_test", []);

#[cfg(not(feature = "no_heap"))]
exe_test!(bytestring_test, "crypto/bytestring/bytestring_test", []);

exe_test!(constant_time_test, "crypto/constant_time_test", []);

#[cfg(not(feature = "no_heap"))]
exe_test!(ecdsa_test, "crypto/ecdsa/ecdsa_test", []);

#[cfg(not(feature = "no_heap"))] // XXX: Rewrite to avoid OPENSSL_malloc
exe_test!(poly1305_test, "crypto/poly1305/poly1305_test",
          ["crypto/poly1305/poly1305_test.txt"]);

#[cfg(not(feature = "no_heap"))]
exe_test!(rsa_test, "crypto/rsa/rsa_test", []);

exe_test!(thread_test, "crypto/thread_test", []);
