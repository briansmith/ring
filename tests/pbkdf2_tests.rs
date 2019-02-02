// Copyright 2015-2017 Brian Smith.
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

#![forbid(
    anonymous_parameters,
    box_pointers,
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    warnings
)]

use ring::{digest, error, pbkdf2, test, test_file};
use std::num::NonZeroU32;

#[test]
pub fn pbkdf2_tests() {
    test::run(test_file!("pbkdf2_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = &test_case.consume_digest_alg("Hash").unwrap();
        let iterations = test_case.consume_usize("c");
        let iterations = NonZeroU32::new(iterations as u32).unwrap();
        let secret = test_case.consume_bytes("P");
        let salt = test_case.consume_bytes("S");
        let dk = test_case.consume_bytes("DK");
        let verify_expected_result = test_case.consume_string("Verify");
        let verify_expected_result = match verify_expected_result.as_str() {
            "OK" => Ok(()),
            "Err" => Err(error::Unspecified),
            _ => panic!("Unsupported value of \"Verify\""),
        };

        {
            let mut out = vec![0u8; dk.len()];
            pbkdf2::derive(digest_alg, iterations, &salt, &secret, &mut out);
            assert_eq!(dk == out, verify_expected_result.is_ok() || dk.is_empty());
        }

        assert_eq!(
            pbkdf2::verify(digest_alg, iterations, &salt, &secret, &dk),
            verify_expected_result
        );

        Ok(())
    });
}

// Control for pkbdf2_zero_iterations
#[test]
pub fn pbkdf2_one_iteration() {
    let secret = "ZeroIterationsTest".as_bytes();
    let iterations = NonZeroU32::new(1).unwrap();
    let salt = "salt".as_bytes();
    let mut out = vec![0u8; 2];
    pbkdf2::derive(&digest::SHA256, iterations, &salt, &secret, &mut out);
}
