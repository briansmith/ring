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

use ring::{error, hkdf, hmac, test, test_file};

#[test]
fn hkdf_tests() {
    test::run(test_file!("hkdf_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case
            .consume_digest_alg("Hash")
            .ok_or(error::Unspecified)?;
        let secret = test_case.consume_bytes("IKM");
        let salt = test_case.consume_bytes("salt");
        let info = test_case.consume_bytes("info");
        let _ = test_case.consume_bytes("PRK");
        let expected_out = test_case.consume_bytes("OKM");

        let salt = hmac::SigningKey::new(digest_alg, &salt);

        let mut out = vec![0u8; expected_out.len()];
        hkdf::extract_and_expand(&salt, &secret, &info, &mut out);
        assert_eq!(out, expected_out);

        Ok(())
    });
}
