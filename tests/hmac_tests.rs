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

use ring::{digest, error, hmac, test, test_file};

#[test]
fn hmac_tests() {
    test::run(test_file!("hmac_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case.consume_digest_alg("HMAC");
        let key_value = test_case.consume_bytes("Key");
        let mut input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");

        let digest_alg = match digest_alg {
            Some(digest_alg) => digest_alg,
            None => {
                return Ok(());
            }, // Unsupported digest algorithm
        };

        hmac_test_case_inner(digest_alg, &key_value[..], &input[..], &output[..], true)?;

        // Tamper with the input and check that verification fails.
        if input.is_empty() {
            input.push(0);
        } else {
            input[0] ^= 1;
        }

        hmac_test_case_inner(digest_alg, &key_value[..], &input[..], &output[..], false)
    });
}

fn hmac_test_case_inner(
    digest_alg: &'static digest::Algorithm, key_value: &[u8], input: &[u8], output: &[u8],
    is_ok: bool,
) -> Result<(), error::Unspecified> {
    let s_key = hmac::SigningKey::new(digest_alg, key_value);
    let v_key = hmac::VerificationKey::new(digest_alg, key_value);

    // One-shot API.
    {
        let signature = hmac::sign(&s_key, input);
        assert_eq!(is_ok, signature.as_ref() == output);
        assert_eq!(is_ok, hmac::verify(&v_key, input, output).is_ok());
    }

    // Multi-part API, one single part.
    {
        let mut s_ctx = hmac::SigningContext::with_key(&s_key);
        s_ctx.update(input);
        let signature = s_ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }

    // Multi-part API, byte by byte.
    {
        let mut s_ctx = hmac::SigningContext::with_key(&s_key);
        for b in input {
            s_ctx.update(&[*b]);
        }
        let signature = s_ctx.sign();
        assert_eq!(is_ok, signature.as_ref() == output);
    }

    Ok(())
}

#[test]
fn hmac_debug() {
    let key = hmac::SigningKey::new(&digest::SHA256, &[0; 32]);
    assert_eq!("SigningKey { algorithm: SHA256 }", format!("{:?}", &key));

    let ctx = hmac::SigningContext::with_key(&key);
    assert_eq!(
        "SigningContext { algorithm: SHA256 }",
        format!("{:?}", &ctx)
    );

    let key = hmac::VerificationKey::new(&digest::SHA384, &[0; 32]);
    assert_eq!(
        "VerificationKey { algorithm: SHA384 }",
        format!("{:?}", &key)
    );
}
