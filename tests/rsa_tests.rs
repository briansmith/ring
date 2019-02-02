// Copyright 2017 Brian Smith.
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

#[cfg(feature = "use_heap")]
use ring::{
    error,
    io::der,
    rand,
    signature::{self, KeyPair},
    test, test_file,
};

#[cfg(feature = "use_heap")]
#[test]
fn rsa_from_pkcs8_test() {
    test::run(
        test_file!("rsa_from_pkcs8_tests.txt"),
        |section, test_case| {
            use std::error::Error;

            assert_eq!(section, "");

            let input = test_case.consume_bytes("Input");
            let input = untrusted::Input::from(&input);

            let error = test_case.consume_optional_string("Error");

            match (signature::RsaKeyPair::from_pkcs8(input), error) {
                (Ok(_), None) => (),
                (Err(e), None) => panic!("Failed with error \"{}\", but expected to succeed", e),
                (Ok(_), Some(e)) => panic!("Succeeded, but expected error \"{}\"", e),
                (Err(actual), Some(expected)) => assert_eq!(actual.description(), expected),
            };

            Ok(())
        },
    );
}

#[cfg(feature = "use_heap")]
#[test]
fn test_signature_rsa_pkcs1_sign() {
    let rng = rand::SystemRandom::new();
    test::run(
        test_file!("rsa_pkcs1_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PKCS1_SHA256,
                "SHA384" => &signature::RSA_PKCS1_SHA384,
                "SHA512" => &signature::RSA_PKCS1_SHA512,
                _ => panic!("Unsupported digest: {}", digest_name),
            };

            let private_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RsaKeyPair::from_der(private_key);
            if result == "Fail-Invalid-Key" {
                assert!(key_pair.is_err());
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            let mut actual = vec![0u8; key_pair.public_modulus_len()];
            key_pair
                .sign(alg, &rng, &msg, actual.as_mut_slice())
                .unwrap();
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[cfg(feature = "use_heap")]
#[test]
fn test_signature_rsa_pss_sign() {
    test::run(
        test_file!("rsa_pss_sign_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_SHA256,
                "SHA384" => &signature::RSA_PSS_SHA384,
                "SHA512" => &signature::RSA_PSS_SHA512,
                _ => panic!("Unsupported digest: {}", digest_name),
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RsaKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let msg = test_case.consume_bytes("Msg");
            let salt = test_case.consume_bytes("Salt");
            let expected = test_case.consume_bytes("Sig");

            let rng = test::rand::FixedSliceRandom { bytes: &salt };

            let mut actual = vec![0u8; key_pair.public_modulus_len()];
            key_pair.sign(alg, &rng, &msg, actual.as_mut_slice())?;
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        },
    );
}

#[cfg(feature = "use_heap")]
#[test]
fn test_signature_rsa_pkcs1_verify() {
    test::run(
        test_file!("rsa_pkcs1_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA1" => &signature::RSA_PKCS1_2048_8192_SHA1,
                "SHA256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                "SHA384" => &signature::RSA_PKCS1_2048_8192_SHA384,
                "SHA512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                _ => panic!("Unsupported digest: {}", digest_name),
            };

            let public_key = test_case.consume_bytes("Key");
            let public_key = untrusted::Input::from(&public_key);

            // Sanity check that we correctly DER-encoded the originally-
            // provided separate (n, e) components. When we add test vectors
            // for improperly-encoded signatures, we'll have to revisit this.
            assert!(public_key
                .read_all(error::Unspecified, |input| der::nested(
                    input,
                    der::Tag::Sequence,
                    error::Unspecified,
                    |input| {
                        let _ = der::positive_integer(input)?;
                        let _ = der::positive_integer(input)?;
                        Ok(())
                    }
                ))
                .is_ok());

            let msg = test_case.consume_bytes("Msg");
            let msg = untrusted::Input::from(&msg);

            let sig = test_case.consume_bytes("Sig");
            let sig = untrusted::Input::from(&sig);

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        },
    );
}

#[cfg(feature = "use_heap")]
#[test]
fn test_signature_rsa_pss_verify() {
    test::run(
        test_file!("rsa_pss_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_2048_8192_SHA256,
                "SHA384" => &signature::RSA_PSS_2048_8192_SHA384,
                "SHA512" => &signature::RSA_PSS_2048_8192_SHA512,
                _ => panic!("Unsupported digest: {}", digest_name),
            };

            let public_key = test_case.consume_bytes("Key");
            let public_key = untrusted::Input::from(&public_key);

            // Sanity check that we correctly DER-encoded the originally-
            // provided separate (n, e) components. When we add test vectors
            // for improperly-encoded signatures, we'll have to revisit this.
            assert!(public_key
                .read_all(error::Unspecified, |input| der::nested(
                    input,
                    der::Tag::Sequence,
                    error::Unspecified,
                    |input| {
                        let _ = der::positive_integer(input)?;
                        let _ = der::positive_integer(input)?;
                        Ok(())
                    }
                ))
                .is_ok());

            let msg = test_case.consume_bytes("Msg");
            let msg = untrusted::Input::from(&msg);

            let sig = test_case.consume_bytes("Sig");
            let sig = untrusted::Input::from(&sig);

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        },
    );
}

// Test for `primitive::verify()`. Read public key parts from a file
// and use them to verify a signature.
#[cfg(feature = "use_heap")]
#[test]
fn test_signature_rsa_primitive_verification() {
    test::run(
        test_file!("rsa_primitive_verify_tests.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let n = test_case.consume_bytes("n");
            let e = test_case.consume_bytes("e");
            let msg = test_case.consume_bytes("Msg");
            let sig = test_case.consume_bytes("Sig");
            let expected = test_case.consume_string("Result");
            let result = signature::primitive::verify_rsa(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                (untrusted::Input::from(&n), untrusted::Input::from(&e)),
                untrusted::Input::from(&msg),
                untrusted::Input::from(&sig),
            );
            assert_eq!(result.is_ok(), expected == "Pass");
            Ok(())
        },
    )
}

#[cfg(feature = "use_heap")]
#[test]
fn rsa_test_public_key_coverage() {
    const PRIVATE_KEY: &'static [u8] = include_bytes!("rsa_test_private_key_2048.p8");
    const PUBLIC_KEY: &'static [u8] = include_bytes!("rsa_test_public_key_2048.der");
    const PUBLIC_KEY_DEBUG: &'static str = include_str!("rsa_test_public_key_2048_debug.txt");

    let key_pair = signature::RsaKeyPair::from_pkcs8(untrusted::Input::from(PRIVATE_KEY)).unwrap();

    // Test `AsRef<[u8]>`
    assert_eq!(key_pair.public_key().as_ref(), PUBLIC_KEY);

    // Test `Clone`.
    let _ = key_pair.public_key().clone();

    // Test `exponent()`.
    assert_eq!(
        &[0x01, 0x00, 0x01],
        key_pair
            .public_key()
            .exponent()
            .big_endian_without_leading_zero()
            .as_slice_less_safe()
    );

    // Test `Debug`
    assert_eq!(PUBLIC_KEY_DEBUG, format!("{:?}", key_pair.public_key()));
    assert_eq!(
        format!("RsaKeyPair {{ public_key: {:?} }}", key_pair.public_key()),
        format!("{:?}", key_pair)
    );
}
