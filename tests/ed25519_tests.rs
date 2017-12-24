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
    warnings,
)]

extern crate ring;
extern crate untrusted;

use ring::{signature, test};
use signature::Ed25519KeyPair;

/// Test vectors from BoringSSL.
#[test]
fn test_signature_ed25519() {
    test::from_file("tests/ed25519_tests.txt", |section, test_case| {
        assert_eq!(section, "");
        let seed = test_case.consume_bytes("SEED");
        assert_eq!(32, seed.len());
        let seed = untrusted::Input::from(&seed);

        let public_key = test_case.consume_bytes("PUB");
        assert_eq!(32, public_key.len());
        let public_key = untrusted::Input::from(&public_key);

        let msg = test_case.consume_bytes("MESSAGE");

        let expected_sig = test_case.consume_bytes("SIG");

        {
            let key_pair = Ed25519KeyPair::from_seed_and_public_key(
                seed, public_key).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_ref());
        }

        // Test PKCS#8 generation, parsing, and private-to-public calculations.
        let rng = test::rand::FixedSliceRandom {
            bytes: seed.as_slice_less_safe()
        };
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(
            untrusted::Input::from(&pkcs8)).unwrap();
        assert_eq!(public_key, key_pair.public_key_bytes());

        // Test Signature generation.
        let actual_sig = key_pair.sign(&msg);
        assert_eq!(&expected_sig[..], actual_sig.as_ref());

        // Test Signature verification.
        assert!(signature::verify(
            &signature::ED25519, public_key, untrusted::Input::from(&msg),
            untrusted::Input::from(&expected_sig)).is_ok());
        Ok(())
    });
}

#[test]
fn test_ed25519_from_seed_and_public_key_misuse() {
    const PRIVATE_KEY: &[u8] = include_bytes!("ed25519_test_private_key.bin");
    const PUBLIC_KEY: &[u8] = include_bytes!("ed25519_test_public_key.bin");

    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(PRIVATE_KEY),
        untrusted::Input::from(PUBLIC_KEY)).is_ok());

    // Truncated private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&PRIVATE_KEY[..31]),
        untrusted::Input::from(PUBLIC_KEY)).is_err());

    // Truncated public key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(PRIVATE_KEY),
        untrusted::Input::from(&PUBLIC_KEY[..31])).is_err());

    // Swapped public and private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(PUBLIC_KEY),
        untrusted::Input::from(PRIVATE_KEY)).is_err());
}

#[test]
fn test_ed25519_from_pkcs8_unchecked() {
    // Just test that we can parse the input.
    test::from_file("tests/ed25519_from_pkcs8_unchecked_tests.txt",
                    |section, test_case| {
        assert_eq!(section, "");
        let input = test_case.consume_bytes("Input");
        let error = test_case.consume_optional_string("Error");
        assert_eq!(
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(
                untrusted::Input::from(&input)).is_ok(),
            error.is_none());
        Ok(())
    });
}

#[test]
fn test_ed25519_from_pkcs8() {
    // Just test that we can parse the input.
    test::from_file("tests/ed25519_from_pkcs8_tests.txt", |section, test_case| {
        assert_eq!(section, "");
        let input = test_case.consume_bytes("Input");
        let error = test_case.consume_optional_string("Error");
        assert_eq!(
            Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&input)).is_ok(),
            error.is_none());
        Ok(())
    });
}
