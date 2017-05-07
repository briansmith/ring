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

extern crate ring;
extern crate untrusted;

use ring::{rand, signature, test};
use signature::Ed25519KeyPair;

/// Test vectors from BoringSSL.
#[test]
fn test_signature_ed25519() {
    test::from_file("tests/ed25519_tests.txt", |section, test_case| {
        assert_eq!(section, "");
        let private_key = test_case.consume_bytes("PRIV");
        assert_eq!(64, private_key.len());
        let public_key = test_case.consume_bytes("PUB");
        assert_eq!(32, public_key.len());
        let msg = test_case.consume_bytes("MESSAGE");
        let expected_sig = test_case.consume_bytes("SIG");

        let key_pair =
            Ed25519KeyPair::from_seed_and_public_key(
                untrusted::Input::from(&private_key[..32]),
                untrusted::Input::from(&public_key)).unwrap();
        let actual_sig = key_pair.sign(&msg);
        assert_eq!(&expected_sig[..], actual_sig.as_ref());

        let public_key = untrusted::Input::from(&public_key);
        let msg = untrusted::Input::from(&msg);
        let expected_sig = untrusted::Input::from(&expected_sig);

        assert!(signature::verify(&signature::ED25519, public_key, msg,
                                  expected_sig).is_ok());
        Ok(())
    });
}

#[test]
fn test_ed25519_from_seed_and_public_key_misuse() {
    let rng = rand::SystemRandom::new();
    let (_, bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();

    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&bytes.private_key),
        untrusted::Input::from(&bytes.public_key)).is_ok());

    // Truncated private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&bytes.private_key[..31]),
        untrusted::Input::from(&bytes.public_key)).is_err());

    // Truncated public key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&bytes.private_key),
        untrusted::Input::from(&bytes.public_key[..31])).is_err());

    // Swapped public and private key.
    assert!(Ed25519KeyPair::from_seed_and_public_key(
        untrusted::Input::from(&bytes.public_key),
        untrusted::Input::from(&bytes.private_key)).is_err());
}
