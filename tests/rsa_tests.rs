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

extern crate ring;
extern crate untrusted;

use ring::{der, error, signature, test};

#[cfg(feature = "rsa_signing")]
use ring::rand;


#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_rsa_encryption_2048() {
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_rsaEncryption_2048_e65537.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_ok());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_rsa_encryption_3072() {
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_rsaEncryption_3072_e65537.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_ok());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_rsa_encryption_invalid_e3() {
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_rsaEncryption_2048_e3.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_err());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_rsa_encryption_2048_truncated() {
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_rsaEncryption_2048_e65537.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(&INPUT[..(INPUT.len() - 1)])).is_err());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_ecc() {
    // The input is a valid P-256 private key, which isn't a valid RSA key.
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_ecPublicKey_p256.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_err());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_rsa_encryption_ecc() {
    // The input's algorithm ID is rsaEncryption, but it contains a P-256
    // ECPrivateKey.
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_rsaEncryption_ecc.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_err());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_from_pkcs8_ecc_rsa_private_key() {
    // The input contains an RSAPrivateKey, but marked as an ecPublicKey w/
    // P-256.
    const INPUT: &'static [u8] =
        include_bytes!("pkcs8_test_ecPublicKey_p256_RSAPrivateKey.pk8");
    assert!(signature::RSAKeyPair::from_pkcs8(
        untrusted::Input::from(INPUT)).is_err());
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_signature_rsa_pkcs1_sign() {
    let rng = rand::SystemRandom::new();
    test::from_file("tests/rsa_pkcs1_sign_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let digest_name = test_case.consume_string("Digest");
        let alg = match digest_name.as_ref() {
            "SHA256" => &signature::RSA_PKCS1_SHA256,
            "SHA384" => &signature::RSA_PKCS1_SHA384,
            "SHA512" => &signature::RSA_PKCS1_SHA512,
            _ => { panic!("Unsupported digest: {}", digest_name) }
        };

        let private_key = test_case.consume_bytes("Key");
        let msg = test_case.consume_bytes("Msg");
        let expected = test_case.consume_bytes("Sig");
        let result = test_case.consume_string("Result");

        let private_key = untrusted::Input::from(&private_key);
        let key_pair = signature::RSAKeyPair::from_der(private_key);
        if result == "Fail-Invalid-Key" {
            assert!(key_pair.is_err());
            return Ok(());
        }
        let key_pair = key_pair.unwrap();
        let key_pair = std::sync::Arc::new(key_pair);

        // XXX: This test is too slow on Android ARM Travis CI builds.
        // TODO: re-enable these tests on Android ARM.
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();
        let mut actual: std::vec::Vec<u8> =
            vec![0; signing_state.key_pair().public_modulus_len()];
        signing_state.sign(alg, &rng, &msg, actual.as_mut_slice()).unwrap();
        assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
        Ok(())
    });
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_signature_rsa_pss_sign() {
    // Outputs the same value whenever a certain length is requested (the same
    // as the length of the salt). Otherwise, the rng is used.
    struct DeterministicSalt<'a> {
        salt: &'a [u8],
        rng: &'a rand::SecureRandom
    }
    impl<'a> rand::SecureRandom for DeterministicSalt<'a> {
        fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
            let dest_len = dest.len();
            if dest_len != self.salt.len() {
                try!(self.rng.fill(dest));
            } else {
                dest.copy_from_slice(&self.salt);
            }
            Ok(())
        }
    }
    let rng = rand::SystemRandom::new();

    test::from_file("tests/rsa_pss_sign_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let digest_name = test_case.consume_string("Digest");
        let alg = match digest_name.as_ref() {
            "SHA256" => &signature::RSA_PSS_SHA256,
            "SHA384" => &signature::RSA_PSS_SHA384,
            "SHA512" => &signature::RSA_PSS_SHA512,
            _ =>  { panic!("Unsupported digest: {}", digest_name) }
        };

        let result = test_case.consume_string("Result");
        let private_key = test_case.consume_bytes("Key");
        let private_key = untrusted::Input::from(&private_key);
        let key_pair = signature::RSAKeyPair::from_der(private_key);
        if key_pair.is_err() && result == "Fail-Invalid-Key" {
            return Ok(());
        }
        let key_pair = key_pair.unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let msg = test_case.consume_bytes("Msg");
        let salt = test_case.consume_bytes("Salt");
        let expected = test_case.consume_bytes("Sig");

        let new_rng = DeterministicSalt { salt: &salt, rng: &rng };

        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();
        let mut actual: std::vec::Vec<u8> =
            vec![0; signing_state.key_pair().public_modulus_len()];
        try!(signing_state.sign(alg, &new_rng, &msg, actual.as_mut_slice()));
        assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
        Ok(())
    });
}

#[cfg(feature = "rsa_signing")]
#[test]
fn test_rsa_key_pair_sync_and_send() {
    const PRIVATE_KEY_DER: &'static [u8] =
        include_bytes!("../src/rsa/signature_rsa_example_private_key.der");
    let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
    let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
    let key_pair = std::sync::Arc::new(key_pair);

    let _: &Send = &key_pair;
    let _: &Sync = &key_pair;

    let signing_state = signature::RSASigningState::new(key_pair).unwrap();
    let _: &Send = &signing_state;
    // TODO: Test that signing_state is NOT Sync; i.e.
    // `let _: &Sync = &signing_state;` must fail
}


#[test]
fn test_signature_rsa_pkcs1_verify() {
    test::from_file("tests/rsa_pkcs1_verify_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let digest_name = test_case.consume_string("Digest");
        let alg = match digest_name.as_ref() {
            "SHA1" => &signature::RSA_PKCS1_2048_8192_SHA1,
            "SHA256" => &signature::RSA_PKCS1_2048_8192_SHA256,
            "SHA384" => &signature::RSA_PKCS1_2048_8192_SHA384,
            "SHA512" => &signature::RSA_PKCS1_2048_8192_SHA512,
            _ =>  { panic!("Unsupported digest: {}", digest_name) }
        };

        let public_key = test_case.consume_bytes("Key");
        let public_key = untrusted::Input::from(&public_key);

        // Sanity check that we correctly DER-encoded the originally-
        // provided separate (n, e) components. When we add test vectors
        // for improperly-encoded signatures, we'll have to revisit this.
        assert!(public_key.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let _ = try!(der::positive_integer(input));
                let _ = try!(der::positive_integer(input));
                Ok(())
            })
        }).is_ok());

        let msg = test_case.consume_bytes("Msg");
        let msg = untrusted::Input::from(&msg);

        let sig = test_case.consume_bytes("Sig");
        let sig = untrusted::Input::from(&sig);

        let expected_result = test_case.consume_string("Result");

        let actual_result = signature::verify(alg, public_key, msg, sig);
        assert_eq!(actual_result.is_ok(), expected_result == "P");

        Ok(())
    });
}

#[test]
fn test_signature_rsa_pss_verify() {
    test::from_file("tests/rsa_pss_verify_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let digest_name = test_case.consume_string("Digest");
        let alg = match digest_name.as_ref() {
            "SHA256" => &signature::RSA_PSS_2048_8192_SHA256,
            "SHA384" => &signature::RSA_PSS_2048_8192_SHA384,
            "SHA512" => &signature::RSA_PSS_2048_8192_SHA512,
            _ =>  { panic!("Unsupported digest: {}", digest_name) }
        };

        let public_key = test_case.consume_bytes("Key");
        let public_key = untrusted::Input::from(&public_key);

        // Sanity check that we correctly DER-encoded the originally-
        // provided separate (n, e) components. When we add test vectors
        // for improperly-encoded signatures, we'll have to revisit this.
        assert!(public_key.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let _ = try!(der::positive_integer(input));
                let _ = try!(der::positive_integer(input));
                Ok(())
            })
        }).is_ok());

        let msg = test_case.consume_bytes("Msg");
        let msg = untrusted::Input::from(&msg);

        let sig = test_case.consume_bytes("Sig");
        let sig = untrusted::Input::from(&sig);

        let expected_result = test_case.consume_string("Result");

        let actual_result = signature::verify(alg, public_key, msg, sig);
        assert_eq!(actual_result.is_ok(), expected_result == "P");

        Ok(())
    });
}

// Test for `primitive::verify()`. Read public key parts from a file
// and use them to verify a signature.
#[test]
fn test_signature_rsa_primitive_verification() {
    test::from_file("tests/rsa_primitive_verify_tests.txt",
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
            untrusted::Input::from(&msg), untrusted::Input::from(&sig));
        assert_eq!(result.is_ok(), expected == "Pass");
        Ok(())
    })
}
