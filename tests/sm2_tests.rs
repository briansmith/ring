// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM2 integration tests: signing, verification, PKCS#8, and ECDH.

#![cfg(feature = "sm")]
#![allow(missing_docs)]

use ring::{
    agreement, rand,
    signature::{self, KeyPair},
};
use untrusted;

/// Test: SM2 sign/verify roundtrip with fixed-length signatures.
#[test]
fn sm2_sign_verify_fixed_roundtrip() {
    let rng = rand::SystemRandom::new();

    let key_pair = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, key_pair.as_ref(), &rng)
            .unwrap();

    let message = b"Hello, SM2!";
    let sig = key_pair.sign(&rng, message).unwrap();

    let public_key = key_pair.public_key();
    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, public_key.as_ref())
        .verify(message, sig.as_ref())
        .expect("SM2 fixed-length signature verification failed");
}

/// Test: SM2 sign/verify roundtrip with ASN.1 DER-encoded signatures.
#[test]
fn sm2_sign_verify_asn1_roundtrip() {
    let rng = rand::SystemRandom::new();

    let key_pair = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_ASN1_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_ASN1_SIGNING, key_pair.as_ref(), &rng)
            .unwrap();

    let message = b"Hello, SM2 ASN.1!";
    let sig = key_pair.sign(&rng, message).unwrap();

    let public_key = key_pair.public_key();
    signature::UnparsedPublicKey::new(&signature::SM2_SM3_ASN1, public_key.as_ref())
        .verify(message, sig.as_ref())
        .expect("SM2 ASN.1 signature verification failed");
}

/// Test: SM2 sign with custom signer ID.
#[test]
fn sm2_sign_verify_custom_id() {
    let rng = rand::SystemRandom::new();

    let key_pair = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, key_pair.as_ref(), &rng)
            .unwrap();

    let message = b"Custom ID test message";
    let signer_id = b"user@example.com";
    let sig = key_pair.sign_with_id(&rng, message, signer_id).unwrap();

    // Verification with default ID should fail (different Z value).
    let public_key = key_pair.public_key();
    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, public_key.as_ref())
        .verify(message, sig.as_ref())
        .expect_err("Verification with default ID should fail when signed with custom ID");

    // Verify using verify_with_id with the correct custom ID.
    signature::SM2_SM3_FIXED
        .verify_with_id(
            untrusted::Input::from(public_key.as_ref()),
            untrusted::Input::from(message.as_slice()),
            untrusted::Input::from(sig.as_ref()),
            signer_id,
        )
        .expect("SM2 verification with custom ID failed");
}

/// Test: tampered signature is rejected.
#[test]
fn sm2_tampered_signature_rejected() {
    let rng = rand::SystemRandom::new();

    let key_pair = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, key_pair.as_ref(), &rng)
            .unwrap();

    let message = b"Tamper test";
    let sig = key_pair.sign(&rng, message).unwrap();

    let mut tampered = sig.as_ref().to_vec();
    tampered[0] ^= 1; // Flip a bit in r.

    let public_key = key_pair.public_key();
    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, public_key.as_ref())
        .verify(message, &tampered)
        .expect_err("Tampered SM2 signature should be rejected");
}

/// Test: wrong message is rejected.
#[test]
fn sm2_wrong_message_rejected() {
    let rng = rand::SystemRandom::new();

    let key_pair = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, key_pair.as_ref(), &rng)
            .unwrap();

    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let sig = key_pair.sign(&rng, message).unwrap();

    let public_key = key_pair.public_key();
    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, public_key.as_ref())
        .verify(wrong_message, sig.as_ref())
        .expect_err("Wrong message should fail SM2 verification");
}

/// Test: PKCS#8 generate and parse roundtrip.
#[test]
fn sm2_pkcs8_roundtrip() {
    let rng = rand::SystemRandom::new();

    let pkcs8 = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair1 =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

    // Re-generate PKCS#8 from the parsed key is not possible, but we can verify
    // the public key is preserved by signing and verifying.
    let message = b"PKCS8 roundtrip test";
    let sig = key_pair1.sign(&rng, message).unwrap();
    let pub_key = key_pair1.public_key();

    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, pub_key.as_ref())
        .verify(message, sig.as_ref())
        .expect("SM2 PKCS#8 roundtrip: sign/verify failed");
}

/// Test: SM2 ECDH key agreement produces the same shared secret.
#[test]
fn sm2_ecdh_roundtrip() {
    let rng = rand::SystemRandom::new();

    let alice_private =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_SM2, &rng).unwrap();
    let alice_public = alice_private.compute_public_key().unwrap();

    let bob_private =
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_SM2, &rng).unwrap();
    let bob_public = bob_private.compute_public_key().unwrap();

    let alice_shared = agreement::agree_ephemeral(
        alice_private,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_SM2, bob_public.as_ref()),
        |s| Ok::<Vec<u8>, ()>(s.to_vec()),
    )
    .unwrap();

    let bob_shared = agreement::agree_ephemeral(
        bob_private,
        &agreement::UnparsedPublicKey::new(&agreement::ECDH_SM2, alice_public.as_ref()),
        |s| Ok::<Vec<u8>, ()>(s.to_vec()),
    )
    .unwrap();

    assert_eq!(alice_shared, bob_shared, "SM2 ECDH shared secrets don't match");
}

/// Test: SM2 from_private_key_and_public_key constructor.
#[test]
fn sm2_from_private_and_public_key() {
    let rng = rand::SystemRandom::new();

    // Generate a key pair first via PKCS#8.
    let pkcs8 = signature::Sm2KeyPair::generate_pkcs8(
        &signature::SM2_SM3_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair =
        signature::Sm2KeyPair::from_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();

    let public_key_bytes = key_pair.public_key().as_ref().to_vec();

    // Extract private key bytes from PKCS#8 (offset 0x24, length 32).
    let pkcs8_bytes = pkcs8.as_ref();
    let private_key_bytes = &pkcs8_bytes[0x24..0x44];

    let key_pair2 = signature::Sm2KeyPair::from_private_key_and_public_key(
        &signature::SM2_SM3_FIXED_SIGNING,
        private_key_bytes,
        &public_key_bytes,
        &rng,
    )
    .unwrap();

    // Both key pairs should produce signatures verifiable by the same public key.
    let message = b"from_private_key_and_public_key test";
    let sig = key_pair2.sign(&rng, message).unwrap();

    signature::UnparsedPublicKey::new(&signature::SM2_SM3_FIXED, &public_key_bytes)
        .verify(message, sig.as_ref())
        .expect("SM2 from_private_key_and_public_key: verification failed");
}
