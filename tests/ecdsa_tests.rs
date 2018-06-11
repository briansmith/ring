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
    warnings,
)]

extern crate ring;
extern crate untrusted;

use ring::{rand, signature, test};

// ECDSA *signing* tests are in src/ec/ecdsa/signing.rs.

#[test]
fn ecdsa_from_pkcs8_test() {
    test::from_file("tests/ecdsa_from_pkcs8_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let ((this_fixed, this_asn1), (other_fixed, other_asn1)) =
            match curve_name.as_str() {
                "P-256" => ((&signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                             &signature::ECDSA_P256_SHA256_ASN1_SIGNING),
                            (&signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                             &signature::ECDSA_P384_SHA384_ASN1_SIGNING)),
                "P-384" => ((&signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                             &signature::ECDSA_P384_SHA384_ASN1_SIGNING),
                            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                             &signature::ECDSA_P256_SHA256_ASN1_SIGNING)),
                _ => unreachable!(),
            };

        let input = test_case.consume_bytes("Input");
        let input = untrusted::Input::from(&input);

        let error = test_case.consume_optional_string("Error");

        assert_eq!(
            signature::key_pair_from_pkcs8(this_fixed, input).is_ok(),
            error.is_none());
        assert_eq!(
            signature::key_pair_from_pkcs8(this_asn1, input).is_ok(),
            error.is_none());
        assert!(
            signature::key_pair_from_pkcs8(other_fixed, input).is_err());
        assert!(
            signature::key_pair_from_pkcs8(other_asn1, input).is_err());

        Ok(())
    });
}

// Verify that, at least, we generate PKCS#8 documents that we can read.
#[test]
fn ecdsa_generate_pkcs8_test() {
    let rng = rand::SystemRandom::new();

    for alg in &[&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                 &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                 &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                 &signature::ECDSA_P384_SHA384_FIXED_SIGNING] {
        let pkcs8 = signature::ECDSAKeyPair::generate_pkcs8(alg, &rng).unwrap();
        println!();
        for b in pkcs8.as_ref() {
            print!("{:02x}", *b);
        }
        println!();
        println!();
        let _ = signature::key_pair_from_pkcs8(
            *alg, untrusted::Input::from(pkcs8.as_ref())).unwrap();
    }
}

#[test]
fn signature_ecdsa_verify_asn1_test() {
    test::from_file("tests/ecdsa_verify_asn1_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let msg = untrusted::Input::from(&msg);

        let public_key = test_case.consume_bytes("Q");
        let public_key = untrusted::Input::from(&public_key);

        let sig = test_case.consume_bytes("Sig");
        let sig = untrusted::Input::from(&sig);

        let expected_result = test_case.consume_string("Result");

        let alg = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_ASN1,
            ("P-256", "SHA384") => &signature::ECDSA_P256_SHA384_ASN1,
            ("P-384", "SHA256") => &signature::ECDSA_P384_SHA256_ASN1,
            ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_ASN1,
            _ => {
                panic!("Unsupported curve+digest: {}+{}", curve_name,
                       digest_name);
            }
        };

        let actual_result = signature::verify(alg, public_key, msg, sig);
        assert_eq!(actual_result.is_ok(), expected_result == "P (0 )");

        Ok(())
    });
}

#[test]
fn signature_ecdsa_verify_fixed_test() {
    test::from_file("tests/ecdsa_verify_fixed_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let digest_name = test_case.consume_string("Digest");

        let msg = test_case.consume_bytes("Msg");
        let msg = untrusted::Input::from(&msg);

        let public_key = test_case.consume_bytes("Q");
        let public_key = untrusted::Input::from(&public_key);

        let sig = test_case.consume_bytes("Sig");
        let sig = untrusted::Input::from(&sig);

        let expected_result = test_case.consume_string("Result");

        let alg = match (curve_name.as_str(), digest_name.as_str()) {
            ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_FIXED,
            ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_FIXED,
            _ => {
                panic!("Unsupported curve+digest: {}+{}", curve_name,
                       digest_name);
            }
        };

        let actual_result = signature::verify(alg, public_key, msg, sig);
        assert_eq!(actual_result.is_ok(), expected_result == "P (0 )");

        Ok(())
    });
}
