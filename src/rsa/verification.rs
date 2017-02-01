// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// RSA PKCS#1 1.5 signatures.

use {bits, digest, error, private, signature};
use super::{bigint, N, PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN, RSAParameters,
            parse_public_key};
use untrusted;


impl signature::VerificationAlgorithm for RSAParameters {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input)
              -> Result<(), error::Unspecified> {
        let public_key = try!(parse_public_key(public_key));
        verify_rsa(self, public_key, msg, signature)
    }
}

impl private::Private for RSAParameters {}

macro_rules! rsa_params {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $PADDING_ALGORITHM:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        ///
        /// Only available in `use_heap` mode.
        pub static $VERIFY_ALGORITHM: RSAParameters =
            RSAParameters {
                padding_alg: $PADDING_ALGORITHM,
                min_bits: bits::BitLength($min_bits),
            };
    }
}

rsa_params!(RSA_PKCS1_2048_8192_SHA1, 2048, &super::padding::RSA_PKCS1_SHA1,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-1.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PKCS1_2048_8192_SHA256, 2048, &super::RSA_PKCS1_SHA256,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-256.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PKCS1_2048_8192_SHA384, 2048, &super::RSA_PKCS1_SHA384,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-384.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PKCS1_2048_8192_SHA512, 2048, &super::RSA_PKCS1_SHA512,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PKCS#1.5 padding, and SHA-512.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PKCS1_3072_8192_SHA384, 3072, &super::RSA_PKCS1_SHA384,
            "Verification of signatures using RSA keys of 3072-8192 bits,
             PKCS#1.5 padding, and SHA-384.\n\nSee \"`RSA_PKCS1_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");

rsa_params!(RSA_PSS_2048_8192_SHA256, 2048, &super::RSA_PSS_SHA256,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-256.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PSS_2048_8192_SHA384, 2048, &super::RSA_PSS_SHA384,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-384.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");
rsa_params!(RSA_PSS_2048_8192_SHA512, 2048, &super::RSA_PSS_SHA512,
            "Verification of signatures using RSA keys of 2048-8192 bits,
             PSS padding, and SHA-512.\n\nSee \"`RSA_PSS_*` Details\" in
             `ring::signature`'s module-level documentation for more details.");


/// Lower-level API for the verification of RSA signatures.
///
/// When the public key is in DER-encoded PKCS#1 ASN.1 format, it is
/// recommended to use `ring::signature::verify()` with
/// `ring::signature::RSA_PKCS1_*`, because `ring::signature::verify()`
/// will handle the parsing in that case. Otherwise, this function can be used
/// to pass in the raw bytes for the public key components as
/// `untrusted::Input` arguments.
///
/// `params` determine what algorithm parameters (padding, digest algorithm,
/// key length range, etc.) are used in the verification. `msg` is the message
/// and `signature` is the signature.
///
/// `n` is the public key modulus and `e` is the public key exponent. Both are
/// interpreted as unsigned big-endian encoded values. Both must be positive
/// and neither may have any leading zeros.
//
// There are a small number of tests that test `verify_rsa` directly, but the
// test coverage for this function mostly depends on the test coverage for the
// `signature::VerificationAlgorithm` implementation for `RSAParameters`. If we
// change that, test coverage for `verify_rsa()` will need to be reconsidered.
// (The NIST test vectors were originally in a form that was optimized for
// testing `verify_rsa` directly, but the testing work for RSA PKCS#1
// verification was done during the implementation of
// `signature::VerificationAlgorithm`, before `verify_rsa` was factored out).
pub fn verify_rsa(params: &RSAParameters,
                  (n, e): (untrusted::Input, untrusted::Input),
                  msg: untrusted::Input, signature: untrusted::Input)
                  -> Result<(), error::Unspecified> {
    // Partially validate the public key. See
    // `check_public_modulus_and_exponent()` for more details.
    let n = try!(bigint::Positive::from_be_bytes(n));
    let e = try!(bigint::Positive::from_be_bytes(e));
    let max_bits = try!(bits::BitLength::from_usize_bytes(
        PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN));
    let (n, e) =
        try!(super::check_public_modulus_and_exponent(n, e, params.min_bits,
                                                      max_bits));
    let n_bits = n.bit_length();

    // The signature must be the same length as the modulus, in bytes.
    if signature.len() != n_bits.as_usize_bytes_rounded_up() {
        return Err(error::Unspecified);
    }

    // RFC 8017 Section 5.2.2: RSAVP1.

    // Step 1.
    let s = try!(bigint::Positive::from_be_bytes_padded(signature));
    let s = try!(s.into_elem_decoded::<N>(&n));

    // Step 2.
    let m = try!(bigint::elem_exp_vartime(s, e, &n));

    // Step 3.
    let mut decoded = [0u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN];
    let decoded = &mut decoded[..n_bits.as_usize_bytes_rounded_up()];
    try!(m.fill_be_bytes(decoded));

    // Verify the padded message is correct.
    let m_hash = digest::digest(params.padding_alg.digest_alg(),
                                msg.as_slice_less_safe());
    untrusted::Input::from(decoded).read_all(
        error::Unspecified, |m| params.padding_alg.verify(&m_hash, m, n_bits))
}


#[cfg(test)]
mod tests {
    // We intentionally avoid `use super::*` so that we are sure to use only
    // the public API; this ensures that enough of the API is public.
    use {der, error, signature, test};
    use untrusted;

    #[test]
    fn test_signature_rsa_pkcs1_verify() {
        test::from_file("src/rsa/rsa_pkcs1_verify_tests.txt",
                        |section, test_case| {
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
                der::nested(input, der::Tag::Sequence, error::Unspecified,
                            |input| {
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
        test::from_file("src/rsa/rsa_pss_verify_tests.txt",
                        |section, test_case| {
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
                der::nested(input, der::Tag::Sequence, error::Unspecified,
                            |input| {
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
        test::from_file("src/rsa/rsa_primitive_verify_tests.txt",
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
}
