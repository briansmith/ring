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

use {bn, bssl, c, core, error, private, signature};
use super::{RSAParameters, parse_public_key};
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

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $PADDING_ALGORITHM:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        ///
        /// Only available in `use_heap` mode.
        pub static $VERIFY_ALGORITHM: RSAParameters =
            RSAParameters {
                padding_alg: $PADDING_ALGORITHM,
                min_bits: $min_bits,
            };
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1, 2048, &super::padding::RSA_PKCS1_SHA1,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-1.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256, 2048, &super::RSA_PKCS1_SHA256,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-256.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384, 2048, &super::RSA_PKCS1_SHA384,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-384.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512, 2048, &super::RSA_PKCS1_SHA512,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-512.");
rsa_pkcs1!(RSA_PKCS1_3072_8192_SHA384, 3072, &super::RSA_PKCS1_SHA384,
           "Verification of signatures using RSA keys of 3072-8192 bits,
            PKCS#1.5 padding, and SHA-384.");

extern {
    fn GFp_rsa_check_modulus_and_exponent(n: *const bn::BIGNUM,
                                          e: *const bn::BIGNUM,
                                          min_bits: c::size_t,
                                          max_bits: c::size_t) -> c::int;
}

fn rsa_public_decrypt(out: &mut [u8], public_key_n: &bn::PositiveInteger,
                      public_key_e: &bn::PositiveInteger, ciphertext: &[u8],
                      min_bits: usize, max_bits: usize)
                      -> Result<(), error::Unspecified> {
    // We define this closure as a translation of `goto`. We want to use
    // an early-return code style, but we also need to manually free any
    // heap-allocated |BIGNUM| substructures using a foreign call.
    let mut decrypt = |f: *mut bn::BIGNUM, result: *mut bn::BIGNUM| {
        let rsa_size: usize = unsafe {
            bn::GFp_BN_num_bytes(public_key_n.as_ref())
        };

        if out.len() != rsa_size {
            // RSA_R_OUTPUT_BUFFER_TOO_SMALL
            return Err(error::Unspecified);
        }

        if ciphertext.len() != rsa_size {
            // RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN
            return Err(error::Unspecified);
        }

        try!(bssl::map_result(unsafe {
            GFp_rsa_check_modulus_and_exponent(public_key_n.as_ref(),
                                               public_key_e.as_ref(),
                                               min_bits, max_bits)
        }));

        let ret = unsafe {
            bn::GFp_BN_bin2bn(ciphertext.as_ptr(), ciphertext.len(), f)
        };
        if ret.is_null() {
            return Err(error::Unspecified);
        }

        if unsafe { bn::GFp_BN_ucmp(f, public_key_n.as_ref()) } >= 0 {
            // RSA_R_DATA_TOO_LARGE_FOR_MODULUS
            return Err(error::Unspecified);
        }

        try!(bssl::map_result(unsafe {
            bn::GFp_BN_mod_exp_mont_vartime(result, f, public_key_e.as_ref(),
                                        public_key_n.as_ref(),
                                        core::ptr::null())
        }));

        try!(bssl::map_result(unsafe {
            bn::GFp_BN_bn2bin_padded(out.as_mut_ptr(), out.len(), result)
        }));

        Ok(())
    };

    let mut f = bn::BIGNUM::new();
    let mut result = bn::BIGNUM::new();

    let res = decrypt(&mut f, &mut result);

    unsafe {
        bn::GFp_BN_free(&mut result);
        bn::GFp_BN_free(&mut f);
    }

    res
}

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
    const MAX_BITS: usize = 8192;

    let signature = signature.as_slice_less_safe();
    let mut decoded = [0u8; (MAX_BITS + 7) / 8];
    if signature.len() > decoded.len() {
        return Err(error::Unspecified);
    }

    let n = try!(bn::PositiveInteger::from_be_bytes(n));
    let e = try!(bn::PositiveInteger::from_be_bytes(e));
    let decoded = &mut decoded[..signature.len()];

    try!(rsa_public_decrypt(decoded, &n, &e, signature, params.min_bits,
                            MAX_BITS));

    params.padding_alg.verify(msg, untrusted::Input::from(decoded))
}


#[cfg(test)]
mod tests {
    use {der, error, signature, test};

    use super::*;
    use untrusted;

    #[test]
    fn test_signature_rsa_pkcs1_verify() {
        test::from_file("src/rsa/rsa_pkcs1_verify_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = if digest_name == "SHA1" {
                &RSA_PKCS1_2048_8192_SHA1
            } else if digest_name == "SHA256" {
                &RSA_PKCS1_2048_8192_SHA256
            } else if digest_name == "SHA384" {
                &RSA_PKCS1_2048_8192_SHA384
            } else if digest_name == "SHA512" {
                &RSA_PKCS1_2048_8192_SHA512
            } else {
                panic!("Unsupported digest: {}", digest_name);
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
            let result = verify_rsa(&RSA_PKCS1_2048_8192_SHA256,
                                    (untrusted::Input::from(&n),
                                     untrusted::Input::from(&e)),
                                    untrusted::Input::from(&msg),
                                    untrusted::Input::from(&sig));
            assert_eq!(result.is_ok(), expected == "Pass");
            Ok(())
        })
    }
}
