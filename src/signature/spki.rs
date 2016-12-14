// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use der;
use signature;
use untrusted;

/// An error that occurs during certificate validation or name validation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VerifyWithSPKIError {
    /// The encoding of some ASN.1 DER-encoded item is invalid.
    BadDER,

    /// The signature is invalid for the given public key.
    InvalidSignatureForPublicKey,

    /// The SignatureAlgorithm does not match the algorithm of the SPKI.
    /// A mismatch could be because of the algorithm (RSA vs DSA, etc) or the
    /// parameters (ECDSA_p256 vs ECDSA_384, etc).
    UnsupportedSignatureAlgorithmForPublicKey,

}

pub fn verify_signature(signature_alg: &SignatureAlgorithm,
                        spki_value: untrusted::Input, msg: untrusted::Input,
                        signature: untrusted::Input) -> Result<(), VerifyWithSPKIError> {
    let spki = try!(parse_spki_value(spki_value));
    if !signature_alg.public_key_alg_id
        .matches_algorithm_id_value(spki.algorithm_id_value) {
        return Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey);
    }
    signature::verify(signature_alg.verification_alg, spki.key_value, msg,
                      signature)
        .map_err(|_| VerifyWithSPKIError::InvalidSignatureForPublicKey)
}

struct SubjectPublicKeyInfo<'a> {
    algorithm_id_value: untrusted::Input<'a>,
    key_value: untrusted::Input<'a>,
}

// Parse the public key into an algorithm OID, an optional curve OID, and the
// key value. The caller needs to check whether these match the
// `PublicKeyAlgorithm` for the `SignatureAlgorithm` that is matched when
// parsing the signature.
fn parse_spki_value(input: untrusted::Input)
                    -> Result<SubjectPublicKeyInfo, VerifyWithSPKIError> {
    input.read_all(VerifyWithSPKIError::BadDER, |input| {
        let algorithm_id_value =
        try!(der::expect_tag_and_get_value(input, der::Tag::Sequence)
            .map_err(|_| VerifyWithSPKIError::BadDER));
        let key_value = try!(der::bit_string_with_no_unused_bits(input)
            .map_err(|_| VerifyWithSPKIError::BadDER));
        Ok(SubjectPublicKeyInfo {
            algorithm_id_value: algorithm_id_value,
            key_value: key_value,
        })
    })
}


/// A signature algorithm.
pub struct SignatureAlgorithm {
    public_key_alg_id: AlgorithmIdentifier,
    signature_alg_id: AlgorithmIdentifier,
    verification_alg: &'static signature::VerificationAlgorithm,
}

// RFC 5758 Section 3.2 (ECDSA with SHA-2), and RFC 3279 Section 2.2.3 (ECDSA
// with SHA-1) say that parameters must be omitted. RFC 4055 Section 5 and RFC
// 3279 Section 2.2.1 both say that parameters for RSA must be encoded as NULL;
// we relax that requirement by allowing the NULL to be omitted, to match all
// the other signature algorithms we support and for compatibility.

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P256,
    signature_alg_id: ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P256,
    signature_alg_id: ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P384,
    signature_alg_id: ECDSA_SHA256,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: ECDSA_P384,
    signature_alg_id: ECDSA_SHA384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

/// RSA PKCS#1 1.5 signatures using SHA-1 for keys of 2048-8192 bits.
/// Deprecated.
pub static RSA_PKCS1_2048_8192_SHA1: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA1,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA1,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA256,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA512,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PKCS1_SHA384,
    verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: SignatureAlgorithm =
SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA256,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
};

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: SignatureAlgorithm =
SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA384,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
};

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: SignatureAlgorithm =
SignatureAlgorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    signature_alg_id: RSA_PSS_SHA512,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
};

struct AlgorithmIdentifier {
    asn1_id_value: &'static [u8],
}

impl AlgorithmIdentifier {
    fn matches_algorithm_id_value(&self, encoded: untrusted::Input) -> bool {
        encoded == self.asn1_id_value
    }
}

// See src/data/README.md.

const ECDSA_P256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p256.der"),
};

const ECDSA_P384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p384.der"),
};

const ECDSA_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-sha256.der"),
};

const ECDSA_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-sha384.der"),
};

const RSA_ENCRYPTION: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-encryption.der"),
};

const RSA_PKCS1_SHA1: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha1.der"),
};

const RSA_PKCS1_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha256.der"),
};

const RSA_PKCS1_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha384.der"),
};

const RSA_PKCS1_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pkcs1-sha512.der"),
};

const RSA_PSS_SHA256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha256.der"),
};

const RSA_PSS_SHA384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha384.der"),
};

const RSA_PSS_SHA512: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-pss-sha512.der"),
};


#[cfg(test)]
mod tests {
    use rustc_serialize::base64::FromBase64;
    use std;
    use std::io::BufRead;
    use der;
    use untrusted;
    use signature::spki;
    use signature::spki::VerifyWithSPKIError;

    // TODO: The expected results need to be modified for SHA-1 deprecation.

    macro_rules! test_verify_signature {
        ($fn_name:ident, $file_name:expr, $signature_alg:expr, $expected_result:expr) => {
            #[test]
            fn $fn_name() {
                test_verify_signature($file_name, $signature_alg, $expected_result);
            }
        }
    }

    fn test_verify_signature(file_name: &str,
                             signature_algorithm: &'static spki::SignatureAlgorithm,
                             expected_result: Result<(), VerifyWithSPKIError>) {
        let tsd = parse_test_signed_data(file_name);
        let spki_value = untrusted::Input::from(&tsd.spki);
        let spki_value = spki_value.read_all(VerifyWithSPKIError::BadDER, |input| {
            der::expect_tag_and_get_value(input, der::Tag::Sequence)
                .map_err(|_| VerifyWithSPKIError::BadDER)
        }).unwrap();

        let signature = untrusted::Input::from(&tsd.signature);
        let signature = signature.read_all(VerifyWithSPKIError::BadDER, |input| {
            der::bit_string_with_no_unused_bits(input)
                .map_err(|_| VerifyWithSPKIError::BadDER)
        }).unwrap();

        assert_eq!(expected_result,
        spki::verify_signature(signature_algorithm,
                               spki_value,
                               untrusted::Input::from(&tsd.data),
                               signature));
    }

    // XXX: This is testing code that is not even in this module.
    macro_rules! test_parse_spki_bad_outer {
        ($fn_name:ident, $file_name:expr, $error:expr) => {
            #[test]
            fn $fn_name() {
                test_parse_spki_bad_outer($file_name, $error)
            }
        }
    }

    fn test_parse_spki_bad_outer(file_name: &str, expected_error: VerifyWithSPKIError) {
        let tsd = parse_test_signed_data(file_name);
        let spki = untrusted::Input::from(&tsd.spki);
        assert_eq!(Err(expected_error),
        spki.read_all(VerifyWithSPKIError::BadDER, |input| {
            der::expect_tag_and_get_value(input, der::Tag::Sequence)
                .map_err(|_| VerifyWithSPKIError::BadDER)
        }));
    }

    // XXX: Some of the BadDER tests should have better error codes, maybe?

    test_verify_signature!(test_ecdsa_secp384r1_sha256_corrupted_data,
                             "ecdsa-secp384r1-sha256-corrupted-data.pem",
                             &spki::ECDSA_P384_SHA256,
                             Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
    test_verify_signature!(test_ecdsa_secp384r1_sha256,
                             "ecdsa-secp384r1-sha256.pem",
                              &spki::ECDSA_P384_SHA256,
                              Ok(()));
    test_verify_signature!(
        test_ecdsa_using_rsa_key, "ecdsa-using-rsa-key.pem",
        &spki::ECDSA_P256_SHA256,
        Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));

    // TODO this only tests DER decoding, not signature logic
    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha1_bad_key_der_length,
                               "rsa-pkcs1-sha1-bad-key-der-length.pem",
                               VerifyWithSPKIError::BadDER);
    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha1_bad_key_der_null,
                               "rsa-pkcs1-sha1-bad-key-der-null.pem",
                               VerifyWithSPKIError::BadDER);
    test_verify_signature!(test_rsa_pkcs1_sha1_key_params_absent,
                             "rsa-pkcs1-sha1-key-params-absent.pem",
                             &spki::RSA_PKCS1_2048_8192_SHA1,
                             Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
    // We only support rsa keys identified as "rsaEncyrption", not rsa pss, so this is really only
    // a test that "rsaEncryption" != "rsassapss", not about params.
    test_verify_signature!( test_rsa_pkcs1_sha1_using_pss_key_no_params,
        "rsa-pkcs1-sha1-using-pss-key-no-params.pem",
        &spki::RSA_PKCS1_2048_8192_SHA1,
        Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
    // XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
    // 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
    // our results differ from Chromium's. TODO: this means we need a 2048+ bit
    // version of this test.
    test_verify_signature!(test_rsa_pkcs1_sha1,
                           "rsa-pkcs1-sha1.pem",
                           &spki::RSA_PKCS1_2048_8192_SHA1,
                           Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
    // XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
    // 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
    // our results differ from Chromium's. TODO: this means we need a 2048+ bit
    // version of this test.
    test_verify_signature!(test_rsa_pkcs1_sha256,
                           "rsa-pkcs1-sha256.pem",
                           &spki::RSA_PKCS1_2048_8192_SHA256,
                           Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
    // TODO this only tests DER decoding, not signature logic
    test_parse_spki_bad_outer!(test_rsa_pkcs1_sha256_key_encoded_ber,
                               "rsa-pkcs1-sha256-key-encoded-ber.pem",
                               VerifyWithSPKIError::BadDER);
    test_verify_signature!(test_rsa_pkcs1_sha256_spki_non_null_params,
                             "rsa-pkcs1-sha256-spki-non-null-params.pem",
                             &spki::RSA_PKCS1_2048_8192_SHA256,
                             Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
    test_verify_signature!(
        test_rsa_pkcs1_sha256_using_id_ea_rsa,
        "rsa-pkcs1-sha256-using-id-ea-rsa.pem",
        &spki::RSA_PKCS1_2048_8192_SHA256,
        Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));

    /// Our PSS tests that should work.
    test_verify_signature!(
        test_rsa_pss_sha256_salt32,
        "ours/rsa-pss-sha256-salt32.pem",
        &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        Ok(()));
    test_verify_signature!(
        test_rsa_pss_sha384_salt48,
        "ours/rsa-pss-sha384-salt48.pem",
        &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        Ok(()));
    test_verify_signature!(
        test_rsa_pss_sha512_salt64,
        "ours/rsa-pss-sha512-salt64.pem",
        &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        Ok(()));
    test_verify_signature!(
        test_rsa_pss_sha256_salt32_corrupted_data,
        "ours/rsa-pss-sha256-salt32-corrupted-data.pem",
        &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
    test_verify_signature!(
        test_rsa_pss_sha384_salt48_corrupted_data,
        "ours/rsa-pss-sha384-salt48-corrupted-data.pem",
        &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
    test_verify_signature!(
        test_rsa_pss_sha512_salt64_corrupted_data,
        "ours/rsa-pss-sha512-salt64-corrupted-data.pem",
        &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

    test_verify_signature!(
        test_rsa_using_ec_key, "rsa-using-ec-key.pem",
        &spki::RSA_PKCS1_2048_8192_SHA256,
        Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
    test_verify_signature!(test_rsa2048_pkcs1_sha512,
                           "rsa2048-pkcs1-sha512.pem",
                           &spki::RSA_PKCS1_2048_8192_SHA512,
                           Ok(()));

    struct TestSignedData {
        spki: std::vec::Vec<u8>,
        data: std::vec::Vec<u8>,
        signature: std::vec::Vec<u8>
    }

    fn parse_test_signed_data(file_name: &str) -> TestSignedData {
        let path =
        std::path::PathBuf::from(
            "third-party/chromium/data/verify_signed_data").join(file_name);
        let file = std::fs::File::open(path).unwrap();
        let mut lines = std::io::BufReader::new(&file).lines();

        let spki = read_pem_section(&mut lines, "PUBLIC KEY");
        let data = read_pem_section(&mut lines, "DATA");
        let signature = read_pem_section(&mut lines, "SIGNATURE");

        TestSignedData {
            spki: spki,
            data: data,
            signature: signature
        }
    }

    type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

    fn read_pem_section(lines: & mut FileLines, section_name: &str)
                        -> std::vec::Vec<u8> {
        // Skip comments and header
        let begin_section = format!("-----BEGIN {}-----", section_name);
        loop {
            let line = lines.next().unwrap().unwrap();
            if line == begin_section {
                break;
            }
        }

        let mut base64 = std::string::String::new();

        let end_section = format!("-----END {}-----", section_name);
        loop {
            let line = lines.next().unwrap().unwrap();
            if line == end_section {
                break;
            }
            base64.push_str(&line);
        }

        base64.from_base64().unwrap()
    }
}
