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

/// An error that occurs while parsing an SPKI public key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ParseSPKIError {
    /// The encoding of some ASN.1 DER-encoded item is invalid.
    BadDER,

    /// The SignatureAlgorithm does not match the algorithm of the SPKI.
    /// A mismatch could be because of the algorithm (RSA vs DSA, etc) or the
    /// parameters (ECDSA_p256 vs ECDSA_384, etc).
    UnsupportedSignatureAlgorithmForPublicKey,
}

/// Parse a public key in the DER-encoded ASN.1 `SubjectPublicKeyInfo`
/// format described in [RFC 5280 Section 4.1], which is a sequence of an
/// `AlgorithmIdentifier` and the key value.
///
/// If the `AlgorithmIdentifier` in the SPKI does not match the provided
/// `signature_alg`, or if the DER encoding is invalid, an error will be
/// returned.
///
/// If the function returns successfully, the `key_value` field in the
/// resulting `SubjectPublicKeyInfo` struct is suitable for use with
/// `signature::verify()`.
///
/// A common situation where this encoding is encountered is when using public
/// keys exported by OpenSSL. If you export an RSA or ECDSA public key from a
/// keypair with `-pubout` and friends, you will get DER-encoded
/// `SubjectPublicKeyInfo`.
///
/// [RFC 5280 Section 4.1]: https://tools.ietf.org/html/rfc5280#section-4.1
pub fn parse_spki<'a>(signature_alg: &Algorithm, public_key_spki: untrusted::Input<'a>)
        -> Result<SubjectPublicKeyInfo<'a>, ParseSPKIError> {
    let unwrapped_spki_der = try!(public_key_spki.read_all(ParseSPKIError::BadDER, |input| {
        der::expect_tag_and_get_value(input, der::Tag::Sequence)
            .map_err(|_| ParseSPKIError::BadDER)
    }));

    let spki = try!(parse_spki_value(unwrapped_spki_der));
    if !signature_alg.public_key_alg_id
        .matches_algorithm_id_value(spki.algorithm_id_value) {
        return Err(ParseSPKIError::UnsupportedSignatureAlgorithmForPublicKey);
    }

    Ok(spki)
}

/// Represents the contents of `SubjectPublicKeyInfo` described in
/// RFC 5280 Section 4.1: https://tools.ietf.org/html/rfc5280#section-4.1
#[derive(Debug)]
pub struct SubjectPublicKeyInfo<'a> {
    /// The algorithm id ASN.1.
    pub algorithm_id_value: untrusted::Input<'a>,
    /// The key ASN.1 bit string.
    pub key_value: untrusted::Input<'a>,
}

// Parse the public key into an algorithm OID, an optional curve OID, and the
// key value. The caller needs to check whether these match the
// `PublicKeyAlgorithm` for the `SignatureAlgorithm` that is matched when
// parsing the signature.
fn parse_spki_value(input: untrusted::Input)
                    -> Result<SubjectPublicKeyInfo, ParseSPKIError> {
    input.read_all(ParseSPKIError::BadDER, |input| {
        let algorithm_id_value =
            try!(der::expect_tag_and_get_value(input, der::Tag::Sequence)
                .map_err(|_| ParseSPKIError::BadDER));
        let key_value = try!(der::bit_string_with_no_unused_bits(input)
            .map_err(|_| ParseSPKIError::BadDER));
        Ok(SubjectPublicKeyInfo {
            algorithm_id_value: algorithm_id_value,
            key_value: key_value,
        })
    })
}

/// Groups an ASN.1 AlgorithmIdentifier and a `ring` VerificationAlgorithm.
pub struct Algorithm {
    /// The `algorithm` member in SPKI from https://tools.ietf.org/html/rfc5280#section-4.1.
    public_key_alg_id: AlgorithmIdentifier,
    /// The verification algorithm corresponding to the algorithm id.
    pub verification_alg: &'static signature::VerificationAlgorithm,
}

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

/// RSA PKCS#1 1.5 signatures using SHA-1 for keys of 2048-8192 bits.
/// Deprecated.
pub static RSA_PKCS1_2048_8192_SHA1: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA1,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
};

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
};

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
};

struct AlgorithmIdentifier {
    /// Binary DER for ASN.1 AlgorithmIdentifier without outer SEQUENCE or length.
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

const RSA_ENCRYPTION: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-encryption.der"),
};

