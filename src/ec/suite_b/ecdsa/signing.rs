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

//! ECDSA Signatures using the P-256 and P-384 curves.

use core;
use {ec, error, pkcs8, rand};
use untrusted;

/// An ECDSA signing algorithm.
pub struct Algorithm {
    curve: &'static ec::Curve,
    pkcs8_template: &'static pkcs8::Template,
    id: AlgorithmID
}

#[derive(PartialEq, Eq)]
enum AlgorithmID {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool { self.id == other.id }
}

impl Eq for Algorithm {}

/// An ECDSA key pair, used for signing.
#[doc(hidden)]
pub struct Key {
    #[allow(dead_code)] // XXX: Temporary, since signing isn't implemented yet.
    key_pair: ec::KeyPair,

    #[allow(dead_code)] // XXX: Temporary, since signing isn't implemented yet.
    alg: &'static Algorithm,
}

impl<'a> Key {
    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 document.
    ///
    /// The PKCS#8 document will be a v1 `OneAsymmetricKey` with the public key
    /// included in the `ECPrivateKey` structure, as described in
    /// [RFC 5958 Section 2] and [RFC 5915]. The `ECPrivateKey` structure will
    /// not have a `parameters` field so the generated key is compatible with
    /// PKCS#11.
    ///
    /// [RFC 5915]: https://tools.ietf.org/html/rfc5915
    /// [RFC 5958 Section 2]: https://tools.ietf.org/html/rfc5958#section-2
    pub fn generate_pkcs8(alg: &'static Algorithm, rng: &rand::SecureRandom)
                          -> Result<pkcs8::Document, error::Unspecified> {
        let private_key = ec::PrivateKey::generate(alg.curve, rng)?;
        let mut public_key_bytes = [0; ec::PUBLIC_KEY_MAX_LEN];
        let public_key_bytes = &mut public_key_bytes[..alg.curve.public_key_len];
        (alg.curve.public_from_private)(public_key_bytes, &private_key)?;
        Ok(pkcs8::wrap_key(&alg.pkcs8_template, private_key.bytes(alg.curve),
                           public_key_bytes))
    }

    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// The input must be in PKCS#8 v1 format. It must contain the public key in
    /// the `ECPrivateKey` structure; `from_pkcs8()` will verify that the public
    /// key and the private key are consistent with each other. The algorithm
    /// identifier must identify the curve by name; it must not use an
    /// "explicit" encoding of the curve. The `parameters` field of the
    /// `ECPrivateKey`, if present, must be the same named curve that is in the
    /// algorithm identifier in the PKCS#8 header.
    pub fn from_pkcs8(alg: &'static Algorithm, input: untrusted::Input)
                      -> Result<Self, error::Unspecified> {
        let key_pair = ec::suite_b::key_pair_from_pkcs8(alg.curve,
            alg.pkcs8_template, input)?;
        Ok(Self { key_pair, alg })
    }

    /// Constructs an ECDSA key pair directly from the big-endian-encoded
    /// private key and public key bytes.
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `ECDSAKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    pub fn from_private_key_and_public_key(alg: &'static Algorithm,
                                           private_key: untrusted::Input,
                                           public_key: untrusted::Input)
                                           -> Result<Self, error::Unspecified> {
        let key_pair = ec::suite_b::key_pair_from_bytes(
            alg.curve, private_key, public_key)?;
        Ok(Self { key_pair, alg })
    }
}

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-256 curve and SHA-256.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
#[doc(hidden)]
pub static ECDSA_P256_SHA256_FIXED_SIGNING: Algorithm = Algorithm {
    curve: &ec::suite_b::curve::P256,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P256_SHA256_FIXED_SIGNING,
};

/// Signing of fixed-length (PKCS#11 style) ECDSA signatures using the
/// P-384 curve and SHA-384.
///
/// See "`ECDSA_*_FIXED` Details" in `ring::signature`'s module-level
/// documentation for more details.
#[doc(hidden)]
pub static ECDSA_P384_SHA384_FIXED_SIGNING: Algorithm = Algorithm {
    curve: &ec::suite_b::curve::P384,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-256 curve and
/// SHA-256.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
#[doc(hidden)]
pub static ECDSA_P256_SHA256_ASN1_SIGNING: Algorithm = Algorithm {
    curve: &ec::suite_b::curve::P256,
    pkcs8_template: &EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P256_SHA256_ASN1_SIGNING,
};

/// Signing of ASN.1 DER-encoded ECDSA signatures using the P-384 curve and
/// SHA-384.
///
/// See "`ECDSA_*_ASN1` Details" in `ring::signature`'s module-level
/// documentation for more details.
#[doc(hidden)]
pub static ECDSA_P384_SHA384_ASN1_SIGNING: Algorithm = Algorithm {
    curve: &ec::suite_b::curve::P384,
    pkcs8_template: &EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE,
    id: AlgorithmID::ECDSA_P384_SHA384_ASN1_SIGNING,
};

static EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes ! ("ecPublicKey_p256_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};

static EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p384_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 24 },
    curve_id_index: 9,
    private_key_index: 0x23,
};
