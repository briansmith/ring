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

//! PKCS#8 is specified in [RFC 5958].
//!
//! [RFC 5958]: https://tools.ietf.org/html/rfc5958.

use core;
use {der, ec, error};
use untrusted;

pub enum Version {
    V1Only,
    V1OrV2,
    V2Only,
}

/// A template for constructing PKCS#8 documents.
///
/// Note that this only works for ECC.
pub struct Template {
    pub bytes: &'static [u8],

    // The range within `bytes` that holds the value (not including the tag and
    // length) for use in the PKCS#8 document's privateKeyAlgorithm field.
    pub alg_id_range: core::ops::Range<usize>,

    // `bytes[alg_id_range][curve_id_index..]` contains the OID identifying the,
    // curve, including the tag and length.
    pub curve_id_index: usize,

    // `bytes` will be split into two parts at `private_key_index`, where the
    // first part is written before the private key and the second part is
    // written after the private key. The public key is written after the second
    // part.
    pub private_key_index: usize,
}

impl Template {
    #[inline]
    fn alg_id_value(&self) -> &[u8] {
        &self.bytes[self.alg_id_range.start..self.alg_id_range.end]
    }

    #[inline]
    pub fn curve_oid(&self) -> &[u8] {
        &self.alg_id_value()[self.curve_id_index..]
    }
}

/// Parses an unencrypted PKCS#8 private key, verifies that it is the right type
/// of key, and returns the key value.
///
/// PKCS#8 is specified in [RFC 5958].
///
/// [RFC 5958]: https://tools.ietf.org/html/rfc5958.
pub fn unwrap_key<'a>(template: &Template, version: Version,
                      input: untrusted::Input<'a>)
        -> Result<(untrusted::Input<'a>, Option<untrusted::Input<'a>>),
                   error::Unspecified> {
    unwrap_key_(template.alg_id_value(), version, input)
}

/// Parses an unencrypted PKCS#8 private key, verifies that it is the right type
/// of key, and returns the key value.
///
/// `alg_id` must be the encoded value (not including the outermost `SEQUENCE`
/// tag and length) of the `AlgorithmIdentifier` that identifies the key type.
/// The result will be an encoded `RSAPrivateKey` or `ECPrivateKey` or similar.
///
/// PKCS#8 is specified in [RFC 5958].
///
/// [RFC 5958]: https://tools.ietf.org/html/rfc5958.
pub fn unwrap_key_<'a>(alg_id: &[u8], version: Version,
                       input: untrusted::Input<'a>)
        -> Result<(untrusted::Input<'a>, Option<untrusted::Input<'a>>),
                  error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            // Currently we only support algorithms that should only be encoded
            // in v1 form, so reject v2 and any later form.
            let require_public_key =
                    match (der::small_nonnegative_integer(input)?, version) {
                (0, Version::V1Only) => false,
                (0, Version::V1OrV2) => false,
                (1, Version::V1OrV2) |
                (1, Version::V2Only) => true,
                _ => { return Err(error::Unspecified); }
            };

            let actual_alg_id =
                der::expect_tag_and_get_value(input, der::Tag::Sequence)?;
            if actual_alg_id != alg_id {
                return Err(error::Unspecified);
            }

            let private_key =
                der::expect_tag_and_get_value(input, der::Tag::OctetString)?;

            // Ignore any attributes that are present.
            if input.peek(der::Tag::ContextSpecificConstructed0 as u8) {
                let _ = der::expect_tag_and_get_value(input,
                    der::Tag::ContextSpecificConstructed0)?;
            }

            let public_key = if require_public_key {
                Some(der::nested(
                    input, der::Tag::ContextSpecificConstructed1,
                    error::Unspecified, der::bit_string_with_no_unused_bits)?)
            } else {
                None
            };

            Ok((private_key, public_key))
        })
    })
}

/// A generated PKCS#8 document.
pub struct PKCS8Document {
    bytes: [u8; ec::PKCS8_DOCUMENT_MAX_LEN],
    len: usize,
}

impl AsRef<[u8]> for PKCS8Document {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.bytes[..self.len] }
}

pub fn wrap_key(template: &Template, private_key: &[u8], public_key: &[u8])
                -> PKCS8Document {
    let mut result = PKCS8Document {
        bytes: [0; ec::PKCS8_DOCUMENT_MAX_LEN],
        len: template.bytes.len() + private_key.len() + public_key.len(),
    };
    wrap_key_(template, private_key, public_key, &mut result.bytes[..result.len]);
    result
}

/// Formats a private key "prefix||private_key||middle||public_key" where
/// `template` is "prefix||middle" split at position `private_key_index`.
pub fn wrap_key_(template: &Template, private_key: &[u8], public_key: &[u8],
                 bytes: &mut [u8]) {
    let (before_private_key, after_private_key) =
        template.bytes.split_at(template.private_key_index);
    let private_key_end_index = template.private_key_index + private_key.len();
    bytes[..template.private_key_index].copy_from_slice(before_private_key);
    bytes[template.private_key_index..private_key_end_index]
        .copy_from_slice(&private_key);
    bytes[private_key_end_index..
          (private_key_end_index + after_private_key.len())]
        .copy_from_slice(after_private_key);
    bytes[(private_key_end_index + after_private_key.len())..]
        .copy_from_slice(public_key);
}
