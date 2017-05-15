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

use {der, error};
use untrusted;

pub enum Version {
    V1Only,
    V1OrV2,
    V2Only,
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
pub fn unwrap_key<'a>(version: Version, input: untrusted::Input<'a>,
                      alg_id: &[u8])
        -> Result<(untrusted::Input<'a>, Option<untrusted::Input<'a>>),
                  error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            // Currently we only support algorithms that should only be encoded
            // in v1 form, so reject v2 and any later form.
            let require_public_key =
                    match (try!(der::small_nonnegative_integer(input)), version) {
                (0, Version::V1Only) => false,
                (0, Version::V1OrV2) => false,
                (1, Version::V1OrV2) |
                (1, Version::V2Only) => true,
                _ => { return Err(error::Unspecified); }
            };

            let actual_alg_id =
                try!(der::expect_tag_and_get_value(input, der::Tag::Sequence));
            if actual_alg_id != alg_id {
                return Err(error::Unspecified);
            }

            let private_key =
                try!(der::expect_tag_and_get_value(input, der::Tag::OctetString));

            // Ignore any attributes that are present.
            if input.peek(der::Tag::ContextSpecificConstructed0 as u8) {
                let _ = try!(der::expect_tag_and_get_value(input,
                    der::Tag::ContextSpecificConstructed0));
            }

            let public_key = if require_public_key {
                Some(try!(der::nested(
                    input, der::Tag::ContextSpecificConstructed1,
                    error::Unspecified, der::bit_string_with_no_unused_bits)))
            } else {
                None
            };

            Ok((private_key, public_key))
        })
    })
}

/// Formats a private key "prefix||private_key||middle||public_key" where
/// `template` is "prefix||middle" split at position `private_key_index`.
pub fn wrap_key(template: &[u8], private_key_index: usize, private_key: &[u8],
                public_key: &[u8], bytes: &mut [u8]) {
    let (before_private_key, after_private_key) =
        template.split_at(private_key_index);
    let private_key_end_index = private_key_index + private_key.len();
    bytes[..private_key_index].copy_from_slice(before_private_key);
    bytes[private_key_index..private_key_end_index]
        .copy_from_slice(&private_key);
    bytes[private_key_end_index..
          (private_key_end_index + after_private_key.len())]
        .copy_from_slice(after_private_key);
    bytes[(private_key_end_index + after_private_key.len())..]
        .copy_from_slice(public_key);
}
