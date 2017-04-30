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

use {der, error};
use untrusted;

/// Parses an unencrypted PKCS#8 privatg key, verifies that it is the right type
/// of key, and returns the key value. `alg_id` must be the encoded value (not
/// including the outermost `SEQUENCE` tag and length) of the
/// `AlgorithmIdentifier` that identifies the key type. The result will be an
/// encoded `RSAPrivateKey` or `ECPrivateKey` or similar.
///
/// PKCS#8 is specified in [RFC 5958]. Only v1 keys are supported, as none of
/// the algorithms we support require v2 support.
///
/// [RFC 5958]: https://tools.ietf.org/html/rfc5958.
pub fn unwrap_key<'a>(input: untrusted::Input<'a>, alg_id: &[u8])
                      -> Result<untrusted::Input<'a>, error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            // Currently we only support algorithms that should only be encoded
            // in v1 form, so reject v2 and any later form.
            let version = try!(der::small_nonnegative_integer(input));
            if version != 0 {
                return Err(error::Unspecified);
            }

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

            Ok(private_key)
        })
    })
}
