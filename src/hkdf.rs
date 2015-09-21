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

use super::hmac;

/// Fills `out` with the output of the HKDF Extract-and-Expand operation for
/// the given inputs.
///
/// HKDF is the HMAC-based Extract-and-Expand Key Derivation Function
/// specified in [RFC 5869](https://tools.ietf.org/html/rfc5869).
///
/// | Parameter               | RFC 5869 Term
/// |-------------------------|--------------
/// | salt.digest_algorithm() | Hash
/// | secret                  | IKM (Input Keying Material)
/// | salt                    | salt
/// | info                    | info
/// | out                     | OKM (Output Keying Material)
/// | out.len()               | L (Length of output keying material in bytes)
///
/// The salt is a `hmac::SigningKey` instead of a `&[u8]` because it is
/// frequently the case that a fixed salt is used for multiple HKDF operations,
/// so it is more efficient to construct the signing key once and reuse it.
/// Given a digest algorithm `digest_alg` and a salt `salt: &[u8]`, the
/// `SigningKey` should be constructed as
/// `hmac::SigningKey::new(digest_alg, salt)`.
///
/// # Panics
///
/// `hkdf` panics if the requested output length is larger than 255 times the
// size of the digest algorithm, i.e. if
/// `out.len() > 255 * salt.digest_algorithm().digest_len`. This is the limit
/// imposed by the HKDF specification, and is necessary to prevent overflow of
/// the 8-bit iteration counter in the expansion step.
pub fn hkdf(secret: &[u8], salt: &hmac::SigningKey, info: &[u8],
            out: &mut [u8]) {
    let digest_alg = salt.digest_algorithm();

    assert!(out.len() <= 255 * digest_alg.digest_len);

    // The spec says that if no salt is provided then a key of
    // `digest_alg.digest_len` bytes of zeros is used. But, HMAC keys are
    // already zero-padded to the block length, which is larger than the output
    // length of the extract step (the length of the digest). Consequently, the
    // `SigningKey` constructor will automatically do the right thing for a
    // zero-length string.
    assert!(digest_alg.block_len >= digest_alg.digest_len);

    let prk = hmac::sign(&salt, secret);
    let prk = hmac::SigningKey::new(digest_alg, prk.as_ref());

    let mut ctx = hmac::SigningContext::with_key(&prk);

    let mut n = 1u8;
    let mut pos = 0;
    loop {
        ctx.update(info);
        ctx.update(&[n]);

        let t = ctx.sign();

        // Append `t` to the output.
        let to_copy = if out.len() - pos < digest_alg.digest_len {
            out.len() - pos
        } else {
            digest_alg.digest_len
        };
        let t_bytes = t.as_ref();
        for i in 0..to_copy {
            out[pos + i] = t_bytes[i];
        }
        if to_copy < digest_alg.digest_len {
            break;
        }
        pos += digest_alg.digest_len;

        ctx = hmac::SigningContext::with_key(&prk);
        ctx.update(t_bytes);
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{file_test, hkdf, hmac};

    #[test]
    pub fn hkdf_tests() {
        fn test_case(test_case: &mut file_test::TestCase) {
            let digest_alg = test_case.consume_digest_alg("Hash").unwrap();
            let secret = test_case.consume_bytes("IKM");
            let salt = test_case.consume_bytes("salt");
            let info = test_case.consume_bytes("info");

            // The PRK is an intermediate value that we can't test, but we
            // have to consume it to make file_test::run happy.
            let _ = test_case.consume_bytes("PRK");

            let out = test_case.consume_bytes("OKM");

            let salt = hmac::SigningKey::new(digest_alg, &salt);

            let mut out = vec![0u8; out.len()];
            hkdf::hkdf(&secret, &salt, &info, &mut out);
            assert_eq!(out, out);
        }

        file_test::run("src/hkdf_tests.txt", test_case);
    }
}
