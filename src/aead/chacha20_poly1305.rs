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

use {aead, chacha, error, poly1305, polyfill};

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: chacha::KEY_LEN_IN_BYTES,
    init: chacha20_poly1305_init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
};

/// Copies |key| into |ctx_buf|.
pub fn chacha20_poly1305_init(ctx_buf: &mut [u8], key: &[u8])
                              -> Result<(), error::Unspecified> {
    ctx_buf[..key.len()].copy_from_slice(key);
    Ok(())
}

fn chacha20_poly1305_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], ad: &[u8],
                          in_out: &mut [u8], tag_out: &mut [u8; aead::TAG_LEN])
                          -> Result<(), error::Unspecified> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = chacha::make_counter(nonce, 1);
    chacha::chacha20_xor_in_place(&chacha20_key, &counter, in_out);
    counter[0] = 0;
    aead_poly1305(tag_out, chacha20_key, &counter, ad, in_out);
    Ok(())
}

fn chacha20_poly1305_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], ad: &[u8],
                          in_prefix_len: usize, in_out: &mut [u8],
                          tag_out: &mut [u8; aead::TAG_LEN])
                          -> Result<(), error::Unspecified> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = chacha::make_counter(nonce, 0);
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(tag_out, chacha20_key, &counter, ad, ciphertext);
    }
    counter[0] = 1;
    chacha::chacha20_xor_overlapping(&chacha20_key, &counter, in_out,
                                     in_prefix_len);
    Ok(())
}

fn ctx_as_key(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS])
              -> Result<&chacha::Key, error::Unspecified> {
    slice_as_array_ref!(
        &polyfill::slice::u64_as_u32(ctx)[..(chacha::KEY_LEN_IN_BYTES / 4)],
        chacha::KEY_LEN_IN_BYTES / 4)
}

fn aead_poly1305(tag_out: &mut [u8; aead::TAG_LEN], chacha20_key: &chacha::Key,
                 counter: &chacha::Counter, ad: &[u8], ciphertext: &[u8]) {
    debug_assert_eq!(counter[0], 0);
    let key = poly1305::Key::derive_using_chacha(chacha20_key, counter);
    let mut ctx = poly1305::SigningContext::from_key(key);
    ctx.update_padded(ad);
    ctx.update_padded(ciphertext);
    let lengths =
        [polyfill::u64_from_usize(ad.len()).to_le(),
         polyfill::u64_from_usize(ciphertext.len()).to_le()];
    ctx.update_padded_final(polyfill::slice::u64_as_u8(&lengths), tag_out);
}


#[cfg(test)]
mod tests {
    use aead;

    #[test]
    pub fn test_chacha20_poly1305() {
        aead::tests::test_aead(&aead::CHACHA20_POLY1305,
            "src/aead/chacha20_poly1305_tests.txt");
    }
}
