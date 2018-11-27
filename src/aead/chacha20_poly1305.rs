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

use super::poly1305;
use crate::{aead, chacha, error, polyfill};

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: chacha::KEY_LEN,
    init: chacha20_poly1305_init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
    id: aead::AlgorithmID::CHACHA20_POLY1305,
    max_input_len: max_input_len!(CHACHA20_BLOCK_LEN, CHACHA20_OVERHEAD_BLOCKS_PER_NONCE),
};

const CHACHA20_BLOCK_LEN: u64 = 64;
const CHACHA20_OVERHEAD_BLOCKS_PER_NONCE: u64 = 1;

/// Copies |key| into |ctx_buf|.
fn chacha20_poly1305_init(key: &[u8]) -> Result<aead::KeyInner, error::Unspecified> {
    Ok(aead::KeyInner::ChaCha20Poly1305(chacha::Key::from(
        slice_as_array_ref!(key, chacha::KEY_LEN)?,
    )))
}

fn chacha20_poly1305_seal(
    key: &aead::KeyInner, nonce: &[u8; aead::NONCE_LEN], ad: &[u8], in_out: &mut [u8],
    tag_out: &mut [u8; aead::TAG_LEN],
) -> Result<(), error::Unspecified> {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    let mut counter = chacha::make_counter(nonce, 1);
    chacha::chacha20_xor_in_place(chacha20_key, &counter, in_out);
    counter[0] = 0;
    aead_poly1305(tag_out, chacha20_key, &counter, ad, in_out);
    Ok(())
}

fn chacha20_poly1305_open(
    key: &aead::KeyInner, nonce: &[u8; aead::NONCE_LEN], ad: &[u8], in_prefix_len: usize,
    in_out: &mut [u8], tag_out: &mut [u8; aead::TAG_LEN],
) -> Result<(), error::Unspecified> {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    let mut counter = chacha::make_counter(nonce, 0);
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(tag_out, chacha20_key, &counter, ad, ciphertext);
    }
    counter[0] = 1;
    chacha::chacha20_xor_overlapping(chacha20_key, &counter, in_out, in_prefix_len);
    Ok(())
}

pub type Key = chacha::Key;

fn aead_poly1305(
    tag_out: &mut [u8; aead::TAG_LEN], chacha20_key: &chacha::Key, counter: &chacha::Counter,
    ad: &[u8], ciphertext: &[u8],
) {
    debug_assert_eq!(counter[0], 0);
    let key = poly1305::Key::derive_using_chacha(chacha20_key, counter);
    let mut ctx = poly1305::SigningContext::from_key(key);
    poly1305_update_padded_16(&mut ctx, ad);
    poly1305_update_padded_16(&mut ctx, ciphertext);
    let lengths = [
        polyfill::u64_from_usize(ad.len()).to_le(),
        polyfill::u64_from_usize(ciphertext.len()).to_le(),
    ];
    ctx.update(polyfill::slice::u64_as_u8(&lengths));
    tag_out.copy_from_slice(&ctx.finish()[..]);
}

#[inline]
fn poly1305_update_padded_16(ctx: &mut poly1305::SigningContext, data: &[u8]) {
    ctx.update(data);
    if data.len() % 16 != 0 {
        static PADDING: [u8; 16] = [0u8; 16];
        ctx.update(&PADDING[..PADDING.len() - (data.len() % 16)])
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // Errata 4858 at https://www.rfc-editor.org/errata_search.php?rfc=7539.
        assert_eq!(super::CHACHA20_POLY1305.max_input_len, 274_877_906_880u64);
    }
}
