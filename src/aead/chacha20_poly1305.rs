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

use super::{
    block::{Block, BLOCK_LEN},
    poly1305, Tag,
};
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
) -> Result<Tag, error::Unspecified> {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    let mut counter = chacha::make_counter(nonce, 1);
    chacha::chacha20_xor_in_place(chacha20_key, &counter, in_out);
    counter[0] = 0;
    Ok(aead_poly1305(chacha20_key, &counter, ad, in_out))
}

fn chacha20_poly1305_open(
    key: &aead::KeyInner, nonce: &[u8; aead::NONCE_LEN], ad: &[u8], in_prefix_len: usize,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    let mut counter = chacha::make_counter(nonce, 0);
    let tag = {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(chacha20_key, &counter, ad, ciphertext)
    };
    counter[0] = 1;
    chacha::chacha20_xor_overlapping(chacha20_key, &counter, in_out, in_prefix_len);
    Ok(tag)
}

pub type Key = chacha::Key;

fn aead_poly1305(
    chacha20_key: &chacha::Key, counter: &chacha::Counter, ad: &[u8], ciphertext: &[u8],
) -> Tag {
    debug_assert_eq!(counter[0], 0);

    let mut ctx = {
        let key = derive_poly1305_key(chacha20_key, counter);
        poly1305::Context::from_key(key)
    };

    poly1305_update_padded_16(&mut ctx, ad);
    poly1305_update_padded_16(&mut ctx, ciphertext);
    let lengths = [
        polyfill::u64_from_usize(ad.len()).to_le(),
        polyfill::u64_from_usize(ciphertext.len()).to_le(),
    ];
    ctx.update_block(Block::from(lengths), poly1305::Pad::Pad);
    ctx.finish()
}

#[inline]
fn poly1305_update_padded_16(ctx: &mut poly1305::Context, input: &[u8]) {
    let remainder_len = input.len() % BLOCK_LEN;
    let whole_len = input.len() - remainder_len;
    if whole_len > 0 {
        ctx.update_blocks(&input[..whole_len]);
    }
    if remainder_len > 0 {
        let mut block = Block::zero();
        block.partial_copy_from(&input[whole_len..]);
        ctx.update_block(block, poly1305::Pad::Pad)
    }
}

// Also used by chacha20_poly1305_openssh.
pub(super) fn derive_poly1305_key(
    chacha_key: &chacha::Key, counter: &chacha::Counter,
) -> poly1305::Key {
    let mut bytes = [0u8; poly1305::KEY_LEN];
    chacha::chacha20_xor_in_place(chacha_key, counter, &mut bytes);
    poly1305::Key::from(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // Errata 4858 at https://www.rfc-editor.org/errata_search.php?rfc=7539.
        assert_eq!(super::CHACHA20_POLY1305.max_input_len, 274_877_906_880u64);
    }
}
