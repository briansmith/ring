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
    chacha::{self, Counter},
    nonce::Iv,
    poly1305, Aad, Block, Direction, Nonce, Tag, BLOCK_LEN,
};
use crate::{
    aead, cpu,
    endian::*,
    error,
    polyfill::{self, convert::*},
};

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
    max_input_len: super::max_input_len(64, 1),
};

/// Copies |key| into |ctx_buf|.
fn chacha20_poly1305_init(
    key: &[u8], _todo: cpu::Features,
) -> Result<aead::KeyInner, error::Unspecified> {
    let key: &[u8; chacha::KEY_LEN] = key.try_into_()?;
    Ok(aead::KeyInner::ChaCha20Poly1305(chacha::Key::from(key)))
}

fn chacha20_poly1305_seal(
    key: &aead::KeyInner, nonce: Nonce, aad: Aad, in_out: &mut [u8], cpu_features: cpu::Features,
) -> Tag {
    aead(key, nonce, aad, in_out, Direction::Sealing, cpu_features)
}

fn chacha20_poly1305_open(
    key: &aead::KeyInner, nonce: Nonce, aad: Aad, in_prefix_len: usize, in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Tag {
    aead(
        key,
        nonce,
        aad,
        in_out,
        Direction::Opening { in_prefix_len },
        cpu_features,
    )
}

pub type Key = chacha::Key;

#[inline(always)] // Statically eliminate branches on `direction`.
fn aead(
    key: &aead::KeyInner, nonce: Nonce, Aad(aad): Aad, in_out: &mut [u8], direction: Direction,
    _todo: cpu::Features,
) -> Tag {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };

    let mut counter = Counter::zero(nonce);
    let mut ctx = {
        let key = derive_poly1305_key(chacha20_key, counter.increment());
        poly1305::Context::from_key(key)
    };

    poly1305_update_padded_16(&mut ctx, aad);

    let in_out_len = match direction {
        Direction::Opening { in_prefix_len } => {
            poly1305_update_padded_16(&mut ctx, &in_out[in_prefix_len..]);
            chacha20_key.encrypt_overlapping(counter, in_out, in_prefix_len);
            in_out.len() - in_prefix_len
        },
        Direction::Sealing => {
            chacha20_key.encrypt_in_place(counter, in_out);
            poly1305_update_padded_16(&mut ctx, in_out);
            in_out.len()
        },
    };

    ctx.update_block(
        Block::from_u64_le(
            LittleEndian::from(polyfill::u64_from_usize(aad.len())),
            LittleEndian::from(polyfill::u64_from_usize(in_out_len)),
        ),
        poly1305::Pad::Pad,
    );
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
pub(super) fn derive_poly1305_key(chacha_key: &chacha::Key, iv: Iv) -> poly1305::Key {
    let mut blocks = [Block::zero(); poly1305::KEY_BLOCKS];
    chacha_key.encrypt_iv_xor_blocks_in_place(
        iv,
        <&mut [u8; poly1305::KEY_BLOCKS * BLOCK_LEN]>::from_(&mut blocks),
    );
    poly1305::Key::from(blocks)
}

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // Errata 4858 at https://www.rfc-editor.org/errata_search.php?rfc=7539.
        assert_eq!(super::CHACHA20_POLY1305.max_input_len, 274_877_906_880u64);
    }
}
