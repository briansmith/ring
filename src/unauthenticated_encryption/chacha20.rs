// Copyright 2018 Brian Smith.
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

use crate::{chacha, error, polyfill, unauthenticated_encryption};
use polyfill::slice::u32_from_le_u8;

/// ChaCha20 unauthenticated stream cipher.
///
/// The keys are 256 bits long and the nonces are 128 bits long, rather then
/// the usual 96 bits. The first 32 bits of the 128-bit nonce represents an
/// explicit initial counter parameter.
pub static CHACHA20: unauthenticated_encryption::Algorithm =
                                        unauthenticated_encryption::Algorithm {
    key_len: chacha::KEY_LEN_IN_BYTES,
    init: chacha::chacha20_init,
    xor_keystream: chacha20_xor_keystream,
    id: unauthenticated_encryption::AlgorithmID::CHACHA20,
    max_input_len: max_input_len!(chacha::CHACHA20_BLOCK_LEN,
                                  chacha::CHACHA20_OVERHEAD_BLOCKS_PER_NONCE),
};

fn chacha20_xor_keystream(ctx: &[u64; unauthenticated_encryption::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; unauthenticated_encryption::NONCE_LEN],
                          in_out: &mut [u8]) -> Result<(), error::Unspecified> {
    let chacha20_key = ctx_as_key(ctx)?;
    let mut counter = make_counter(nonce);
    chacha::chacha20_xor_in_place(&chacha20_key, &counter, in_out);
    counter[0] = 0;
    Ok(())
}

fn ctx_as_key(ctx: &[u64; unauthenticated_encryption::KEY_CTX_BUF_ELEMS])
              -> Result<&chacha::Key, error::Unspecified> {
    slice_as_array_ref!(
        &polyfill::slice::u64_as_u32(ctx)[..(chacha::KEY_LEN_IN_BYTES / 4)],
        chacha::KEY_LEN_IN_BYTES / 4)
}

#[inline]
fn make_counter(nonce: &[u8; unauthenticated_encryption::NONCE_LEN]) -> chacha::Counter {
    [u32_from_le_u8(slice_as_array_ref!(&nonce[0..4], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[4..8], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[8..12], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[12..16], 4).unwrap())]
}
