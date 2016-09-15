// Copyright 2015-2016 Brian Smith.
// Portions Copyright (c) 2015, Google Inc.
// Portions Copyright (c) 2016, Google Inc.
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

use {aead, c, chacha, error, polyfill};

const POLY1305_STATE_LEN: usize = 256;
const POLY1305_KEY_LEN: usize = 32;


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
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                          -> Result<(), error::Unspecified> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = chacha::make_counter(nonce, 1);
    chacha::chacha20_xor_in_place(&chacha20_key, &counter, in_out);
    counter[0] = 0;
    aead_poly1305(tag_out, chacha20_key, &counter, ad, in_out);
    Ok(())
}

fn chacha20_poly1305_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          in_prefix_len: usize,
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
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

type UpdateFn = fn(state: &mut [u8; POLY1305_STATE_LEN], ad: &[u8],
                   ciphertext: &[u8]);

fn aead_poly1305(tag_out: &mut [u8; aead::TAG_LEN],
                 chacha20_key: &chacha::Key, counter: &chacha::Counter,
                 ad: &[u8], ciphertext: &[u8]) {
    debug_assert_eq!(counter[0], 0);
    let mut poly1305_key = [0u8; POLY1305_KEY_LEN];
    chacha::chacha20_xor_in_place(chacha20_key, counter, &mut poly1305_key);
    let mut ctx = [0u8; POLY1305_STATE_LEN];
    poly1305_init(&mut ctx, &poly1305_key);
    poly1305_update_padded_16(&mut ctx, ad);
    poly1305_update_padded_16(&mut ctx, ciphertext);
    poly1305_update_length(&mut ctx, ad.len());
    poly1305_update_length(&mut ctx, ciphertext.len());
    poly1305_finish(&mut ctx, tag_out);
}

#[inline]
fn poly1305_update_padded_16(state: &mut [u8; POLY1305_STATE_LEN],
                                data: &[u8]) {
    poly1305_update(state, data);
    if data.len() % 16 != 0 {
        static PADDING: [u8; 16] = [0u8; 16];
        poly1305_update(state, &PADDING[..PADDING.len() - (data.len() % 16)])
    }
}

/// Updates the Poly1305 context |ctx| with the 64-bit little-endian encoded
/// length value |len|.
#[inline]
fn poly1305_update_length(ctx: &mut [u8; POLY1305_STATE_LEN], len: usize) {
    let mut j = len;
    let mut length_bytes = [0u8; 8];
    for b in &mut length_bytes {
        *b = j as u8;
        j >>= 8;
    }
    poly1305_update(ctx, &length_bytes);
}


#[inline(always)]
fn poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                 key: &[u8; POLY1305_KEY_LEN]) {
    unsafe {
        GFp_poly1305_init(state, key)
    }
}

// XXX: The BoringSSL code says that `poly1305_finish` requires a
// 16-byte-aligned output, but we're not ensuring 16-byte alignment because we
// can't in Rust yet. Where does this alignment requirement come from?
// TODO: address this.
#[inline(always)]
fn poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                   tag_out: &mut [u8; aead::TAG_LEN]) {
    unsafe {
        GFp_poly1305_finish(state, tag_out)
    }
}

#[inline(always)]
fn poly1305_update(state: &mut [u8; POLY1305_STATE_LEN], in_: &[u8]) {
    unsafe {
        GFp_poly1305_update(state, in_.as_ptr(), in_.len())
    }
}

extern {
    fn GFp_poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                         key: &[u8; POLY1305_KEY_LEN]);
    fn GFp_poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                           mac: &mut [u8; aead::TAG_LEN]);
    fn GFp_poly1305_update(state: &mut [u8; POLY1305_STATE_LEN],
                           in_: *const u8, in_len: c::size_t);
}

#[cfg(test)]
mod tests {
    use {aead, c, error, test};
    use core;
    use super::{POLY1305_STATE_LEN, POLY1305_KEY_LEN, poly1305_init,
                poly1305_finish, poly1305_update};
    #[test]
    pub fn test_chacha20_poly1305() {
        aead::tests::test_aead(&aead::CHACHA20_POLY1305,
            "src/aead/chacha20_poly1305_tests.txt");
    }

    #[test]
    pub fn test_poly1305_state_len() {
        assert_eq!((POLY1305_STATE_LEN + 255) / 256,
                   (unsafe { GFp_POLY1305_STATE_LEN } + 255) / 256);
    }

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::from_file("src/aead/poly1305_test.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, POLY1305_KEY_LEN).unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let expected_mac = slice_as_array_ref!(&expected_mac,
                                                   aead::TAG_LEN).unwrap();

            // Test single-shot operation.
            let mut state = [0u8; POLY1305_STATE_LEN];
            let mut actual_mac = [0u8; aead::TAG_LEN];
            poly1305_init(&mut state, &key);
            poly1305_update(&mut state, &input);
            poly1305_finish(&mut state, &mut actual_mac);
            assert_eq!(expected_mac[..], actual_mac[..]);

            // Test streaming byte-by-byte.
            let mut state = [0u8; POLY1305_STATE_LEN];
            let mut actual_mac = [0u8; aead::TAG_LEN];
            poly1305_init(&mut state, &key);
            for chunk in input.chunks(1) {
                poly1305_update(&mut state, chunk);
            }
            poly1305_finish(&mut state, &mut actual_mac);
            assert_eq!(&expected_mac[..], &actual_mac[..]);

            try!(test_poly1305_simd(0, key, &input, expected_mac));
            try!(test_poly1305_simd(16, key, &input, expected_mac));
            try!(test_poly1305_simd(32, key, &input, expected_mac));
            try!(test_poly1305_simd(48, key, &input, expected_mac));

            Ok(())
        })
    }

    fn test_poly1305_simd(excess: usize, key: &[u8; POLY1305_KEY_LEN],
                          input: &[u8], expected_mac: &[u8; aead::TAG_LEN])
                          -> Result<(), error::Unspecified> {
        let mut state = [0u8; POLY1305_STATE_LEN];
        poly1305_init(&mut state, &key);

        // Some implementations begin in non-SIMD mode and upgrade on demand.
        // Stress the upgrade path.
        let init = core::cmp::min(input.len(), 16);
        poly1305_update(&mut state, &input[..init]);

        let long_chunk_len = 128 + excess;
        for chunk in input[init..].chunks(long_chunk_len + excess) {
            if chunk.len() > long_chunk_len {
                let (long, short) = chunk.split_at(long_chunk_len);

                // Feed 128 + |excess| bytes to test SIMD mode.
                poly1305_update(&mut state, long);

                // Feed |excess| bytes to ensure SIMD mode can handle short
                // inputs.
                poly1305_update(&mut state, short);
            } else {
                // Handle the last chunk.
                poly1305_update(&mut state, chunk);
            }
        }

        let mut actual_mac = [0u8; aead::TAG_LEN];
        poly1305_finish(&mut state, &mut actual_mac);
        assert_eq!(expected_mac, &actual_mac, "SIMD pattern failed.");

        Ok(())
    }

    extern {
        static GFp_POLY1305_STATE_LEN: c::size_t;
    }
}
