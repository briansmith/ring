// Copyright 2015-2016 Brian Smith.
// Portions Copyright (c) 2015, Google Inc.
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

// TODO: enforce maximum input length.

use c;

pub struct SigningContext {
    state: State,
}

impl SigningContext {
    #[inline]
    pub fn with_key(key: &Key) -> SigningContext {
        let mut ctx = SigningContext {
            state: [0u8; STATE_LEN],
        };
        unsafe { GFp_poly1305_init(&mut ctx.state, key); }
        ctx
    }

    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            GFp_poly1305_update(&mut self.state, input.as_ptr(), input.len());
        }
    }

    #[inline]
    pub fn sign(mut self, tag_out: &mut Tag) {
        unsafe { GFp_poly1305_finish(&mut self.state, tag_out); }
    }
}

/// A Poly1305 key.
pub type Key = [u8; KEY_LEN];

/// The length of a `key`.
pub const KEY_LEN: usize = 32;

/// A Poly1305 tag.
pub type Tag = [u8; TAG_LEN];

/// The length of a `Tag`.
pub const TAG_LEN: usize = 128 / 8;

type State = [u8; STATE_LEN];
const STATE_LEN: usize = 256;

extern {
    fn GFp_poly1305_init(state: &mut State, key: &Key);
    fn GFp_poly1305_finish(state: &mut State, mac: &mut Tag);
    fn GFp_poly1305_update(state: &State, in_: *const u8, in_len: c::size_t);
}

#[cfg(test)]
mod tests {
    use {c, error, test};
    use core;
    use super::*;

    #[test]
    pub fn test_poly1305_state_len() {
        assert_eq!((super::STATE_LEN + 255) / 256,
                   (unsafe { GFp_POLY1305_STATE_LEN } + 255) / 256);
    }

    // Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
    #[test]
    pub fn test_poly1305() {
        test::from_file("src/poly1305_test.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, KEY_LEN).unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let expected_mac =
                slice_as_array_ref!(&expected_mac, TAG_LEN).unwrap();

            // Test single-shot operation.
            {
                let mut ctx = SigningContext::with_key(&key);
                ctx.update(&input);
                let mut actual_mac = [0; TAG_LEN];
                ctx.sign(&mut actual_mac);
                assert_eq!(&expected_mac[..], &actual_mac[..]);
            }

            // Test streaming byte-by-byte.
            {
                let mut ctx = SigningContext::with_key(&key);
                for chunk in input.chunks(1) {
                    ctx.update(chunk);
                }
                let mut actual_mac = [0u8; TAG_LEN];
                ctx.sign(&mut actual_mac);
                assert_eq!(&expected_mac[..], &actual_mac[..]);
            }

            try!(test_poly1305_simd(0, key, &input, expected_mac));
            try!(test_poly1305_simd(16, key, &input, expected_mac));
            try!(test_poly1305_simd(32, key, &input, expected_mac));
            try!(test_poly1305_simd(48, key, &input, expected_mac));

            Ok(())
        })
    }

    fn test_poly1305_simd(excess: usize, key: &[u8; KEY_LEN],
                          input: &[u8], expected_mac: &[u8; TAG_LEN])
                          -> Result<(), error::Unspecified> {
        let mut ctx = SigningContext::with_key(key);

        // Some implementations begin in non-SIMD mode and upgrade on demand.
        // Stress the upgrade path.
        let init = core::cmp::min(input.len(), 16);
        ctx.update(&input[..init]);

        let long_chunk_len = 128 + excess;
        for chunk in input[init..].chunks(long_chunk_len + excess) {
            if chunk.len() > long_chunk_len {
                let (long, short) = chunk.split_at(long_chunk_len);

                // Feed 128 + |excess| bytes to test SIMD mode.
                ctx.update(long);

                // Feed |excess| bytes to ensure SIMD mode can handle short
                // inputs.
                ctx.update(short);
            } else {
                // Handle the last chunk.
                ctx.update(chunk);
            }
        }

        let mut actual_mac = [0u8; TAG_LEN];
        ctx.sign(&mut actual_mac);
        assert_eq!(&expected_mac[..], &actual_mac);

        Ok(())
    }

    extern {
        static GFp_POLY1305_STATE_LEN: c::size_t;
    }
}
