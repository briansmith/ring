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

#![allow(unsafe_code)]

use {aead, c, error, polyfill};
use core;

const CHACHA20_KEY_LEN: usize = 256 / 8;
const POLY1305_STATE_LEN: usize = 256;
const POLY1305_KEY_LEN: usize = 32;


/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: CHACHA20_KEY_LEN,
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
    let mut counter = make_counter(1, nonce);
    debug_assert!(core::mem::align_of_val(chacha20_key) >= 4);
    debug_assert!(core::mem::align_of_val(&counter) >= 4);
    unsafe {
        GFp_ChaCha20_ctr32(in_out.as_mut_ptr(), in_out.as_ptr(), in_out.len(),
                           chacha20_key, &counter);
    }
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
    let mut counter = make_counter(0, nonce);
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(tag_out, chacha20_key, &counter, ad, ciphertext);
    }
    counter[0] = 1;
    debug_assert!(core::mem::align_of_val(chacha20_key) >= 4);
    debug_assert!(core::mem::align_of_val(&counter) >= 4);
    unsafe {
        // XXX: The x86 and at least one branch of the ARM assembly language
        // code doesn't allow overlapping input and output unless they are
        // exactly overlapping. TODO: Figure out which branch of the ARM code
        // has this limitation and come up with a better solution.
        //
        // https://rt.openssl.org/Ticket/Display.html?id=4362
        if cfg!(any(target_arch = "arm", target_arch = "x86")) &&
           in_prefix_len != 0 {
            GFp_ChaCha20_ctr32(in_out[in_prefix_len..].as_mut_ptr(),
                               in_out[in_prefix_len..].as_ptr(),
                               in_out.len() - in_prefix_len, chacha20_key,
                               &counter);
            core::ptr::copy(in_out[in_prefix_len..].as_ptr(),
                            in_out.as_mut_ptr(), in_out.len() - in_prefix_len);
        } else {
            GFp_ChaCha20_ctr32(in_out.as_mut_ptr(),
                               in_out[in_prefix_len..].as_ptr(),
                               in_out.len() - in_prefix_len, chacha20_key,
                               &counter);
        }
    }
    Ok(())
}

fn ctx_as_key(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS])
              -> Result<&[u32; CHACHA20_KEY_LEN / 4], error::Unspecified> {
    slice_as_array_ref!(
        &polyfill::slice::u64_as_u32(ctx)[..(CHACHA20_KEY_LEN / 4)],
        CHACHA20_KEY_LEN / 4)
}

#[inline]
fn make_counter(counter: u32, nonce: &[u8; aead::NONCE_LEN]) -> [u32; 4] {
    use polyfill::slice::u32_from_le_u8;
    [counter.to_le(),
     u32_from_le_u8(slice_as_array_ref!(&nonce[0..4], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[4..8], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[8..12], 4).unwrap())]
}

type UpdateFn = fn(state: &mut [u8; POLY1305_STATE_LEN], ad: &[u8],
                   ciphertext: &[u8]);

fn aead_poly1305(tag_out: &mut [u8; aead::TAG_LEN],
                 chacha20_key: &[u32; CHACHA20_KEY_LEN / 4],
                 counter: &[u32; 4], ad: &[u8], ciphertext: &[u8]) {
    debug_assert_eq!(counter[0], 0);
    let mut poly1305_key = [0u8; POLY1305_KEY_LEN];
    debug_assert!(core::mem::align_of_val(chacha20_key) >= 4);
    debug_assert!(core::mem::align_of_val(&counter) >= 4);
    unsafe {
        GFp_ChaCha20_ctr32(poly1305_key.as_mut_ptr(), poly1305_key.as_ptr(),
                           POLY1305_KEY_LEN, chacha20_key, &counter);
    }
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
    fn GFp_ChaCha20_ctr32(out: *mut u8, in_: *const u8, in_len: c::size_t,
                          key: &[u32; CHACHA20_KEY_LEN / 4],
                          counter: &[u32; 4]);
    fn GFp_poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                         key: &[u8; POLY1305_KEY_LEN]);
    fn GFp_poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                           mac: &mut [u8; aead::TAG_LEN]);
    fn GFp_poly1305_update(state: &mut [u8; POLY1305_STATE_LEN],
                           in_: *const u8, in_len: c::size_t);
}

#[cfg(test)]
mod tests {
    use {aead, c, polyfill, test};
    use super::{GFp_ChaCha20_ctr32, CHACHA20_KEY_LEN, make_counter};

    bssl_test!(test_poly1305, bssl_poly1305_test_main);

    #[test]
    pub fn test_chacha20_poly1305() {
        aead::tests::test_aead(&aead::CHACHA20_POLY1305,
            "crypto/cipher/test/chacha20_poly1305_tests.txt");
    }

    #[test]
    pub fn test_poly1305_state_len() {
        assert_eq!((super::POLY1305_STATE_LEN + 255) / 256,
                   (unsafe { GFp_POLY1305_STATE_LEN } + 255) / 256);
    }

    // This verifies the encryption functionality provided by ChaCha20_ctr32
    // is successful when either computed on disjoint input/output buffers,
    // or on overlapping input/output buffers. On some branches of the 32-bit
    // x86 and ARM code the in-place operation fails in some situations where
    // the input/output buffers are not exactly overlapping. Such failures are
    // dependent not only on the degree of overlapping but also the length of
    // the data. `open()` works around that by moving the input data to the
    // output location so that the buffers exactly overlap, for those targets.
    // This test exists largely as a canary for detecting if/when that type of
    // problem spreads to other platforms.
    #[test]
    pub fn chacha20_tests() {
        test::from_file("src/aead/chacha_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let key_bytes = test_case.consume_bytes("Key");
            let mut key = [0u32; CHACHA20_KEY_LEN / 4];
            for ki in 0..(CHACHA20_KEY_LEN / 4) {
                let kb =
                    slice_as_array_ref!(&key_bytes[ki * 4..][..4], 4).unwrap();
                key[ki] = polyfill::slice::u32_from_le_u8(kb);
            }

            let ctr = test_case.consume_usize("Ctr");
            let nonce_bytes = test_case.consume_bytes("Nonce");
            let nonce = slice_as_array_ref!(&nonce_bytes,
                                            aead::NONCE_LEN).unwrap();
            let ctr = make_counter(ctr as u32, &nonce);
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("Output");

            // Pre-allocate buffer for use in test_cases.
            let mut in_out_buf = vec![0u8; input.len() + 276];

            // Run the test case over all prefixes of the input because the
            // behavior of ChaCha20 implementation changes dependent on the
            // length of the input.
            for len in 0..(input.len() + 1) {
                chacha20_test_case_inner(&key, &ctr, &input[..len],
                                         &output[..len], len, &mut in_out_buf);
            }

            Ok(())
        });
    }

    fn chacha20_test_case_inner(key: &[u32; CHACHA20_KEY_LEN / 4],
                                ctr: &[u32; 4], input: &[u8], expected: &[u8],
                                len: usize, in_out_buf: &mut [u8]) {
        // Straightforward encryption into disjoint buffers is computed
        // correctly.
        unsafe {
          GFp_ChaCha20_ctr32(in_out_buf.as_mut_ptr(), input[..len].as_ptr(),
                             len, key, &ctr);
        }
        assert_eq!(&in_out_buf[..len], expected);

        // Do not test offset buffers for x86 and ARM architectures (see above
        // for rationale).
        let max_offset =
            if cfg!(any(target_arch = "x86", target_arch = "arm")) {
                0
            } else {
                259
            };

        // Check that in-place encryption works successfully when the pointers
        // to the input/output buffers are (partially) overlapping.
        for alignment in 0..16 {
            for offset in 0..(max_offset + 1) {
              in_out_buf[alignment+offset..][..len].copy_from_slice(input);
              unsafe {
                  GFp_ChaCha20_ctr32(in_out_buf[alignment..].as_mut_ptr(),
                                     in_out_buf[alignment + offset..].as_ptr(),
                                     len, key, ctr);
                  assert_eq!(&in_out_buf[alignment..][..len], expected);
              }
            }
        }
    }

    extern {
        static GFp_POLY1305_STATE_LEN: c::size_t;
    }
}
