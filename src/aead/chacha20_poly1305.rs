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
// Portions Copyright (c) 2015, Google Inc.

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
    init: init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
};

fn chacha20_poly1305_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                          -> Result<(), error::Unspecified> {
    seal(chacha20_poly1305_update, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          in_prefix_len: usize,
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                          -> Result<(), error::Unspecified> {
    open(chacha20_poly1305_update, ctx, nonce, in_out, in_prefix_len, tag_out,
         ad)
}

fn chacha20_poly1305_update(state: &mut [u8; POLY1305_STATE_LEN], ad: &[u8],
                            ciphertext: &[u8]) {
    fn update_padded_16(state: &mut [u8; POLY1305_STATE_LEN], data: &[u8]) {
        poly1305_update(state, data);
        if data.len() % 16 != 0 {
            static PADDING: [u8; 16] = [0u8; 16];
            poly1305_update(state,
                            &PADDING[..PADDING.len() - (data.len() % 16)])
        }
    }
    update_padded_16(state, ad);
    update_padded_16(state, ciphertext);
    poly1305_update_length(state, ad.len());
    poly1305_update_length(state, ciphertext.len());
}


/// The old ChaCha20-Poly13065 construction used in OpenSSH's
/// [chacha20-poly1305@openssh.com] and the experimental TLS cipher suites with
/// IDs `0xCC13` (ECDHE-RSA) and `0xCC14` (ECDHE-ECDSA). Use
/// `CHACHA20_POLY1305` instead.
///
/// The keys are 256 bits long and the nonces are 96 bits. The first four bytes
/// of the nonce must be `[0, 0, 0, 0]` in order to interoperate with other
/// implementations, which use 64-bit nonces.
///
/// [chacha20-poly1305@openssh.com]:
///     http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.chacha20poly1305
pub static CHACHA20_POLY1305_OLD: aead::Algorithm = aead::Algorithm {
    key_len: CHACHA20_KEY_LEN,
    init: init,
    seal: chacha20_poly1305_old_seal,
    open: chacha20_poly1305_old_open,
};

fn chacha20_poly1305_old_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                              nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                              tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                              -> Result<(), error::Unspecified> {
    seal(chacha20_poly1305_update_old, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_old_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                              nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                              in_prefix_len: usize,
                              tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                              -> Result<(), error::Unspecified> {
    open(chacha20_poly1305_update_old, ctx, nonce, in_out, in_prefix_len,
         tag_out, ad)
}

fn chacha20_poly1305_update_old(state: &mut [u8; POLY1305_STATE_LEN],
                                ad: &[u8], ciphertext: &[u8]) {
    poly1305_update(state, ad);
    poly1305_update_length(state, ad.len());
    poly1305_update(state, ciphertext);
    poly1305_update_length(state, ciphertext.len());
}


/// Copies |key| into |ctx_buf|.
pub fn init(ctx_buf: &mut [u8], key: &[u8]) -> Result<(), error::Unspecified> {
    ctx_buf[..key.len()].copy_from_slice(key);
    Ok(())
}

fn seal(update: UpdateFn, ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
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
    aead_poly1305(update, tag_out, chacha20_key, &counter, ad, in_out);
    Ok(())
}

fn open(update: UpdateFn, ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
        nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8], in_prefix_len: usize,
        tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
        -> Result<(), error::Unspecified> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = make_counter(0, nonce);
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(update, tag_out, chacha20_key, &counter, ad, ciphertext);
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
    slice_as_array_ref!(&polyfill::slice::u64_as_u32(ctx)[..(CHACHA20_KEY_LEN / 4)],
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

fn aead_poly1305(update: UpdateFn, tag_out: &mut [u8; aead::TAG_LEN],
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
    update(&mut ctx, ad, ciphertext);
    poly1305_finish(&mut ctx, tag_out);
}

/// Updates the Poly1305 context |ctx| with the 64-bit little-endian encoded
/// length value |len|.
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
    use {aead, c, error, polyfill, test};
    use super::{GFp_ChaCha20_ctr32, CHACHA20_KEY_LEN, make_counter,
                POLY1305_STATE_LEN, POLY1305_KEY_LEN, poly1305_init,
                poly1305_finish, poly1305_update};
    #[test]
    pub fn test_chacha20_poly1305() {
        aead::tests::test_aead(&aead::CHACHA20_POLY1305,
                               "crypto/cipher/test/chacha20_poly1305_tests.txt");
    }

    #[test]
    pub fn test_chacha20_poly1305_old() {
        aead::tests::test_aead(&aead::CHACHA20_POLY1305_OLD,
                               "crypto/cipher/test/chacha20_poly1305_old_tests.txt");
    }

    #[test]
    pub fn test_poly1305_state_len() {
        assert_eq!((POLY1305_STATE_LEN + 255) / 256,
                   (GFp_POLY1305_STATE_LEN + 255) / 256);
    }

    #[test]
    pub fn test_poly1305() {
        test::from_file("src/aead/poly1305_test.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, POLY1305_KEY_LEN).unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let expected_mac = slice_as_array_ref!(&expected_mac, aead::TAG_LEN).unwrap();

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

            try!(test_simd(0, key, &input, expected_mac));
            try!(test_simd(16, key, &input, expected_mac));
            try!(test_simd(32, key, &input, expected_mac));
            try!(test_simd(48, key, &input, expected_mac));

            Ok(())
        })
    }

    fn test_simd(excess: usize, key: &[u8; POLY1305_KEY_LEN],
                 input: &[u8], expected_mac: &[u8; aead::TAG_LEN])
                 -> Result<(), error::Unspecified> {
        let mut state = [0u8; POLY1305_STATE_LEN];
        poly1305_init(&mut state, &key);

        // Feed 16 bytes in. Some implementations begin in non-SIMD mode and
        // upgrade on-demand. Stress the upgrade path.
        let init = if input.len() < 16 { input.len() } else { 16 };

        poly1305_update(&mut state, &input[..init]);
        for chunk in input[init..].chunks(128 + 2 * excess) {
            let (long, short) = if chunk.len() < 128 + excess {
                (chunk, &[][..])
            } else {
                chunk.split_at(128 + excess)
            };
            // Feed 128 + |excess| bytes to test SIMD mode.
            poly1305_update(&mut state, long);
            // Feed |excess| bytes to ensure SIMD mode can handle short inputs.
            if !short.is_empty() {
                poly1305_update(&mut state, short);
            }
        }

        let mut actual_mac = [0u8; aead::TAG_LEN];
        poly1305_finish(&mut state, &mut actual_mac);
        assert_eq!(expected_mac, &actual_mac, "SIMD pattern failed.");
        Ok(())
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
    pub fn test_chacha20_ctr32() {
        test::from_file("src/aead/chacha_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let key_bytes = test_case.consume_bytes("Key");
            let ctr = test_case.consume_usize("Ctr");
            let nonce_bytes = test_case.consume_bytes("Nonce");
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("Output");

            assert_eq!(key_bytes.len(), CHACHA20_KEY_LEN);
            let key = {
                let mut buf = [0u32; CHACHA20_KEY_LEN / 4];
                for (val, chunk) in buf.iter_mut().zip(key_bytes.chunks(4)) {
                    let arr_ref = slice_as_array_ref!(chunk, 4).unwrap();
                    *val = polyfill::slice::u32_from_le_u8(arr_ref);
                }
                buf
            };

            let nonce = slice_as_array_ref!(&nonce_bytes, aead::NONCE_LEN).unwrap();
            let counter = make_counter(ctr as u32, &nonce);


            // Pre-allocate buffer for use in test_cases.
            let mut buf = vec![0u8; input.len() + 276];

            // Run the test case over all prefixes of the input because the
            // behavior of ChaCha20 implementation changes dependent on the
            // length of the input.
            for len in 0..(input.len() + 1) {
                chacha20_test_case_inner(&key, &counter, &input[..len],
                                         &output[..len], len, &mut buf);
            }

            Ok(())
        });
    }

    fn chacha20_test_case_inner(key: &[u32; CHACHA20_KEY_LEN / 4],
                                ctr: &[u32; 4], input: &[u8], output: &[u8],
                                len: usize, buf: &mut [u8]) {
        // Straightforward encryption into disjoint buffers is computed
        // correctly.
        unsafe {
            GFp_ChaCha20_ctr32(buf.as_mut_ptr(), input[..len].as_ptr(),
                             len, key, &ctr);
        }
        assert_eq!(&buf[..len], output);

        // Do not test offset buffers for x86 and ARM architectures (see above
        // for rationale).
        let max_offset = if cfg!(any(target_arch = "x86", target_arch = "arm")) {
            0
        } else {
            259
        };

        // Check that in-place encryption works successfully when the pointers
        // to the input/output buffers are (partially) overlapping.
        for alignment in 0..16 {
            for offset in 0..(max_offset + 1) {
                let input_offset = alignment + offset;
                buf[input_offset..][..len].copy_from_slice(input);
                unsafe {
                    GFp_ChaCha20_ctr32(buf[alignment..].as_mut_ptr(),
                                   buf[input_offset..].as_ptr(),
                                   len, key, ctr);
                }
                assert_eq!(&buf[alignment..][..len], output);
            }
        }
    }

    extern "C" {
        static GFp_POLY1305_STATE_LEN: c::size_t;
    }
}
