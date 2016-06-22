// Copyright 2015-2016 Brian Smith.
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

#![allow(unsafe_code)]

use {aead, c, polyfill};
use core;

const CHACHA20_KEY_LEN: usize = 256 / 8;
const POLY1305_STATE_LEN: usize = 256;
const POLY1305_KEY_LEN: usize = 32;


/// ChaCha20-Poly1305 as described in
/// [RFC 7539](https://tools.ietf.org/html/rfc7539).
///
/// The keys are 256 bits long and the nonces are 96 bits long.
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: CHACHA20_KEY_LEN,
    init: init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
};

fn chacha20_poly1305_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                          -> Result<(), ()> {
    seal(chacha20_poly1305_update, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                          in_prefix_len: usize,
                          tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                          -> Result<(), ()> {
    open(chacha20_poly1305_update, ctx, nonce, in_out, in_prefix_len, tag_out,
         ad)
}

fn chacha20_poly1305_update(state: &mut [u8; POLY1305_STATE_LEN],
                            ad: &[u8], ciphertext: &[u8]) {
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
/// [chacha20-poly1305@openssh.com](http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL.chacha20poly1305)
/// and the experimental TLS cipher suites with IDs `0xCC13` (ECDHE-RSA) and
/// `0xCC14` (ECDHE-ECDSA). Use `CHACHA20_POLY1305` instead.
///
/// The keys are 256 bits long and the nonces are 96 bits. The first four bytes
/// of the nonce must be `[0, 0, 0, 0]` in order to interoperate with other
/// implementations, which use 64-bit nonces.
pub static CHACHA20_POLY1305_OLD: aead::Algorithm = aead::Algorithm {
    key_len: CHACHA20_KEY_LEN,
    init: init,
    seal: chacha20_poly1305_old_seal,
    open: chacha20_poly1305_old_open,
};

fn chacha20_poly1305_old_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                              nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                              tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                              -> Result<(), ()> {
    seal(chacha20_poly1305_update_old, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_old_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                              nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
                              in_prefix_len: usize,
                              tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                              -> Result<(), ()> {
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
pub fn init(ctx_buf: &mut [u8], key: &[u8]) -> Result<(), ()> {
    polyfill::slice::fill_from_slice(&mut ctx_buf[..key.len()], key);
    Ok(())
}

fn seal(update: UpdateFn, ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
        nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8],
        tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8]) -> Result<(), ()> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = make_counter(1, nonce);
    debug_assert!(core::mem::align_of_val(chacha20_key) >= 4);
    debug_assert!(core::mem::align_of_val(&counter) >= 4);
    unsafe {
        ChaCha20_ctr32(in_out.as_mut_ptr(), in_out.as_ptr(), in_out.len(),
                       chacha20_key, &counter);
    }
    counter[0] = 0;
    aead_poly1305(update, tag_out, chacha20_key, &counter, ad, in_out);
    Ok(())
}

fn open(update: UpdateFn, ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
        nonce: &[u8; aead::NONCE_LEN], in_out: &mut [u8], in_prefix_len: usize,
        tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8]) -> Result<(), ()> {
    let chacha20_key = try!(ctx_as_key(ctx));
    let mut counter = make_counter(0, nonce);
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(update, tag_out, chacha20_key, &counter, ad, &ciphertext);
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
            ChaCha20_ctr32(in_out[in_prefix_len..].as_mut_ptr(),
                           in_out[in_prefix_len..].as_ptr(),
                           in_out.len() - in_prefix_len, chacha20_key, &counter);
            core::ptr::copy(in_out[in_prefix_len..].as_ptr(),
                            in_out.as_mut_ptr(), in_out.len() - in_prefix_len);
        } else {
            ChaCha20_ctr32(in_out.as_mut_ptr(), in_out[in_prefix_len..].as_ptr(),
                           in_out.len() - in_prefix_len, chacha20_key, &counter);
        }
    }
    Ok(())
}

fn ctx_as_key(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS])
              -> Result<&[u32; CHACHA20_KEY_LEN / 4], ()> {
    slice_as_array_ref!(
        &polyfill::slice::u64_as_u32(ctx)[..(CHACHA20_KEY_LEN / 4)],
        CHACHA20_KEY_LEN / 4)
}

#[inline]
fn make_counter(counter: u32, nonce: &[u8; aead::NONCE_LEN]) -> [u32; 4] {
    fn from_le_bytes(bytes: &[u8]) -> u32 {
        u32::from(bytes[0]) |
            (u32::from(bytes[1]) << 8) |
            (u32::from(bytes[2]) << 16) |
            (u32::from(bytes[3]) << 24)
    }
    [counter.to_le(),
     from_le_bytes(&nonce[0..4]),
     from_le_bytes(&nonce[4..8]),
     from_le_bytes(&nonce[8..12])]
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
        ChaCha20_ctr32(poly1305_key.as_mut_ptr(), poly1305_key.as_ptr(),
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


/// Safe wrapper around |CRYPTO_poly1305_init|.
#[inline(always)]
fn poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                 key: &[u8; POLY1305_KEY_LEN]) {
    unsafe {
        CRYPTO_poly1305_init(state, key)
    }
}

/// Safe wrapper around |CRYPTO_poly1305_finish|.
#[inline(always)]
fn poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                   tag_out: &mut [u8; aead::TAG_LEN]) {
    unsafe {
        CRYPTO_poly1305_finish(state, tag_out)
    }
}

/// Safe wrapper around |CRYPTO_poly1305_update|.
#[inline(always)]
fn poly1305_update(state: &mut [u8; POLY1305_STATE_LEN], in_: &[u8]) {
    unsafe {
        CRYPTO_poly1305_update(state, in_.as_ptr(), in_.len())
    }
}

extern {
    fn ChaCha20_ctr32(out: *mut u8, in_: *const u8, in_len: c::size_t,
                      key: &[u32; CHACHA20_KEY_LEN / 4], counter: &[u32; 4]);
    fn CRYPTO_poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                            key: &[u8; POLY1305_KEY_LEN]);
    fn CRYPTO_poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                              mac: &mut [u8; aead::TAG_LEN]);
    fn CRYPTO_poly1305_update(state: &mut [u8; POLY1305_STATE_LEN],
                              in_: *const u8, in_len: c::size_t);
}

#[cfg(test)]
mod tests {
    use {aead, c};

    bssl_test!(test_chacha, bssl_chacha_test_main);
    bssl_test!(test_poly1305, bssl_poly1305_test_main);

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
        assert_eq!((super::POLY1305_STATE_LEN + 255) / 256,
                    (CRYPTO_POLY1305_STATE_LEN + 255) / 256);
    }

    extern {
        static CRYPTO_POLY1305_STATE_LEN: c::size_t;
    }
}
