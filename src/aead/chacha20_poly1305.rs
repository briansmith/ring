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

use {aead, c, core, polyfill};

const CHACHA20_KEY_LEN: usize = 256 / 8;
const POLY1305_STATE_LEN: usize = 512;
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

fn chacha20_poly1305_seal(ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
                          in_out: &mut [u8], tag_out: &mut [u8; aead::TAG_LEN],
                          ad: &[u8]) -> Result<(), ()> {
    seal(chacha20_poly1305_update, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_open(ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
                          in_out: &mut [u8], in_prefix_len: usize,
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

fn chacha20_poly1305_old_seal(ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
                              in_out: &mut [u8],
                              tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
                              -> Result<(), ()> {
    seal(chacha20_poly1305_update_old, ctx, nonce, in_out, tag_out, ad)
}

fn chacha20_poly1305_old_open(ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
                              in_out: &mut [u8], in_prefix_len: usize,
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

fn seal(update: UpdateFn, ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
        in_out: &mut [u8], tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8])
        -> Result<(), ()> {
    let chacha20_key =
        try!(slice_as_array_ref!(&ctx[..CHACHA20_KEY_LEN], CHACHA20_KEY_LEN));
    unsafe {
        CRYPTO_chacha_20(in_out.as_mut_ptr(), in_out.as_ptr(), in_out.len(),
                         chacha20_key.as_ptr(), nonce.as_ptr(), 1);
    }
    aead_poly1305(update, tag_out, chacha20_key, nonce, ad, in_out);
    Ok(())
}

fn open(update: UpdateFn, ctx: &[u8], nonce: &[u8; aead::NONCE_LEN],
        in_out: &mut [u8], in_prefix_len: usize,
        tag_out: &mut [u8; aead::TAG_LEN], ad: &[u8]) -> Result<(), ()> {
    let chacha20_key =
        try!(slice_as_array_ref!(&ctx[..CHACHA20_KEY_LEN], CHACHA20_KEY_LEN));
    {
        let ciphertext = &in_out[in_prefix_len..];
        aead_poly1305(update, tag_out, chacha20_key, nonce, ad, &ciphertext);
    }
    unsafe {
        CRYPTO_chacha_20(in_out.as_mut_ptr(),
                         in_out[in_prefix_len..].as_ptr(),
                         in_out.len() - in_prefix_len, ctx.as_ptr(),
                         nonce.as_ptr(), 1);
    }
    Ok(())
}

type UpdateFn = fn(state: &mut [u8; POLY1305_STATE_LEN], ad: &[u8],
                   ciphertext: &[u8]);

fn aead_poly1305(update: UpdateFn, tag_out: &mut [u8; aead::TAG_LEN],
                 chacha20_key: &[u8; CHACHA20_KEY_LEN],
                 nonce: &[u8; aead::NONCE_LEN], ad: &[u8], ciphertext: &[u8]) {
    let mut poly1305_key = [0; POLY1305_KEY_LEN];
    unsafe {
        CRYPTO_chacha_20(poly1305_key.as_mut_ptr(), poly1305_key.as_ptr(),
                         core::mem::size_of_val(&poly1305_key),
                         chacha20_key.as_ptr(), nonce.as_ptr(), 0)
    }
    let mut ctx = [0; POLY1305_STATE_LEN];
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
fn poly1305_init(state: &mut [u8; POLY1305_STATE_LEN],
                 key: &[u8; POLY1305_KEY_LEN]) {
    unsafe {
        CRYPTO_poly1305_init(state.as_mut_ptr(), key.as_ptr())
    }
}

/// Safe wrapper around |CRYPTO_poly1305_finish|.
fn poly1305_finish(state: &mut [u8; POLY1305_STATE_LEN],
                   tag_out: &mut [u8; aead::TAG_LEN]) {
    unsafe {
        CRYPTO_poly1305_finish(state.as_mut_ptr(), tag_out.as_mut_ptr())
    }
}

/// Safe wrapper around |CRYPTO_poly1305_update|.
fn poly1305_update(state: &mut [u8; POLY1305_STATE_LEN], in_: &[u8]) {
    unsafe {
        CRYPTO_poly1305_update(state.as_mut_ptr(), in_.as_ptr(), in_.len())
    }
}

extern {
    fn CRYPTO_chacha_20(out: *mut u8, in_: *const u8, in_len: c::size_t,
                        key: *const u8, nonce: *const u8, counter: u32);
    fn CRYPTO_poly1305_init(state: *mut u8, key: *const u8);
    fn CRYPTO_poly1305_finish(state: *mut u8, mac: *mut u8);
    fn CRYPTO_poly1305_update(state: *mut u8, in_: *const u8,
                              in_len: c::size_t);
}
