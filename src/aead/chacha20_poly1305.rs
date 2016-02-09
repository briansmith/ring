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

use {aead, c};

const CHACHA20_KEY_LEN: usize = 32; // 256 / 8
const POLY1305_TAG_LEN: usize = 128 / 8;

/// ChaCha20-Poly1305 as described in
/// [RFC 7539](https://tools.ietf.org/html/rfc7539).
///
/// The keys are 256 bits long and the nonces are 96 bits long.
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: CHACHA20_KEY_LEN,
    nonce_len: 96 / 8,
    max_overhead_len: POLY1305_TAG_LEN,
    tag_len: POLY1305_TAG_LEN,
    init: evp_aead_chacha20_poly1305_init,
    seal: evp_aead_chacha20_poly1305_seal,
    open: evp_aead_chacha20_poly1305_open,
};

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
    nonce_len: 96 / 8,
    max_overhead_len: POLY1305_TAG_LEN,
    tag_len: POLY1305_TAG_LEN,
    init: evp_aead_chacha20_poly1305_init,
    seal: evp_aead_chacha20_poly1305_old_seal,
    open: evp_aead_chacha20_poly1305_old_open,
};

extern {
    fn evp_aead_chacha20_poly1305_init(ctx_buf: *mut u64,
                                       ctx_buf_len: c::size_t, key: *const u8,
                                       key_len: c::size_t) -> c::int;

    fn evp_aead_chacha20_poly1305_seal(ctx_buf: *const u64, out: *mut u8,
                                       out_len: &mut c::size_t,
                                       max_out_len: c::size_t,
                                       nonce: *const u8, in_: *const u8,
                                       in_len: c::size_t, ad: *const u8,
                                       ad_len: c::size_t) -> c::int;

    fn evp_aead_chacha20_poly1305_open(ctx_buf: *const u64, out: *mut u8,
                                       out_len: &mut c::size_t,
                                       max_out_len: c::size_t,
                                       nonce: *const u8, in_: *const u8,
                                       in_len: c::size_t, ad: *const u8,
                                       ad_len: c::size_t) -> c::int;

    fn evp_aead_chacha20_poly1305_old_seal(ctx_buf: *const u64, out: *mut u8,
                                           out_len: &mut c::size_t,
                                           max_out_len: c::size_t,
                                           nonce: *const u8, in_: *const u8,
                                           in_len: c::size_t, ad: *const u8,
                                           ad_len: c::size_t) -> c::int;

    fn evp_aead_chacha20_poly1305_old_open(ctx_buf: *const u64, out: *mut u8,
                                           out_len: &mut c::size_t,
                                           max_out_len: c::size_t,
                                           nonce: *const u8, in_: *const u8,
                                           in_len: c::size_t, ad: *const u8,
                                           ad_len: c::size_t) -> c::int;
}
