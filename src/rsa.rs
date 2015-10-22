// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! RSA signing and verification.

use libc;
use super::{digest, ffi};

/// Verifies that the PKCS#1 1.5 RSA signature encoded in `sig` is valid for
/// the data hashed to `digest` using the ASN.1-DER-encoded public key `key`.
///
/// C analogs: `RSA_verify_pkcs1_signed_digest` (*ring* only),
///            `RSA_public_key_from_bytes` + `RSA_verify` (*ring* and BoringSSL),
///            `d2i_RSAPublicKey` + `RSA_verify`.
pub fn verify_rsa_pkcs1_signed_digest_asn1(digest: &digest::Digest, sig: &[u8],
                                           key: &[u8]) -> Result<(),()> {
    ffi::map_bssl_result(unsafe {
        RSA_verify_pkcs1_signed_digest(digest.algorithm().nid,
                                       digest.as_ref().as_ptr(),
                                       digest.as_ref().len() as libc::size_t,
                                       sig.as_ptr(), sig.len() as libc::size_t,
                                       key.as_ptr(), key.len() as libc::size_t)
    })
}

// XXX: As of Rust 1.4, the compiler will no longer warn about the use of
// `usize` and `isize` in FFI declarations. Remove the `allow(improper_ctypes)`
// when Rust 1.4 is released.
#[allow(improper_ctypes)]
extern {
    fn RSA_verify_pkcs1_signed_digest(hash_nid: libc::c_int, digest: *const u8,
                                      digest_len: libc::size_t, sig: *const u8,
                                      sig_len: libc::size_t, key_der: *const u8,
                                      key_der_len: libc::size_t) -> libc::c_int;
}
