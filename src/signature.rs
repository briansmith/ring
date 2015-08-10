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

use libc;

/// An elliptic curve. See `CURVE_P256`, `CURVE_P256`, and `CURVE_521`.
///
/// C analog: `EC_GROUP`
#[derive(Debug)]
pub struct EllipticCurve { nid: libc::c_int }

/// The NIST P-256 curve, a.k.a. secp256r1.
///
/// C analog: `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`
pub static CURVE_P256: EllipticCurve = EllipticCurve { nid: 415 };

/// The NIST P-384 curve, a.k.a. secp384r1.
///
/// C analog: `EC_GROUP_new_by_curve_name(NID_secp384)`
pub static CURVE_P384: EllipticCurve = EllipticCurve { nid: 715 };

/// The NIST P-521 curve, a.k.a. secp521r1.
///
/// C analog: `EC_GROUP_new_by_curve_name(NID_secp521)`
pub static CURVE_P521: EllipticCurve = EllipticCurve { nid: 716 };

/// Identifies a digest algorithm used in a signature.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum SignatureDigestAlgorithm {
    /// SHA-1.
    ///
    /// C analog: `NID_sha1`
    SHA1 = 64,

    /// SHA-256.
    ///
    /// C analog: `NID_sha256'
    SHA256 = 672,

    /// SHA-384.
    ///
    /// C analog: `NID_sha384'
    SHA384 = 673,

    /// SHA-512.
    ///
    /// C analog: `NID_sha512'
    SHA512 = 674,
}


/// Verifies that the ASN.1-DER-encoded ECDSA signature encoded in `sig` is
/// valid for the data hashed to `digest` using the encoded public key `key`,
/// which must be in the Elliptic-Curve-Point-to-Octet-String format described
/// in http://www.secg.org/sec1-v2.pdf.
///
/// C analogs: `RSA_verify_pkcs1_signed_digest` (*ring* only),
///            `EC_POINT_oct2point` + `ECDSA_verify`.
pub fn verify_ecdsa_signed_digest_asn1(digest_alg: SignatureDigestAlgorithm,
                                       digest: &[u8], sig: &[u8],
                                       curve: &EllipticCurve, key: &[u8])
                                       -> Result<(),()> {
    let x;
    unsafe {
        x = ECDSA_verify_signed_digest(digest_alg as libc::c_int,
                                       digest.as_ptr(),
                                       digest.len() as libc::size_t,
                                       sig.as_ptr(),
                                       sig.len() as libc::size_t,
                                       curve.nid, key.as_ptr(),
                                       key.len() as libc::size_t);
    }
    match x {
        1 => Ok(()),
        _ => Err(())
    }
}


/// Verifies that the PKCS#1 1.5 RSA signature encoded in `sig` is valid for
/// the data hashed to `digest` using the ASN.1-DER-encoded public key `key`.
///
/// C analogs: `RSA_verify_pkcs1_signed_digest` (*ring* only),
///            `RSA_public_key_from_bytes` + `RSA_verify` (*ring* and BoringSSL),
///            `d2i_RSAPublicKey` + `RSA_verify`.
pub fn verify_rsa_pkcs1_signed_digest_asn1(
         digest_alg: SignatureDigestAlgorithm, digest: &[u8], sig: &[u8],
         key: &[u8]) -> Result<(),()> {
    let x;
    unsafe {
        x = RSA_verify_pkcs1_signed_digest(digest_alg as libc::c_int,
                                           digest.as_ptr(),
                                           digest.len() as libc::size_t,
                                           sig.as_ptr(),
                                           sig.len() as libc::size_t,
                                           key.as_ptr(),
                                           key.len() as libc::size_t);
    }
    match x {
        1 => Ok(()),
        _ => Err(())
    }
}

extern {
    fn RSA_verify_pkcs1_signed_digest(hash_nid: libc::c_int, digest: *const u8,
                                      digest_len: libc::size_t, sig: *const u8,
                                      sig_len: libc::size_t, key_der: *const u8,
                                      key_der_len: libc::size_t) -> libc::c_int;

    fn ECDSA_verify_signed_digest(hash_nid: libc::c_int, digest: *const u8,
                                  digest_len: libc::size_t, sig_der: *const u8,
                                  sig_der_len: libc::size_t,
                                  curve_nid: libc::c_int, key_octets: *const u8,
                                  key_octets_len: libc::size_t) -> libc::c_int;
}
