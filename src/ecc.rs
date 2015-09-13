// Copyright 2015 Brian Smith.
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

//! Elliptic curve cryptography.

use libc;
use std;
use super::{digest, ffi};

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

const MAX_COORDINATE_LEN: usize = (521 + 7) / 8;
const MAX_PUBLIC_KEY_LEN: usize = 1 + (2 * MAX_COORDINATE_LEN);

#[derive(Clone, Copy)]
pub struct RawKeyMaterial<'a> {
    pub bytes: &'a [u8]
}

/// Performs an ECDH key agreement with an ephemeral key pair.
///
/// `curve` is the curve to use. `peer_pub_point` is the peer's public key
/// point; `ecdh_ephemeral` will verify that it is on the curve. `error_value`
/// is the value to return if an error occurs.
///
/// After the ECDH key agreement is done, `ecdh_ephemeral` calls `kdf` with the
/// raw key material and the encoded ephemeral public key, returning what `kdf`
/// returns.
///
/// C analogs: `ECDH_ephemeral` (*ring* only), `ECDH_compute_key`.
pub fn ecdh_ephemeral<'a, F, R, E>(curve: &EllipticCurve, peer_pub_point: &[u8],
                                   error_value: E, kdf: F) -> Result<R, E>
                                   where F: FnOnce(RawKeyMaterial, &[u8])
                                                   -> Result<R, E> {
    // TODO: size capacity correctly.
    // TODO: use arrayvec.
    let mut pms: [u8; MAX_PUBLIC_KEY_LEN] =
	unsafe { std::mem::uninitialized() };
    let mut my_pub_key_bytes: [u8; MAX_PUBLIC_KEY_LEN] =
	unsafe { std::mem::uninitialized() };

    let mut pms_len = pms.len() as libc::size_t;
    let mut my_pub_key_bytes_len = my_pub_key_bytes.len() as libc::size_t;

    let result = unsafe {
        ECDH_ephemeral(pms.as_mut_ptr(), &mut pms_len,
                       my_pub_key_bytes.as_mut_ptr(),
                       &mut my_pub_key_bytes_len, curve.nid,
                       peer_pub_point.as_ptr(),
                       peer_pub_point.len() as libc::size_t)
    };
	
    match result {
        1 => {
            kdf(RawKeyMaterial { bytes: &pms[0..(pms_len as usize)] },
		&my_pub_key_bytes[0..(my_pub_key_bytes_len as usize)])
        },

        _ => Err(error_value)
    }
}

/// Verifies that the ASN.1-DER-encoded ECDSA signature encoded in `sig` is
/// valid for the data hashed to `digest` using the encoded public key
/// `key`, which must be in the Elliptic-Curve-Point-to-Octet-String format
/// described in http://www.secg.org/sec1-v2.pdf.
///
/// C analogs: `ECDSA_verify_pkcs1_signed_digest` (*ring* only),
///            `EC_POINT_oct2point` with `ECDSA_verify`.
pub fn verify_ecdsa_signed_digest_asn1(curve: &EllipticCurve,
                                       digest: &digest::Digest, sig: &[u8],
                                       key: &[u8]) -> Result<(),()> {
    ffi::map_bssl_result(unsafe {
        ECDSA_verify_signed_digest(0, digest.as_ref().as_ptr(),
                                   digest.as_ref().len() as libc::size_t,
                                   sig.as_ptr(), sig.len() as libc::size_t,
                                   curve.nid, key.as_ptr(),
                                   key.len() as libc::size_t)
    })
}

extern {
    fn ECDH_ephemeral(pre_master_secret: *mut u8,
                      pre_master_secret_len: *mut libc::size_t,
                      my_pub_point_bytes: *mut u8,
                      my_pub_point_bytes_len: *mut libc::size_t,
                      curve_nid: libc::c_int,
                      peer_pub_point_bytes: *const u8,
                      peer_pub_point_bytes_len: libc::size_t) -> libc::c_int;

    fn ECDSA_verify_signed_digest(hash_nid: libc::c_int, digest: *const u8,
                                  digest_len: libc::size_t, sig_der: *const u8,
                                  sig_der_len: libc::size_t,
                                  curve_nid: libc::c_int, key_octets: *const u8,
                                  key_octets_len: libc::size_t) -> libc::c_int;
}
