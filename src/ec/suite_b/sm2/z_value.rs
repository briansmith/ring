// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM2 Z value computation (GB/T 32918.2 §5).
//!
//! The Z value is a hash of the signer's distinguishing identifier together
//! with the public domain parameters and the signer's public key:
//!
//! ```text
//! Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
//! ```
//!
//! where:
//! - `ENTL` = 2-byte big-endian length of `ID` in **bits**
//! - `ID`   = signer's distinguishing identifier (default: `"1234567812345678"`)
//! - `a`, `b` = curve coefficients (unencoded, big-endian, 32 bytes each)
//! - `xG`, `yG` = base point coordinates (unencoded, big-endian, 32 bytes each)
//! - `xA`, `yA` = public key coordinates (extracted from the 65-byte public key)
//!
//! After computing Z, the message digest `e = SM3(Z || M)` is computed.

use crate::{digest, error};

/// Curve parameters in unencoded (not Montgomery) form, big-endian 32 bytes.
///
/// SM2 curve (GB/T 32918.1-2016 Appendix A):
/// a = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
/// b = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
/// Gx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
/// Gy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
const SM2_A_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
];

const SM2_B_BYTES: [u8; 32] = [
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
];

const SM2_GX_BYTES: [u8; 32] = [
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
];

const SM2_GY_BYTES: [u8; 32] = [
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
];

/// Computes Z and then the full SM2 message digest `e = SM3(Z || M)`.
///
/// # Parameters
/// - `digest_alg`: the digest algorithm (SM3)
/// - `public_key_bytes`: 65-byte uncompressed public key (`04 || xA || yA`)
/// - `signer_id`: signer's distinguishing identifier (typically 16 bytes)
/// - `message`: the message to be signed
///
/// # Returns
/// The digest `e = SM3(Z || M)`.
pub(super) fn compute_z_then_e(
    digest_alg: &'static digest::Algorithm,
    public_key_bytes: &[u8],
    signer_id: &[u8],
    message: &[u8],
) -> Result<digest::Digest, error::Unspecified> {
    // GB/T 32918.2 §5.2: ENTL is the bit-length of ID, as a 2-byte big-endian integer.
    // Reason: ID length is expressed in bits, not bytes, in the standard.
    let id_bit_len = signer_id
        .len()
        .checked_mul(8)
        .filter(|&bits| bits <= 0xFFFF)
        .ok_or(error::Unspecified)?;
    #[allow(clippy::cast_possible_truncation)]
    let entl = [(id_bit_len >> 8) as u8, id_bit_len as u8];

    // Extract xA, yA from uncompressed public key: 04 || xA (32 bytes) || yA (32 bytes).
    if public_key_bytes.len() != 65 || public_key_bytes[0] != 0x04 {
        return Err(error::Unspecified);
    }
    let xa = &public_key_bytes[1..33];
    let ya = &public_key_bytes[33..65];

    // Compute Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA).
    let mut z_ctx = digest::Context::new(digest_alg);
    z_ctx.update(&entl);
    z_ctx.update(signer_id);
    z_ctx.update(&SM2_A_BYTES);
    z_ctx.update(&SM2_B_BYTES);
    z_ctx.update(&SM2_GX_BYTES);
    z_ctx.update(&SM2_GY_BYTES);
    z_ctx.update(xa);
    z_ctx.update(ya);
    let z = z_ctx.finish();

    // Compute e = SM3(Z || M).
    let mut e_ctx = digest::Context::new(digest_alg);
    e_ctx.update(z.as_ref());
    e_ctx.update(message);
    Ok(e_ctx.finish())
}
