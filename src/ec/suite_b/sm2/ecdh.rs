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

//! SM2 Key Agreement (simple ECDH mode, GB/T 32918.3 simplified).
//!
//! This implements basic EC Diffie-Hellman on the SM2 curve: given a private
//! key `d` and a peer's public key `Q`, compute the shared secret `x` where
//! `(x, y) = d * Q`.
//!
//! This is the same operation as ECDH P-256, just using SM2 curve parameters.
//! The full GB/T 32918.3 protocol (with confirmation hashes) requires multiple
//! rounds and is not supported here.

use crate::{
    agreement, cpu, ec, error,
    ec::suite_b::{
        ops::sm2 as sm2_ops,
        private_key::{
            big_endian_affine_from_jacobian, private_key_as_scalar,
        },
        public_key::parse_uncompressed_point,
    },
};

/// ECDH using the SM2 curve (GB/T 32918.3, simple ECDH mode).
///
/// Public keys are encoded in uncompressed form (`04 || x || y`, 65 bytes).
/// The shared secret output is the x-coordinate of the product point, 32 bytes.
pub static ECDH_SM2: agreement::Algorithm = agreement::Algorithm {
    curve: &crate::ec::suite_b::curve::SM2,
    ecdh: sm2_ecdh,
};

fn sm2_ecdh(
    out: &mut [u8],
    my_private_key: &ec::Seed,
    peer_public_key: untrusted::Input,
    cpu: cpu::Features,
) -> Result<(), error::Unspecified> {
    let private_key_ops = &sm2_ops::PRIVATE_KEY_OPS;
    let public_key_ops = &sm2_ops::PUBLIC_KEY_OPS;

    let q = &public_key_ops.common.elem_modulus(cpu);

    // Parse and validate the peer's public key.
    let peer_public_key = parse_uncompressed_point(public_key_ops, q, peer_public_key)?;

    // Compute the shared point [d]Q.
    let n = &private_key_ops.common.scalar_modulus(cpu);
    let my_private_key_scalar = private_key_as_scalar(n, my_private_key);
    let product = private_key_ops.point_mul(&my_private_key_scalar, &peer_public_key, cpu);

    // Extract x-coordinate of [d]Q as the shared secret.
    big_endian_affine_from_jacobian(private_key_ops, q, out, None, &product)
}
