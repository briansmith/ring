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

//! SM2 Signature Verification (GB/T 32918.2 §7).
//!
//! SM2 verification algorithm:
//!
//! 1. Parse and range-check (r, s) from the signature.
//! 2. Compute `t = (r + s) mod n`.
//! 3. Compute `P = s·G + t·Q` using the signer's public key Q.
//! 4. Compute `R = (e + Px) mod n`.
//! 5. Accept iff `R == r`.
//!
//! The message digest `e = SM3(Z || M)` is computed first (see `z_value.rs`).

use super::z_value::compute_z_then_e;
use crate::{
    cpu, digest,
    ec::suite_b::{
        ops::{sm2 as sm2_ops, *},
        public_key::parse_uncompressed_point,
    },
    error, limb, sealed, signature,
};

/// An SM2 signature verification algorithm.
pub struct Sm2VerificationAlgorithm {
    pub(super) ops: &'static PublicScalarOps,
    pub(super) digest_alg: &'static digest::Algorithm,
    split_rs:
        for<'a> fn(
            ops: &'static ScalarOps,
            input: &mut untrusted::Reader<'a>,
        )
            -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::Unspecified>,
    id: AlgorithmID,
}

#[derive(Debug)]
enum AlgorithmID {
    SM2_SM3_FIXED,
    SM2_SM3_ASN1,
}

derive_debug_via_id!(Sm2VerificationAlgorithm);

impl signature::VerificationAlgorithm for Sm2VerificationAlgorithm {
    fn verify_(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
        _: sealed::Arg,
    ) -> Result<(), error::Unspecified> {
        // Use default signer ID per GB/T 32918.2.
        self.verify_with_id(public_key, msg, signature, b"1234567812345678")
    }
}

impl Sm2VerificationAlgorithm {
    /// Verify an SM2 signature with an explicit signer ID.
    pub fn verify_with_id(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
        signer_id: &[u8],
    ) -> Result<(), error::Unspecified> {
        let cpu = cpu::features();
        let public_key_ops = self.ops.public_key_ops;
        let scalar_ops = self.ops.scalar_ops;
        let q = &public_key_ops.common.elem_modulus(cpu);
        let n = &scalar_ops.scalar_modulus(cpu);

        // Parse and validate the signer's public key Q.
        let peer_pub_key = parse_uncompressed_point(public_key_ops, q, public_key)?;

        // Compute e = SM3(Z || M).
        let e_digest = compute_z_then_e(
            self.digest_alg,
            public_key.as_slice_less_safe(),
            signer_id,
            msg.as_slice_less_safe(),
        )?;
        // Convert digest to scalar e mod n.
        let e = sm2_ops::sm2_digest_bytes_to_scalar(n, e_digest.as_ref());

        // Parse (r, s) from the signature.
        let (r, s) = signature.read_all(error::Unspecified, |input| {
            (self.split_rs)(scalar_ops, input)
        })?;

        // Validate r, s in [1, n-1].
        let r = scalar_parse_big_endian_variable(n, limb::AllowZero::No, r)?;
        let s = scalar_parse_big_endian_variable(n, limb::AllowZero::No, s)?;

        // GB/T 32918.2 §7 Step 4: t = (r + s) mod n.
        // Reason: SM2 uses t = r+s, not s^{-1} like ECDSA.
        let t = {
            let mut t = r;
            n.add_assign(&mut t, &s);
            // If t == 0, the signature is invalid.
            if n.is_zero(&t) {
                return Err(error::Unspecified);
            }
            t
        };

        // GB/T 32918.2 §7 Step 5: P = s·G + t·Q.
        let product = (self.ops.twin_mul)(&s, &t, &peer_pub_key, cpu);

        // GB/T 32918.2 §7 Step 6: verify (e + Px_affine) mod n == r.
        //
        // Compute the actual affine x-coordinate of P using Z^{-2}.
        // This requires elem_inverse_squared which is accessed via sm2_jacobian_x_affine_unenc.
        let x_unenc = sm2_ops::sm2_jacobian_x_affine_unenc(q, &product)?;
        let x_as_scalar = n.elem_reduced_to_scalar(&x_unenc);
        let mut computed_r = x_as_scalar;
        n.add_assign(&mut computed_r, &e);

        // Check computed_r == r using constant-time comparison.
        // Both are Scalar<Unencoded>.
        if sm2_ops::sm2_scalars_equal(scalar_ops, &computed_r, &r) {
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }
}

fn split_rs_fixed<'a>(
    ops: &'static ScalarOps,
    input: &mut untrusted::Reader<'a>,
) -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::Unspecified> {
    let scalar_len = ops.scalar_bytes_len();
    let r = input.read_bytes(scalar_len)?;
    let s = input.read_bytes(scalar_len)?;
    Ok((r, s))
}

fn split_rs_asn1<'a>(
    _ops: &'static ScalarOps,
    input: &mut untrusted::Reader<'a>,
) -> Result<(untrusted::Input<'a>, untrusted::Input<'a>), error::Unspecified> {
    use crate::io::der;
    der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
        let r = der::positive_integer(input)?.big_endian_without_leading_zero_as_input();
        let s = der::positive_integer(input)?.big_endian_without_leading_zero_as_input();
        Ok((r, s))
    })
}

/// Verification of fixed-length SM2 signatures with SM3 hash.
///
/// Signature format: `r || s` (each 32 bytes, big-endian).
pub static SM2_SM3_FIXED: Sm2VerificationAlgorithm = Sm2VerificationAlgorithm {
    ops: &sm2_ops::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    split_rs: split_rs_fixed,
    id: AlgorithmID::SM2_SM3_FIXED,
};

/// Verification of ASN.1 DER-encoded SM2 signatures with SM3 hash.
///
/// Signature format: DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`.
pub static SM2_SM3_ASN1: Sm2VerificationAlgorithm = Sm2VerificationAlgorithm {
    ops: &sm2_ops::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    split_rs: split_rs_asn1,
    id: AlgorithmID::SM2_SM3_ASN1,
};
