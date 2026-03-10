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

//! SM2 Signature (GB/T 32918.2)
//!
//! SM2 signing differs from ECDSA in two ways:
//!
//! 1. Message preprocessing: `e = SM3(Z || M)` where
//!    `Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)`.
//!
//! 2. Signature equations:
//!    - Sign:   r = (e + x₁) mod n,  s = (1+d)⁻¹(k - r·d) mod n
//!    - Verify: t = (r+s) mod n,  R = sG + tQ,  verify (e + Rx) mod n == r

use super::z_value::compute_z_then_e;
use crate::{
    arithmetic::montgomery::*,
    cpu, digest, ec,
    ec::suite_b::{
        curve,
        ops::*,
        private_key::{affine_from_jacobian, private_key_as_scalar, random_scalar},
    },
    error, limb, pkcs8, rand, signature,
};
use crate::ec::suite_b::ops::sm2 as sm2_ops;

/// An SM2 signing algorithm.
pub struct Sm2SigningAlgorithm {
    pub(crate) curve: &'static ec::Curve,
    pub(super) private_scalar_ops: &'static PrivateScalarOps,
    pub(super) private_key_ops: &'static PrivateKeyOps,
    pub(crate) public_scalar_ops: &'static PublicScalarOps,
    pub(super) digest_alg: &'static digest::Algorithm,
    pub(super) pkcs8_template: &'static pkcs8::Template,
    /// Function to encode (r, s) into the output signature bytes.
    /// `r` is Scalar<Unencoded>, `s` is Scalar<R> (Montgomery form).
    format_rs: fn(
        ops: &'static ScalarOps,
        r: &Scalar,
        s_mont: &Scalar<R>,
        out: &mut [u8],
        cpu: cpu::Features,
    ) -> usize,
    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    SM2_SM3_FIXED_SIGNING,
    SM2_SM3_ASN1_SIGNING,
}

derive_debug_via_id!(Sm2SigningAlgorithm);

impl PartialEq for Sm2SigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Sm2SigningAlgorithm {}

/// An SM2 key pair used for signing.
pub struct Sm2KeyPair {
    d: Scalar<R>,
    one_plus_d_inv: Scalar<R>,
    nonce_key: NonceRandomKey,
    alg: &'static Sm2SigningAlgorithm,
    public_key: PublicKey,
}

derive_debug_via_field!(Sm2KeyPair, stringify!(Sm2KeyPair), public_key);

impl Sm2KeyPair {
    /// Generates a new SM2 key pair and returns it serialized as a PKCS#8
    /// document.
    pub fn generate_pkcs8(
        alg: &'static Sm2SigningAlgorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<pkcs8::Document, error::Unspecified> {
        let cpu = cpu::features();
        let private_key = ec::Seed::generate(alg.curve, rng, cpu)?;
        let public_key = private_key.compute_public_key(cpu)?;
        Ok(pkcs8::wrap_key(
            alg.pkcs8_template,
            private_key.bytes_less_safe(),
            public_key.as_ref(),
        ))
    }

    /// Constructs an SM2 key pair by parsing an unencrypted PKCS#8 v1
    /// `ECPrivateKey` key.
    pub fn from_pkcs8(
        alg: &'static Sm2SigningAlgorithm,
        pkcs8: &[u8],
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_pkcs8(
            alg.curve,
            alg.pkcs8_template,
            untrusted::Input::from(pkcs8),
            cpu::features(),
        )?;
        Self::new(alg, key_pair, rng)
    }

    /// Constructs an SM2 key pair from the private key and public key bytes.
    pub fn from_private_key_and_public_key(
        alg: &'static Sm2SigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let key_pair = ec::suite_b::key_pair_from_bytes(
            alg.curve,
            untrusted::Input::from(private_key),
            untrusted::Input::from(public_key),
            cpu::features(),
        )?;
        Self::new(alg, key_pair, rng)
    }

    fn new(
        alg: &'static Sm2SigningAlgorithm,
        key_pair: ec::KeyPair,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let cpu = cpu::features();

        let (seed, public_key) = key_pair.split();
        let n = &alg.private_scalar_ops.scalar_ops.scalar_modulus(cpu);
        let d = private_key_as_scalar(n, &seed);
        let d = alg.private_scalar_ops.to_mont(&d, cpu);

        // Precompute (1 + d)^{-1} mod n (used in SM2 signing formula).
        let one_plus_d_inv = sm2_ops::sm2_compute_one_plus_d_inv(
            alg.private_scalar_ops.scalar_ops,
            alg.public_scalar_ops,
            &d,
            cpu,
        )?;

        let nonce_key = NonceRandomKey::new(alg, &seed, rng)?;
        Ok(Self {
            d,
            one_plus_d_inv,
            nonce_key,
            alg,
            public_key: PublicKey(public_key),
        })
    }

    /// Signs `message` using the default SM2 signer ID `"1234567812345678"`.
    pub fn sign(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        self.sign_with_id(rng, message, b"1234567812345678")
    }

    /// Signs `message` using the given `signer_id`.
    pub fn sign_with_id(
        &self,
        rng: &dyn rand::SecureRandom,
        message: &[u8],
        signer_id: &[u8],
    ) -> Result<signature::Signature, error::Unspecified> {
        let cpu = cpu::features();
        let e_digest = compute_z_then_e(
            self.alg.digest_alg,
            self.public_key.as_ref(),
            signer_id,
            message,
        )?;
        let nonce_rng = NonceRandom {
            key: &self.nonce_key,
            message_digest: &e_digest,
            rng,
        };
        self.sign_digest(&e_digest, &nonce_rng, cpu)
    }

    fn sign_digest(
        &self,
        e_digest: &digest::Digest,
        rng: &dyn rand::SecureRandom,
        cpu: cpu::Features,
    ) -> Result<signature::Signature, error::Unspecified> {
        let ops = self.alg.private_scalar_ops;
        let scalar_ops = ops.scalar_ops;
        let cops = scalar_ops.common;
        let private_key_ops = self.alg.private_key_ops;
        let q = &cops.elem_modulus(cpu);
        let n = &scalar_ops.scalar_modulus(cpu);

        let e = sm2_ops::sm2_digest_bytes_to_scalar(n, e_digest.as_ref());

        for _ in 0..100 {
            let k = random_scalar(private_key_ops, n, rng)?;

            // [k]G
            let p1 = private_key_ops.point_mul_base(&k, cpu);
            let (x1, _) = affine_from_jacobian(private_key_ops, q, &p1)?;
            let x1_unenc = q.elem_unencoded(&x1);

            // r = (e + x1) mod n
            let x1_as_scalar = n.elem_reduced_to_scalar(&x1_unenc);
            let mut r = x1_as_scalar;
            n.add_assign(&mut r, &e);
            if n.is_zero(&r) {
                continue;
            }

            // s = (1+d)^{-1} * (k - r*d) mod n
            // Convert r to Montgomery form, then compute rd = r_mont * d_mont → Scalar<R>.
            let r_mont = sm2_ops::sm2_to_mont_scalar(&r, cpu);
            let rd = scalar_ops.scalar_product(&r_mont, &self.d, cpu);
            // Convert k to Montgomery form for the subtraction.
            let k_mont = ops.to_mont(&k, cpu);
            // neg_rd = -rd mod n (in Montgomery form)
            let neg_rd = sm2_ops::sm2_negate_scalar_mont(cops, &rd);
            // k_minus_rd = k - rd = k + (-rd)
            let mut k_minus_rd = k_mont;
            n.add_assign(&mut k_minus_rd, &neg_rd);
            // s = (1+d)^{-1} * (k - rd)  [both Montgomery → result Montgomery]
            let s = scalar_ops.scalar_product(&self.one_plus_d_inv, &k_minus_rd, cpu);
            if n.is_zero(&s) {
                continue;
            }

            // Encode r and s as big-endian bytes.
            // r is Scalar<Unencoded>, s is Scalar<R>.
            let alg = self.alg;
            return Ok(signature::Signature::new(|sig_bytes| {
                (alg.format_rs)(scalar_ops, &r, &s, sig_bytes, cpu)
            }));
        }

        Err(error::Unspecified)
    }
}

struct NonceRandom<'a> {
    key: &'a NonceRandomKey,
    message_digest: &'a digest::Digest,
    rng: &'a dyn rand::SecureRandom,
}

impl core::fmt::Debug for NonceRandom<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonceRandom").finish()
    }
}

impl rand::sealed::SecureRandom for NonceRandom<'_> {
    fn fill_impl(&self, dest: &mut [u8], _: crate::sealed::Arg) -> Result<(), error::Unspecified> {
        let digest_alg = self.key.0.algorithm();
        let mut ctx = digest::Context::new(digest_alg);
        let key = self.key.0.as_ref();
        ctx.update(key);
        assert!(key.len() <= digest_alg.block_len() / 2);
        {
            let mut rand = [0u8; digest::MAX_BLOCK_LEN];
            let rand = &mut rand[..digest_alg.block_len() - key.len()];
            assert!(rand.len() >= dest.len());
            self.rng.fill(rand)?;
            ctx.update(rand);
        }
        ctx.update(self.message_digest.as_ref());
        let nonce = ctx.finish();
        dest.copy_from_slice(nonce.as_ref());
        Ok(())
    }
}

struct NonceRandomKey(digest::Digest);

impl NonceRandomKey {
    fn new(
        alg: &Sm2SigningAlgorithm,
        seed: &ec::Seed,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let mut rand = [0; digest::MAX_OUTPUT_LEN];
        let rand = &mut rand[0..alg.curve.elem_scalar_seed_len];
        rng.fill(rand)
            .map_err(|error::Unspecified| error::KeyRejected::rng_failed())?;
        let mut ctx = digest::Context::new(alg.digest_alg);
        ctx.update(rand);
        ctx.update(seed.bytes_less_safe());
        Ok(Self(ctx.finish()))
    }
}

impl signature::KeyPair for Sm2KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

/// The public key of an SM2 key pair.
#[derive(Clone, Copy)]
pub struct PublicKey(ec::PublicKey);

derive_debug_self_as_ref_hex_bytes!(PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// SM2 with SM3, fixed-length (64-byte) signatures (`r || s`).
pub static SM2_SM3_FIXED_SIGNING: Sm2SigningAlgorithm = Sm2SigningAlgorithm {
    curve: &curve::SM2,
    private_scalar_ops: &sm2_ops::PRIVATE_SCALAR_OPS,
    private_key_ops: &sm2_ops::PRIVATE_KEY_OPS,
    public_scalar_ops: &sm2_ops::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    pkcs8_template: &EC_PUBLIC_KEY_SM2_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_fixed,
    id: AlgorithmID::SM2_SM3_FIXED_SIGNING,
};

/// SM2 with SM3, ASN.1 DER-encoded signatures.
pub static SM2_SM3_ASN1_SIGNING: Sm2SigningAlgorithm = Sm2SigningAlgorithm {
    curve: &curve::SM2,
    private_scalar_ops: &sm2_ops::PRIVATE_SCALAR_OPS,
    private_key_ops: &sm2_ops::PRIVATE_KEY_OPS,
    public_scalar_ops: &sm2_ops::PUBLIC_SCALAR_OPS,
    digest_alg: &digest::SM3,
    pkcs8_template: &EC_PUBLIC_KEY_SM2_PKCS8_V1_TEMPLATE,
    format_rs: format_rs_asn1,
    id: AlgorithmID::SM2_SM3_ASN1_SIGNING,
};

/// Fixed-format encoder: writes `r || s` each as big-endian bytes.
fn format_rs_fixed(
    ops: &'static ScalarOps,
    r: &Scalar,
    s_mont: &Scalar<R>,
    out: &mut [u8],
    cpu: cpu::Features,
) -> usize {
    let scalar_len = ops.scalar_bytes_len();
    let (r_out, rest) = out.split_at_mut(scalar_len);
    let (s_out, _) = rest.split_at_mut(scalar_len);
    limb::big_endian_from_limbs(ops.leak_limbs(r), r_out);
    sm2_ops::sm2_scalar_mont_to_bytes(ops, s_mont, s_out, cpu);
    2 * scalar_len
}

/// ASN.1 DER encoder: writes `SEQUENCE { INTEGER r, INTEGER s }`.
fn format_rs_asn1(
    ops: &'static ScalarOps,
    r: &Scalar,
    s_mont: &Scalar<R>,
    out: &mut [u8],
    cpu: cpu::Features,
) -> usize {
    use crate::ec;
    use crate::io::der;

    fn format_integer_tlv(ops: &ScalarOps, a: &Scalar, out: &mut [u8]) -> usize {
        let mut fixed = [0u8; ec::SCALAR_MAX_BYTES + 1];
        let fixed = &mut fixed[..(ops.scalar_bytes_len() + 1)];
        limb::big_endian_from_limbs(ops.leak_limbs(a), &mut fixed[1..]);
        // The extra leading zero byte ensures no high-bit ambiguity.
        debug_assert_eq!(fixed[0], 0);
        let first_index = fixed.iter().position(|b| *b != 0).unwrap();
        // If the first byte has its high bit set, prefix with 0x00.
        let first_index = if fixed[first_index] & 0x80 != 0 {
            first_index - 1
        } else {
            first_index
        };
        let value = &fixed[first_index..];
        out[0] = der::Tag::Integer.into();
        assert!(value.len() < 128);
        #[allow(clippy::cast_possible_truncation)]
        {
            out[1] = value.len() as u8;
        }
        out[2..][..value.len()].copy_from_slice(value);
        2 + value.len()
    }

    // Decode s from Montgomery form, then encode as integer TLV.
    let mut s_bytes_buf = [0u8; ec::SCALAR_MAX_BYTES];
    let scalar_len = ops.scalar_bytes_len();
    sm2_ops::sm2_scalar_mont_to_bytes(ops, s_mont, &mut s_bytes_buf[..scalar_len], cpu);
    // Parse s_bytes as a scalar for format_integer_tlv.
    // (We need a Scalar<Unencoded> to call leak_limbs.)
    // Use a temporary buffer approach: write s bytes, then format as TLV.
    fn format_raw_integer_tlv(value_bytes: &[u8], out: &mut [u8]) -> usize {
        // Find first non-zero byte.
        let first_nonzero = value_bytes.iter().position(|b| *b != 0).unwrap_or(value_bytes.len() - 1);
        // Determine if we need a leading zero for sign (high bit set means negative in DER).
        let needs_zero = value_bytes[first_nonzero] & 0x80 != 0;
        let value = &value_bytes[first_nonzero..];
        let value_len = value.len() + usize::from(needs_zero);
        out[0] = der::Tag::Integer.into();
        assert!(value_len < 128);
        #[allow(clippy::cast_possible_truncation)]
        { out[1] = value_len as u8; }
        let body = &mut out[2..];
        if needs_zero {
            body[0] = 0;
            body[1..][..value.len()].copy_from_slice(value);
        } else {
            body[..value.len()].copy_from_slice(value);
        }
        2 + value_len
    }

    let r_len = format_integer_tlv(ops, r, &mut out[2..]);
    let s_len = format_raw_integer_tlv(&s_bytes_buf[..scalar_len], &mut out[2 + r_len..]);
    let seq_len = r_len + s_len;
    out[0] = der::Tag::Sequence.into();
    assert!(seq_len < 128);
    #[allow(clippy::cast_possible_truncation)]
    {
        out[1] = seq_len as u8;
    }
    2 + seq_len
}

static EC_PUBLIC_KEY_SM2_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("../../../ec/sm2/ecPublicKey_sm2_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};
