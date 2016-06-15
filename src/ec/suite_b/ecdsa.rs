// Copyright 2015-2016 Brian Smith.
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

#![allow(unsafe_code)]

//! ECDSA Signatures using the P-256 and P-384 curves.

use {bssl, c, der, digest, signature, signature_impl};
use super::ops::*;
use super::public_key::*;
use untrusted;

struct ECDSA {
    ops: &'static PublicScalarOps,
    digest_alg: &'static digest::Algorithm,
}

#[cfg(feature = "use_heap")]
impl signature_impl::VerificationAlgorithmImpl for ECDSA {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), ()> {

        let (r, s) = try!(signature.read_all((), |input| {
            der::nested(input, der::Tag::Sequence, (), |input| {
                let r = try!(self.ops.scalar_parse(input));
                let s = try!(self.ops.scalar_parse(input));
                Ok((r, s))
            })
        }));

        let (x, y) =
            try!(parse_uncompressed_point(self.ops.public_key_ops, public_key));

        let m = digest_scalar(self.ops, self.digest_alg, msg);
        let s_inv_mont = self.ops.scalar_inv_to_mont(&s);
        bssl::map_result(unsafe {
            ECDSA_verify_signed_digest(self.ops.public_key_ops.common.ec_group,
                                       m.limbs_as_ptr(), r.limbs_as_ptr(),
                                       s.limbs_as_ptr(),
                                       s_inv_mont.limbs_as_ptr(),
                                       x.limbs_as_ptr(), y.limbs_as_ptr())
        })
    }
}


/// Calculate the digest of `msg` using the digest algorithm `digest_alg`. Then
/// convert the digest to a scalar in the range [0, n) as described in
/// NIST's FIPS 186-4 Section 4.2. Note that this is one of the few cases where
/// a `Scalar` is allowed to have the value zero.
///
/// NIST's FIPS 186-4 4.2 says "When the length of the output of the hash
/// function is greater than N (i.e., the bit length of q), then the leftmost N
/// bits of the hash function output block shall be used in any calculation
/// using the hash function output during the generation or verification of a
/// digital signature."
///
/// "Leftmost N bits" means "N most significant bits" because we interpret the
/// digest as a bit-endian encoded integer.
///
/// The NSA guide instead vaguely suggests that we should convert the digest
/// value to an integer and then reduce it mod `n`. However, real-world
/// implementations (e.g. `digest_to_bn` in OpenSSL and `hashToInt` in Go) do
/// what FIPS 186-4 says to do, not what the NSA guide suggests.
///
/// Why shifting the value right by at most one bit is sufficient: P-256's `n`
/// has its 256th bit set; i.e. 2**255 < n < 2**256. Once we've truncated the
/// digest to 256 bits and converted it to an integer, it will have a value
/// less than 2**256. If the value is larger than `n` then shifting it one bit
/// right will give a value less than 2**255, which is less than `n`. The
/// analogous argument applies for P-384. However, it does *not* apply in
/// general; for example, it doesn't apply to P-521.
fn digest_scalar(ops: &PublicScalarOps, digest_alg: &'static digest::Algorithm,
                 msg: untrusted::Input) -> Scalar {
    let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
    digest_scalar_(ops, digest.as_ref())
}

// This is a separate function solely so that we can test specific digest
// values like all-zero values and values larger than `n`.
fn digest_scalar_(ops: &PublicScalarOps, digest: &[u8]) -> Scalar {
    let num_limbs = ops.public_key_ops.common.num_limbs;

    let digest = if digest.len() > num_limbs * LIMB_BYTES {
        &digest[..(num_limbs * LIMB_BYTES)]
    } else {
        digest
    };

    // XXX: unwrap
    let mut limbs = parse_big_endian_value(digest, num_limbs).unwrap();
    let n = &ops.n[..num_limbs];
    if !limbs_less_than_limbs(&limbs[..num_limbs], n) {
        let mut carried_bit = 0;
        for i in 0..num_limbs {
            let next_carried_bit =
                limbs[num_limbs - i - 1] << (LIMB_BITS - 1);
            limbs[num_limbs - i - 1] =
                (limbs[num_limbs - i - 1] >> 1) | carried_bit;
            carried_bit = next_carried_bit;
        }
        debug_assert!(limbs_less_than_limbs(&limbs[..num_limbs], &n));
    }
    Scalar::from_limbs_unchecked(&limbs)
}


macro_rules! ecdsa {
    ( $VERIFY_ALGORITHM:ident, $curve_name:expr, $ecdsa_verify_ops:expr,
      $digest_alg_name:expr, $digest_alg:expr ) => {
        #[doc="Verification of ECDSA signatures using the "]
        #[doc=$curve_name]
        #[doc=" curve and the "]
        #[doc=$digest_alg_name]
        #[doc=" digest algorithm."]
        ///
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in [SEC 1: Elliptic
        /// Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
        /// Public keys are validated during key agreement as described in
        /// using the ECC
        /// Partial Public-Key Validation Routine from Section 5.6.2.3.3 of
        /// [NIST Special Publication 800-56A, revision
        /// 2](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
        /// and Appendix A.3 of the NSA's [Suite B implementer's guide to FIPS
        /// 186-3](https://github.com/briansmith/ring/doc/ecdsa.pdf). Note
        /// that, as explained in the NSA guide, ECC Partial Public-Key
        /// Validation is equivalent to ECC Full Public-Key Validation for
        /// prime-order curves like this one.
        ///
        /// The signature will be parsed as a DER-encoded `Ecdsa-Sig-Value` as
        /// described in [RFC 3279 Section
        /// 2.2.3](https://tools.ietf.org/html/rfc3279#section-2.2.3).
        ///
        /// Only available in `use_heap` mode.
        pub static $VERIFY_ALGORITHM: signature::VerificationAlgorithm =
                signature::VerificationAlgorithm {
            implementation: &ECDSA {
                ops: $ecdsa_verify_ops,
                digest_alg: $digest_alg,
            }
        };
    }
}

ecdsa!(ECDSA_P256_SHA1_VERIFY, "P-256 (secp256r1)", &p256::PUBLIC_SCALAR_OPS,
       "SHA-1", &digest::SHA1);
ecdsa!(ECDSA_P256_SHA256_VERIFY, "P-256 (secp256r1)", &p256::PUBLIC_SCALAR_OPS,
       "SHA-256", &digest::SHA256);
ecdsa!(ECDSA_P256_SHA384_VERIFY, "P-256 (secp256r1)", &p256::PUBLIC_SCALAR_OPS,
       "SHA-384", &digest::SHA384);
ecdsa!(ECDSA_P256_SHA512_VERIFY, "P-256 (secp256r1)", &p256::PUBLIC_SCALAR_OPS,
       "SHA-512", &digest::SHA512);


ecdsa!(ECDSA_P384_SHA1_VERIFY, "P-384 (secp384r1)", &p384::PUBLIC_SCALAR_OPS,
       "SHA-1", &digest::SHA1);
ecdsa!(ECDSA_P384_SHA256_VERIFY, "P-384 (secp384r1)", &p384::PUBLIC_SCALAR_OPS,
       "SHA-256", &digest::SHA256);
ecdsa!(ECDSA_P384_SHA384_VERIFY, "P-384 (secp384r1)", &p384::PUBLIC_SCALAR_OPS,
       "SHA-384", &digest::SHA384);
ecdsa!(ECDSA_P384_SHA512_VERIFY, "P-384 (secp384r1)", &p384::PUBLIC_SCALAR_OPS,
       "SHA-512", &digest::SHA512);


extern {
    fn ECDSA_verify_signed_digest(group: *const EC_GROUP, m: *const Limb,
                                  sig_r: *const Limb, sig_s: *const Limb,
                                  sig_s_inv_mont: *const Limb,
                                  peer_public_key_x: *const Limb,
                                  peer_public_key_y: *const Limb) -> c::int;
}


#[cfg(test)]
mod tests {
    use {digest, file_test, signature};
    use super::digest_scalar_;
    use super::super::ops::*;
    use untrusted;

    #[test]
    fn signature_ecdsa_verify_test() {
        file_test::run("src/ec/suite_b/ecdsa_verify_tests.txt",
                       |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let digest_name = test_case.consume_string("Digest");
            let (alg, _, _) =
                alg_from_curve_and_digest(&curve_name, &digest_name);

            let msg = test_case.consume_bytes("Msg");
            let msg = try!(untrusted::Input::new(&msg));

            let public_key = test_case.consume_bytes("Q");
            let public_key = try!(untrusted::Input::new(&public_key));

            let sig = test_case.consume_bytes("Sig");
            let sig = try!(untrusted::Input::new(&sig));

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P (0 )");

            Ok(())
        });
    }

    #[test]
    fn ecdsa_digest_scalar_test() {
        file_test::run("src/ec/suite_b/ecdsa_digest_scalar_tests.txt",
                       |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let digest_name = test_case.consume_string("Digest");
            let (_, ops, digest_alg) =
                alg_from_curve_and_digest(&curve_name, &digest_name);

            let num_limbs = ops.public_key_ops.common.num_limbs;

            let input = test_case.consume_bytes("Input");
            assert_eq!(input.len(), digest_alg.output_len);

            let output = test_case.consume_bytes("Output");
            assert_eq!(output.len(),
                       ops.public_key_ops.common.num_limbs * LIMB_BYTES);
            let expected = try!(parse_big_endian_value(&output, num_limbs));

            let actual = digest_scalar_(ops, &input);

            assert_eq!(actual.limbs[..num_limbs], expected[..num_limbs]);

            Ok(())
        });
    }

    fn alg_from_curve_and_digest(curve_name: &str, digest_name: &str)
                                 -> (&'static signature::VerificationAlgorithm,
                                     &'static PublicScalarOps,
                                     &'static digest::Algorithm) {
        if curve_name == "P-256" {
            if digest_name == "SHA1" {
                (&signature::ECDSA_P256_SHA1_VERIFY, &p256::PUBLIC_SCALAR_OPS,
                 &digest::SHA1)
            } else if digest_name == "SHA256" {
                (&signature::ECDSA_P256_SHA256_VERIFY, &p256::PUBLIC_SCALAR_OPS,
                 &digest::SHA256)
            } else if digest_name == "SHA384" {
                (&signature::ECDSA_P256_SHA384_VERIFY, &p256::PUBLIC_SCALAR_OPS,
                 &digest::SHA384)
            } else if digest_name == "SHA512" {
                (&signature::ECDSA_P256_SHA512_VERIFY, &p256::PUBLIC_SCALAR_OPS,
                 &digest::SHA512)
            } else {
                panic!("Unsupported digest algorithm: {}", digest_name);
            }
        } else if curve_name == "P-384" {
            if digest_name == "SHA1" {
                (&signature::ECDSA_P384_SHA1_VERIFY, &p384::PUBLIC_SCALAR_OPS,
                 &digest::SHA1)
            } else if digest_name == "SHA256" {
                (&signature::ECDSA_P384_SHA256_VERIFY, &p384::PUBLIC_SCALAR_OPS,
                 &digest::SHA256)
            } else if digest_name == "SHA384" {
                (&signature::ECDSA_P384_SHA384_VERIFY, &p384::PUBLIC_SCALAR_OPS,
                 &digest::SHA384)
            } else if digest_name == "SHA512" {
                (&signature::ECDSA_P384_SHA512_VERIFY, &p384::PUBLIC_SCALAR_OPS,
                 &digest::SHA512)
            } else {
                panic!("Unsupported digest algorithm: {}", digest_name);
            }
        } else {
            panic!("Unsupported curve: {}", curve_name);
        }
    }
}
