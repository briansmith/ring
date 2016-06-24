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
        let digest = digest::digest(self.digest_alg, msg.as_slice_less_safe());

        let (r, s) = try!(signature.read_all((), |input| {
            der::nested(input, der::Tag::Sequence, (), |input| {
                let r = try!(self.ops.scalar_parse(input));
                let s = try!(self.ops.scalar_parse(input));
                Ok((r, s))
            })
        }));

        let (x, y) =
            try!(parse_uncompressed_point(self.ops.public_key_ops, public_key));

        bssl::map_result(unsafe {
            ECDSA_verify_signed_digest(self.ops.public_key_ops.common.ec_group,
                                       digest.algorithm().nid,
                                       digest.as_ref().as_ptr(),
                                       digest.as_ref().len(), r.limbs_as_ptr(),
                                       s.limbs_as_ptr(), x.limbs_as_ptr(),
                                       y.limbs_as_ptr())
        })
    }
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
        /// [NIST Special Publication 800-56A, revision
        /// 2](http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-56Arev1_3-8-07.pdf)
        /// Section 5.6.2.5 and the NSA's "Suite B implementer's guide to FIPS
        /// 186-3," Appendix A.3. Note that, as explained in the NSA guide,
        /// "partial" validation is equivalent to "full" validation for
        /// prime-order curves like this one.
        ///
        /// The signature will be parsed as a DER-encoded `Ecdsa-Sig-Value` as
        /// described in [RFC 3279 Section
        /// 2.2.3](https://tools.ietf.org/html/rfc3279#section-2.2.3). Both *r*
        /// and *s* are verified to be in the range [1, *n* - 1].
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
    fn ECDSA_verify_signed_digest(group: *const EC_GROUP, hash_nid: c::int,
                                  digest: *const u8, digest_len: c::size_t,
                                  sig_r: *const Limb, sig_s: *const Limb,
                                  peer_public_key_x: *const Limb,
                                  peer_public_key_y: *const Limb) -> c::int;
}


#[cfg(test)]
mod tests {
    use {file_test, der, signature};
    use super::*;
    use untrusted;

    #[test]
    fn test_signature_ecdsa_verify() {
        file_test::run("src/ec/ecdsa_verify_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let digest_name = test_case.consume_string("Digest");
            let alg = alg_from_curve_and_digest(&curve_name, &digest_name);

            let msg = test_case.consume_bytes("Msg");
            let msg = try!(untrusted::Input::new(&msg));

            let public_key = test_case.consume_bytes("Q");
            let public_key = try!(untrusted::Input::new(&public_key));

            let sig = test_case.consume_bytes("Sig");
            let sig = try!(untrusted::Input::new(&sig));

            // Sanity check that we correctly DER-encoded the
            // originally-provided separate (r, s) components. When we add test
            // vectors for improperly-encoded signatures, we'll have to revisit
            // this.
            try!(sig.read_all((), |input| {
                der::nested(input, der::Tag::Sequence, (), |input| {
                    let _ = try!(der::positive_integer(input));
                    let _ = try!(der::positive_integer(input));
                    Ok(())
                })
            }));

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P (0 )");

            Ok(())
        });
    }

    fn alg_from_curve_and_digest(curve_name: &str, digest_name: &str)
                                 -> &'static signature::VerificationAlgorithm {
        if curve_name == "P-256" {
            if digest_name == "SHA1" {
                &ECDSA_P256_SHA1_VERIFY
            } else if digest_name == "SHA256" {
                &ECDSA_P256_SHA256_VERIFY
            } else if digest_name == "SHA384" {
                &ECDSA_P256_SHA384_VERIFY
            } else if digest_name == "SHA512" {
                &ECDSA_P256_SHA512_VERIFY
            } else {
                panic!("Unsupported digest algorithm: {}", digest_name);
            }
        } else if curve_name == "P-384" {
            if digest_name == "SHA1" {
                &ECDSA_P384_SHA1_VERIFY
            } else if digest_name == "SHA256" {
                &ECDSA_P384_SHA256_VERIFY
            } else if digest_name == "SHA384" {
                &ECDSA_P384_SHA384_VERIFY
            } else if digest_name == "SHA512" {
                &ECDSA_P384_SHA512_VERIFY
            } else {
                panic!("Unsupported digest algorithm: {}", digest_name);
            }
        } else {
            panic!("Unsupported curve: {}", curve_name);
        }
    }
}
