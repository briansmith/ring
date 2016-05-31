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

use {bssl, c, der, digest, ec, input, signature, signature_impl};
use input::Input;

#[cfg(not(feature = "no_heap"))]
struct ECDSA {
    digest_alg: &'static digest::Algorithm,
    curve: &'static ec::suite_b::Curve,
}

#[cfg(not(feature = "no_heap"))]
impl signature_impl::VerificationAlgorithmImpl for ECDSA {
    fn verify(&self, public_key: Input, msg: Input, signature: Input)
              -> Result<(), ()> {
        let digest = digest::digest(self.digest_alg, msg.as_slice_less_safe());

        let (r, s) = try!(input::read_all(signature, (), |input| {
            der::nested(input, der::Tag::Sequence, (), |input| {
                let r = try!(der::positive_integer(input));
                let s = try!(der::positive_integer(input));
                Ok((r.as_slice_less_safe(), s.as_slice_less_safe()))
            })
        }));

        let (x, y) = try!(
            ec::suite_b::parse_uncompressed_point(public_key, self.curve));

        bssl::map_result(unsafe {
            ECDSA_verify_signed_digest((self.curve.ec_group_fn)(),
                                       digest.algorithm().nid,
                                       digest.as_ref().as_ptr(),
                                       digest.as_ref().len(), r.as_ptr(),
                                       r.len(), s.as_ptr(), s.len(),
                                       x.limbs.as_ptr(), y.limbs.as_ptr())
        })
    }
}

macro_rules! ecdsa {
    ( $VERIFY_ALGORITHM:ident, $curve_name:expr, $curve:expr,
      $digest_alg_name:expr, $digest_alg:expr ) => {
        #[cfg(not(feature = "no_heap"))]
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
        /// Section 5.6.2.5 and the [Suite B Implementer's Guide to NIST SP
        /// 800-56A](https://www.nsa.gov/ia/_files/suiteb_implementer_g-113808.pdf)
        /// Appendix B.3. Note that, as explained in the NSA guide, "partial"
        /// validation is equivalent to "full" validation for prime-order
        /// curves like this one.
        ///
        /// The signature will be parsed as a DER-encoded `Ecdsa-Sig-Value` as
        /// described in [RFC 3279 Section
        /// 2.2.3](https://tools.ietf.org/html/rfc3279#section-2.2.3). Both *r*
        /// and *s* are verified to be in the range [1, *n* - 1].
        ///
        /// Not available in `no_heap` mode.
        pub static $VERIFY_ALGORITHM: signature::VerificationAlgorithm =
                signature::VerificationAlgorithm {
            implementation: &ECDSA {
                digest_alg: $digest_alg,
                curve: $curve,
            }
        };
    }
}

ecdsa!(ECDSA_P256_SHA1_VERIFY, "P-256 (secp256r1)", &ec::suite_b::P256,
       "SHA-1", &digest::SHA1);
ecdsa!(ECDSA_P256_SHA256_VERIFY, "P-256 (secp256r1)", &ec::suite_b::P256,
       "SHA-256", &digest::SHA256);
ecdsa!(ECDSA_P256_SHA384_VERIFY, "P-256 (secp256r1)", &ec::suite_b::P256,
       "SHA-384", &digest::SHA384);
ecdsa!(ECDSA_P256_SHA512_VERIFY, "P-256 (secp256r1)", &ec::suite_b::P256,
       "SHA-512", &digest::SHA512);

ecdsa!(ECDSA_P384_SHA1_VERIFY, "P-384 (secp384r1)", &ec::suite_b::P384,
       "SHA-1", &digest::SHA1);
ecdsa!(ECDSA_P384_SHA256_VERIFY, "P-384 (secp384r1)", &ec::suite_b::P384,
       "SHA-256", &digest::SHA256);
ecdsa!(ECDSA_P384_SHA384_VERIFY, "P-384 (secp384r1)", &ec::suite_b::P384,
       "SHA-384", &digest::SHA384);
ecdsa!(ECDSA_P384_SHA512_VERIFY, "P-384 (secp384r1)", &ec::suite_b::P384,
       "SHA-512", &digest::SHA512);


extern {
    #[cfg(not(feature = "no_heap"))]
    fn ECDSA_verify_signed_digest(group: *const ec::suite_b::EC_GROUP,
                                  hash_nid: c::int, digest: *const u8,
                                  digest_len: c::size_t,
                                  sig_r: *const u8, sig_r_len: c::size_t,
                                  sig_s: *const u8, sig_s_len: c::size_t,
                                  peer_public_key_x: *const ec::suite_b::Limb,
                                  peer_public_key_y: *const ec::suite_b::Limb)
                                  -> c::int;
}


#[cfg(test)]
mod tests {
    use {file_test, der, input, signature};
    use input::Input;
    use super::*;

    #[test]
    fn test_signature_ecdsa_verify() {
        file_test::run("src/ec/ecdsa_verify_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let digest_name = test_case.consume_string("Digest");
            let alg = alg_from_curve_and_digest(&curve_name, &digest_name);

            let msg = test_case.consume_bytes("Msg");
            let msg = Input::new(&msg).unwrap();

            let public_key = test_case.consume_bytes("Q");
            let public_key = Input::new(&public_key).unwrap();

            let sig = test_case.consume_bytes("Sig");
            let sig = Input::new(&sig).unwrap();

            // Sanity check that we correctly DER-encoded the
            // originally-provided separate (r, s) components. When we add test
            // vectors for improperly-encoded signatures, we'll have to revisit
            // this.
            assert!(input::read_all(sig, (), |input| {
                der::nested(input, der::Tag::Sequence, (), |input| {
                    let _ = try!(der::positive_integer(input));
                    let _ = try!(der::positive_integer(input));
                    Ok(())
                })
            }).is_ok());

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P (0 )");
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
