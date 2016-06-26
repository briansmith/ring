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

//! ECDH key agreement using the P-256 and P-384 curves.

use {agreement, ec};
use super::ops::*;
use super::private_key::*;
use super::public_key::*;
use untrusted;

/// A key agreement algorithm.
macro_rules! ecdh {
    ( $NAME:ident, $bits:expr, $name_str:expr, $private_key_ops:expr,
      $public_key_ops:expr, $nid:expr, $ecdh:ident, $generate_private_key:expr,
      $public_from_private:ident ) =>
    {
        #[doc="ECDH using the NSA Suite B"]
        #[doc=$name_str]
        #[doc="curve."]
        ///
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in [SEC 1: Elliptic
        /// Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
        /// Public keys are validated during key agreement according to
        /// [NIST Special Publication 800-56A, revision
        /// 2](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)
        /// and Appendix B.3 of the NSA's [Suite B Implementer's Guide to NIST
        /// SP 800-56A](https://github.com/briansmith/ring/doc/ecdh.pdf)."
        ///
        /// Only available in `use_heap` mode.
        pub static $NAME: agreement::Algorithm = agreement::Algorithm {
            i: ec::AgreementAlgorithmImpl {
                public_key_len: 1 + (2 * (($bits + 7) / 8)),
                elem_and_scalar_len: ($bits + 7) / 8,
                nid: $nid,
                generate_private_key: $generate_private_key,
                public_from_private: $public_from_private,
                ecdh: $ecdh,
            },
        };

        fn $ecdh(out: &mut [u8], my_private_key: &ec::PrivateKey,
                 peer_public_key: untrusted::Input) -> Result<(), ()> {
            ecdh($private_key_ops, $public_key_ops, out, my_private_key,
                 peer_public_key)
        }

        fn $public_from_private(public_out: &mut [u8],
                                private_key: &ec::PrivateKey)
                                -> Result<(), ()> {
            public_from_private($private_key_ops, public_out, private_key)
        }
    }
}

ecdh!(ECDH_P256, 256, "P-256 (secp256r1)", &p256::PRIVATE_KEY_OPS,
      &p256::PUBLIC_KEY_OPS, 415 /*NID_X9_62_prime256v1*/, p256_ecdh,
      p256::GFp_p256_generate_private_key, p256_public_from_private);

ecdh!(ECDH_P384, 384, "P-384 (secp384r1)", &p384::PRIVATE_KEY_OPS,
      &p384::PUBLIC_KEY_OPS, 715 /*NID_secp384r1*/, p384_ecdh,
      p384::GFp_p384_generate_private_key, p384_public_from_private);


fn ecdh(private_key_ops: &PrivateKeyOps, public_key_ops: &PublicKeyOps,
        out: &mut [u8], my_private_key: &ec::PrivateKey,
        peer_public_key: untrusted::Input) -> Result<(), ()> {
    // The NIST SP 800-56Ar2 steps are from section 5.7.1.2 Elliptic Curve
    // Cryptography Cofactor Diffie-Hellman (ECC CDH) Primitive.
    //
    // The "NSA Guide" steps are from section 3.1 of the NSA guide, "Ephemeral
    // Unified Model."

    // NSA Guide Step 1 is handled separately.

    // NIST SP 800-56Ar2 5.6.2.2.2.
    // NSA Guide Step 2.
    //
    // `parse_uncompressed_point` verifies that the point is not at infinity
    // and that it is on the curve, using the Partial Public-Key Validation
    // Routine.
    let peer_public_key =
        try!(parse_uncompressed_point(public_key_ops, peer_public_key));

    // NIST SP 800-56Ar2 Steps 1 and 2.
    // NSA Guide Step 3.
    //
    // Note that the cofactor (h) is one since we only support prime-order
    // curves, so we can safely ignore the cofactor.
    //
    // It is impossible for the result to be the point at infinity because our
    // private key is in the range [1, n) and the curve has prime order and
    // `parse_uncompressed_point` verified that the peer public key is on the
    // curve and not at infinity. However, since the standards require the
    // check, we do it using `assert!`.
    //
    // NIST SP 800-56Ar2 defines "Destroy" thusly: "In this Recommendation, to
    // destroy is an action applied to a key or a piece of secret data. After
    // a key or a piece of secret data is destroyed, no information about its
    // value can be recovered." We interpret "destroy" somewhat liberally: we
    // assume that since we throw away the values to be destroyed, no
    // information about their values can be recovered. This doesn't meet the
    // NSA guide's explicit requirement to "zeroize" them though.
    let my_private_key = private_key_as_scalar(private_key_ops, my_private_key);
    let (x, y, z) =
        try!(var_point_mult(private_key_ops.common, &my_private_key,
                            &peer_public_key));
    assert!(public_key_ops.common.elem_verify_is_not_zero(&z).is_ok());

    // NIST SP 800-56Ar2 Steps 3, 4, and 5.
    // NSA Guide Step 4.
    //
    // Again, we have a pretty liberal interpretation of the NIST's spec's
    // "Destroy" that doesn't meet the NSA requirement to "zeroize."
    big_endian_affine_from_jacobian(private_key_ops, Some(out), None,
                                    &(x, y, z));

    // NSA Guide Step 5 & 6 are deferred to the caller. Again, we have a
    // pretty liberal interpretation of the NIST's spec's "Destroy" that
    // doesn't meet the NSA requirement to "zeroize."

    Ok(())
}


#[cfg(test)]
mod tests {
    use {agreement, rand};

    static SUPPORTED_SUITE_B_ALGS: [&'static agreement::Algorithm; 2] = [
        &agreement::ECDH_P256,
        &agreement::ECDH_P384,
    ];

    #[test]
    fn test_agreement_suite_b_ecdh_generate() {
        struct FixedByteRandom {
            byte: u8
        };

        impl rand::SecureRandom for FixedByteRandom {
            fn fill(&self, dest: &mut [u8]) -> Result<(), ()> {
                for d in dest {
                    *d = self.byte
                }
                Ok(())
            }
        }

        // Generates a string of bytes 0x00...00, which will always result in
        // a scalar value of zero.
        let random_00 = FixedByteRandom { byte: 0 };

        // Generates a string of bytes 0xFF...FF, which will be larger than the
        // group order of any curve that is supported.
        let random_ff = FixedByteRandom { byte: 0xff };

        for alg in SUPPORTED_SUITE_B_ALGS.iter() {
            // Test that the private key value zero is rejected and that
            // `generate` gives up after a while of only getting zeros.
            assert!(agreement::EphemeralPrivateKey::generate(alg, &random_00)
                        .is_err());

            // Test that the private key value larger than the group order is
            // rejected and that `generate` gives up after a while of only
            // getting values larger than the group order.
            assert!(agreement::EphemeralPrivateKey::generate(alg, &random_ff)
                        .is_err());

            // TODO XXX: Test that a private key value exactly equal to the
            // group order is rejected and that `generate` gives up after a
            // while of only getting that value from the PRNG. This is
            // non-trivial because it requires the test PRNG to generate a
            // series of bytes of output that, when interpreted as an array of
            // `BN_ULONG`s (which vary in size and endianness by platform), is
            // equal to the group order.
        }
    }
}
