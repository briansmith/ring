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

//! ECDH Key agreement.

#![allow(unsafe_code)]

use {c, ec, init, rand};

use bssl;
use input::Input;

/// A key agreement algorithm.
#[cfg_attr(not(test), allow(dead_code))]
pub struct Algorithm {
    public_key_len: usize,
    elem_len: usize,
    scalar_len: usize,

    nid: c::int,

    generate_private_key:
        unsafe extern fn(out: *mut u8, rng: *mut rand::RAND) -> c::int,

    public_from_private:
        unsafe extern fn(public_out: *mut u8, private_key: *const u8) -> c::int,

    ecdh:
        unsafe extern fn(out: *mut u8, private_key: *const u8,
                         peer_public_key: *const u8) -> c::int,
}

/// An ephemeral key pair for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `EphemeralPrivateKey` can be
/// used for at most one key agreement.
pub struct EphemeralPrivateKey {
    private_key: ec::PrivateKey,
    alg: &'static Algorithm,
}

impl EphemeralPrivateKey {
    /// Generate a new ephemeral key pair for the given algorithm.
    ///
    /// C analog: `EC_KEY_new_by_curve_name` + `EC_KEY_generate_key`.
    pub fn generate(alg: &'static Algorithm, rng: &rand::SecureRandom)
                    -> Result<EphemeralPrivateKey, ()> {
        init::init_once();
        let mut result = EphemeralPrivateKey {
            private_key: ec::PrivateKey {
                bytes: ec::INVALID_ZERO_PRIVATE_KEY_BYTES,
            },
            alg: alg,
        };
        let mut rng = rand::RAND::new(rng);
        try!(bssl::map_result(unsafe {
            (alg.generate_private_key)(result.private_key.bytes.as_mut_ptr(),
                                       &mut rng)
        }));
        Ok(result)
    }

    #[cfg(test)]
    fn from_test_vector(alg: &'static Algorithm, test_vector: &[u8])
                        -> EphemeralPrivateKey {
        init::init_once();
        let mut result = EphemeralPrivateKey {
            private_key: ec::PrivateKey {
                bytes: ec::INVALID_ZERO_PRIVATE_KEY_BYTES,
            },
            alg: alg,
        };
        {
            let private_key_bytes =
                &mut result.private_key.bytes[..alg.scalar_len];
            assert_eq!(test_vector.len(), private_key_bytes.len());
            for i in 0..private_key_bytes.len() {
                private_key_bytes[i] = test_vector[i];
            }
        }
        result
    }

    /// The size in bytes of the encoded public key.
    #[inline(always)]
    pub fn public_key_len(&self) -> usize { self.alg.public_key_len }

    /// Computes the public key from the private key's value and fills `out`
    /// with the public point encoded in the standard form for the algorithm.
    ///
    /// `out.len()` must be equal to the value returned by `public_key_len`.
    pub fn compute_public_key(&self, out: &mut [u8]) -> Result<(), ()> {
        if out.len() != self.public_key_len() {
            return Err(());
        }
        bssl::map_result(unsafe {
            (self.alg.public_from_private)(
                out.as_mut_ptr(), self.private_key.bytes.as_ptr())
        })
    }
}

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private_key to use. Since it is moved, it
/// will not be usable after calling `agree_ephemeral`, thus guaranteeing that
/// the key is used for only one key agreement.
///
/// `peer_public_key_alg` is the algorithm/curve for the peer's public key
/// point; `agree_ephemeral` will return `Err(())` if it does not match
/// `my_private_key's` algorithm/curve.
///
/// `peer_pubic_key` is the peer's public key. `agree_ephemeral` verifies that
/// it is encoded in the standard form for the algorithm and that the key is
/// *valid*; see the algorithm's documentation for details on how keys are to
/// be encoded and what constitutes a valid key for that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
///
/// C analogs: `EC_POINT_oct2point` + `ECDH_compute_key`.
pub fn agree_ephemeral<F, R, E>(my_private_key: EphemeralPrivateKey,
                                peer_public_key_alg: &Algorithm,
                                peer_public_key: Input,
                                error_value: E, kdf: F) -> Result<R, E>
                                where F: FnOnce(&[u8]) -> Result<R, E> {
    if peer_public_key_alg.nid != my_private_key.alg.nid {
        return Err(error_value);
    }
    let peer_public_key = peer_public_key.as_slice_less_safe();
    if peer_public_key.len() != my_private_key.public_key_len() {
        return Err(error_value);
    }
    let mut shared_key = [0u8; ec::ELEM_MAX_BYTES];
    match unsafe {
        (my_private_key.alg.ecdh)(shared_key.as_mut_ptr(),
            my_private_key.private_key.bytes.as_ptr(), peer_public_key.as_ptr())
    } {
        1 => kdf(&shared_key[..my_private_key.alg.elem_len]),
        _ => Err(error_value),
    }
}


macro_rules! nist_ecdh {
    ( $NAME:ident, $bits:expr, $name_str:expr, $nid:expr,
      $generate_private_key:ident, $public_from_private:ident, $ecdh:ident ) => {
        #[doc="ECDH using the NIST"]
        #[doc=$name_str]
        #[doc="curve."]
        ///
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in [SEC 1: Elliptic
        /// Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
        /// Public keys are validated during key agreement according as
        /// described in [NIST Special Publication 800-56A, revision
        /// 2](http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-56Arev1_3-8-07.pdf)
        /// Section 5.6.2.5 and the [Suite B Implementer's Guide to NIST SP
        /// 800-56A](https://www.nsa.gov/ia/_files/suiteb_implementer_g-113808.pdf)
        /// Appendix B.3. Note that, as explained in the NSA guide, "partial"
        /// validation is equivalent to "full" validation for prime-order
        /// curves like this one.
        ///
        /// TODO: Each of the encoded coordinates are verified to be the
        /// correct length, but values of the allowed length that haven't been
        /// reduced modulo *q* are currently reduced mod *q* during
        /// verification. Soon, coordinates larger than *q* - 1 will be
        /// rejected.
        ///
        /// Not available in `no_heap` mode.
        pub static $NAME: Algorithm = Algorithm {
            public_key_len: 1 + (2 * (($bits + 7) / 8)),
            elem_len: ($bits + 7) / 8,
            scalar_len: ($bits + 7) / 8,
            nid: $nid,
            generate_private_key: $generate_private_key,
            public_from_private: $public_from_private,
            ecdh: $ecdh,
        };

        #[allow(improper_ctypes)]
        extern {
            fn $generate_private_key(out: *mut u8, rng: *mut rand::RAND)
                                     -> c::int;
        }

        extern {
            fn $public_from_private(public_key_out: *mut u8,
                                    private_key: *const u8)
                                    -> c::int;

            fn $ecdh(out: *mut u8, private_key: *const u8,
                     peer_public_key: *const u8) -> c::int;
        }
    }
}

nist_ecdh!(ECDH_P256, 256, "P-256 (secp256r1)", 415 /*NID_X9_62_prime256v1*/,
           GFp_p256_generate_private_key, GFp_p256_public_from_private,
           GFp_p256_ecdh);

nist_ecdh!(ECDH_P384, 384, "P-384 (secp384r1)", 715 /*NID_secp384r1*/,
           GFp_p384_generate_private_key, GFp_p384_public_from_private,
           GFp_p384_ecdh);

#[cfg(test)]
mod tests {
    use {ec, file_test, rand};
    use ec::ecdh::*;
    use input::Input;

    static SUPPORTED_ALGS: [&'static Algorithm; 2] = [
        &ECDH_P256,
        &ECDH_P384,
    ];

    #[test]
    fn test_nist_ecdh_generate() {
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

        for alg in SUPPORTED_ALGS.iter() {
            // Test that the private key value zero is rejected and that
            // `generate` gives up after a while of only getting zeros.
            assert!(
                EphemeralPrivateKey::generate(alg, &random_00).is_err());

            // Test that the private key value larger than the group order is
            // rejected and that `generate` gives up after a while of only
            // getting values larger than the group order.
            assert!(
                EphemeralPrivateKey::generate(alg, &random_ff).is_err());

            // TODO XXX: Test that a private key value exactly equal to the
            // group order is rejected and that `generate` gives up after a
            // while of only getting that value from the PRNG. This is
            // non-trivial because it requires the test PRNG to generate a
            // series of bytes of output that, when interpreted as an array of
            // `BN_ULONG`s (which vary in size and endianness by platform), is
            // equal to the group order.
        }
    }

    #[test]
    fn test_nist_ecdh_agree_ephemeral() {
        let rng = rand::SystemRandom::new();

        file_test::run("src/ec/ecdh_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let alg = if curve_name == "P-256" {
                &ECDH_P256
            } else if curve_name == "P-384" {
                &ECDH_P384
            } else {
                panic!("Unsupported curve: {}", curve_name);
            };

            let peer_public = test_case.consume_bytes("PeerQ");
            let peer_public = Input::new(&peer_public).unwrap();

            match test_case.consume_optional_string("Error") {
                None => {
                    let my_private = test_case.consume_bytes("D");
                    let my_public = test_case.consume_bytes("MyQ");
                    let output = test_case.consume_bytes("Output");

                    let private_key =
                        EphemeralPrivateKey::from_test_vector(alg, &my_private);

                    let mut computed_public = [0u8; 1 + (ec::ELEM_MAX_BITS * 2)];
                    let computed_public =
                        &mut computed_public[..private_key.public_key_len()];
                    private_key.compute_public_key(computed_public).unwrap();
                    assert_eq!(computed_public, &my_public[..]);

                    agree_ephemeral(private_key, alg, peer_public, (),
                                    |key_material| {
                        assert_eq!(key_material, &output[..]);
                        Ok(())
                    }).unwrap();
                },

                Some(_) => {
                    let dummy_private_key =
                        EphemeralPrivateKey::generate(alg, &rng).unwrap();
                    fn kdf_not_called(_: &[u8]) -> Result<(), ()> {
                        panic!("The KDF was called during ECDH when the peer's \
                                public key is invalid.");
                    }
                    assert!(
                        agree_ephemeral(dummy_private_key, alg, peer_public,
                                        (), kdf_not_called).is_err());
                }
            }
        });
    }
}
