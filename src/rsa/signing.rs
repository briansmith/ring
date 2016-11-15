// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// RSA PKCS#1 1.5 signatures.

use {bits, bssl, c, der, error};
use rand;
use std;
use super::{BIGNUM, GFp_BN_free, BN_MONT_CTX, GFp_BN_MONT_CTX_free,
            PositiveInteger};
use untrusted;

/// An RSA key pair, used for signing. Feature: `rsa_signing`.
///
/// After constructing an `RSAKeyPair`, construct one or more
/// `RSASigningState`s that reference the `RSAKeyPair` and use
/// `RSASigningState::sign()` to generate signatures. See `ring::signature`'s
/// module-level documentation for an example.
pub struct RSAKeyPair {
    rsa: RSA,

    // The length of the public modulus in bits.
    n_bits: bits::BitLength,
}

impl RSAKeyPair {
    /// Parse a private key in DER-encoded ASN.1 `RSAPrivateKey` form (see
    /// [RFC 3447 Appendix A.1.2]).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet. An upcoming
    /// version of *ring* will likely replace the support for the
    /// `RSAPrivateKey` format with support for the PKCS#8 format.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    pub fn from_der(input: untrusted::Input)
                    -> Result<RSAKeyPair, error::Unspecified> {
        input.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let version = try!(der::small_nonnegative_integer(input));
                if version != 0 {
                    return Err(error::Unspecified);
                }
                let n = try!(PositiveInteger::from_der(input));
                let n_bits = n.bit_length();
                let e = try!(PositiveInteger::from_der(input));
                let d = try!(PositiveInteger::from_der(input));
                let p = try!(PositiveInteger::from_der(input));
                let q = try!(PositiveInteger::from_der(input));
                let dmp1 = try!(PositiveInteger::from_der(input));
                let dmq1 = try!(PositiveInteger::from_der(input));
                let iqmp = try!(PositiveInteger::from_der(input));
                let mut rsa = RSA {
                    e: e.into_raw(), dmp1: dmp1.into_raw(),
                    dmq1: dmq1.into_raw(), iqmp: iqmp.into_raw(),
                    mont_n: std::ptr::null_mut(), mont_p: std::ptr::null_mut(),
                    mont_q: std::ptr::null_mut(),
                    mont_qq: std::ptr::null_mut(),
                    qmn_mont: std::ptr::null_mut(),
                    iqmp_mont: std::ptr::null_mut(),
                };
                try!(bssl::map_result(unsafe {
                    GFp_rsa_new_end(&mut rsa, n.as_ref(), d.as_ref(),
                                    p.as_ref(), q.as_ref())
                }));
                Ok(RSAKeyPair {
                    rsa: rsa,
                    n_bits: n_bits,
                })
            })
        })
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn public_modulus_len(&self) -> usize {
        self.n_bits.as_usize_bytes_rounded_up()
    }
}

unsafe impl Send for RSAKeyPair {}
unsafe impl Sync for RSAKeyPair {}

/// Needs to be kept in sync with `struct rsa_st` (in `include/openssl/rsa.h`).
#[repr(C)]
struct RSA {
    e: *mut BIGNUM,
    dmp1: *mut BIGNUM,
    dmq1: *mut BIGNUM,
    iqmp: *mut BIGNUM,
    mont_n: *mut BN_MONT_CTX,
    mont_p: *mut BN_MONT_CTX,
    mont_q: *mut BN_MONT_CTX,
    mont_qq: *mut BN_MONT_CTX,
    qmn_mont: *mut BIGNUM,
    iqmp_mont: *mut BIGNUM,
}

impl Drop for RSA {
    fn drop(&mut self) {
        unsafe {
            GFp_BN_free(self.e);
            GFp_BN_free(self.dmp1);
            GFp_BN_free(self.dmq1);
            GFp_BN_free(self.iqmp);
            GFp_BN_MONT_CTX_free(self.mont_n);
            GFp_BN_MONT_CTX_free(self.mont_p);
            GFp_BN_MONT_CTX_free(self.mont_q);
            GFp_BN_MONT_CTX_free(self.mont_qq);
            GFp_BN_free(self.qmn_mont);
            GFp_BN_free(self.iqmp_mont);
        }
    }
}


/// State used for RSA Signing. Feature: `rsa_signing`.
///
/// # Performance Considerations
///
/// Every time `sign` is called, some internal state is updated. Usually the
/// state update is relatively cheap, but the first time, and periodically, a
/// relatively expensive computation (computing the modular inverse of a random
/// number modulo the public key modulus, for blinding the RSA exponentiation)
/// will be done. Reusing the same `RSASigningState` when generating multiple
/// signatures improves the computational efficiency of signing by minimizing
/// the frequency of the expensive computations.
///
/// `RSASigningState` is not `Sync`; i.e. concurrent use of an `sign()` on the
/// same `RSASigningState` from multiple threads is not allowed. An
/// `RSASigningState` can be wrapped in a `Mutex` to be shared between threads;
/// this would maximize the computational efficiency (as explained above) and
/// minimizes memory usage, but it also minimizes concurrency because all the
/// calls to `sign()` would be serialized. To increases concurrency one could
/// create multiple `RSASigningState`s that share the same `RSAKeyPair`; the
/// number of `RSASigningState` in use at once determines the concurrency
/// factor. This increases memory usage, but only by a small amount, as each
/// `RSASigningState` is much smaller than the `RSAKeyPair` that they would
/// share. Using multiple `RSASigningState` per `RSAKeyPair` may also decrease
/// computational efficiency by increasing the frequency of the expensive
/// modular inversions; managing a pool of `RSASigningState`s in a
/// most-recently-used fashion would improve the computational efficiency.
pub struct RSASigningState {
    key_pair: std::sync::Arc<RSAKeyPair>,
    blinding: Blinding,
}

impl RSASigningState {
    /// Construct an `RSASigningState` for the given `RSAKeyPair`.
    pub fn new(key_pair: std::sync::Arc<RSAKeyPair>)
               -> Result<Self, error::Unspecified> {
        let blinding = unsafe { GFp_BN_BLINDING_new() };
        if blinding.is_null() {
            return Err(error::Unspecified);
        }
        Ok(RSASigningState {
            key_pair: key_pair,
            blinding: Blinding { blinding: blinding },
        })
    }

    /// The `RSAKeyPair`. This can be used, for example, to access the key
    /// pair's public key through the `RSASigningState`.
    pub fn key_pair(&self) -> &RSAKeyPair { self.key_pair.as_ref() }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` is used for blinding the message during
    /// signing, to mitigate some side-channel (e.g. timing) attacks.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly. To help mitigate the current
    /// imperfections, and for defense-in-depth, base blinding is always done.
    /// Exponent blinding is not done, but it may be done in the future.
    pub fn sign(&mut self, padding_alg: &'static ::signature::RSAEncoding,
                rng: &rand::SecureRandom, msg: &[u8], signature: &mut [u8])
                -> Result<(), error::Unspecified> {
        let mod_bits = self.key_pair.n_bits;
        if signature.len() != mod_bits.as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        try!(padding_alg.encode(msg, signature, mod_bits, rng));
        let mut rand = rand::RAND::new(rng);
        bssl::map_result(unsafe {
            GFp_rsa_private_transform(&self.key_pair.rsa,
                                      signature.as_mut_ptr(), signature.len(),
                                      self.blinding.blinding, &mut rand)
        })
    }
}

struct Blinding {
    blinding: *mut BN_BLINDING,
}

impl Drop for Blinding {
    fn drop(&mut self) { unsafe { GFp_BN_BLINDING_free(self.blinding) } }
}

unsafe impl Send for Blinding {}

/// Needs to be kept in sync with `bn_blinding_st` in `crypto/rsa/blinding.c`.
#[allow(non_camel_case_types)]
#[repr(C)]
struct BN_BLINDING {
    a: *mut BIGNUM,
    ai: *mut BIGNUM,
    counter: u32,
}


extern {
    fn GFp_BN_BLINDING_new() -> *mut BN_BLINDING;
    fn GFp_BN_BLINDING_free(b: *mut BN_BLINDING);
    fn GFp_rsa_new_end(rsa: *mut RSA, n: &BIGNUM, d: &BIGNUM, p: &BIGNUM,
                       q: &BIGNUM) -> c::int;
}

#[allow(improper_ctypes)]
extern {
    fn GFp_rsa_private_transform(rsa: *const RSA, inout: *mut u8,
                                 len: c::size_t, blinding: *mut BN_BLINDING,
                                 rng: *mut rand::RAND) -> c::int;
}


#[cfg(test)]
mod tests {
    // We intentionally avoid `use super::*` so that we are sure to use only
    // the public API; this ensures that enough of the API is public.
    use {error, rand, signature, test};
    use std;
    use untrusted;

    extern {
        static GFp_BN_BLINDING_COUNTER: u32;
    }

    #[test]
    fn test_signature_rsa_pkcs1_sign() {
        let rng = rand::SystemRandom::new();
        test::from_file("src/rsa/rsa_pkcs1_sign_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PKCS1_SHA256,
                "SHA384" => &signature::RSA_PKCS1_SHA384,
                "SHA512" => &signature::RSA_PKCS1_SHA512,
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let private_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);

            // XXX: This test is too slow on Android ARM Travis CI builds.
            // TODO: re-enable these tests on Android ARM.
            let mut signing_state =
                signature::RSASigningState::new(key_pair).unwrap();
            let mut actual: std::vec::Vec<u8> =
                vec![0; signing_state.key_pair().public_modulus_len()];
            signing_state.sign(alg, &rng, &msg, actual.as_mut_slice()).unwrap();
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }



    // `RSAKeyPair::sign` requires that the output buffer is the same length as
    // the public key modulus. Test what happens when it isn't the same length.
    #[test]
    fn test_signature_rsa_pkcs1_sign_output_buffer_len() {
        // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
        // SHA256 digest algorithm.
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        // The output buffer is one byte too short.
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len() - 1];

        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());

        // The output buffer is the right length.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_ok());


        // The output buffer is one byte too long.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());
    }

    // Once the `BN_BLINDING` in an `RSAKeyPair` has been used
    // `GFp_BN_BLINDING_COUNTER` times, a new blinding should be created. we
    // don't check that a new blinding was created; we just make sure to
    // exercise the code path, so this is basically a coverage test.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_reuse() {
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signature = vec![0; key_pair.public_modulus_len()];

        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        let blinding_counter = unsafe { GFp_BN_BLINDING_COUNTER };

        for _ in 0..(blinding_counter + 1) {
            let prev_counter =
                unsafe { (*signing_state.blinding.blinding).counter };

            let _ = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                       MESSAGE, &mut signature);

            let counter = unsafe { (*signing_state.blinding.blinding).counter };

            assert_eq!(counter, (prev_counter + 1) % blinding_counter);
        }
    }

    // In `crypto/rsa/blinding.c`, when `bn_blinding_create_param` fails to
    // randomly generate an invertible blinding factor too many times in a
    // loop, it returns an error. Check that we observe this.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_creation_failure() {
        const MESSAGE: &'static [u8] = b"hello, world";

        // Stub RNG that is constantly 0. In `bn_blinding_create_param`, this
        // causes the candidate blinding factors to always be 0, which has no
        // inverse, so `BN_mod_inverse_no_branch` fails.
        let rng = rand::test_util::FixedByteRandom { byte: 0x00 };

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len()];
        let result = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                        MESSAGE, &mut signature);

        assert!(result.is_err());
    }

    #[cfg(feature = "rsa_signing")]
    #[test]
    fn test_signature_rsa_pss_sign() {
        // Outputs the same value whenever a certain length is requested (the
        // same as the length of the salt). Otherwise, the rng is used.
        struct DeterministicSalt<'a> {
            salt: &'a [u8],
            rng: &'a rand::SecureRandom
        }
        impl<'a> rand::SecureRandom for DeterministicSalt<'a> {
            fn fill(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
                let dest_len = dest.len();
                if dest_len != self.salt.len() {
                    try!(self.rng.fill(dest));
                } else {
                    dest.copy_from_slice(&self.salt);
                }
                Ok(())
            }
        }
        let rng = rand::SystemRandom::new();

        test::from_file("src/rsa/rsa_pss_sign_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &signature::RSA_PSS_SHA256,
                "SHA384" => &signature::RSA_PSS_SHA384,
                "SHA512" => &signature::RSA_PSS_SHA512,
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let result = test_case.consume_string("Result");
            let private_key = test_case.consume_bytes("Key");
            let private_key = untrusted::Input::from(&private_key);
            let key_pair = signature::RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();
            let key_pair = std::sync::Arc::new(key_pair);
            let msg = test_case.consume_bytes("Msg");
            let salt = test_case.consume_bytes("Salt");
            let expected = test_case.consume_bytes("Sig");

            let new_rng = DeterministicSalt { salt: &salt, rng: &rng };

            let mut signing_state =
                signature::RSASigningState::new(key_pair).unwrap();
            let mut actual: std::vec::Vec<u8> =
                vec![0; signing_state.key_pair().public_modulus_len()];
            try!(signing_state.sign(alg, &new_rng, &msg, actual.as_mut_slice()));
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }


    #[test]
    fn test_sync_and_send() {
        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);

        let _: &Send = &key_pair;
        let _: &Sync = &key_pair;

        let signing_state = signature::RSASigningState::new(key_pair).unwrap();
        let _: &Send = &signing_state;
        // TODO: Test that signing_state is NOT Sync; i.e.
        // `let _: &Sync = &signing_state;` must fail
    }
}
