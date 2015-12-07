// Copyright 2015 Brian Smith.
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

//! Public key signatures: signing and verification.
//!
//! Use the `verify` function to verify signatures, passing a reference to the
//! `_VERIFY` algorithm that identifies the algorithm. See the documentation
//! for `verify` for examples.
//!
//! The design of this module is unusual compared to other public key signature
//! APIs. Algorithms like split into "signing" and "verification" algorithms.
//! Also, this API treats each combination of parameters as a separate
//! algorithm. For example, instead of having a single "RSA" algorithm with a
//! verification function that takes a bunch of parameters, there are
//! `RSA_PKCS1_2048_8192_SHA256_VERIFY`, `RSA_PKCS1_2048_8192_SHA512_VERIFY`,
//! etc. which encode sets of parameter choices into objects. This design is
//! designed to reduce the risks of algorithm agility. It is also designed to
//! be optimized for Ed25519, which has a fixed signature format, a fixed curve,
//! a fixed key size, and a fixed digest algorithm.
//!
//! Currently this module does not support digesting the message to be signed
//! separately from the public key operation, as it is currently being
//! optimized for Ed25519 and for the implementation of protocols that do not
//! requiring signing large messages. An interface for efficiently supporting
//! larger messages will be added later. Similarly, the signing interface is
//! not available yet.

use super::{c, digest, ffi};
use super::input::Input;

/// An algorithm for verifying signatures, to be passed to the `verify`
/// function.
pub struct VerificationAlgorithm {
    verify: fn(public_key: Input, msg: Input, signature: Input)
               -> Result<(), ()>,
}

/// Verify the signature `signature` of message `msg` with the public key
/// `public_key` using the algorithm `alg`.
///
/// # Examples
///
/// ## Verify a RSA PKCS#1 signature that uses the SHA-256 digest
///
/// ```
/// use ring::input::Input;
/// use ring::signature;
///
/// // Ideally this function should take its inputs as `Input`s instead of
/// // slices. It takes its input as slices to illustrate how to convert slices
/// // to `Input`s.
/// fn verify_rsa_pkcs1_sha256(public_key: &[u8], msg: &[u8], sig: &[u8])
///                            -> Result<(), ()> {
///    let public_key = try!(Input::new(public_key));
///    let msg = try!(Input::new(msg));
///    let sig = try!(Input::new(sig));
///    signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256_VERIFY,
///                      public_key, msg, sig)
/// }
/// ```
pub fn verify(alg: &VerificationAlgorithm, public_key: Input, msg: Input,
              signature: Input) -> Result<(), ()> {
    (alg.verify)(public_key, msg, signature)
}

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $verify_fn:ident, $digest_alg_name:expr,
      $digest_alg:expr ) => {
        #[doc="Verification of RSA PKCS#1 1.5 signatures from 2048-8192 bits "]
        #[doc="using the "]
        #[doc=$digest_alg_name]
        #[doc=" digest algorithm."]
        pub const $VERIFY_ALGORITHM: VerificationAlgorithm =
                VerificationAlgorithm {
            verify: $verify_fn,
        };

        fn $verify_fn(public_key: Input, msg: Input, signature: Input)
                      -> Result<(), ()> {
            rsa_pkcs1_verify(2048, 8192, $digest_alg, public_key, msg,
                             signature)
        }
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1_VERIFY, rsa_pkcs1_2048_8192_sha1_verify,
           "SHA-1", &digest::SHA1);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256_VERIFY, rsa_pkcs1_2048_8192_sha256_verify,
           "SHA-256", &digest::SHA256);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384_VERIFY, rsa_pkcs1_2048_8192_sha384_verify,
           "SHA-384", &digest::SHA384);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512_VERIFY, rsa_pkcs1_2048_8192_sha512_verify,
           "SHA-512", &digest::SHA512);

fn rsa_pkcs1_verify(min_bits: usize, max_bits: usize,
                    digest_alg: &'static digest::Algorithm, public_key: Input,
                    msg: Input, signature: Input) -> Result<(),()> {
    let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
    let signature = signature.as_slice_less_safe();
    let public_key = public_key.as_slice_less_safe();
    ffi::map_bssl_result(unsafe {
        RSA_verify_pkcs1_signed_digest(min_bits, max_bits,
                                       digest.algorithm().nid,
                                       digest.as_ref().as_ptr(),
                                       digest.as_ref().len(), signature.as_ptr(),
                                       signature.len(), public_key.as_ptr(),
                                       public_key.len())
    })
}


extern {
    fn RSA_verify_pkcs1_signed_digest(min_bits: usize, max_bits: usize,
                                      digest_nid: c::int, digest: *const u8,
                                      digest_len: c::size_t, sig: *const u8,
                                      sig_len: c::size_t, key_der: *const u8,
                                      key_der_len: c::size_t) -> c::int;
}
