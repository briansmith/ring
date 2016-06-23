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

//! Public key signatures: signing and verification.
//!
//! Use the `verify` function to verify signatures, passing a reference to the
//! `_VERIFY` algorithm that identifies the algorithm. See the documentation
//! for `verify` for examples.
//!
//! For signature verification, this API treats each combination of parameters
//! as a separate algorithm. For example, instead of having a single "RSA"
//! algorithm with a verification function that takes a bunch of parameters,
//! there are `RSA_PKCS1_2048_8192_SHA256_VERIFY`,
//! `RSA_PKCS1_2048_8192_SHA384_VERIFY`, etc., which encode sets of parameter
//! choices into objects. This is designed to reduce the risks of algorithm
//! agility and to provide consistency with ECDSA and EdDSA.
//!
//! Currently this module does not support digesting the message to be signed
//! separately from the public key operation, as it is currently being
//! optimized for Ed25519 and for the implementation of protocols that do not
//! requiring signing large messages. An interface for efficiently supporting
//! larger messages may be added later.
//!
//! # Examples
//!
//! ## Signing and verifying with Ed25519
//!
//! ```
//! extern crate ring;
//! extern crate untrusted;
//!
//! use ring::{rand, signature};
//!
//! # fn sign_and_verify_ed25519() -> Result<(), ()> {
//! // Generate a key pair.
//! let rng = rand::SystemRandom::new();
//! let generated_key_pair = try!(signature::Ed25519KeyPair::generate(&rng));
//!
//! // Normally after generating the key pair, the application would extract
//! // the private and public components and store them persistently for future
//! // use.
//! let priv_key_bytes = generated_key_pair.private_key_bytes();
//! let pub_key_bytes = generated_key_pair.public_key_bytes();
//!
//! // Normally the application would later deserialize the private and public
//! // key from storage and then create an `Ed25519KeyPair` from the
//! // deserialized bytes.
//! let key_pair =
//!    try!(signature::Ed25519KeyPair::from_bytes(priv_key_bytes,
//!                                               pub_key_bytes));
//!
//! // Sign the message "hello, world".
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let sig = key_pair.sign(MESSAGE);
//!
//! // Normally, an application would extract the bytes of the signature and
//! // send them in a protocol message to the peer(s).
//! let sig_bytes = sig.as_slice();
//!
//! // Verify the signature of the message using the public key. Normally the
//! // verifier of the message would parse the inputs to `signature::verify`
//! // out of the protocol message(s) sent by the signer.
//! let pub_key_input = try!(untrusted::Input::new(pub_key_bytes));
//! let msg_input = try!(untrusted::Input::new(MESSAGE));
//! let sig_input = try!(untrusted::Input::new(sig_bytes));
//!
//! try!(signature::verify(&signature::ED25519_VERIFY, pub_key_input,
//!                        msg_input, sig_input));
//!
//! # Ok(())
//! # }
//!
//! # fn main() { sign_and_verify_ed25519().unwrap() }
//! ```
//!
//! ## Signing and verifying with RSA (PKCS#1 1.5 padding)
//!
//! ```
//! extern crate ring;
//! extern crate untrusted;
//!
//! use ring::{rand, signature};
//!
//! # #[cfg(feature = "use_heap")]
//! # fn sign_and_verify_rsa() -> Result<(), ()> {
//!
//! // Create an `RSAKeyPair` from the DER-encoded bytes. This example uses
//! // a 2048-bit key, but larger keys are also supported.
//! let key_bytes_der = try!(
//!    untrusted::Input::new(
//!         include_bytes!("src/signature_rsa_example_private_key.der")));
//! let key_pair =
//!    try!(signature::RSAKeyPair::from_der(key_bytes_der));
//!
//! // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
//! // SHA256 digest algorithm.
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let rng = rand::SystemRandom::new();
//! let mut signature = vec![0; key_pair.public_modulus_len()];
//! try!(key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
//!                    &mut signature));
//!
//! // Verify the signature.
//! let public_key_bytes_der = try!(
//!     untrusted::Input::new(
//!         include_bytes!("src/signature_rsa_example_public_key.der")));
//! let message = try!(untrusted::Input::new(MESSAGE));
//! let signature = try!(untrusted::Input::new(&signature));
//! try!(signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256_VERIFY,
//!                        public_key_bytes_der, message, signature));
//! # Ok(())
//! # }
//! #
//! # #[cfg(not(feature = "use_heap"))]
//! # fn sign_and_verify_rsa() -> Result<(), ()> { Ok(()) }
//! #
//! # fn main() { sign_and_verify_rsa().unwrap() }
//! ```


use {init, signature_impl};
use untrusted;

#[cfg(feature = "use_heap")]
pub use ec::suite_b::ecdsa::{
    ECDSA_P256_SHA1_VERIFY,
    ECDSA_P256_SHA256_VERIFY,
    ECDSA_P256_SHA384_VERIFY,
    ECDSA_P256_SHA512_VERIFY,

    ECDSA_P384_SHA1_VERIFY,
    ECDSA_P384_SHA256_VERIFY,
    ECDSA_P384_SHA384_VERIFY,
    ECDSA_P384_SHA512_VERIFY,
};

pub use ec::eddsa::{ED25519_VERIFY, Ed25519KeyPair};

#[cfg(feature = "use_heap")]
pub use rsa::RSAKeyPair;

#[cfg(feature = "use_heap")]
pub use rsa::{
    // `RSA_PKCS1_SHA1` is intentionally not exposed. At a minimum, we'd need
    // to create test vectors for signing with it, which we don't currently
    // have. But, it's a bad idea to use SHA-1 anyway, so perhaps we just won't
    // ever expose it.
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    RSA_PKCS1_2048_8192_SHA1_VERIFY,
    RSA_PKCS1_2048_8192_SHA256_VERIFY,
    RSA_PKCS1_2048_8192_SHA384_VERIFY,
    RSA_PKCS1_2048_8192_SHA512_VERIFY,

    RSA_PKCS1_3072_8192_SHA384_VERIFY,
};

/// A public key signature.
pub struct Signature {
    value: [u8; 64],
}

impl<'a> Signature {
    // Initialize a 64-byte signature from slice of bytes. XXX: This is public
    // so that other *ring* submodules can use it, but it isn't intended for
    // public use.
    #[doc(hidden)]
    pub fn new(signature_bytes: [u8; 64]) -> Signature {
        Signature { value: signature_bytes }
    }

    /// Returns a reference to the signature's encoded value.
    pub fn as_slice(&'a self) -> &'a [u8] {
        &self.value[..]
    }
}

/// A signature verification algorithm.
//
// The `VerificationAlgorithm` struct is just a wrapper around a
// `VerificationAlgorithmImpl`. This is done to be consistent with the rest of
// *ring*, which avoids exposing traits in its API, and to save users from
// encountering errors such as:
//
// ```output
// the trait `core::marker::Sync` is not implemented for the type
// `signature::VerificationAlgorithm + 'static` [E0277]
// note: shared static variables must have a type that implements `Sync`
// ```
//
// Although users could resolve such errors by adding `+ Sync` as we do here,
// it's confusing and hard to debug for newcomers.
pub struct VerificationAlgorithm {
    // XXX: This is public so that `VerificationAlgorithm`s can be defined in
    // other `ring` submodules, but it isn't actually useful outside `ring`
    // since `signature_impl` isn't public.
    #[doc(hidden)]
    pub implementation:
        &'static (signature_impl::VerificationAlgorithmImpl + Sync),
}

/// Verify the signature `signature` of message `msg` with the public key
/// `public_key` using the algorithm `alg`.
///
/// # Examples
///
/// ## Verify a RSA PKCS#1 signature that uses the SHA-256 digest
///
/// ```
/// extern crate ring;
/// extern crate untrusted;
///
/// use ring::signature;
///
/// # #[cfg(feature = "use_heap")]
/// fn verify_rsa_pkcs1_sha256(public_key: untrusted::Input,
///                            msg: untrusted::Input, sig: untrusted::Input)
///                            -> Result<(), ()> {
///    signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256_VERIFY,
///                      public_key, msg, sig)
/// }
/// # fn main() { }
/// ```
pub fn verify(alg: &VerificationAlgorithm, public_key: untrusted::Input,
              msg: untrusted::Input, signature: untrusted::Input)
              -> Result<(), ()> {
    init::init_once();
    alg.implementation.verify(public_key, msg, signature)
}


#[cfg(test)]
mod tests {
    // ECDSA tests are in crypto/ec/ecdsa.rs.
    // EdDSA tests are in crypto/ec/eddsa.rs.
}
