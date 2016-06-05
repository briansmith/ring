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
//! The design of this module is unusual compared to other public key signature
//! APIs. Algorithms are split into "signing" (suffixed `_SIGN`, and not yet
//! implemented) and "verification" (suffixed `_VERIFY`) algorithms in order to
//! make it easier for the linker to discard unused code in the case where only
//! signing is done or only verification is done with a given algorithm.
//!
//! Also, this API treats each combination of parameters as a separate
//! algorithm. For example, instead of having a single "RSA" algorithm with a
//! verification function that takes a bunch of parameters, there are
//! `RSA_PKCS1_2048_8192_SHA256_VERIFY`, `RSA_PKCS1_2048_8192_SHA256_VERIFY`,
//! etc. which encode sets of parameter choices into objects. This is designed
//! to reduce the risks of algorithm agility and to provide consistency with
//! ECDSA and EdDSA.
//!
//! Currently this module does not support digesting the message to be signed
//! separately from the public key operation, as it is currently being
//! optimized for Ed25519 and for the implementation of protocols that do not
//! requiring signing large messages. An interface for efficiently supporting
//! larger messages may be added later.

use {init, signature_impl};
use untrusted;

#[cfg(not(feature = "no_heap"))]
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

#[cfg(not(feature = "no_heap"))]
pub use rsa::{
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
/// extern crate untrusted;
/// extern crate ring;
///
/// use ring::signature;
///
/// // Ideally this function should take its inputs as `untrusted::Input`s
/// // instead of slices. It takes its input as slices to illustrate how to
/// // convert slices to `untrusted::Input`s.
/// # #[cfg(not(feature = "no_heap"))]
/// fn verify_rsa_pkcs1_sha256(public_key: &[u8], msg: &[u8], sig: &[u8])
///                            -> Result<(), ()> {
///    let public_key = try!(untrusted::Input::new(public_key));
///    let msg = try!(untrusted::Input::new(msg));
///    let sig = try!(untrusted::Input::new(sig));
///    signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256_VERIFY,
///                      public_key, msg, sig)
/// }
///
/// # fn main() { }
/// ```
///
/// ## Verify an Ed25519 signature
///
/// ```
/// extern crate ring;
/// extern crate untrusted;
///
/// use ring::signature;
///
/// fn verify_ed25519(public_key: untrusted::Input, msg: untrusted::Input,
///                   sig: untrusted::Input) -> Result<(), ()> {
///    signature::verify(&signature::ED25519_VERIFY, public_key, msg, sig)
/// }
///
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
