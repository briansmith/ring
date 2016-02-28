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
//! APIs. Algorithms like split into "signing" and "verification" algorithms.
//! Also, this API treats each combination of parameters as a separate
//! algorithm. For example, instead of having a single "RSA" algorithm with a
//! verification function that takes a bunch of parameters, there are
//! `RSA_PKCS1_2048_8192_SHA256`, `RSA_PKCS1_2048_8192_SHA512`,
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

mod ecdsa;
mod ed_dsa;
mod rsa_pkcs1;

use super::input::Input;

pub use self::ecdsa::{ECDSA_P256_SHA1, ECDSA_P256_SHA256, ECDSA_P256_SHA384,
                      ECDSA_P256_SHA512, ECDSA_P384_SHA1, ECDSA_P384_SHA256,
                      ECDSA_P384_SHA384, ECDSA_P384_SHA512};

pub use self::ed_dsa::ED25519;

pub use self::rsa_pkcs1::{RSA_PKCS1_2048_8192_SHA1,
                          RSA_PKCS1_2048_8192_SHA256,
                          RSA_PKCS1_2048_8192_SHA384,
                          RSA_PKCS1_2048_8192_SHA512,
                          RSA_PKCS1_3072_8192_SHA384};

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
    implementation: &'static (VerificationAlgorithmImpl + Sync),
}

trait VerificationAlgorithmImpl {
    fn verify(&self, public_key: Input, msg: Input, signature: Input)
              -> Result<(), ()>;
}

/// Verify the signature `signature` of message `msg` with the public key
/// `public_key` using the algorithm `alg`.
///
/// # Examples
///
/// ## Verify a RSA PKCS#1 signature that uses the SHA-256 digest
///
/// ```ignore
/// # // XXX: Re-enable when https://github.com/rust-lang/rust/pull/30372
/// # // reaches stable.
/// #
/// use ring::input::Input;
/// use ring::signature;
///
/// // Ideally this function should take its inputs as `Input`s instead of
/// // slices. It takes its input as slices to illustrate how to convert slices
/// // to `Input`s.
/// # #[cfg(not(feature = "no_heap"))]
/// fn verify_rsa_pkcs1_sha256(public_key: &[u8], msg: &[u8], sig: &[u8])
///                            -> Result<(), ()> {
///    let public_key = try!(Input::new(public_key));
///    let msg = try!(Input::new(msg));
///    let sig = try!(Input::new(sig));
///    signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256, public_key,
///                      msg, sig)
/// }
/// ```
///
/// ## Verify an Ed25519 signature
///
/// ```
/// use ring::input::Input;
/// use ring::signature;
///
/// fn verify_ed25519(public_key: Input, msg: Input, sig: Input)
///                   -> Result<(), ()> {
///    signature::verify(&signature::ED25519, public_key, msg, sig)
/// }
/// ```
pub fn verify(alg: &VerificationAlgorithm, public_key: Input, msg: Input,
              signature: Input) -> Result<(), ()> {
    alg.implementation.verify(public_key, msg, signature)
}
