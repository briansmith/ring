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
//! algorithm that identifies the algorithm. See the documentation for `verify`
//! for examples.
//!
//! For signature verification, this API treats each combination of parameters
//! as a separate algorithm. For example, instead of having a single "RSA"
//! algorithm with a verification function that takes a bunch of parameters,
//! there are `RSA_PKCS1_2048_8192_SHA256`, `RSA_PKCS1_2048_8192_SHA384`, etc.,
//! which encode sets of parameter choices into objects. This is designed to
//! reduce the risks of algorithm agility and to provide consistency with ECDSA
//! and EdDSA.
//!
//! Currently this module does not support digesting the message to be signed
//! separately from the public key operation, as it is currently being
//! optimized for Ed25519 and for the implementation of protocols that do not
//! requiring signing large messages. An interface for efficiently supporting
//! larger messages may be added later.
//!
//!
//! # Algorithm Details
//!
//! ## `ECDSA_*_ASN1` Details: ASN.1-encoded ECDSA Signatures
//!
//! The signature is a ASN.1 DER-encoded `Ecdsa-Sig-Value` as described in
//! [RFC 3279 Section 2.2.3]. This is the form of ECDSA signature used in
//! X.509-related structures and in TLS's `ServerKeyExchange` messages.
//!
//! The public key is encoding in uncompressed form using the
//! Octet-String-to-Elliptic-Curve-Point algorithm in
//! [SEC 1: Elliptic Curve Cryptography, Version 2.0].
//!
//! During verification, the public key is validated using the ECC Partial
//! Public-Key Validation Routine from Section 5.6.2.3.3 of
//! [NIST Special Publication 800-56A, revision 2] and Appendix A.3 of the
//! NSA's [Suite B implementer's guide to FIPS 186-3]. Note that, as explained
//! in the NSA guide, ECC Partial Public-Key Validation is equivalent to ECC
//! Full Public-Key Validation for prime-order curves like this one.
//!
//!
//! ## `RSA_PKCS1_*` Details: RSA PKCS#1 1.5 Signatures
//!
//! The signature is an RSASSA-PKCS1-v1_5 signature as described in
//! [RFC 3447 Section 8.2].
//!
//! The public key is encoded as an ASN.1 `RSAPublicKey` as described in
//! [RFC 3447 Appendix-A.1.1]. The public key modulus length, rounded *up* to
//! the nearest (larger) multiple of 8 bits, must be in the range given in the
//! name of the algorithm. The public exponent must be an odd integer of 2-33
//! bits, inclusive.
//!
//!
//! ## `RSA_PSS_*` Details: RSA PSS Signatures
//!
//! The signature is an RSASSA-PSS signature as described in
//! [RFC 3447 Section 8.1].
//!
//! The public key is encoded as an ASN.1 `RSAPublicKey` as described in
//! [RFC 3447 Appendix-A.1.1]. The public key modulus length, rounded *up* to
//! the nearest (larger) multiple of 8 bits, must be in the range given in the
//! name of the algorithm. The public exponent must be an odd integer of 2-33
//! bits, inclusive.
//!
//! During verification, signatures will only be accepted if the MGF1 digest
//! algorithm is the same as the message digest algorithm and if the salt
//! length is the same length as the message digest. This matches the
//! requirements in TLS 1.3 and other recent specifications.
//!
//! During signing, the message digest algorithm will be used as the MGF1
//! digest algorithm. The salt will be the same length as the message digest.
//! This matches the requirements in TLS 1.3 and other recent specifications.
//! Additionally, the entire salt is randomly generated separately for each
//! signature using the secure random number generator passed to `sign()`.
//!
//!
//! [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
//!     http://www.secg.org/sec1-v2.pdf
//! [NIST Special Publication 800-56A, revision 2]:
//!     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
//! [Suite B implementer's guide to FIPS 186-3]:
//!     https://github.com/briansmith/ring/blob/master/doc/ecdsa.pdf
//! [RFC 3279 Section 2.2.3]:
//!     https://tools.ietf.org/html/rfc3279#section-2.2.3
//! [RFC 3447 Section 8.2]:
//!     https://tools.ietf.org/html/rfc3447#section-7.2
//! [RFC 3447 Section 8.1]:
//!     https://tools.ietf.org/html/rfc3447#section-8.1
//! [RFC 3447 Appendix-A.1.1]:
//!     https://tools.ietf.org/html/rfc3447#appendix-A.1.1
//!
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
//! # fn sign_and_verify_ed25519() -> Result<(), ring::error::Unspecified> {
//! // Generate a key pair.
//! let rng = rand::SystemRandom::new();
//! let (generated, generated_bytes) =
//!     try!(signature::Ed25519KeyPair::generate_serializable(&rng));
//!
//! // Normally after generating the key pair, the application would extract
//! // the private and public components and store them persistently for future
//! // use.
//!
//! // Normally the application would later deserialize the private and public
//! // key from storage and then create an `Ed25519KeyPair` from the
//! // deserialized bytes.
//! let key_pair =
//!    try!(signature::Ed25519KeyPair::from_bytes(&generated_bytes.private_key,
//!                                               &generated_bytes.public_key));
//!
//! // Sign the message "hello, world".
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let sig = key_pair.sign(MESSAGE);
//!
//! // Normally, an application would extract the bytes of the signature and
//! // send them in a protocol message to the peer(s). Here we just use the
//! // public key from the private key we just generated.
//! let peer_public_key_bytes = &generated_bytes.public_key;
//! let sig_bytes = sig.as_slice();
//!
//! // Verify the signature of the message using the public key. Normally the
//! // verifier of the message would parse the inputs to `signature::verify`
//! // out of the protocol message(s) sent by the signer.
//! let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
//! let msg = untrusted::Input::from(MESSAGE);
//! let sig = untrusted::Input::from(sig_bytes);
//!
//! try!(signature::verify(&signature::ED25519, peer_public_key, msg, sig));
//!
//! # Ok(())
//! # }
//!
//! # fn main() { sign_and_verify_ed25519().unwrap() }
//! ```
//!
//! ## Signing and verifying with RSA (PKCS#1 1.5 padding)
//!
//! RSA signing (but not verification) requires the `rsa_signing` feature to
//! be enabled.
//!
//! ```
//! extern crate ring;
//! extern crate untrusted;
//!
//! use ring::{rand, signature};
//!
//! # #[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
//! # fn sign_and_verify_rsa() -> Result<(), ring::error::Unspecified> {
//!
//! // Create an `RSAKeyPair` from the DER-encoded bytes. This example uses
//! // a 2048-bit key, but larger keys are also supported.
//! let key_bytes_der =
//!    untrusted::Input::from(
//!         include_bytes!("src/rsa/signature_rsa_example_private_key.der"));
//! let key_pair =
//!    try!(signature::RSAKeyPair::from_der(key_bytes_der));
//!
//! // Create a signing state.
//! let key_pair = std::sync::Arc::new(key_pair);
//! let mut signing_state = try!(signature::RSASigningState::new(key_pair));
//!
//! // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
//! // SHA256 digest algorithm.
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let rng = rand::SystemRandom::new();
//! let signature_len = signing_state.key_pair().public_key().modulus_len();
//! let mut signature = vec![0; signature_len];
//! try!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
//!                         &mut signature));
//!
//! // Verify the signature.
//! let public_key_bytes_der =
//!     untrusted::Input::from(
//!         include_bytes!("src/rsa/signature_rsa_example_public_key.der"));
//! let message = untrusted::Input::from(MESSAGE);
//! let signature = untrusted::Input::from(&signature);
//! try!(signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256,
//!                        public_key_bytes_der, message, signature));
//! # Ok(())
//! # }
//! #
//! # #[cfg(not(all(feature = "rsa_signing", feature = "use_heap")))]
//! # fn sign_and_verify_rsa() -> Result<(), ring::error::Unspecified> {
//! #     Ok(())
//! # }
//! #
//! # fn main() { sign_and_verify_rsa().unwrap() }
//! ```


use {error, init, private};
use untrusted;

pub use ec::suite_b::ecdsa::{
    ECDSAParameters,

    ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA384_ASN1,

    ECDSA_P384_SHA256_ASN1,
    ECDSA_P384_SHA384_ASN1,
};

pub use ec::eddsa::{
    EdDSAParameters,

    ED25519,

    Ed25519KeyPair,
    Ed25519KeyPairBytes
};

#[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
pub use rsa::signing::{RSAKeyPair, RSASigningState};

#[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
pub use rsa::{
    RSAEncoding,

    // `RSA_PKCS1_SHA1` is intentionally not exposed. At a minimum, we'd need
    // to create test vectors for signing with it, which we don't currently
    // have. But, it's a bad idea to use SHA-1 anyway, so perhaps we just won't
    // ever expose it.
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};

#[cfg(feature = "use_heap")]
pub use rsa::{RSAPublicKey, RSAParameters};

#[cfg(feature = "use_heap")]
pub use rsa::verification::{
    RSA_PKCS1_2048_8192_SHA1,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,

    RSA_PKCS1_3072_8192_SHA384,

    RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512,
};

/// Lower-level verification primitives. Usage of `ring::signature::verify()`
/// is preferred when the public key and signature are encoded in standard
/// formats, as it also handles the parsing.
#[cfg(feature = "use_heap")]
pub mod primitive {
    pub use rsa::verification::verify_rsa;
}

/// A public key signature returned from a signing operation.
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
    pub fn as_slice(&'a self) -> &'a [u8] { &self.value[..] }
}

/// A signature verification algorithm.
pub trait VerificationAlgorithm: Sync + private::Private {
    /// Verify the signature `signature` of message `msg` with the public key
    /// `public_key`.
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified>;
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
/// enum Error {
///     InvalidSignature,
/// }
///
/// # #[cfg(feature = "use_heap")]
/// fn verify_rsa_pkcs1_sha256(public_key: untrusted::Input,
///                            msg: untrusted::Input, sig: untrusted::Input)
///                            -> Result<(), Error> {
///    signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256, public_key,
///                      msg, sig).map_err(|_| Error::InvalidSignature)
/// }
/// # fn main() { }
/// ```
pub fn verify(alg: &VerificationAlgorithm, public_key: untrusted::Input,
              msg: untrusted::Input, signature: untrusted::Input)
              -> Result<(), error::Unspecified> {
    init::init_once();
    alg.verify(public_key, msg, signature)
}


#[cfg(test)]
mod tests {
    // ECDSA tests are in crypto/ec/ecdsa.rs.
    // EdDSA tests are in crypto/ec/eddsa.rs.
}
