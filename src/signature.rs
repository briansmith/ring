// Copyright 2015-2017 Brian Smith.
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
//! ## `ECDSA_*_FIXED` Details: Fixed-length (PKCS#11-style) ECDSA Signatures
//!
//! The signature is *r*||*s*, where || denotes concatenation, and where both
//! *r* and *s* are both big-endian-encoded values that are left-padded to the
//! maximum length. A P-256 signature will be 64 bytes long (two 32-byte
//! components) and a P-384 signature will be 96 bytes long (two 48-byte
//! components). This is the form of ECDSA signature used PKCS#11 and DNSSEC.
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
//! // Generate a key pair in PKCS#8 (v2) format.
//! let rng = rand::SystemRandom::new();
//! let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
//!
//! // Normally the application would store the PKCS#8 file persistently. Later
//! // it would read the PKCS#8 file from persistent storage to use it.
//!
//! let key_pair =
//!    signature::Ed25519KeyPair::from_pkcs8(
//!             untrusted::Input::from(&pkcs8_bytes))?;
//!
//! // Sign the message "hello, world".
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let sig = key_pair.sign(MESSAGE);
//!
//! // Normally an application would extract the bytes of the signature and
//! // send them in a protocol message to the peer(s). Here we just get the
//! // public key key directly from the key pair.
//! let peer_public_key_bytes = key_pair.public_key_bytes();
//! let sig_bytes = sig.as_ref();
//!
//! // Verify the signature of the message using the public key. Normally the
//! // verifier of the message would parse the inputs to `signature::verify`
//! // out of the protocol message(s) sent by the signer.
//! let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
//! let msg = untrusted::Input::from(MESSAGE);
//! let sig = untrusted::Input::from(sig_bytes);
//!
//! signature::verify(&signature::ED25519, peer_public_key, msg, sig)?;
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
//! By default OpenSSL writes RSA public keys in SubjectPublicKeyInfo format,
//! not RSAPublicKey format, and Base64-encodes them (“PEM” format).
//!
//! To convert the PEM SubjectPublicKeyInfo format (“BEGIN PUBLIC KEY”) to the
//! binary RSAPublicKey format needed by `verify()`, use:
//!
//! ```sh
//! openssl rsa -pubin \
//!             -in public_key.pem \
//!             -inform PEM \
//!             -RSAPublicKey_out \
//!             -outform DER \
//!             -out public_key.der
//! ```
//!
//! To extract the RSAPublicKey-formatted public key from an ASN.1 (binary)
//! DER-encoded RSAPrivateKey format private key file, use:
//!
//! ```sh
//! openssl rsa -in private_key.der \
//!             -inform DER \
//!             -RSAPublicKey_out \
//!             -outform DER \
//!             -out public_key.der
//! ```
//!
//! ```
//! extern crate ring;
//! extern crate untrusted;
//!
//! use ring::{rand, signature};
//!
//! # #[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
//! fn sign_and_verify_rsa(private_key_path: &std::path::Path,
//!                        public_key_path: &std::path::Path)
//!                        -> Result<(), MyError> {
//! // Create an `RSAKeyPair` from the DER-encoded bytes. This example uses
//! // a 2048-bit key, but larger keys are also supported.
//! let private_key_der = read_file(private_key_path)?;
//! let private_key_der = untrusted::Input::from(&private_key_der);
//! let key_pair = signature::RSAKeyPair::from_der(private_key_der)
//!     .map_err(|ring::error::Unspecified| MyError::BadPrivateKey)?;
//!
//! // Create a signing state.
//! let key_pair = std::sync::Arc::new(key_pair);
//! let mut signing_state = signature::RSASigningState::new(key_pair)
//!     .map_err(|ring::error::Unspecified| MyError::OOM)?;
//!
//! // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
//! // SHA256 digest algorithm.
//! const MESSAGE: &'static [u8] = b"hello, world";
//! let rng = rand::SystemRandom::new();
//! let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
//! signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
//!                    &mut signature)
//!     .map_err(|ring::error::Unspecified| MyError::OOM)?;
//!
//! // Verify the signature.
//! let public_key_der = read_file(public_key_path)?;
//! let public_key_der = untrusted::Input::from(&public_key_der);
//! let message = untrusted::Input::from(MESSAGE);
//! let signature = untrusted::Input::from(&signature);
//! signature::verify(&signature::RSA_PKCS1_2048_8192_SHA256,
//!                   public_key_der, message, signature)
//!     .map_err(|ring::error::Unspecified| MyError::BadSignature)?;
//!
//! Ok(())
//! }
//!
//! #[derive(Debug)]
//! enum MyError {
//! #  #[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
//!    IO(std::io::Error),
//!    BadPrivateKey,
//!    OOM,
//!    BadSignature,
//! }
//!
//! # #[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
//! fn read_file(path: &std::path::Path) -> Result<Vec<u8>, MyError> {
//!     use std::io::Read;
//!
//!     let mut file = std::fs::File::open(path).map_err(|e| MyError::IO(e))?;
//!     let mut contents: Vec<u8> = Vec::new();
//!     file.read_to_end(&mut contents).map_err(|e| MyError::IO(e))?;
//!     Ok(contents)
//! }
//! #
//! # #[cfg(not(all(feature = "rsa_signing", feature = "use_heap")))]
//! # fn sign_and_verify_rsa(_private_key_path: &std::path::Path,
//! #                        _public_key_path: &std::path::Path)
//! #                        -> Result<(), ()> {
//! #     Ok(())
//! # }
//! #
//! # fn main() {
//! #     let private_key_path =
//! #         std::path::Path::new("src/rsa/signature_rsa_example_private_key.der");
//! #     let public_key_path =
//! #         std::path::Path::new("src/rsa/signature_rsa_example_public_key.der");
//! #     sign_and_verify_rsa(&private_key_path, &public_key_path).unwrap()
//! # }
//! ```


use core;
use {error, init, private, rand};
use untrusted;

#[cfg(feature = "use_heap")]
use std;

pub use ec::suite_b::ecdsa::{
    signing::{
        Key as ECDSAKeyPair,
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
    },

    verification::{
        Algorithm as ECDSAVerification,
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA384_ASN1,
        ECDSA_P384_SHA256_ASN1,
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED,
    },
};

pub use ec::curve25519::ed25519::{
    EdDSAParameters,

    ED25519,

    KeyPair as Ed25519KeyPair,
    ED25519_PKCS8_V2_LEN,
    ED25519_PUBLIC_KEY_LEN,
};

#[cfg(all(feature = "rsa_signing", feature = "use_heap"))]
pub use rsa::signing::{KeyPair as RSAKeyPair, SigningState as RSASigningState};

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
pub use rsa::RSAParameters;

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

pub use signature_impl::Signature;

/// Lower-level verification primitives. Usage of `ring::signature::verify()`
/// is preferred when the public key and signature are encoded in standard
/// formats, as it also handles the parsing.
#[cfg(feature = "use_heap")]
pub mod primitive {
    pub use rsa::verification::verify_rsa;
}

/// A key pair for signing.
#[derive(Debug)]
pub struct KeyPair {
    inner: std::boxed::Box<KeyPairImpl + Send + Sync>,
}

impl KeyPair {
    pub(crate) fn new<I: KeyPairImpl + Sync>(inner: I) -> Self {
        Self {
            inner: std::boxed::Box::new(inner),
        }
    }
}

pub(crate) trait KeyPairImpl: core::fmt::Debug + Send + 'static {
    fn sign(&self, rng: &rand::SecureRandom, msg: untrusted::Input)
            -> Result<Signature, error::Unspecified>;
}

/// An algorithm for signing.
#[cfg(feature = "use_heap")]
pub trait SigningAlgorithm: core::fmt::Debug + Sync + 'static + private::Sealed {
    /// Parses the key out of the given PKCS#8 document, verifying that it is
    /// valid for the algorithm.
    fn from_pkcs8(&'static self, input: untrusted::Input)
        -> Result<KeyPair, error::Unspecified>;
}

/// Returns a key for signing that is parsed from a PKCS#8 document.
///
/// The key is checked to ensure it is valid for the given algorithm.
#[inline]
pub fn key_pair_from_pkcs8(alg: &'static SigningAlgorithm, input: untrusted::Input)
    -> Result<KeyPair, error::Unspecified>
{
    alg.from_pkcs8(input)
}

/// Returns a signature of the given data using the given key. The signing may or may
/// not use `rng`, depending on the `key_pair's algorithm.
#[inline]
pub fn sign(key_pair: &KeyPair, rng: &rand::SecureRandom, msg: untrusted::Input)
            -> Result<Signature, error::Unspecified> {
    key_pair.inner.sign(rng, msg)
}

/// A signature verification algorithm.
pub trait VerificationAlgorithm: core::fmt::Debug + Sync + private::Sealed {
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
