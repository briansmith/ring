// Copyright 2015-2017 Brian Smith.
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

//! Key Agreement: ECDH, including X25519.
//!
//! # Example
//!
//! Note that this example uses X25519, but ECDH using NIST P-256/P-384 is done
//! exactly the same way, just substituting
//! `agreement::ECDH_P256`/`agreement::ECDH_P384` for `agreement::X25519`.
//!
//! ```
//! # fn x25519_agreement_example() -> Result<(), ring::error::Unspecified> {
//! use ring::{agreement, rand};
//! use untrusted;
//!
//! let rng = rand::SystemRandom::new();
//!
//! let my_private_key =
//!     agreement::PrivateKey::<agreement::Ephemeral>::generate(&agreement::X25519, &rng)?;
//!
//! // Make `my_public_key` a byte slice containing my public key. In a real
//! // application, this would be sent to the peer in an encoded protocol
//! // message.
//! let mut my_public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//! let my_public_key = &mut my_public_key[..my_private_key.public_key_len()];
//! my_private_key.compute_public_key(my_public_key)?;
//!
//! // In a real application, the peer public key would be parsed out of a
//! // protocol message. Here we just generate one.
//! let mut peer_public_key_buf = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//! let peer_public_key;
//! {
//!     let peer_private_key =
//!         agreement::PrivateKey::<agreement::Ephemeral>::generate(&agreement::X25519, &rng)?;
//!     peer_public_key = &mut peer_public_key_buf[..peer_private_key.public_key_len()];
//!     peer_private_key.compute_public_key(peer_public_key)?;
//! }
//! let peer_public_key = untrusted::Input::from(peer_public_key);
//!
//! // In a real application, the protocol specifies how to determine what
//! // algorithm was used to generate the peer's private key. Here, we know it
//! // is X25519 since we just generated it.
//! let peer_public_key_alg = &agreement::X25519;
//!
//! let input_keying_material = my_private_key.agree(peer_public_key_alg, peer_public_key)?;
//! input_keying_material.derive(|_key_material| {
//!     // In a real application, we'd apply a KDF to the key material and the
//!     // public keys (as recommended in RFC 7748) and then derive session
//!     // keys from the result. We omit all that here.
//!     Ok(())
//! })
//! # }
//! # fn main() { x25519_agreement_example().unwrap() }
//! ```

// The "NSA Guide" steps here are from from section 3.1, "Ephemeral Unified
// Model."

use crate::{ec, error, rand};
use untrusted;

pub use crate::ec::{
    curve25519::x25519::X25519,
    suite_b::ecdh::{ECDH_P256, ECDH_P384},
    PUBLIC_KEY_MAX_LEN,
};
use core::marker::PhantomData;

/// A key agreement algorithm.
pub struct Algorithm {
    pub(crate) curve: &'static ec::Curve,
    pub(crate) ecdh: fn(
        out: &mut [u8],
        private_key: &ec::PrivateKey,
        peer_public_key: untrusted::Input,
    ) -> Result<(), error::Unspecified>,
}

derive_debug_via_self!(Algorithm, self.curve);

impl Eq for Algorithm {}
impl PartialEq for Algorithm {
    fn eq(&self, other: &Algorithm) -> bool { self.curve.id == other.curve.id }
}

/// How many times the key may be used.
pub trait Usage: self::sealed::Sealed {}

/// The key may be used at most once.
pub struct Ephemeral {}
impl Usage for Ephemeral {}
impl self::sealed::Sealed for Ephemeral {}

/// The key may be used more than once.
pub struct Static {}
impl Usage for Static {}
impl self::sealed::Sealed for Static {}

/// A private key for key agreement.
pub struct PrivateKey<U: Usage> {
    private_key: ec::PrivateKey,
    alg: &'static Algorithm,
    usage: PhantomData<U>,
}

impl<U: Usage> PrivateKey<U> {
    /// Generate a new private key for the given algorithm.
    ///
    /// C analog: `EC_KEY_new_by_curve_name` + `EC_KEY_generate_key`.
    pub fn generate(
        alg: &'static Algorithm, rng: &rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        // NSA Guide Step 1.
        //
        // This only handles the key generation part of step 1. The rest of
        // step one is done by `compute_public_key()`.
        let private_key = ec::PrivateKey::generate(&alg.curve, rng)?;
        Ok(Self {
            private_key,
            alg,
            usage: PhantomData,
        })
    }

    /// The key exchange algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm { self.alg }

    /// The size in bytes of the encoded public key.
    #[inline(always)]
    pub fn public_key_len(&self) -> usize { self.alg.curve.public_key_len }

    /// Computes the public key from the private key's value and fills `out`
    /// with the public point encoded in the standard form for the algorithm.
    ///
    /// `out.len()` must be equal to the value returned by `public_key_len`.
    #[inline(always)]
    pub fn compute_public_key(&self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        // NSA Guide Step 1.
        //
        // Obviously, this only handles the part of Step 1 between the private
        // key generation and the sending of the public key to the peer. `out`
        // is what should be sent to the peer.
        self.private_key.compute_public_key(&self.alg.curve, out)
    }

    /// Performs a key agreement with an private key and the given public key.
    ///
    /// Since `self` is consumed, it will not be usable after calling `agree`.
    ///
    /// `peer_public_key_alg` is the algorithm/curve for the peer's public key
    /// point; `agree` will return `Err(error_value)` if it does not match this
    /// private key's algorithm/curve.
    ///
    /// `peer_public_key` is the peer's public key. `agree` verifies that it is
    /// encoded in the standard form for the algorithm and that the key is
    /// *valid*; see the algorithm's documentation for details on how keys are
    /// to be encoded and what constitutes a valid key for that algorithm.
    ///
    /// C analogs: `EC_POINT_oct2point` + `ECDH_compute_key`, `X25519`.
    pub fn agree(
        self, peer_public_key_alg: &Algorithm, peer_public_key: untrusted::Input,
    ) -> Result<InputKeyMaterial, error::Unspecified> {
        agree_(
            &self.private_key,
            self.alg,
            peer_public_key_alg,
            peer_public_key,
        )
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self, curve: &ec::Curve) -> &[u8] { self.private_key.bytes(curve) }
}

impl PrivateKey<Static> {
    /// Performs a key agreement with a static private key and the given
    /// public key.
    ///
    /// `peer_public_key_alg` is the algorithm/curve for the peer's public key
    /// point; `agree_static` will return `Err(error_value)` if it does not
    /// match `my_private_key's` algorithm/curve.
    ///
    /// `peer_public_key` is the peer's public key. `agree_static` verifies
    /// that it is encoded in the standard form for the algorithm and that
    /// the key is *valid*; see the algorithm's documentation for details on
    /// how keys are to be encoded and what constitutes a valid key for that
    /// algorithm.
    ///
    /// C analogs: `EC_POINT_oct2point` + `ECDH_compute_key`, `X25519`.
    pub fn agree_static(
        &self, peer_public_key_alg: &Algorithm, peer_public_key: untrusted::Input,
    ) -> Result<InputKeyMaterial, error::Unspecified> {
        agree_(
            &self.private_key,
            self.alg,
            peer_public_key_alg,
            peer_public_key,
        )
    }
}

fn agree_(
    my_private_key: &ec::PrivateKey, my_alg: &Algorithm, peer_public_key_alg: &Algorithm,
    peer_public_key: untrusted::Input,
) -> Result<InputKeyMaterial, error::Unspecified> {
    let alg = &my_alg;

    // NSA Guide Prerequisite 1.
    //
    // The domain parameters are hard-coded. This check verifies that the
    // peer's public key's domain parameters match the domain parameters of
    // this private key.
    if peer_public_key_alg != *alg {
        return Err(error::Unspecified);
    }

    // NSA Guide Prerequisite 2, regarding which KDFs are allowed, is delegated
    // to the caller.

    // NSA Guide Prerequisite 3, "Prior to or during the key-agreement process,
    // each party shall obtain the identifier associated with the other party
    // during the key-agreement scheme," is delegated to the caller.

    // NSA Guide Step 1 is handled by `Self::generate()` and
    // `Self::compute_public_key()`.

    // NSA Guide Steps 2, 3, and 4.
    //
    // We have a pretty liberal interpretation of the NIST's spec's "Destroy"
    // that doesn't meet the NSA requirement to "zeroize."
    let mut ikm = InputKeyMaterial {
        bytes: [0; ec::ELEM_MAX_BYTES],
        len: alg.curve.elem_and_scalar_len,
    };
    (alg.ecdh)(&mut ikm.bytes[..ikm.len], my_private_key, peer_public_key)?;

    // NSA Guide Steps 5 and 6 are deferred to `InputKeyMaterial::derive`.
    Ok(ikm)
}

/// The result of a key agreement operation, to be fed into a KDF.
///
/// Intentionally not `Clone` or `Copy` since the value should only be
/// used once.
#[must_use]
pub struct InputKeyMaterial {
    bytes: [u8; ec::ELEM_MAX_BYTES],
    len: usize,
}

mod sealed {
    pub trait Sealed {}
}

impl InputKeyMaterial {
    /// Calls `kdf` with the raw key material and then returns what `kdf`
    /// returns, consuming `Self` so that the key material can only be used
    /// once.
    pub fn derive<F, R>(self, kdf: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        kdf(&self.bytes[..self.len])

        // NSA Guide Steps 5 and 6.
        // Again, we have a pretty liberal interpretation of the NIST's spec's
        // "Destroy" that doesn't meet the NSA requirement to "zeroize."
    }
}
