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

//! Key Agreement: ECDH, including X25519.
//!
//! # Example
//!
//! Note that this example uses X25519, but ECDH using NIST P-256/P-384 is done
//! exactly the same way, just substituting
//! `agreement::ECDH_P256`/`agreement::ECDH_P384` for `agreement::X25519`.
//!
//! ```
//! # extern crate untrusted;
//! # extern crate ring;
//! #
//! # fn x25519_agreement_example() -> Result<(), ()> {
//! use ring::{agreement, rand};
//! use untrusted;
//!
//! let rng = rand::SystemRandom::new();
//!
//! let my_private_key =
//!     try!(agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng));
//!
//! // Make `my_public_key` a byte slice containing my public key. In a real
//! // application, this would be sent to the peer in an encoded protocol
//! // message.
//! let mut my_public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//! let my_public_key =
//!     &mut my_public_key[..my_private_key.public_key_len()];
//! try!(my_private_key.compute_public_key(my_public_key));
//!
//! // In a real application, the peer public key would be parsed out of a
//! // protocol message. Here we just generate one.
//! let mut peer_public_key_buf = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//! let peer_public_key;
//! {
//!     let peer_private_key =
//!        try!(agreement::EphemeralPrivateKey::generate(&agreement::X25519,
//!                                                      &rng));
//!     peer_public_key =
//!         &mut peer_public_key_buf[..peer_private_key.public_key_len()];
//!     try!(peer_private_key.compute_public_key(peer_public_key));
//! }
//! let peer_public_key = untrusted::Input::from(peer_public_key);
//!
//! // In a real application, the protocol specifies how to determine what
//! // algorithm was used to generate the peer's private key. Here, we know it
//! // is X25519 since we just generated it.
//! let peer_public_key_alg = &agreement::X25519;
//!
//! let error_value = ();
//!
//! agreement::agree_ephemeral(my_private_key, peer_public_key_alg,
//!                            peer_public_key, error_value, |_key_material| {
//!     // In a real application, we'd apply a KDF to the key material and the
//!     // public keys (as recommended in RFC 7748) and then derive session
//!     // keys from the result. We omit all that here.
//!     Ok(())
//! })
//! # }
//! # fn main() { x25519_agreement_example().unwrap() }
//! ```

// The "NSA Guide" steps here are from from section 3.1, "Ephemeral Unified Model."



use {ec, rand};
use untrusted;


pub use ec::PUBLIC_KEY_MAX_LEN;

pub use ec::suite_b::ecdh::ECDH_P256;

#[cfg(feature = "use_heap")]
pub use ec::suite_b::ecdh::ECDH_P384;

pub use ec::x25519::X25519;


/// A key agreement algorithm.
#[cfg_attr(not(test), allow(dead_code))]
pub struct Algorithm {
    // XXX: This is public so that `Algorithms`s can be defined in other `ring`
    // submodules, but it isn't actually useful outside `ring` since
    // `ec::AgreementAlgorithmImpl` isn't public.
    #[doc(hidden)]
    pub i: ec::AgreementAlgorithmImpl,
}

/// An ephemeral private key for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `EphemeralPrivateKey` can be
/// used for at most one key agreement.
pub struct EphemeralPrivateKey {
    private_key: ec::PrivateKey,
    alg: &'static Algorithm,
}

impl <'a> EphemeralPrivateKey {
    /// Generate a new ephemeral private key for the given algorithm.
    ///
    /// C analog: `EC_KEY_new_by_curve_name` + `EC_KEY_generate_key`.
    pub fn generate(alg: &'static Algorithm, rng: &rand::SecureRandom)
                    -> Result<EphemeralPrivateKey, ()> {
        // NSA Guide Step 1.
        //
        // This only handles the key generation part of step 1. The rest of
        // step one is done by `compute_public_key()`.
        Ok(EphemeralPrivateKey {
            private_key:
                try!(ec::PrivateKey::generate(&alg.i, rng)),
            alg: alg,
        })
    }

    #[cfg(test)]
    pub fn from_test_vector(alg: &'static Algorithm, test_vector: &[u8])
                            -> EphemeralPrivateKey {
        EphemeralPrivateKey {
            private_key: ec::PrivateKey::from_test_vector(&alg.i, test_vector),
            alg: alg,
        }
    }

    /// The size in bytes of the encoded public key.
    #[inline(always)]
    pub fn public_key_len(&self) -> usize { self.alg.i.public_key_len }

    /// Computes the public key from the private key's value and fills `out`
    /// with the public point encoded in the standard form for the algorithm.
    ///
    /// `out.len()` must be equal to the value returned by `public_key_len`.
    #[inline(always)]
    pub fn compute_public_key(&self, out: &mut [u8]) -> Result<(), ()> {
        // NSA Guide Step 1.
        //
        // Obviously, this only handles the part of Step 1 between the private
        // key generation and the sending of the public key to the peer. `out`
        // is what should be sent to the peer.
        self.private_key.compute_public_key(&self.alg.i, out)
    }

    #[cfg(test)]
    pub fn bytes(&'a self) -> &'a [u8] {
        self.private_key.bytes()
    }
}

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private key to use. Since it is moved, it
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
/// C analogs: `EC_POINT_oct2point` + `ECDH_compute_key`, `X25519`.
pub fn agree_ephemeral<F, R, E>(my_private_key: EphemeralPrivateKey,
                                peer_public_key_alg: &Algorithm,
                                peer_public_key: untrusted::Input,
                                error_value: E, kdf: F) -> Result<R, E>
                                where F: FnOnce(&[u8]) -> Result<R, E> {
    // NSA Guide Prerequisite 1.
    //
    // The domain parameters are hard-coded. This check verifies that the
    // peer's public key's domain parameters match the domain parameters of
    // this private key.
    if peer_public_key_alg.i.nid != my_private_key.alg.i.nid {
        return Err(error_value);
    }

    // NSA Guide Prerequisite 2, regarding which KDFs are allowed, is delegated
    // to the caller.

    // NSA Gudie Prerequisite 3, "Prior to or during the key-agreement process,
    // each party shall obtain the identifier associated with the other party
    // during the key-agreement scheme," is delegated to the caller.

    // NSA Guide Step 1 is handled by `EphemeralPrivateKey::generate()` and
    // `EphemeralPrivateKey::compute_public_key()`.

    let mut shared_key = [0u8; ec::ELEM_MAX_BYTES];
    let shared_key =
        &mut shared_key[..my_private_key.alg.i.elem_and_scalar_len];

    // NSA Guide Steps 2, 3, and 4.
    //
    // We have a pretty liberal interpretation of the NIST's spec's "Destroy"
    // that doesn't meet the NSA requirement to "zeroize."
    try!((my_private_key.alg.i.ecdh)(shared_key, &my_private_key.private_key,
                                     peer_public_key).map_err(|_| error_value));

    // NSA Guide Steps 5 and 6.
    //
    // Again, we have a pretty liberal interpretation of the NIST's spec's
    // "Destroy" that doesn't meet the NSA requirement to "zeroize."
    kdf(shared_key)
}


#[cfg(test)]
mod tests {
    use {test, rand};
    use untrusted;
    use super::*;

    #[test]
    fn test_agreement_agree_ephemeral() {
        let rng = rand::SystemRandom::new();

        test::from_file("src/ec/ecdh_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let curve_name = test_case.consume_string("Curve");
            let alg = alg_from_curve_name(&curve_name);
            let peer_public = test_case.consume_bytes("PeerQ");
            let peer_public = untrusted::Input::from(&peer_public);

            match test_case.consume_optional_string("Error") {
                None => {
                    let my_private = test_case.consume_bytes("D");
                    let my_public = test_case.consume_bytes("MyQ");
                    let output = test_case.consume_bytes("Output");

                    // In the no-heap mode, some algorithms aren't supported so
                    // we have to skip those algorithms' test cases.
                    let alg = match alg {
                        None => { return Ok(()); }
                        Some(alg) => alg,
                    };

                    let private_key =
                        EphemeralPrivateKey::from_test_vector(alg, &my_private);

                    let mut computed_public = [0u8; PUBLIC_KEY_MAX_LEN];
                    let computed_public =
                        &mut computed_public[..private_key.public_key_len()];
                    assert!(
                        private_key.compute_public_key(computed_public).is_ok());
                    assert_eq!(computed_public, &my_public[..]);

                    assert!(agree_ephemeral(private_key, alg, peer_public, (),
                                            |key_material| {
                        assert_eq!(key_material, &output[..]);
                        Ok(())
                    }).is_ok());
                },

                Some(_) => {
                    // In the no-heap mode, some algorithms aren't supported so
                    // we have to skip those algorithms' test cases.
                    let alg = match alg {
                        None => { return Ok(()); }
                        Some(alg) => alg
                    };

                    let dummy_private_key =
                        try!(EphemeralPrivateKey::generate(alg, &rng));
                    fn kdf_not_called(_: &[u8]) -> Result<(), ()> {
                        panic!("The KDF was called during ECDH when the peer's \
                                public key is invalid.");
                    }
                    assert!(
                        agree_ephemeral(dummy_private_key, alg, peer_public,
                                        (), kdf_not_called).is_err());
                }
            }

            return Ok(());
        });
    }

    #[cfg(feature = "use_heap")]
    fn alg_from_curve_name(curve_name: &str) -> Option<&'static Algorithm> {
        if curve_name == "P-256" {
            Some(&ECDH_P256)
        } else if curve_name == "P-384" {
            Some(&ECDH_P384)
        } else if curve_name == "X25519" {
            Some(&X25519)
        } else {
            panic!("Unsupported curve: {}", curve_name);
        }
    }

    #[cfg(not(feature = "use_heap"))]
    fn alg_from_curve_name(curve_name: &str) -> Option<&'static Algorithm> {
        if curve_name == "P-256" {
            Some(&ECDH_P256)
        } else if curve_name == "P-384" {
            None
        } else if curve_name == "X25519" {
            Some(&X25519)
        } else {
            panic!("Unsupported curve: {}", curve_name);
        }
    }
}
