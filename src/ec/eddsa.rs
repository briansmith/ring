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

#![allow(unsafe_code)]

//! EdDSA Signatures.

use {bssl, c, rand, signature};
use untrusted;

pub struct EdDSA;

/// An Ed25519 key pair, used for signing.
pub struct Ed25519KeyPair {
    private_public: [u8; 64],
}

pub struct Ed25519KeyPairBytes {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl<'a> Ed25519KeyPair {
    /// Generates a new random key pair. There is no way to extract the private
    /// key bytes to save them. If you need to save the private key bytes for
    /// future use then use `generate_serializable()` instead.
    pub fn generate(rng: &rand::SecureRandom) -> Result<Ed25519KeyPair, ()> {
        Ed25519KeyPair::generate_serializable(rng)
            .map(|(key_pair, _)| key_pair)
    }

    /// Generates a new key pair and returns the key pair as both an
    /// `Ed25519KeyPair` and a `Ed25519KeyPairBytes`. There is no way to
    /// extract the private key bytes from an `Ed25519KeyPair`, so extracting
    /// the values from the `Ed25519KeyPairBytes` is the only way to get them.
    pub fn generate_serializable(rng: &rand::SecureRandom)
            -> Result<(Ed25519KeyPair, Ed25519KeyPairBytes), ()> {
        let mut bytes = Ed25519KeyPairBytes {
            private_key: [0; 32],
            public_key: [0; 32],
        };
        try!(rng.fill(&mut bytes.private_key));
        unsafe {
            GFp_ed25519_public_from_private(bytes.public_key.as_mut_ptr(),
                                            bytes.private_key.as_ptr());
        }
        let key_pair =
            try!(Ed25519KeyPair::from_bytes_unchecked(&bytes.private_key,
                                                      &bytes.public_key));
        Ok((key_pair, bytes))
    }

    /// Copies key data from the given slices to create a new key pair. The
    /// first slice must hold the private key and the second slice must hold
    /// the public key. Both slices must contain 32 little-endian-encoded
    /// bytes.
    ///
    /// This is intended for use by code that deserializes key pairs.
    ///
    /// The private and public keys will be verified to be consistent. This
    /// helps protect, for example, against the accidental swapping of the
    /// public and private components of the key pair. This also detects
    /// corruption that might have occurred during storage of the key pair.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8])
                      -> Result<Ed25519KeyPair, ()> {
        let pair =
            try!(Ed25519KeyPair::from_bytes_unchecked(private_key, public_key));
        let mut public_key_check = [0; 32];
        unsafe {
            GFp_ed25519_public_from_private(public_key_check.as_mut_ptr(),
                                            pair.private_public.as_ptr());
        }
        if public_key != public_key_check {
            return Err(());
        }
        Ok(pair)
    }

    fn from_bytes_unchecked(private_key: &[u8], public_key: &[u8])
                            -> Result<Ed25519KeyPair, ()> {
        if private_key.len() != 32 {
            return Err(());
        } else if public_key.len() != 32 {
            return Err(());
        }
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        for i in 0..32 {
            pair.private_public[i] = private_key[i];
            pair.private_public[32 + i] = public_key[i];
        }
        Ok(pair)
    }

    /// Returns a reference to the little-endian-encoded public key bytes.
    pub fn public_key_bytes(&'a self) -> &'a [u8] {
        &self.private_public[32..]
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        let mut signature_bytes = [0u8; 64];
        unsafe {
            GFp_ed25519_sign(signature_bytes.as_mut_ptr(), msg.as_ptr(),
                             msg.len(), self.private_public.as_ptr());
        }
        signature::Signature::new(signature_bytes)
    }
}


/// Verification of [Ed25519](http://ed25519.cr.yp.to/) signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
pub static ED25519: signature::VerificationAlgorithm =
    signature::VerificationAlgorithm::ED25519(EdDSA);


impl EdDSA {
    pub fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
                  signature: untrusted::Input) -> Result<(), ()> {
        let public_key = public_key.as_slice_less_safe();
        if public_key.len() != 32 || signature.len() != 64 {
            return Err(())
        }
        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();
        bssl::map_result(unsafe {
            GFp_ed25519_verify(msg.as_ptr(), msg.len(), signature.as_ptr(),
                               public_key.as_ptr())
        })
    }
}


extern  {
    fn GFp_ed25519_public_from_private(out: *mut u8/*[32]*/,
                                       in_: *const u8/*[32]*/);

    fn GFp_ed25519_sign(out_sig: *mut u8/*[64]*/, message: *const u8,
                        message_len: c::size_t, private_key: *const u8/*[64]*/);

    fn GFp_ed25519_verify(message: *const u8, message_len: c::size_t,
                          signature: *const u8/*[64]*/,
                          public_key: *const u8/*[32]*/) -> c::int;
}


#[cfg(test)]
mod tests {
    use {test, rand, signature};
    use super::Ed25519KeyPair;
    use untrusted;

    /// Test vectors from BoringSSL.
    #[test]
    fn test_signature_ed25519() {
        test::from_file("src/ed25519_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let private_key = test_case.consume_bytes("PRIV");
            assert_eq!(64, private_key.len());
            let public_key = test_case.consume_bytes("PUB");
            assert_eq!(32, public_key.len());
            let msg = test_case.consume_bytes("MESSAGE");
            let expected_sig = test_case.consume_bytes("SIG");

            let key_pair = Ed25519KeyPair::from_bytes(&private_key[..32],
                                                      &public_key).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_slice());

            let public_key = untrusted::Input::from(&public_key);
            let msg = untrusted::Input::from(&msg);
            let expected_sig = untrusted::Input::from(&expected_sig);

            assert!(signature::verify(&signature::ED25519, public_key,
                                      msg, expected_sig).is_ok());

            Ok(())
        });
    }

    #[test]
    fn test_ed25519_from_bytes_misuse() {
        let rng = rand::SystemRandom::new();
        let (_, bytes) =
            Ed25519KeyPair::generate_serializable(&rng).unwrap();

        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key,
                                           &bytes.public_key).is_ok());

        // Truncated private key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key[..31],
                                           &bytes.public_key).is_err());

        // Truncated public key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key,
                                           &bytes.public_key[..31]).is_err());

        // Swapped public and private key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.public_key,
                                           &bytes.private_key).is_err());
    }
}
