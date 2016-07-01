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

use {bssl, c, rand, signature, signature_impl};
use untrusted;

struct EdDSA;

/// An Ed25519 key pair.
pub struct Ed25519KeyPair {
    private_public: [u8; 64],
}

impl<'a> Ed25519KeyPair {
    /// Generates a new key pair.
    pub fn generate(rng: &rand::SecureRandom) -> Result<Ed25519KeyPair, ()> {
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        try!(rng.fill(&mut pair.private_public[0..32]));
        unsafe {
            GFp_ed25519_public_from_private(
                pair.private_public[32..].as_mut_ptr(),
                pair.private_public.as_ptr());
        }
        Ok(pair)
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
        if private_key.len() != 32 {
            return Err(());
        } else if public_key.len() != 32 {
            return Err(());
        }
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        for i in 0..32 {
            pair.private_public[i] = private_key[i];
        }
        unsafe {
            GFp_ed25519_public_from_private(
                pair.private_public[32..].as_mut_ptr(),
                pair.private_public.as_ptr());
        }
        if &pair.private_public[32..] != public_key {
            return Err(());
        }
        Ok(pair)
    }

    /// Returns a reference to the little-endian-encoded private key bytes.
    ///
    /// This is intended for use by code that serializes the key pair.
    pub fn private_key_bytes(&'a self) -> &'a [u8] {
        &self.private_public[..32]
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
        signature::VerificationAlgorithm {
    implementation: &EdDSA,
};


impl signature_impl::VerificationAlgorithmImpl for EdDSA {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
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
    use {file_test, rand, signature};
    use super::Ed25519KeyPair;
    use untrusted;

    /// Test vectors from BoringSSL.
    #[test]
    fn test_signature_ed25519() {
        file_test::run("src/ed25519_tests.txt", |section, test_case| {
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
        let key_pair = Ed25519KeyPair::generate(&rng).unwrap();

        assert!(Ed25519KeyPair::from_bytes(key_pair.private_key_bytes(),
                                           key_pair.public_key_bytes())
                                           .is_ok());

        // Truncated private key.
        assert!(Ed25519KeyPair::from_bytes(&key_pair.private_key_bytes()[..31],
                                           key_pair.public_key_bytes())
                                           .is_err());

        // Truncated public key.
        assert!(Ed25519KeyPair::from_bytes(key_pair.private_key_bytes(),
                                           &key_pair.public_key_bytes()[..31])
                                           .is_err());

        // Swapped public and private key.
        assert!(Ed25519KeyPair::from_bytes(key_pair.public_key_bytes(),
                                           key_pair.private_key_bytes())
                                           .is_err());
    }
}
