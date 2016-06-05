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

use {bssl, c, signature, signature_impl};
use untrusted;
use rand::{RAND, SecureRandom};

struct EdDSA;

/// An Ed25519 key pair.
pub struct Ed25519KeyPair {
    private_public: [u8; 64],
}

impl<'a> Ed25519KeyPair {
    /// Generates a new key pair.
    pub fn generate(rng: &SecureRandom) -> Result<Ed25519KeyPair, ()> {
        let mut rand = RAND::new(rng);
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        try!(bssl::map_result(unsafe {
            ED25519_keypair(pair.private_public.as_mut_ptr(), &mut rand)
        }));
        Ok(pair)
    }

    /// Copies key data from the given slices to create a new key pair.
    /// The arguments are interpreted as little-endian-encoded key bytes.
    ///
    /// This is intended for use by code that deserializes key pairs.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8])
                      -> Result<Ed25519KeyPair, ()> {
        if private_key.len() != 32 {
            return Err(());
        } else if public_key.len() != 32 {
            return Err(());
        }
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        {
            let (pair_priv, pair_pub) = pair.private_public.split_at_mut(32);
            for i in 0..pair_priv.len() {
                pair_priv[i] = private_key[i];
            }
            for i in 0..pair_pub.len() {
                pair_pub[i] = public_key[i];
            }
        }
        Ok(pair)
    }

    /// Returns a reference to the little-endian-encoded private key bytes.
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
            ED25519_sign(signature_bytes.as_mut_ptr(), msg.as_ptr(),
                         msg.len(), self.private_public.as_ptr());
        }
        signature::Signature::new(signature_bytes)
    }
}


/// Verification of [Ed25519](http://ed25519.cr.yp.to/) signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
pub static ED25519_VERIFY: signature::VerificationAlgorithm =
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
            ED25519_verify(msg.as_ptr(), msg.len(), signature.as_ptr(),
                           public_key.as_ptr())
        })
    }
}


#[allow(improper_ctypes)]
extern {
    fn ED25519_keypair(out_private_key: *mut u8/*[64]*/,
                       rng: *mut RAND) -> c::int;
}

extern  {
    fn ED25519_sign(out_sig: *mut u8/*[64]*/, message: *const u8,
                    message_len: c::size_t, private_key: *const u8/*[64]*/);

    fn ED25519_verify(message: *const u8, message_len: c::size_t,
                      signature: *const u8/*[64]*/,
                      public_key: *const u8/*[32]*/) -> c::int;
}


#[cfg(test)]
mod tests {
    use {file_test, signature};
    use untrusted;
    use super::Ed25519KeyPair;

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

            let public_key = untrusted::Input::new(&public_key).unwrap();
            let msg = untrusted::Input::new(&msg).unwrap();
            let expected_sig = untrusted::Input::new(&expected_sig).unwrap();

            assert!(signature::verify(&signature::ED25519_VERIFY, public_key,
                                      msg, expected_sig).is_ok());
        });
    }
}
