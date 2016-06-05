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
use input::Input;

struct EdDSA;

/// Verification of [Ed25519](http://ed25519.cr.yp.to/) signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
pub static ED25519_VERIFY: signature::VerificationAlgorithm =
        signature::VerificationAlgorithm {
    implementation: &EdDSA,
};

#[cfg(test)]
pub fn ed25519_sign(private_key: &[u8], msg: &[u8], signature: &mut [u8])
                    -> Result<(), ()> {
    use init;
    init::init_once();

    if private_key.len() != 64 || signature.len() != 64 {
        return Err(());
    }
    bssl::map_result(unsafe {
        ED25519_sign(signature.as_mut_ptr(), msg.as_ptr(), msg.len(),
                     private_key.as_ptr())
    })
}

impl signature_impl::VerificationAlgorithmImpl for EdDSA {
    fn verify(&self, public_key: Input, msg: Input, signature: Input)
              -> Result<(), ()> {
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


extern {
    #[cfg(test)]
    fn ED25519_sign(out_sig: *mut u8/*[64]*/, message: *const u8,
                    message_len: c::size_t, private_key: *const u8/*[64]*/);

    fn ED25519_verify(message: *const u8, message_len: c::size_t,
                      signature: *const u8/*[64]*/,
                      public_key: *const u8/*[32]*/) -> c::int;
}


#[cfg(test)]
mod tests {
    use {file_test, signature};
    use input::Input;
    use super::ed25519_sign;

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

            let mut actual_sig = [0u8; 64];
            assert!(ed25519_sign(&private_key, &msg, &mut actual_sig).is_ok());
            assert_eq!(&expected_sig[..], &actual_sig[..]);

            let public_key = Input::new(&public_key).unwrap();
            let msg = Input::new(&msg).unwrap();
            let expected_sig = Input::new(&expected_sig).unwrap();

            assert!(signature::verify(&signature::ED25519_VERIFY, public_key,
                                      msg, expected_sig).is_ok());
        });
    }
}
