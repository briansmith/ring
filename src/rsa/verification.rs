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

#![allow(unsafe_code)]

/// RSA PKCS#1 1.5 signatures.

use {bssl, c, digest, error, private, signature};
use super::{RSAParameters, parse_public_key};
use untrusted;


impl signature::VerificationAlgorithm for RSAParameters {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        const MAX_BITS: usize = 8192;

        let (n, e) = try!(parse_public_key(public_key));
        let signature = signature.as_slice_less_safe();

        let mut decoded = [0u8; (MAX_BITS + 7) / 8];
        if signature.len() > decoded.len() {
            return Err(error::Unspecified);
        }
        let decoded = &mut decoded[..signature.len()];
        try!(bssl::map_result(unsafe {
            GFp_rsa_public_decrypt(decoded.as_mut_ptr(), decoded.len(),
                                   n.as_ptr(), n.len(), e.as_ptr(), e.len(),
                                   signature.as_ptr(), signature.len(),
                                   self.min_bits, MAX_BITS)
        }));

        untrusted::Input::from(decoded).read_all(error::Unspecified, |decoded| {
            if try!(decoded.read_byte()) != 0 ||
               try!(decoded.read_byte()) != 1 {
                return Err(error::Unspecified);
            }

            let mut ps_len = 0;
            loop {
                match try!(decoded.read_byte()) {
                    0xff => { ps_len += 1; },
                    0x00 => { break; },
                    _ => { return Err(error::Unspecified); }
                }
            }
            if ps_len < 8 {
                return Err(error::Unspecified);
            }

            let decoded_digestinfo_prefix =
                try!(decoded.skip_and_get_input(
                        self.padding_alg.digestinfo_prefix.len()));
            if decoded_digestinfo_prefix != self.padding_alg.digestinfo_prefix {
                return Err(error::Unspecified);
            }

            let digest_alg = self.padding_alg.digest_alg;
            let decoded_digest =
                try!(decoded.skip_and_get_input(digest_alg.output_len));
            let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
            if decoded_digest != digest.as_ref() {
                return Err(error::Unspecified);
            }

            Ok(())
        })
    }
}

impl private::Private for RSAParameters { }

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $PADDING_ALGORITHM:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        ///
        /// Only available in `use_heap` mode.
        pub static $VERIFY_ALGORITHM: RSAParameters =
            RSAParameters {
                padding_alg: $PADDING_ALGORITHM,
                min_bits: $min_bits,
            };
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1, 2048, &super::RSA_PKCS1_SHA1,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-1.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256, 2048, &super::RSA_PKCS1_SHA256,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-256.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384, 2048, &super::RSA_PKCS1_SHA384,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-384.");
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512, 2048, &super::RSA_PKCS1_SHA512,
           "Verification of signatures using RSA keys of 2048-8192 bits,
            PKCS#1.5 padding, and SHA-512.");
rsa_pkcs1!(RSA_PKCS1_3072_8192_SHA384, 3072, &super::RSA_PKCS1_SHA384,
           "Verification of signatures using RSA keys of 3072-8192 bits,
            PKCS#1.5 padding, and SHA-384.");

extern {
    fn GFp_rsa_public_decrypt(out: *mut u8, out_len: c::size_t,
                              public_key_n: *const u8,
                              public_key_n_len: c::size_t,
                              public_key_e: *const u8,
                              public_key_e_len: c::size_t,
                              ciphertext: *const u8, ciphertext_len: c::size_t,
                              min_bits: c::size_t, max_bits: c::size_t)
                              -> c::int;
}

#[cfg(test)]
mod tests {
    use {der, error, signature, test};

    use super::*;
    use untrusted;

    #[test]
    fn test_signature_rsa_pkcs1_verify() {
        test::from_file("src/rsa/rsa_pkcs1_verify_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = if digest_name == "SHA1" {
                &RSA_PKCS1_2048_8192_SHA1
            } else if digest_name == "SHA256" {
                &RSA_PKCS1_2048_8192_SHA256
            } else if digest_name == "SHA384" {
                &RSA_PKCS1_2048_8192_SHA384
            } else if digest_name == "SHA512" {
                &RSA_PKCS1_2048_8192_SHA512
            } else {
                panic!("Unsupported digest: {}", digest_name);
            };

            let public_key = test_case.consume_bytes("Key");
            let public_key = untrusted::Input::from(&public_key);

            // Sanity check that we correctly DER-encoded the originally-
            // provided separate (n, e) components. When we add test vectors
            // for improperly-encoded signatures, we'll have to revisit this.
            assert!(public_key.read_all(error::Unspecified, |input| {
                der::nested(input, der::Tag::Sequence, error::Unspecified,
                            |input| {
                    let _ = try!(der::positive_integer(input));
                    let _ = try!(der::positive_integer(input));
                    Ok(())
                })
            }).is_ok());

            let msg = test_case.consume_bytes("Msg");
            let msg = untrusted::Input::from(&msg);

            let sig = test_case.consume_bytes("Sig");
            let sig = untrusted::Input::from(&sig);

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        });
    }
}
