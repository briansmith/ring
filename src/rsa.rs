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

use {bssl, c, der, digest, signature, signature_impl};
use untrusted;


#[allow(non_camel_case_types)]
struct RSA_PKCS1 {
    digest_alg: &'static digest::Algorithm,
    min_bits: usize,
    digestinfo_prefix: &'static [u8],
}

impl signature_impl::VerificationAlgorithmImpl for RSA_PKCS1 {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), ()> {
        const MAX_BITS: usize = 8192;

        let (n, e) = try!(parse_public_key(public_key));
        let signature = signature.as_slice_less_safe();

        let mut decoded = [0u8; (MAX_BITS + 7) / 8];
        if signature.len() > decoded.len() {
            return Err(());
        }
        let decoded = &mut decoded[..signature.len()];
        try!(bssl::map_result(unsafe {
            GFp_rsa_public_decrypt(decoded.as_mut_ptr(), decoded.len(),
                                   n.as_ptr(), n.len(), e.as_ptr(), e.len(),
                                   signature.as_ptr(), signature.len(),
                                   self.min_bits, MAX_BITS)
        }));

        let decoded = try!(untrusted::Input::new(decoded));
        decoded.read_all((), |decoded| {
            if try!(decoded.read_byte()) != 0 ||
               try!(decoded.read_byte()) != 1 {
                return Err(());
            }

            let mut ps_len = 0;
            loop {
                match try!(decoded.read_byte()) {
                    0xff => { ps_len += 1; },
                    0x00 => { break; },
                    _ => { return Err(()); }
                }
            }
            if ps_len < 8 {
                return Err(());
            }

            let decoded_digestinfo_prefix =
                try!(decoded.skip_and_get_input(self.digestinfo_prefix.len()));
            if decoded_digestinfo_prefix != self.digestinfo_prefix {
                return Err(());
            }

            let decoded_digest =
                try!(decoded.skip_and_get_input(self.digest_alg.output_len));
            let digest =
                digest::digest(self.digest_alg, msg.as_slice_less_safe());
            if decoded_digest != digest.as_ref() {
                return Err(());
            }

            Ok(())
        })
    }
}

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $min_bits_str:expr,
      $digest_alg_name:expr, $digest_alg:expr, $digestinfo_prefix:expr ) => {
        #[cfg(feature = "use_heap")]
        #[doc="Verification of RSA PKCS#1 1.5 signatures of "]
        #[doc=$min_bits_str]
        #[doc="-8192 bits "]
        #[doc="using the "]
        #[doc=$digest_alg_name]
        #[doc=" digest algorithm."]
        ///
        /// Only available in `use_heap` mode.
        pub static $VERIFY_ALGORITHM: signature::VerificationAlgorithm =
                signature::VerificationAlgorithm {
            implementation: &RSA_PKCS1 {
                digest_alg: $digest_alg,
                min_bits: $min_bits,
                digestinfo_prefix: $digestinfo_prefix,
            }
        };
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1_VERIFY, 2048, "2048", "SHA-1",
           &digest::SHA1, &SHA1_PKCS1_DIGESTINFO_PREFIX);

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256_VERIFY, 2048, "2048", "SHA-256",
           &digest::SHA256, &SHA256_PKCS1_DIGESTINFO_PREFIX);

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384_VERIFY, 2048, "2048", "SHA-384",
           &digest::SHA384, &SHA384_PKCS1_DIGESTINFO_PREFIX);

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512_VERIFY, 2048, "2048", "SHA-512",
           &digest::SHA512, &SHA512_PKCS1_DIGESTINFO_PREFIX);

rsa_pkcs1!(RSA_PKCS1_3072_8192_SHA384_VERIFY, 3072, "3072", "SHA-384",
           &digest::SHA384, &SHA384_PKCS1_DIGESTINFO_PREFIX);

macro_rules! pkcs1_digestinfo_prefix {
    ( $name:ident, $digest_len:expr, $digest_oid_len:expr,
      [ $( $digest_oid:expr ),* ] ) => {
        static $name: [u8; 2 + 8 + $digest_oid_len] = [
            der::Tag::Sequence as u8, 8 + $digest_oid_len + $digest_len,
                der::Tag::Sequence as u8, 2 + $digest_oid_len + 2,
                    der::Tag::OID as u8, $digest_oid_len, $( $digest_oid ),*,
                    der::Tag::Null as u8, 0,
                der::Tag::OctetString as u8, $digest_len,
        ];
    }
}

pkcs1_digestinfo_prefix!(
    SHA1_PKCS1_DIGESTINFO_PREFIX, 20, 5, [ 0x2b, 0x0e, 0x03, 0x02, 0x1a ]);

pkcs1_digestinfo_prefix!(
    SHA256_PKCS1_DIGESTINFO_PREFIX, 32, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 ]);

pkcs1_digestinfo_prefix!(
    SHA384_PKCS1_DIGESTINFO_PREFIX, 48, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 ]);

pkcs1_digestinfo_prefix!(
    SHA512_PKCS1_DIGESTINFO_PREFIX, 64, 9,
    [ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 ]);


fn parse_public_key<'a>(input: untrusted::Input<'a>) ->
                        Result<(&'a [u8], &'a [u8]), ()> {
    input.read_all((), |input| {
        der::nested(input, der::Tag::Sequence, (), |input| {
            let n = try!(der::positive_integer(input));
            let e = try!(der::positive_integer(input));
            Ok((n.as_slice_less_safe(), e.as_slice_less_safe()))
        })
    })
}


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
    use {der, file_test, signature};
    use untrusted;
    use super::*;

    #[test]
    fn test_signature_rsa_pkcs1_verify() {
        file_test::run("src/rsa_pkcs1_verify_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = if digest_name == "SHA1" {
                &RSA_PKCS1_2048_8192_SHA1_VERIFY
            } else if digest_name == "SHA256" {
                &RSA_PKCS1_2048_8192_SHA256_VERIFY
            } else if digest_name == "SHA384" {
                &RSA_PKCS1_2048_8192_SHA384_VERIFY
            } else if digest_name == "SHA512" {
                &RSA_PKCS1_2048_8192_SHA512_VERIFY
            } else {
                panic!("Unsupported digest: {}", digest_name);
            };

            let public_key = test_case.consume_bytes("Key");
            let public_key = try!(untrusted::Input::new(&public_key));

            // Sanity check that we correctly DER-encoded the originally-
            // provided separate (n, e) components. When we add test vectors
            // for improperly-encoded signatures, we'll have to revisit this.
            assert!(public_key.read_all((), |input| {
                der::nested(input, der::Tag::Sequence, (), |input| {
                    let _ = try!(der::positive_integer(input));
                    let _ = try!(der::positive_integer(input));
                    Ok(())
                })
            }).is_ok());

            let msg = test_case.consume_bytes("Msg");
            let msg = try!(untrusted::Input::new(&msg));

            let sig = test_case.consume_bytes("Sig");
            let sig = try!(untrusted::Input::new(&sig));

            let expected_result = test_case.consume_string("Result");

            let actual_result = signature::verify(alg, public_key, msg, sig);
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        });
    }
}
