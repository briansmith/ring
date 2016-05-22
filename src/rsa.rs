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

use {bssl, c, digest, signature, signature_impl};
use input::Input;

#[allow(non_camel_case_types)]
struct RSA_PKCS1 {
    digest_alg: &'static digest::Algorithm,
    min_bits: usize,
}

impl signature_impl::VerificationAlgorithmImpl for RSA_PKCS1 {
    fn verify(&self, public_key: Input, msg: Input, signature: Input)
              -> Result<(), ()> {
        let digest = digest::digest(self.digest_alg, msg.as_slice_less_safe());
        let signature = signature.as_slice_less_safe();
        let public_key = public_key.as_slice_less_safe();
        bssl::map_result(unsafe {
            RSA_verify_pkcs1_signed_digest(self.min_bits, 8192,
                                           digest.algorithm().nid,
                                           digest.as_ref().as_ptr(),
                                           digest.as_ref().len(),
                                           signature.as_ptr(), signature.len(),
                                           public_key.as_ptr(), public_key.len())
        })
    }
}

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $min_bits_str:expr,
      $digest_alg_name:expr, $digest_alg:expr ) => {
        #[cfg(not(feature = "no_heap"))]
        #[doc="Verification of RSA PKCS#1 1.5 signatures of "]
        #[doc=$min_bits_str]
        #[doc="-8192 bits "]
        #[doc="using the "]
        #[doc=$digest_alg_name]
        #[doc=" digest algorithm."]
        ///
        /// Not available in `no_heap` mode.
        pub static $VERIFY_ALGORITHM: signature::VerificationAlgorithm =
                signature::VerificationAlgorithm {
            implementation: &RSA_PKCS1 {
                digest_alg: $digest_alg,
                min_bits: $min_bits
            }
        };
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1_VERIFY, 2048, "2048", "SHA-1",
           &digest::SHA1);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256_VERIFY, 2048, "2048", "SHA-256",
           &digest::SHA256);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384_VERIFY, 2048, "2048", "SHA-384",
           &digest::SHA384);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512_VERIFY, 2048, "2048", "SHA-512",
           &digest::SHA512);

rsa_pkcs1!(RSA_PKCS1_3072_8192_SHA384_VERIFY, 3072, "3072", "SHA-384",
           &digest::SHA384);


extern {
    fn RSA_verify_pkcs1_signed_digest(min_bits: usize, max_bits: usize,
                                      digest_nid: c::int, digest: *const u8,
                                      digest_len: c::size_t, sig: *const u8,
                                      sig_len: c::size_t, key_der: *const u8,
                                      key_der_len: c::size_t) -> c::int;
}
