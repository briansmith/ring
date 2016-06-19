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

use {bssl, c, der, digest, rand, signature, signature_impl};
use std;
use untrusted;


pub struct RSAPadding {
    digest_alg: &'static digest::Algorithm,
    digestinfo_prefix: &'static [u8],
}

impl RSAPadding {
    // Implement padding procedure per EMSA-PKCS1-v1_5,
    // https://tools.ietf.org/html/rfc3447#section-9.2.
    fn pad(&self, msg: &[u8], out: &mut [u8]) -> Result<(), ()> {
        let digest_len =
            self.digestinfo_prefix.len() + self.digest_alg.output_len;

        // Require at least 8 bytes of padding. Since we disallow keys smaller
        // than 2048 bits, this should never happen anyway.
        debug_assert!(out.len() >= digest_len + 11);
        let pad_len = out.len() - digest_len - 3;
        out[0] = 0;
        out[1] = 1;
        for i in 0..pad_len {
            out[2 + i] = 0xff;
        }
        out[2 + pad_len] = 0;

        let (digest_prefix, digest_dst) = out[3 + pad_len..].split_at_mut(
            self.digestinfo_prefix.len());
        digest_prefix.copy_from_slice(self.digestinfo_prefix);
        digest_dst.copy_from_slice(
            digest::digest(self.digest_alg, msg).as_ref());
        Ok(())
    }
}


struct RSAVerificationAlgorithm {
    padding_alg: &'static RSAPadding,
    min_bits: usize,
}


impl signature_impl::VerificationAlgorithmImpl for RSAVerificationAlgorithm {
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
                try!(decoded.skip_and_get_input(
                        self.padding_alg.digestinfo_prefix.len()));
            if decoded_digestinfo_prefix != self.padding_alg.digestinfo_prefix {
                return Err(());
            }

            let digest_alg = self.padding_alg.digest_alg;
            let decoded_digest =
                try!(decoded.skip_and_get_input(digest_alg.output_len));
            let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
            if decoded_digest != digest.as_ref() {
                return Err(());
            }

            Ok(())
        })
    }
}

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg_name:expr,
      $digest_alg:expr, $digestinfo_prefix:expr ) => {

        #[doc="PKCS#1 1.5 padding with the "]
        #[doc=$digest_alg_name]
        #[doc=" digest algorithm."]
        pub static $PADDING_ALGORITHM: RSAPadding = RSAPadding {
            digest_alg: $digest_alg,
            digestinfo_prefix: $digestinfo_prefix,
        };
    }
}

rsa_pkcs1_padding!(RSA_PKCS1_SHA1, "SHA1", &digest::SHA1,
                   &SHA1_PKCS1_DIGESTINFO_PREFIX);
rsa_pkcs1_padding!(RSA_PKCS1_SHA256, "SHA256", &digest::SHA256,
                   &SHA256_PKCS1_DIGESTINFO_PREFIX);
rsa_pkcs1_padding!(RSA_PKCS1_SHA384, "SHA384", &digest::SHA384,
                   &SHA384_PKCS1_DIGESTINFO_PREFIX);
rsa_pkcs1_padding!(RSA_PKCS1_SHA512, "SHA512", &digest::SHA512,
                   &SHA512_PKCS1_DIGESTINFO_PREFIX);

macro_rules! rsa_pkcs1 {
    ( $VERIFY_ALGORITHM:ident, $min_bits:expr, $min_bits_str:expr,
      $digest_alg_name:expr, $PADDING_ALGORITHM:ident ) => {
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
            implementation: &RSAVerificationAlgorithm {
                padding_alg: &$PADDING_ALGORITHM,
                min_bits: $min_bits,
            }
        };
    }
}

rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA1_VERIFY, 2048, "2048", "SHA-1",
           RSA_PKCS1_SHA1);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA256_VERIFY, 2048, "2048", "SHA-256",
           RSA_PKCS1_SHA256);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA384_VERIFY, 2048, "2048", "SHA-384",
           RSA_PKCS1_SHA384);
rsa_pkcs1!(RSA_PKCS1_2048_8192_SHA512_VERIFY, 2048, "2048", "SHA-512",
           RSA_PKCS1_SHA512);
rsa_pkcs1!(RSA_PKCS1_3072_8192_SHA384_VERIFY, 3072, "3072", "SHA-384",
           RSA_PKCS1_SHA384);

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


/// An RSA key pair.
pub struct RSAKeyPair {
    rsa: std::boxed::Box<RSA>,
}

impl RSAKeyPair {
    /// Parse a private key in DER-encoded ASN.1 `RSAPrivateKey` form (see [RFC
    /// 3447
    /// Appendix A.1.2](https://tools.ietf.org/html/rfc3447#appendix-A.1.2)).
    ///
    /// Only two-prime keys (version 0) keys are supported. The public modulus
    /// (n) must be at least 2048 bits. Currently, the public modulus must be
    /// no larger than 4096 bits.
    ///
    /// Here's one way to generate a key in the required format using OpenSSL:
    ///
    /// ```sh
    /// openssl genpkey -algorithm RSA \
    ///                 -pkeyopt rsa_keygen_bits:2048 \
    ///                 -outform der \
    ///                 -out private_key.der
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are
    /// encoded in PEM format, which is not supported by *ring*. PEM-encoded
    /// keys that are in `RSAPrivateKey` format can be decoded into the using
    /// an OpenSSL command like this:
    ///
    /// ```sh
    /// openssl rsa -in private_key.pem -outform DER -out private_key.der
    /// ```
    ///
    /// If these commands don't work, it is likely that the private key is in a
    /// different format like PKCS#8, which isn't supported yet. An upcoming
    /// version of *ring* will likely replace the support for the
    /// `RSAPrivateKey` format with support for the PKCS#8 format.
    pub fn from_der(input: untrusted::Input) -> Result<RSAKeyPair, ()> {
        input.read_all((), |input| {
            der::nested(input, der::Tag::Sequence, (), |input| {
                let version = try!(der::small_nonnegative_integer(input));
                if version != 0 {
                    return Err(());
                }
                let mut n = try!(PositiveInteger::from_der(input, 0));
                let mut e = try!(PositiveInteger::from_der(input, 0));
                let mut d =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut p =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut q =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut dmp1 =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut dmq1 =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut iqmp =
                    try!(PositiveInteger::from_der(input, BN_FLG_CONSTTIME));
                let mut rsa = std::boxed::Box::new(RSA {
                    n: n.into_raw(), e: e.into_raw(), d: d.into_raw(),
                    p: p.into_raw(), q: q.into_raw(), dmp1: dmp1.into_raw(),
                    dmq1: dmq1.into_raw(), iqmp: iqmp.into_raw(),
                    mont_n: std::ptr::null_mut(), mont_p: std::ptr::null_mut(),
                    mont_q: std::ptr::null_mut(),
                    mont_qq: std::ptr::null_mut(),
                    qmn_mont: std::ptr::null_mut(),
                    iqmp_mont: std::ptr::null_mut(),
                });
                try!(bssl::map_result(unsafe {
                    rsa_new_end(rsa.as_mut())
                }));
                Ok(RSAKeyPair { rsa: rsa })
            })
        })
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn public_modulus_len(&self) -> usize {
        unsafe { RSA_size(self.rsa.as_ref()) }
    }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` is used for blinding the message during
    /// signing, to mitigate some side-channel (e.g. timing) attacks.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly. To help mitigate the current
    /// imperfections, and for defense-in-depth, base blinding is always done.
    /// Exponent blinding is not done, but it may be done in the future.
    pub fn sign(&self, padding_alg: &'static RSAPadding,
                rng: &rand::SecureRandom, msg: &[u8], signature: &mut [u8])
                -> Result<(), ()> {
        if signature.len() != self.public_modulus_len() {
            return Err(());
        }

        try!(padding_alg.pad(msg, signature));
        let mut rand = rand::RAND::new(rng);
        bssl::map_result(unsafe {
            let blinding = BN_BLINDING_new();
            let ret =
                GFp_rsa_private_transform(self.rsa.as_ref(),
                                          signature.as_mut_ptr(),
                                          signature.len(), blinding,
                                          &mut rand);
            BN_BLINDING_free(blinding);
            ret
        })
    }
}

impl Drop for RSAKeyPair {
    fn drop(&mut self) {
        unsafe {
            BN_free(self.rsa.n);
            BN_free(self.rsa.e);
            BN_free(self.rsa.d);
            BN_free(self.rsa.p);
            BN_free(self.rsa.q);
            BN_free(self.rsa.dmp1);
            BN_free(self.rsa.dmq1);
            BN_free(self.rsa.iqmp);
            BN_MONT_CTX_free(self.rsa.mont_n);
            BN_MONT_CTX_free(self.rsa.mont_p);
            BN_MONT_CTX_free(self.rsa.mont_q);
            BN_MONT_CTX_free(self.rsa.mont_qq);
            BN_free(self.rsa.qmn_mont);
            BN_free(self.rsa.iqmp_mont);
        }
    }
}

/// Needs to be kept in sync with `struct rsa_st` (in `include/openssl/rsa.h`).
#[repr(C)]
struct RSA {
    n: *mut BIGNUM,
    e: *mut BIGNUM,
    d: *mut BIGNUM,
    p: *mut BIGNUM,
    q: *mut BIGNUM,
    dmp1: *mut BIGNUM,
    dmq1: *mut BIGNUM,
    iqmp: *mut BIGNUM,
    mont_n: *mut BN_MONT_CTX,
    mont_p: *mut BN_MONT_CTX,
    mont_q: *mut BN_MONT_CTX,
    mont_qq: *mut BN_MONT_CTX,
    qmn_mont: *mut BIGNUM,
    iqmp_mont: *mut BIGNUM,
}

struct PositiveInteger {
    value: Option<*mut BIGNUM>,
}

impl PositiveInteger {
    // Parses a single ASN.1 DER-encoded `Integer`, which most be positive.
    fn from_der(input: &mut untrusted::Reader, flags: c::int)
                -> Result<PositiveInteger, ()> {
        let bytes = try!(der::positive_integer(input)).as_slice_less_safe();
        let res = unsafe {
            BN_bin2bn(bytes.as_ptr(), bytes.len(), std::ptr::null_mut())
        };
        if res.is_null() {
            return Err(());
        }
        unsafe { BN_set_flags(res, flags); }
        Ok(PositiveInteger { value: Some(res) })
    }

    fn into_raw(&mut self) -> *mut BIGNUM {
        let res = self.value.unwrap();
        self.value = None;
        res
    }
}

impl Drop for PositiveInteger {
    fn drop(&mut self) {
        match self.value {
            Some(val) => unsafe { BN_free(val); },
            None => { },
        }
    }
}

enum BIGNUM {}

#[allow(non_camel_case_types)]
enum BN_BLINDING {}

#[allow(non_camel_case_types)]
enum BN_MONT_CTX {}

const BN_FLG_CONSTTIME: c::int = 4;


extern {
    fn BN_BLINDING_new() -> *mut BN_BLINDING;
    fn BN_BLINDING_free(b: *mut BN_BLINDING);
    fn BN_bin2bn(in_: *const u8, len: c::size_t, ret: *mut BIGNUM)
                 -> *mut BIGNUM;
    fn BN_set_flags(bn: *mut BIGNUM, flags: c::int);
    fn BN_free(bn: *mut BIGNUM);
    fn BN_MONT_CTX_free(mont: *mut BN_MONT_CTX);

    fn GFp_rsa_public_decrypt(out: *mut u8, out_len: c::size_t,
                              public_key_n: *const u8,
                              public_key_n_len: c::size_t,
                              public_key_e: *const u8,
                              public_key_e_len: c::size_t,
                              ciphertext: *const u8, ciphertext_len: c::size_t,
                              min_bits: c::size_t, max_bits: c::size_t)
                              -> c::int;

    fn rsa_new_end(rsa: *mut RSA) -> c::int;
    fn RSA_size(rsa: *const RSA) -> c::size_t;
}

#[allow(improper_ctypes)]
extern {
    fn GFp_rsa_private_transform(rsa: *const RSA, inout: *mut u8,
                                 len: c::size_t, blinding: *mut BN_BLINDING,
                                 rng: *mut rand::RAND) -> c::int;
}


#[cfg(test)]
mod tests {
    use {der, file_test, rand, signature};
    use untrusted;
    use super::*;
    use std;

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

    #[test]
    fn test_signature_rsa_pkcs1_sign() {
        let rng = rand::SystemRandom::new();
        file_test::run("src/rsa_pkcs1_sign_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = if digest_name == "SHA1" {
                &RSA_PKCS1_SHA1
            } else if digest_name == "SHA256" {
                &RSA_PKCS1_SHA256
            } else if digest_name == "SHA384" {
                &RSA_PKCS1_SHA384
            } else if digest_name == "SHA512" {
                &RSA_PKCS1_SHA512
            } else {
                panic!("Unsupported digest: {}", digest_name);
            };

            let private_key = test_case.consume_bytes("Key");
            let msg = test_case.consume_bytes("Msg");
            let expected = test_case.consume_bytes("Sig");
            let result = test_case.consume_string("Result");

            let private_key = try!(untrusted::Input::new(&private_key));
            let key_pair = RSAKeyPair::from_der(private_key);
            if key_pair.is_err() && result == "Fail-Invalid-Key" {
                return Ok(());
            }
            let key_pair = key_pair.unwrap();

            let mut actual: std::vec::Vec<u8> =
                std::vec::Vec::with_capacity(key_pair.public_modulus_len());
            actual.extend(
                std::iter::repeat(0).take(key_pair.public_modulus_len()));
            try!(key_pair.sign(alg, &rng, &msg, actual.as_mut_slice()));
            assert_eq!(actual.as_slice() == &expected[..], result == "Pass");
            Ok(())
        });
    }
}
