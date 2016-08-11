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

use {der, digest, error};
use untrusted;

/// The term "Encoding" comes from RFC 3447.
#[cfg(feature = "rsa_signing")]
pub trait Encoding: Sync {
    fn encode(&self, msg: &[u8], out: &mut [u8])
              -> Result<(), error::Unspecified>;
}

/// The term "Verification" comes from RFC 3447.
pub trait Verification: Sync {
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input)
              -> Result<(), error::Unspecified>;
}

pub struct PKCS1 {
    digest_alg: &'static digest::Algorithm,
    digestinfo_prefix: &'static [u8],
}

#[cfg(feature ="rsa_signing")]
impl Encoding for PKCS1 {
    // Implement padding procedure per EMSA-PKCS1-v1_5,
    // https://tools.ietf.org/html/rfc3447#section-9.2.
    fn encode(&self, msg: &[u8], out: &mut [u8])
              -> Result<(), error::Unspecified> {
        let digest_len = self.digestinfo_prefix.len() +
                         self.digest_alg.output_len;

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

        let (digest_prefix, digest_dst) = out[3 + pad_len..]
            .split_at_mut(self.digestinfo_prefix.len());
        digest_prefix.copy_from_slice(self.digestinfo_prefix);
        digest_dst.copy_from_slice(
            digest::digest(self.digest_alg, msg).as_ref());
        Ok(())
    }
}

impl Verification for PKCS1 {
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input)
              -> Result<(), error::Unspecified> {
        encoded.read_all(error::Unspecified, |decoded| {
            if try!(decoded.read_byte()) != 0 ||
               try!(decoded.read_byte()) != 1 {
                return Err(error::Unspecified);
            }

            let mut ps_len = 0;
            loop {
                match try!(decoded.read_byte()) {
                    0xff => {
                        ps_len += 1;
                    },
                    0x00 => {
                        break;
                    },
                    _ => {
                        return Err(error::Unspecified);
                    },
                }
            }
            if ps_len < 8 {
                return Err(error::Unspecified);
            }

            let decoded_digestinfo_prefix = try!(decoded.skip_and_get_input(
                        self.digestinfo_prefix.len()));
            if decoded_digestinfo_prefix != self.digestinfo_prefix {
                return Err(error::Unspecified);
            }

            let digest_alg = self.digest_alg;
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

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $digestinfo_prefix:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        /// Feature: `rsa_signing`.
        pub static $PADDING_ALGORITHM: PKCS1 = PKCS1 {
            digest_alg: $digest_alg,
            digestinfo_prefix: $digestinfo_prefix,
        };
    }
}

rsa_pkcs1_padding!(RSA_PKCS1_SHA1, &digest::SHA1,
                   &SHA1_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-1 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA256, &digest::SHA256,
                   &SHA256_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-256 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA384, &digest::SHA384,
                   &SHA384_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-384 for RSA signatures.");
rsa_pkcs1_padding!(RSA_PKCS1_SHA512, &digest::SHA512,
                   &SHA512_PKCS1_DIGESTINFO_PREFIX,
                   "PKCS#1 1.5 padding using SHA-512 for RSA signatures.");

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
