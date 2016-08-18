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

use {der, digest, error, polyfill};
use untrusted;

/// The term "Encoding" comes from RFC 3447.
#[cfg(feature = "rsa_signing")]
pub trait Encoding: Sync {
    fn encode(&self, msg: &[u8], out: &mut [u8])
              -> Result<(), error::Unspecified>;
}

/// The term "Verification" comes from RFC 3447.
pub trait Verification: Sync {
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input,
              public_modulus_len_in_bits: usize)
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
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input, _: usize)
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


/// PSS Padding as described in https://tools.ietf.org/html/rfc3447#section-9.1.
/// It generates a random salt equal in length to the output of the specified
/// digest algorithm and uses MGF1 with that digest algorihtm as the mask
/// generating function.
pub struct PSS {
    digest_alg: &'static digest::Algorithm,
}

// Fixed prefix used in the computation of PSS encoding and verification.
const PSS_PREFIX_ZEROS: [u8; 8] = [0u8; 8];

impl Verification for PSS {
    // PSS verification as specified in
    // https://tools.ietf.org/html/rfc3447#section-9.1.2
    fn verify(&self, msg: untrusted::Input, encoded: untrusted::Input,
              public_modulus_len_in_bits: usize)
              -> Result<(), error::Unspecified> {
        // Number of bytes required to encode message. The maximum length is
        // given by the length of the public modulus in bits minus 1.
        let em_len = 1 + (public_modulus_len_in_bits - 2) / 8;
        assert_eq!(encoded.len(), em_len);
        // Create a bit mask to match the size of the modulus used.
        let top_byte_mask = 0xffu8 >>
            (7 - ((public_modulus_len_in_bits - 2) % 8));
        encoded.read_all(error::Unspecified, |em| {
            let digest_len = self.digest_alg.output_len;

            // Step 2.
            let m_hash = digest::digest(self.digest_alg,
                                        msg.as_slice_less_safe());

            // Step 3: where we assume the digest and salt are of equal length.
            if em_len < 2 + (2 * digest_len) {
                return Err(error::Unspecified);
            }

            // Steps 4 and 5: Parse encoded message as:
            //     masked_db || h_hash || 0xbc
            let db_len = em_len - digest_len - 1;
            let masked_db = try!(em.skip_and_get_input(db_len));
            let h_hash = try!(em.skip_and_get_input(digest_len));
            if try!(em.read_byte()) != 0xbc {
                return Err(error::Unspecified);
            }

            // Step 7.
            let mut db = [0u8; super::PUBLIC_MODULUS_MAX_LEN / 8];
            let db = &mut db[..db_len];

            try!(mgf1(self.digest_alg, h_hash.as_slice_less_safe(), db));

            try!(masked_db.read_all(error::Unspecified, |masked_bytes| {
                // Step 6. Check the top bits of first byte are zero.
                let b = try!(masked_bytes.read_byte());
                if b & !top_byte_mask != 0 {
                    return Err(error::Unspecified);
                }
                db[0] ^= b;

                // Step 8.
                for i in 1..db.len() {
                    db[i] ^= try!(masked_bytes.read_byte());
                }
                Ok(())
            }));

            // Step 9.
            db[0] &= top_byte_mask;

            // Step 10.
            let pad_len = db.len() - digest_len - 1;
            for i in 0..pad_len {
                if db[i] != 0 {
                    return Err(error::Unspecified);
                }
            }
            if db[pad_len] != 1 {
                return Err(error::Unspecified);
            }

            // Step 11.
            let salt = &db[db.len() - digest_len..];

            // Step 12 and 13: compute hash value of:
            //     (0x)00 00 00 00 00 00 00 00 || m_hash || salt
            let mut ctx = digest::Context::new(self.digest_alg);
            ctx.update(&PSS_PREFIX_ZEROS);
            ctx.update(m_hash.as_ref());
            ctx.update(salt);
            let h_hash_check = ctx.finish();

            // Step 14.
            if h_hash != h_hash_check.as_ref() {
                return Err(error::Unspecified);
            }
            Ok(())
        })
    }
}

// Mask-generating function MGF1 as described in
// https://tools.ietf.org/html/rfc3447#appendix-B.2.1.
fn mgf1(digest_alg: &'static digest::Algorithm, seed: &[u8], mask: &mut [u8])
        -> Result<(), error::Unspecified> {
    let digest_len = digest_alg.output_len;

    // Maximum counter value is the value of (mask_len / digest_len) rounded up.
    let ctr_max = (mask.len() - 1) / digest_len;
    assert!(ctr_max <= u32::max_value() as usize);
    for (i, mask_chunk) in mask.chunks_mut(digest_len).enumerate() {
        let mut ctx = digest::Context::new(digest_alg);
        ctx.update(seed);
        ctx.update(&polyfill::slice::be_u8_from_u32(i as u32));
        let digest = ctx.finish();
        let mask_chunk_len = mask_chunk.len();
        mask_chunk.copy_from_slice(&digest.as_ref()[..mask_chunk_len]);
    }

    Ok(())
}

macro_rules! rsa_pss_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        /// Feature: `rsa_signing`.
        pub static $PADDING_ALGORITHM: PSS = PSS {
            digest_alg: $digest_alg,
        };
    }
}

rsa_pss_padding!(RSA_PSS_SHA256, &digest::SHA256,
                 "PSS padding using SHA-256 for RSA signatures.");
rsa_pss_padding!(RSA_PSS_SHA384, &digest::SHA384,
                 "PSS padding using SHA-384 for RSA signatures.");
rsa_pss_padding!(RSA_PSS_SHA512, &digest::SHA512,
                 "PSS padding using SHA-512 for RSA signatures.");

#[cfg(test)]
mod test {
    use test;
    use super::*;
    use untrusted;

    // Tests PSS verification for variable public modulus lengths
    #[test]
    fn test_pss_verify() {

        test::from_file("src/rsa/pss_verify_tests.txt",
                        |section, test_case| {
            assert_eq!(section, "");

            let digest_name = test_case.consume_string("Digest");
            let alg = match digest_name.as_ref() {
                "SHA256" => &RSA_PSS_SHA256,
                _ =>  { panic!("Unsupported digest: {}", digest_name) }
            };

            let msg = test_case.consume_bytes("Msg");
            let msg = untrusted::Input::from(&msg);

            let encoded = test_case.consume_bytes("Encoded");
            let encoded = untrusted::Input::from(&encoded);

            let bit_len = test_case.consume_usize("Len");
            let expected_result = test_case.consume_string("Result");

            let actual_result = alg.verify(msg, encoded, bit_len);
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        });
    }
}
