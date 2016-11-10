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

#[cfg(feature = "rsa_signing")]
use rand;

/// The term "Encoding" comes from RFC 3447.
#[cfg(feature = "rsa_signing")]
pub trait Encoding: Sync {
    fn encode(&self, msg: &[u8], m_out: &mut [u8], mod_bits: usize,
              rng: &rand::SecureRandom) -> Result<(), error::Unspecified>;
}

/// The term "Verification" comes from RFC 3447.
pub trait Verification: Sync {
    fn verify(&self, msg: untrusted::Input, m: &mut untrusted::Reader,
              mod_bits: usize) -> Result<(), error::Unspecified>;
}

pub struct PKCS1 {
    digest_alg: &'static digest::Algorithm,
    digestinfo_prefix: &'static [u8],
}

#[cfg(feature ="rsa_signing")]
impl Encoding for PKCS1 {
    // Implement padding procedure per EMSA-PKCS1-v1_5,
    // https://tools.ietf.org/html/rfc3447#section-9.2.
    fn encode(&self, msg: &[u8], m_out: &mut [u8], _mod_bits: usize,
              _rng: &rand::SecureRandom) -> Result<(), error::Unspecified> {
        let em = m_out;

        let digest_len = self.digestinfo_prefix.len() +
                         self.digest_alg.output_len;

        // Require at least 8 bytes of padding. Since we disallow keys smaller
        // than 2048 bits, this should never happen anyway.
        debug_assert!(em.len() >= digest_len + 11);
        let pad_len = em.len() - digest_len - 3;
        em[0] = 0;
        em[1] = 1;
        for i in 0..pad_len {
            em[2 + i] = 0xff;
        }
        em[2 + pad_len] = 0;

        let (digest_prefix, digest_dst) = em[3 + pad_len..]
            .split_at_mut(self.digestinfo_prefix.len());
        digest_prefix.copy_from_slice(self.digestinfo_prefix);
        digest_dst.copy_from_slice(
            digest::digest(self.digest_alg, msg).as_ref());
        Ok(())
    }
}

impl Verification for PKCS1 {
    fn verify(&self, msg: untrusted::Input, m: &mut untrusted::Reader,
              _mod_bits: usize) -> Result<(), error::Unspecified> {
        let em = m;

        if try!(em.read_byte()) != 0 ||
            try!(em.read_byte()) != 1 {
            return Err(error::Unspecified);
        }

        let mut ps_len = 0;
        loop {
            match try!(em.read_byte()) {
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

        let em_digestinfo_prefix = try!(em.skip_and_get_input(
                    self.digestinfo_prefix.len()));
        if em_digestinfo_prefix != self.digestinfo_prefix {
            return Err(error::Unspecified);
        }

        let digest_alg = self.digest_alg;
        let decoded_digest =
            try!(em.skip_and_get_input(digest_alg.output_len));
        let digest = digest::digest(digest_alg, msg.as_slice_less_safe());
        if decoded_digest != digest.as_ref() {
            return Err(error::Unspecified);
        }

        Ok(())
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


/// PSS padding as described in [RFC 3447 Section 8.1]. The mask generation
/// function is MGF1 using the signature's digest's algorithm.
///
/// [RFC 3447 Section 8.1]: https://tools.ietf.org/html/rfc3447#section-8.1
pub struct PSS {
    digest_alg: &'static digest::Algorithm,
}

#[cfg(feature = "rsa_signing")]
// Maximum supported length of the salt in bytes.
// In practice, this is constrained by the maximum digest length.
const MAX_SALT_LEN: usize = digest::MAX_OUTPUT_LEN;

#[cfg(feature = "rsa_signing")]
impl Encoding for PSS {
    // Implement padding procedure per EMSA-PSS,
    // https://tools.ietf.org/html/rfc3447#section-9.1.
    fn encode(&self, msg: &[u8], m_out: &mut [u8], mod_bits: usize,
              rng: &rand::SecureRandom) -> Result<(), error::Unspecified> {
        // The `m_out` this function fills is the big-endian-encoded value of `m`
        // from the specification, padded to `k` bytes, where `k` is the length
        // in bytes of the public modulus. The spec says "Note that emLen will
        // be one less than k if modBits - 1 is divisible by 8 and equal to k
        // otherwise." In other words we might need to prefix `em` with a
        // leading zero byte to form a correct value of `m`.
        let em = if (mod_bits - 1) % 8 == 0 {
            m_out[0] = 0;
            &mut m_out[1..]
        } else {
            m_out
        };

        // Steps 1 and 2 are done later, out of order.

        // Step 3.
        let metrics = try!(PSSMetrics::new(self.digest_alg, mod_bits));
        assert_eq!(em.len(), metrics.em_len);

        // Step 4.
        let mut salt = [0u8; MAX_SALT_LEN];
        let salt = &mut salt[..metrics.s_len];
        try!(rng.fill(salt));

        // Step 5 and 6.
        let h_hash = pss_digest(self.digest_alg, msg, salt);

        // Re-order steps 7,8, 9 and 10 so that we first output the db mask into
        // the out buffer, and then XOR the value of db.

        // Step 9. First output the mask into the out buffer.
        try!(mgf1(self.digest_alg, h_hash.as_ref(),
                  &mut em[..metrics.db_len]));

        // Steps 7, 8 and 10: XOR into output the value of db:
        //     PS || 0x01 || salt
        // Where PS is all zeros.
        em[metrics.ps_len] ^= 0x01;
        for i in 0..metrics.s_len {
            em[metrics.ps_len + 1 + i] ^= salt[i];
        }

        // Step 11.
        em[0] &= metrics.top_byte_mask;

        // Step 12. Finalise output as:
        //     masked_db || h_hash || 0xbc
        em[metrics.db_len..][..metrics.h_len].copy_from_slice(h_hash.as_ref());
        em[metrics.db_len + metrics.h_len] = 0xbc;

        Ok(())
    }
}

impl Verification for PSS {
    // RSASSA-PSS-VERIFY from https://tools.ietf.org/html/rfc3447#section-8.1.2
    // where steps 1, 2(a), and 2(b) have been done for us.
    fn verify(&self, msg: untrusted::Input, m: &mut untrusted::Reader,
              mod_bits: usize) -> Result<(), error::Unspecified> {
        // RSASSA-PSS-VERIFY Step 2(c). The `m` this function is given is the
        // big-endian-encoded value of `m` from the specification, padded to
        // `k` bytes, where `k` is the length in bytes of the public modulus.
        // The spec. says "Note that emLen will be one less than k if
        // modBits - 1 is divisible by 8 and equal to k otherwise," where `k`
        // is the length in octets of the RSA public modulus `n`. In other
        // words, `em` might have an extra leading zero byte that we need to
        // strip before we start the PSS decoding steps which is an artifact of
        // the `Verification` interface.
        if (mod_bits - 1) % 8 == 0 {
            if try!(m.read_byte()) != 0 {
                return Err(error::Unspecified);
            }
        };
        let em = m;

        // The rest of this function is EMSA-PSS-VERIFY from
        // https://tools.ietf.org/html/rfc3447#section-9.1.2.

        // Steps 1 and 2 are done later, out of order.

        // Step 3.
        let metrics = try!(PSSMetrics::new(self.digest_alg, mod_bits));

        // Step 5, out of order.
        let masked_db = try!(em.skip_and_get_input(metrics.db_len));
        let h_hash = try!(em.skip_and_get_input(metrics.h_len));

        // Step 4.
        if try!(em.read_byte()) != 0xbc {
            return Err(error::Unspecified);
        }

        // Step 7.
        let mut db = [0u8; super::PUBLIC_MODULUS_MAX_LEN / 8];
        let db = &mut db[..metrics.db_len];

        try!(mgf1(self.digest_alg, h_hash.as_slice_less_safe(), db));

        try!(masked_db.read_all(error::Unspecified, |masked_bytes| {
            // Step 6. Check the top bits of first byte are zero.
            let b = try!(masked_bytes.read_byte());
            if b & !metrics.top_byte_mask != 0 {
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
        db[0] &= metrics.top_byte_mask;

        // Step 10.
        let pad_len = db.len() - metrics.s_len - 1;
        for i in 0..pad_len {
            if db[i] != 0 {
                return Err(error::Unspecified);
            }
        }
        if db[pad_len] != 1 {
            return Err(error::Unspecified);
        }

        // Step 11.
        let salt = &db[(db.len() - metrics.s_len)..];

        // Step 12 and 13.
        let h_prime = pss_digest(self.digest_alg, msg.as_slice_less_safe(),
                                 salt);

        // Step 14.
        if h_hash != h_prime.as_ref() {
            return Err(error::Unspecified);
        }

        Ok(())
    }
}

struct PSSMetrics {
    em_len: usize,
    db_len: usize,
    ps_len: usize,
    s_len: usize,
    h_len: usize,
    top_byte_mask: u8,
}

impl PSSMetrics {
    fn new(digest_alg: &'static digest::Algorithm, mod_bits: usize)
           -> Result<PSSMetrics, error::Unspecified> {
        let em_bits = mod_bits - 1;
        let em_len = (em_bits + 7) / 8;
        let leading_zero_bits = (8 * em_len) - em_bits;
        assert!(leading_zero_bits < 8);
        let top_byte_mask = 0xffu8 >> leading_zero_bits;

        let h_len = digest_alg.output_len;

        // We require the salt length to be equal to the digest length.
        let s_len = h_len;

        // Step 3 of both `EMSA-PSS-ENCODE` is `EMSA-PSS-VERIFY` requires that
        // we reject inputs where "emLen < hLen + sLen + 2". The definition of
        // `emBits` in RFC 3447 Sections 9.1.1 and 9.1.2 says `emBits` must be
        // "at least 8hLen + 8sLen + 9". Since 9 bits requires two bytes, these
        // two conditions are equivalent. 9 bits are required as the 0x01
        // before the salt requires 1 bit and the 0xbc after the digest
        // requires 8 bits.
        let db_len = try!(em_len.checked_sub(1 + s_len)
                                .ok_or(error::Unspecified));
        let ps_len = try!(db_len.checked_sub(h_len + 1)
                                .ok_or(error::Unspecified));

        debug_assert!(em_bits >= (8 * h_len) + (8 * s_len) + 9);

        Ok(PSSMetrics {
            em_len: em_len,
            db_len: db_len,
            ps_len: ps_len,
            s_len: s_len,
            h_len: h_len,
            top_byte_mask: top_byte_mask,
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

fn pss_digest(digest_alg: &'static digest::Algorithm, msg: &[u8], salt: &[u8])
              -> digest::Digest {
    // Fixed prefix.
    const PREFIX_ZEROS: [u8; 8] = [0u8; 8];

    // Steps 1 & 2 for both encoding and verification. Step 1 is delegated to
    // the digest implementation.
    let m_hash = digest::digest(digest_alg, msg);

    // Encoding step 5 and 6, Verification step 12 and 13.
    let mut ctx = digest::Context::new(digest_alg);
    ctx.update(&PREFIX_ZEROS);
    ctx.update(m_hash.as_ref());
    ctx.update(salt);
    ctx.finish()
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
    use {error, test};
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

            let actual_result =
                encoded.read_all(error::Unspecified,
                                 |m| alg.verify(msg, m, bit_len));
            assert_eq!(actual_result.is_ok(), expected_result == "P");

            Ok(())
        });
    }
}
