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

use super::PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN;
use crate::{bits, digest, error, io::der, polyfill};

use core::convert::TryInto;
#[cfg(feature = "alloc")]
use {
    crate::rand,
    alloc::{boxed::Box, vec},
};

/// Common features of both RSA padding encoding and RSA padding verification.
pub trait Padding: 'static + Sync + crate::sealed::Sealed + core::fmt::Debug {
    // The digest algorithm used for digesting the message (and maybe for
    // other things).
    fn digest_alg(&self) -> &'static digest::Algorithm;
}

/// An RSA signature encoding as described in [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
#[cfg(feature = "alloc")]
pub trait RsaEncoding: Padding {
    #[doc(hidden)]
    fn encode(
        &self,
        m_hash: digest::Digest,
        m_out: &mut [u8],
        mod_bits: bits::BitLength,
        rng: &dyn rand::SecureRandom,
    ) -> Result<(), error::Unspecified>;
}

/// Verification of an RSA signature encoding as described in
/// [RFC 3447 Section 8].
///
/// [RFC 3447 Section 8]: https://tools.ietf.org/html/rfc3447#section-8
pub trait Verification: Padding {
    fn verify(
        &self,
        m_hash: digest::Digest,
        m: &mut untrusted::Reader,
        mod_bits: bits::BitLength,
    ) -> Result<(), error::Unspecified>;
}

/// PKCS#1 1.5 padding as described in [RFC 3447 Section 8.2].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.2]: https://tools.ietf.org/html/rfc3447#section-8.2
#[derive(Debug)]
pub struct PKCS1 {
    digest_alg: &'static digest::Algorithm,
    digestinfo_prefix: &'static [u8],
}

impl crate::sealed::Sealed for PKCS1 {}

impl Padding for PKCS1 {
    fn digest_alg(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }
}

#[cfg(feature = "alloc")]
impl RsaEncoding for PKCS1 {
    fn encode(
        &self,
        m_hash: digest::Digest,
        m_out: &mut [u8],
        _mod_bits: bits::BitLength,
        _rng: &dyn rand::SecureRandom,
    ) -> Result<(), error::Unspecified> {
        pkcs1_encode(&self, m_hash, m_out);
        Ok(())
    }
}

impl Verification for PKCS1 {
    fn verify(
        &self,
        m_hash: digest::Digest,
        m: &mut untrusted::Reader,
        mod_bits: bits::BitLength,
    ) -> Result<(), error::Unspecified> {
        // `mod_bits.as_usize_bytes_rounded_up() <=
        //      PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN` is ensured by `verify_rsa_()`.
        let mut calculated = [0u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN];
        let calculated = &mut calculated[..mod_bits.as_usize_bytes_rounded_up()];
        pkcs1_encode(&self, m_hash, calculated);
        if m.read_bytes_to_end() != *calculated {
            return Err(error::Unspecified);
        }
        Ok(())
    }
}

// Implement padding procedure per EMSA-PKCS1-v1_5,
// https://tools.ietf.org/html/rfc3447#section-9.2. This is used by both
// verification and signing so it needs to be able to handle moduli of the
// minimum and maximum sizes for both operations.
fn pkcs1_encode(pkcs1: &PKCS1, m_hash: digest::Digest, m_out: &mut [u8]) {
    let em = m_out;

    let digest_len = pkcs1.digestinfo_prefix.len() + pkcs1.digest_alg.output_len;

    // The specification requires at least 8 bytes of padding. Since we
    // disallow keys smaller than 1024 bits, this should always be true.
    assert!(em.len() >= digest_len + 11);
    let pad_len = em.len() - digest_len - 3;
    em[0] = 0;
    em[1] = 1;
    for i in 0..pad_len {
        em[2 + i] = 0xff;
    }
    em[2 + pad_len] = 0;

    let (digest_prefix, digest_dst) = em[3 + pad_len..].split_at_mut(pkcs1.digestinfo_prefix.len());
    digest_prefix.copy_from_slice(pkcs1.digestinfo_prefix);
    digest_dst.copy_from_slice(m_hash.as_ref());
}

macro_rules! rsa_pkcs1_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $digestinfo_prefix:expr,
      $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: PKCS1 = PKCS1 {
            digest_alg: $digest_alg,
            digestinfo_prefix: $digestinfo_prefix,
        };
    };
}

rsa_pkcs1_padding!(
    RSA_PKCS1_SHA1_FOR_LEGACY_USE_ONLY,
    &digest::SHA1_FOR_LEGACY_USE_ONLY,
    &SHA1_PKCS1_DIGESTINFO_PREFIX,
    "PKCS#1 1.5 padding using SHA-1 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA256,
    &digest::SHA256,
    &SHA256_PKCS1_DIGESTINFO_PREFIX,
    "PKCS#1 1.5 padding using SHA-256 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA384,
    &digest::SHA384,
    &SHA384_PKCS1_DIGESTINFO_PREFIX,
    "PKCS#1 1.5 padding using SHA-384 for RSA signatures."
);
rsa_pkcs1_padding!(
    RSA_PKCS1_SHA512,
    &digest::SHA512,
    &SHA512_PKCS1_DIGESTINFO_PREFIX,
    "PKCS#1 1.5 padding using SHA-512 for RSA signatures."
);

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
    SHA1_PKCS1_DIGESTINFO_PREFIX,
    20,
    5,
    [0x2b, 0x0e, 0x03, 0x02, 0x1a]
);

pkcs1_digestinfo_prefix!(
    SHA256_PKCS1_DIGESTINFO_PREFIX,
    32,
    9,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]
);

pkcs1_digestinfo_prefix!(
    SHA384_PKCS1_DIGESTINFO_PREFIX,
    48,
    9,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]
);

pkcs1_digestinfo_prefix!(
    SHA512_PKCS1_DIGESTINFO_PREFIX,
    64,
    9,
    [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]
);

/// RSA PSS padding as described in [RFC 3447 Section 8.1].
///
/// See "`RSA_PSS_*` Details\" in `ring::signature`'s module-level
/// documentation for more details.
///
/// [RFC 3447 Section 8.1]: https://tools.ietf.org/html/rfc3447#section-8.1
#[derive(Debug)]
pub struct PSS {
    digest_alg: &'static digest::Algorithm,
}

impl crate::sealed::Sealed for PSS {}

impl Padding for PSS {
    fn digest_alg(&self) -> &'static digest::Algorithm {
        self.digest_alg
    }
}

impl RsaEncoding for PSS {
    // Implement padding procedure per EMSA-PSS,
    // https://tools.ietf.org/html/rfc3447#section-9.1.
    fn encode(
        &self,
        m_hash: digest::Digest,
        m_out: &mut [u8],
        mod_bits: bits::BitLength,
        rng: &dyn rand::SecureRandom,
    ) -> Result<(), error::Unspecified> {
        let metrics = PSSMetrics::new(self.digest_alg, mod_bits)?;

        // The `m_out` this function fills is the big-endian-encoded value of `m`
        // from the specification, padded to `k` bytes, where `k` is the length
        // in bytes of the public modulus. The spec says "Note that emLen will
        // be one less than k if modBits - 1 is divisible by 8 and equal to k
        // otherwise." In other words we might need to prefix `em` with a
        // leading zero byte to form a correct value of `m`.
        let em = if metrics.top_byte_mask == 0xff {
            m_out[0] = 0;
            &mut m_out[1..]
        } else {
            m_out
        };
        assert_eq!(em.len(), metrics.em_len);

        // Steps 1 and 2 are done by the caller to produce `m_hash`.

        // Step 3 is done by `PSSMetrics::new()` above.

        {
            let (db, digest_terminator) = em.split_at_mut(metrics.db_len);
            let h;
            {
                let separator_pos = db.len() - 1 - metrics.s_len;

                // Step 4.
                let salt: &[u8] = {
                    let salt = &mut db[(separator_pos + 1)..];
                    rng.fill(salt)?; // salt
                    salt
                };

                // Step 5 and 6.
                h = pss_digest(self.digest_alg, m_hash, salt);

                // Step 7.
                polyfill::slice::fill(&mut db[..separator_pos], 0); // ps

                // Step 8.
                db[separator_pos] = 0x01;
            };

            // Steps 9 and 10.
            mgf1(self.digest_alg, h.as_ref(), db);

            // Step 11.
            db[0] &= metrics.top_byte_mask;

            // Step 12.
            digest_terminator[..metrics.h_len].copy_from_slice(h.as_ref());
            digest_terminator[metrics.h_len] = 0xbc;
        }

        // Step 12.

        Ok(())
    }
}

impl Verification for PSS {
    // RSASSA-PSS-VERIFY from https://tools.ietf.org/html/rfc3447#section-8.1.2
    // where steps 1, 2(a), and 2(b) have been done for us.
    fn verify(
        &self,
        m_hash: digest::Digest,
        m: &mut untrusted::Reader,
        mod_bits: bits::BitLength,
    ) -> Result<(), error::Unspecified> {
        let metrics = PSSMetrics::new(self.digest_alg, mod_bits)?;

        // RSASSA-PSS-VERIFY Step 2(c). The `m` this function is given is the
        // big-endian-encoded value of `m` from the specification, padded to
        // `k` bytes, where `k` is the length in bytes of the public modulus.
        // The spec. says "Note that emLen will be one less than k if
        // modBits - 1 is divisible by 8 and equal to k otherwise," where `k`
        // is the length in octets of the RSA public modulus `n`. In other
        // words, `em` might have an extra leading zero byte that we need to
        // strip before we start the PSS decoding steps which is an artifact of
        // the `Verification` interface.
        if metrics.top_byte_mask == 0xff {
            if m.read_byte()? != 0 {
                return Err(error::Unspecified);
            }
        };
        let em = m;

        // The rest of this function is EMSA-PSS-VERIFY from
        // https://tools.ietf.org/html/rfc3447#section-9.1.2.

        // Steps 1 and 2 are done by the caller to produce `m_hash`.

        // Step 3 is done by `PSSMetrics::new()` above.

        // Step 5, out of order.
        let masked_db = em.read_bytes(metrics.db_len)?;
        let h_hash = em.read_bytes(metrics.h_len)?;

        // Step 4.
        if em.read_byte()? != 0xbc {
            return Err(error::Unspecified);
        }

        // Step 7.
        let mut db = [0u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN];
        let db = &mut db[..metrics.db_len];

        mgf1(self.digest_alg, h_hash.as_slice_less_safe(), db);

        masked_db.read_all(error::Unspecified, |masked_bytes| {
            // Step 6. Check the top bits of first byte are zero.
            let b = masked_bytes.read_byte()?;
            if b & !metrics.top_byte_mask != 0 {
                return Err(error::Unspecified);
            }
            db[0] ^= b;

            // Step 8.
            for i in 1..db.len() {
                db[i] ^= masked_bytes.read_byte()?;
            }
            Ok(())
        })?;

        // Step 9.
        db[0] &= metrics.top_byte_mask;

        // Step 10.
        let ps_len = metrics.ps_len;
        for i in 0..ps_len {
            if db[i] != 0 {
                return Err(error::Unspecified);
            }
        }
        if db[metrics.ps_len] != 1 {
            return Err(error::Unspecified);
        }

        // Step 11.
        let salt = &db[(db.len() - metrics.s_len)..];

        // Step 12 and 13.
        let h_prime = pss_digest(self.digest_alg, m_hash, salt);

        // Step 14.
        if h_hash != *h_prime.as_ref() {
            return Err(error::Unspecified);
        }

        Ok(())
    }
}

struct PSSMetrics {
    #[cfg_attr(not(feature = "alloc"), allow(dead_code))]
    em_len: usize,
    db_len: usize,
    ps_len: usize,
    s_len: usize,
    h_len: usize,
    top_byte_mask: u8,
}

impl PSSMetrics {
    fn new(
        digest_alg: &'static digest::Algorithm,
        mod_bits: bits::BitLength,
    ) -> Result<Self, error::Unspecified> {
        let em_bits = mod_bits.try_sub_1()?;
        let em_len = em_bits.as_usize_bytes_rounded_up();
        let leading_zero_bits = (8 * em_len) - em_bits.as_usize_bits();
        debug_assert!(leading_zero_bits < 8);
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
        let db_len = em_len.checked_sub(1 + s_len).ok_or(error::Unspecified)?;
        let ps_len = db_len.checked_sub(h_len + 1).ok_or(error::Unspecified)?;

        debug_assert!(em_bits.as_usize_bits() >= (8 * h_len) + (8 * s_len) + 9);

        Ok(Self {
            em_len,
            db_len,
            ps_len,
            s_len,
            h_len,
            top_byte_mask,
        })
    }
}

// Mask-generating function MGF1 as described in
// https://tools.ietf.org/html/rfc3447#appendix-B.2.1.
fn mgf1(digest_alg: &'static digest::Algorithm, seed: &[u8], mask: &mut [u8]) {
    let digest_len = digest_alg.output_len;

    // Maximum counter value is the value of (mask_len / digest_len) rounded up.
    for (i, mask_chunk) in mask.chunks_mut(digest_len).enumerate() {
        let mut ctx = digest::Context::new(digest_alg);
        ctx.update(seed);
        // The counter will always fit in a `u32` because we reject absurdly
        // long inputs very early.
        ctx.update(&u32::to_be_bytes(i.try_into().unwrap()));
        let digest = ctx.finish();
        for (m, &d) in mask_chunk.iter_mut().zip(digest.as_ref().iter()) {
            *m ^= d;
        }
    }
}

fn pss_digest(
    digest_alg: &'static digest::Algorithm,
    m_hash: digest::Digest,
    salt: &[u8],
) -> digest::Digest {
    // Fixed prefix.
    const PREFIX_ZEROS: [u8; 8] = [0u8; 8];

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
        pub static $PADDING_ALGORITHM: PSS = PSS {
            digest_alg: $digest_alg,
        };
    };
}

rsa_pss_padding!(
    RSA_PSS_SHA256,
    &digest::SHA256,
    "RSA PSS padding using SHA-256 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA384,
    &digest::SHA384,
    "RSA PSS padding using SHA-384 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);
rsa_pss_padding!(
    RSA_PSS_SHA512,
    &digest::SHA512,
    "RSA PSS padding using SHA-512 for RSA signatures.\n\nSee
                 \"`RSA_PSS_*` Details\" in `ring::signature`'s module-level
                 documentation for more details."
);

/// RSA OAEP encoding parameters.
#[derive(Debug, PartialEq, Eq)]
pub struct OaepEncoding {
    digest_alg: &'static digest::Algorithm,
}

impl crate::sealed::Sealed for OaepEncoding {}
impl super::Bounds for OaepEncoding {
    fn n_min_bits(&self) -> bits::BitLength {
        bits::BitLength::from_usize_bits(2048)
    }

    fn n_max_bits(&self) -> bits::BitLength {
        bits::BitLength::from_usize_bits(8192)
    }

    fn e_min_value(&self) -> u64 {
        65537
    }
}

macro_rules! rsa_oaep_padding {
    ( $PADDING_ALGORITHM:ident, $digest_alg:expr, $doc_str:expr ) => {
        #[doc=$doc_str]
        pub static $PADDING_ALGORITHM: OaepEncoding = OaepEncoding {
            digest_alg: $digest_alg,
        };
    };
}

// TODO: improve doc comments.
rsa_oaep_padding!(
    RSA_OAEP_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    &digest::SHA1_FOR_LEGACY_USE_ONLY,
    "RSA OAEP using SHA-1."
);
rsa_oaep_padding!(
    RSA_OAEP_2048_8192_SHA256,
    &digest::SHA256,
    "RSA OAEP using SHA-256."
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::{digest, error, test};
    use alloc::vec;

    #[test]
    fn test_pss_padding_verify() {
        test::run(
            test_file!("rsa_pss_padding_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let digest_name = test_case.consume_string("Digest");
                let alg = match digest_name.as_ref() {
                    "SHA256" => &RSA_PSS_SHA256,
                    "SHA384" => &RSA_PSS_SHA384,
                    "SHA512" => &RSA_PSS_SHA512,
                    _ => panic!("Unsupported digest: {}", digest_name),
                };

                let msg = test_case.consume_bytes("Msg");
                let msg = untrusted::Input::from(&msg);
                let m_hash = digest::digest(alg.digest_alg(), msg.as_slice_less_safe());

                let encoded = test_case.consume_bytes("EM");
                let encoded = untrusted::Input::from(&encoded);

                // Salt is recomputed in verification algorithm.
                let _ = test_case.consume_bytes("Salt");

                let bit_len = test_case.consume_usize_bits("Len");
                let is_valid = test_case.consume_string("Result") == "P";

                let actual_result =
                    encoded.read_all(error::Unspecified, |m| alg.verify(m_hash, m, bit_len));
                assert_eq!(actual_result.is_ok(), is_valid);

                Ok(())
            },
        );
    }

    // Tests PSS encoding for various public modulus lengths.
    #[cfg(feature = "alloc")]
    #[test]
    fn test_pss_padding_encode() {
        test::run(
            test_file!("rsa_pss_padding_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let digest_name = test_case.consume_string("Digest");
                let alg = match digest_name.as_ref() {
                    "SHA256" => &RSA_PSS_SHA256,
                    "SHA384" => &RSA_PSS_SHA384,
                    "SHA512" => &RSA_PSS_SHA512,
                    _ => panic!("Unsupported digest: {}", digest_name),
                };

                let msg = test_case.consume_bytes("Msg");
                let salt = test_case.consume_bytes("Salt");
                let encoded = test_case.consume_bytes("EM");
                let bit_len = test_case.consume_usize_bits("Len");
                let expected_result = test_case.consume_string("Result");

                // Only test the valid outputs
                if expected_result != "P" {
                    return Ok(());
                }

                let rng = test::rand::FixedSliceRandom { bytes: &salt };

                let mut m_out = vec![0u8; bit_len.as_usize_bytes_rounded_up()];
                let digest = digest::digest(alg.digest_alg(), &msg);
                alg.encode(digest, &mut m_out, bit_len, &rng).unwrap();
                assert_eq!(m_out, encoded);

                Ok(())
            },
        );
    }
}

pub(in crate::rsa) fn oaep_decode<'in_out>(
    encoding: &'static OaepEncoding,
    in_out: &'in_out mut [u8],
    mod_bits: bits::BitLength,
) -> Result<&'in_out [u8], error::Unspecified> {
    const L: &[u8] = &[];
    let h_len = encoding.digest_alg.output_len;
    let k = mod_bits.as_usize_bytes_rounded_up();

    // 1.a. is implicit given we don't support a non-empty `L`.

    // 1.b
    if in_out.len() != k {
        return Err(error::Unspecified);
    }

    // 1.c
    if k < (2 * h_len) + 2 {
        return Err(error::Unspecified);
    }

    // 3.a.
    let l_hash = digest::digest(&encoding.digest_alg, L); // TODO: precompute

    // 3.b.
    let (y, rest) = in_out.split_at_mut(1);
    let y = y[0];
    let (seed, db) = rest.split_at_mut(h_len);

    // 3.c and 3.d
    mgf1(&encoding.digest_alg, db, seed);

    // 3.e. and 3.f.
    mgf1(&encoding.digest_alg, seed, db);

    prefixed_extern! {
        fn RSA_padding_check_oaep(
            out_len: &mut crate::c::size_t,
            y: u8,
            db: *const u8,
            db_len: crate::c::size_t,
            phash: *const u8,
            mdlen: crate::c::size_t,
        ) -> crate::bssl::Result;
    }

    let mut plaintext_len: crate::c::size_t = 0;
    Result::from(unsafe {
        RSA_padding_check_oaep(
            &mut plaintext_len,
            y,
            db.as_ptr(),
            db.len(),
            l_hash.as_ref().as_ptr(),
            l_hash.as_ref().len(),
        )
    })?;
    let plaintext_start = db.len() - plaintext_len;

    Ok(&db[plaintext_start..]) // TODo
}

#[cfg(feature = "alloc")]
pub fn oaep_encode(
    encoding: &'static OaepEncoding,
    plaintext: &[u8],
    mod_bits: bits::BitLength,
    rng: &dyn rand::SecureRandom,
) -> Result<Box<[u8]>, error::Unspecified> {
    const L: &[u8] = &[];
    let k = mod_bits.as_usize_bytes_rounded_up();
    let h_len = encoding.digest_alg.output_len;

    // 1.a is implicitly done since `L` is fixed.

    // 1.b
    if plaintext.len() > k - (2 * h_len) - 2 {
        return Err(error::Unspecified);
    }

    let mut em = vec![0u8; k].into_boxed_slice();
    {
        let (zero, rest) = em.split_at_mut(1);
        debug_assert_eq!(zero, &[0]);
        let (seed, db) = rest.split_at_mut(h_len);
        let (l_hash, rest) = db.split_at_mut(h_len);
        l_hash.copy_from_slice(digest::digest(&encoding.digest_alg, L).as_ref());
        let m_index = rest.len() - plaintext.len();
        let (ps, rest) = rest.split_at_mut(m_index - 1);
        debug_assert!(ps.iter().all(|&b| b == 0));

        rest[0] = 0x01;
        rest[1..].copy_from_slice(plaintext);

        // 2.d
        rng.fill(seed)?;

        // 2.e and 2.f
        mgf1(&encoding.digest_alg, seed, db);

        // 2.g and 2.h
        mgf1(&encoding.digest_alg, db, seed);
    }

    Ok(em)
}
