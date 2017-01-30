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

//! Authenticated Encryption with Associated Data (AEAD).
//!
//! See [Authenticated encryption: relations among notions and analysis of the
//! generic composition paradigm][AEAD] for an introduction to the concept of
//! AEADs.
//!
//! C analog: `openssl/aead.h`
//!
//! Go analog: [`crypto.cipher.AEAD`]
//!
//! [AEAD]: http://www-cse.ucsd.edu/~mihir/papers/oem.html
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD

pub mod chacha20_poly1305_openssh;

mod chacha20_poly1305;
mod aes_gcm;

use {constant_time, error, init, poly1305, polyfill};

pub use self::chacha20_poly1305::CHACHA20_POLY1305;
pub use self::aes_gcm::{AES_128_GCM, AES_256_GCM};

/// A key for authenticating and decrypting (“opening”) AEAD-protected data.
///
/// C analog: `EVP_AEAD_CTX` with direction `evp_aead_open`
///
/// Go analog: [`crypto.cipher.AEAD`]
pub struct OpeningKey {
    key: Key,
}

impl OpeningKey {
    /// Create a new opening key.
    ///
    /// `key_bytes` must be exactly `algorithm.key_len` bytes long.
    ///
    /// C analogs: `EVP_AEAD_CTX_init_with_direction` with direction
    ///            `evp_aead_open`, `EVP_AEAD_CTX_init`.
    ///
    /// Go analog:
    ///   [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8])
               -> Result<OpeningKey, error::Unspecified> {
        let mut key = OpeningKey {
            key: Key {
                algorithm: algorithm,
                ctx_buf: [0; KEY_CTX_BUF_ELEMS],
            },
        };
        try!(key.key.init(key_bytes));
        Ok(key)
    }

    /// The key's AEAD algorithm.
    ///
    /// C analog: `EVP_AEAD_CTX.aead`
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.key.algorithm() }
}

/// Authenticates and decrypts (“opens”) data in place. When
///
/// `nonce` must be unique for every use of the key to seal data; it must be
/// exactly `key.algorithm().nonce_len()` bytes long. `ad` is the additional
/// authenticated data, which won't be encrypted; it may be empty. The last
/// `key.algorithm().tag_len()` bytes of `ciphertext_and_tag_modified_in_place`
/// must be the tag. The part of `ciphertext_and_tag_modified_in_place` before
/// the tag is the input ciphertext; it may be empty.
///
/// When `open_in_place()` returns `Ok(plaintext)`, the decrypted output is
/// `plaintext`, which is
/// `&mut ciphertext_and_tag_modified_in_place[..plaintext.len()]`. That is,
/// the output plaintext overwrites the ciphertext.
///
/// When `open_in_place()` returns `Err(..)`,
/// `ciphertext_and_tag_modified_in_place` may have been overwritten in an
/// unspecified way.
///
/// C analog: `EVP_AEAD_CTX_open`
///
/// Go analog: [`AEAD.Open`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn open_in_place<'a>(key: &OpeningKey, nonce: &[u8], ad: &[u8],
                         ciphertext_and_tag_modified_in_place: &'a mut [u8])
                         -> Result<&'a mut [u8], error::Unspecified> {
    let nonce = try!(slice_as_array_ref!(nonce, NONCE_LEN));
    let ciphertext_len =
        try!(ciphertext_and_tag_modified_in_place.len()
                .checked_sub(TAG_LEN).ok_or(error::Unspecified));
    try!(check_per_nonce_max_bytes(ciphertext_len));
    let (ciphertext_in_plaintext_out, received_tag) =
        ciphertext_and_tag_modified_in_place.split_at_mut(ciphertext_len);
    let mut calculated_tag = [0u8; TAG_LEN];
    try!((key.key.algorithm.open)(&key.key.ctx_buf, nonce, &ad,
                                  ciphertext_in_plaintext_out,
                                  &mut calculated_tag));
    if constant_time::verify_slices_are_equal(&calculated_tag, received_tag)
            .is_err() {
        // Zero out the plaintext so that it isn't accidentally leaked or used
        // after verification fails. It would be safest if we could check the
        // tag before decrypting, but some `open` implementations interleave
        // authentication with decryption for performance.
        for b in ciphertext_in_plaintext_out {
            *b = 0;
        }
        return Err(error::Unspecified);
    }
    // `ciphertext_len` is also the plaintext length.
    Ok(ciphertext_in_plaintext_out)
}

/// A key for encrypting and signing (“sealing”) data.
///
/// C analog: `EVP_AEAD_CTX` with direction `evp_aead_seal`.
///
/// Go analog: [`AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub struct SealingKey {
    key: Key,
}

impl SealingKey {
    /// C analogs: `EVP_AEAD_CTX_init_with_direction` with direction
    ///            `evp_aead_seal`, `EVP_AEAD_CTX_init`.
    ///
    /// Go analog:
    ///   [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8])
               -> Result<SealingKey, error::Unspecified> {
        let mut key = SealingKey {
            key: Key {
                algorithm: algorithm,
                ctx_buf: [0; KEY_CTX_BUF_ELEMS],
            },
        };
        try!(key.key.init(key_bytes));
        Ok(key)
    }

    /// The key's AEAD algorithm.
    ///
    /// C analog: `EVP_AEAD_CTX.aead`
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.key.algorithm() }
}

/// Encrypts and signs (“seals”) data in place.
///
/// `nonce` must be unique for every use of the key to seal data; it must be
/// exactly `key.algorithm().nonce_len()` bytes long. `ad` is the additional
/// authenticated data, which won't be encrypted; it may be empty.
/// `plaintext_in_ciphertext_out` must contain the plaintext to encrypt on
/// input and will contain the ciphertext on successful output; it may be
/// empty. `tag_out` must be exactly `key.algorithm().tag_len()` bytes long and
/// will contain the tag on output.
///
/// C analog: `EVP_AEAD_CTX_seal`.
///
/// Go analog: [`AEAD.Seal`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn seal_in_place(key: &SealingKey, nonce: &[u8], ad: &[u8],
                     plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8])
                     -> Result<(), error::Unspecified> {
    let nonce = try!(slice_as_array_ref!(nonce, NONCE_LEN));
    let tag_out = try!(slice_as_array_ref_mut!(tag_out, TAG_LEN));
    try!(check_per_nonce_max_bytes(plaintext_in_ciphertext_out.len()));
    (key.key.algorithm.seal)(&key.key.ctx_buf, nonce, ad,
                             plaintext_in_ciphertext_out, tag_out)
}

/// `OpeningKey` and `SealingKey` are type-safety wrappers around `Key`, which
/// does all the actual work via the C AEAD interface.
///
/// C analog: `EVP_AEAD_CTX`
struct Key {
    ctx_buf: [u64; KEY_CTX_BUF_ELEMS],
    algorithm: &'static Algorithm,
}

// TODO: Implement Drop for Key that zeroizes the key data?

const KEY_CTX_BUF_ELEMS: usize = (KEY_CTX_BUF_LEN + 7) / 8;

// Keep this in sync with `aead_aes_gcm_ctx` in e_aes.c.
const KEY_CTX_BUF_LEN: usize = self::aes_gcm::AES_KEY_CTX_BUF_LEN;

impl Key {
    /// XXX: Assumes self.algorithm is already filled in.
    ///
    /// C analogs: `EVP_AEAD_CTX_init`, `EVP_AEAD_CTX_init_with_direction`
    fn init(&mut self, key_bytes: &[u8]) -> Result<(), error::Unspecified> {
        init::init_once();

        if key_bytes.len() != self.algorithm.key_len() {
            return Err(error::Unspecified);
        }

        let ctx_buf_bytes = polyfill::slice::u64_as_u8_mut(&mut self.ctx_buf);
        (self.algorithm.init)(ctx_buf_bytes, key_bytes)
    }

    /// The key's AEAD algorithm.
    #[inline(always)]
    fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

/// An AEAD Algorithm.
///
/// C analog: `EVP_AEAD`
///
/// Go analog:
///     [`crypto.cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub struct Algorithm {
    init: fn(ctx_buf: &mut [u8], key: &[u8]) -> Result<(), error::Unspecified>,

    seal: fn(ctx: &[u64; KEY_CTX_BUF_ELEMS], nonce: &[u8; NONCE_LEN], ad: &[u8],
             plaintext_in_ciphertext_out: &mut [u8],
             tag_out: &mut [u8; TAG_LEN]) -> Result<(), error::Unspecified>,
    open: fn(ctx: &[u64; KEY_CTX_BUF_ELEMS], nonce: &[u8; NONCE_LEN], ad: &[u8],
             ciphertext_in_plaintext_out: &mut [u8],
             tag_out: &mut [u8; TAG_LEN]) -> Result<(), error::Unspecified>,

    key_len: usize,
}

impl Algorithm {
    /// The length of the key.
    ///
    /// C analog: `EVP_AEAD_key_length`
    #[inline(always)]
    pub fn key_len(&self) -> usize { self.key_len }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    ///
    /// C analog: `EVP_AEAD_max_overhead`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.Overhead`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn tag_len(&self) -> usize { TAG_LEN }

    /// The length of the nonces.
    ///
    /// C analog: `EVP_AEAD_nonce_length`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.NonceSize`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn nonce_len(&self) -> usize { NONCE_LEN }
}


/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = poly1305::TAG_LEN;

// All the AEADs we support use 96-bit nonces.
const NONCE_LEN: usize = 96 / 8;


/// |GFp_chacha_20| uses a 32-bit block counter, so we disallow individual
/// operations that work on more than 256GB at a time, for all AEADs.
fn check_per_nonce_max_bytes(in_out_len: usize)
                             -> Result<(), error::Unspecified> {
    if polyfill::u64_from_usize(in_out_len) >= (1u64 << 32) * 64 - 64 {
        return Err(error::Unspecified);
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::super::{aead, error, test};
    use std::vec::Vec;

    pub fn test_aead(aead_alg: &'static aead::Algorithm, file_path: &str) {
        test_aead_key_sizes(aead_alg);
        test_aead_nonce_sizes(aead_alg).unwrap();

        test::from_file(file_path, |section, test_case| {
            assert_eq!(section, "");
            let key_bytes = test_case.consume_bytes("KEY");
            let nonce = test_case.consume_bytes("NONCE");
            let plaintext = test_case.consume_bytes("IN");
            let ad = test_case.consume_bytes("AD");
            let mut ct = test_case.consume_bytes("CT");
            let tag = test_case.consume_bytes("TAG");
            let error = test_case.consume_optional_string("FAILS");

            let tag_len = aead_alg.tag_len();
            let mut s_in_out_with_tag = plaintext.clone();
            for _ in 0..tag_len {
                s_in_out_with_tag.push(0);
            }
            let s_result = {
                let (s_in_out, s_tag) =
                    s_in_out_with_tag.split_at_mut(plaintext.len());
                let s_key =
                    try!(aead::SealingKey::new(aead_alg, &key_bytes[..]));
                aead::seal_in_place(&s_key, &nonce[..], &ad, s_in_out, s_tag)
            };
            match error {
                None => {
                    assert_eq!(Ok(()), s_result);
                    assert_eq!(&ct[..], &s_in_out_with_tag[..ct.len()]);
                },
                Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                    assert_eq!(Err(error::Unspecified), s_result);
                },
                Some(error) => {
                    unreachable!("Unexpected error test case: {}", error);
                },
            }

            let o_key = try!(aead::OpeningKey::new(aead_alg, &key_bytes[..]));

            ct.extend(tag);

            let mut o_in_out = ct.clone();
            let o_result = aead::open_in_place(&o_key, &nonce[..], &ad,
                                               &mut o_in_out[..]);
            match error {
                None => {
                    assert_eq!(&plaintext[..], o_result.unwrap());
                },
                Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                    assert_eq!(Err(error::Unspecified), o_result);
                },
                Some(error) => {
                    unreachable!("Unexpected error test case: {}", error);
                },
            };

            Ok(())
        });
    }

    fn test_aead_key_sizes(aead_alg: &'static aead::Algorithm) {
        let key_len = aead_alg.key_len();
        let key_data = vec![0u8; key_len * 2];

        // Key is the right size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[..key_len]).is_ok());
        assert!(aead::SealingKey::new(aead_alg, &key_data[..key_len]).is_ok());

        // Key is one byte too small.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[..(key_len - 1)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[..(key_len - 1)])
                    .is_err());

        // Key is one byte too large.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[..(key_len + 1)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[..(key_len + 1)])
                    .is_err());

        // Key is half the required size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[..(key_len / 2)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[..(key_len / 2)])
                    .is_err());

        // Key is twice the required size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[..(key_len * 2)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[..(key_len * 2)])
                    .is_err());

        // Key is empty.
        assert!(aead::OpeningKey::new(aead_alg, &[]).is_err());
        assert!(aead::SealingKey::new(aead_alg, &[]).is_err());

        // Key is one byte.
        assert!(aead::OpeningKey::new(aead_alg, &[0]).is_err());
        assert!(aead::SealingKey::new(aead_alg, &[0]).is_err());
    }

    // Test that we reject non-standard nonce sizes.
    //
    // XXX: This test isn't that great in terms of how it tests
    // `open_in_place`. It should be constructing a valid ciphertext using the
    // unsupported nonce size using a different implementation that supports
    // non-standard nonce sizes. So, when `open_in_place` returns
    // `Err(error::Unspecified)`, we don't know if it is because it rejected
    // the non-standard nonce size or because it tried to process the input
    // with the wrong nonce. But at least we're verifying that `open_in_place`
    // won't crash or access out-of-bounds memory (when run under valgrind or
    // similar). The AES-128-GCM tests have some WRONG_NONCE_LENGTH test cases
    // that tests this more correctly.
    fn test_aead_nonce_sizes(aead_alg: &'static aead::Algorithm)
                             -> Result<(), error::Unspecified> {
        let key_len = aead_alg.key_len;
        let key_data = vec![0u8; key_len];
        let o_key = try!(aead::OpeningKey::new(aead_alg, &key_data[..key_len]));
        let s_key = try!(aead::SealingKey::new(aead_alg, &key_data[..key_len]));

        let nonce_len = aead_alg.nonce_len();

        let nonce = vec![0u8; nonce_len * 2];

        let tag_len = aead_alg.tag_len();
        let ad: [u8; 0] = [];

        // Construct a template input for `seal_in_place`.
        let mut to_seal = b"hello, world".to_vec();
        // Reserve space for tag.
        for _ in 0..tag_len {
            to_seal.push(0);
        }
        let to_seal = &b"hello, world";

        // Construct a template input for `open_in_place`.
        let to_open = {
            let mut to_open = Vec::from(&to_seal[..]);
            // Reserve space for tag.
            for _ in 0..tag_len {
                to_open.push(0);
            }
            {
                let (s_in_out, s_tag) = to_open.split_at_mut(to_seal.len());
                try!(aead::seal_in_place(&s_key, &nonce[..nonce_len], &ad,
                                         s_in_out, s_tag));
            }
            to_open
        };

        // Nonce is the correct length.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..nonce_len], &ad,
                                        s_in_out, s_tag).is_ok());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..nonce_len], &ad,
                                        &mut in_out).is_ok());
        }

        // Nonce is one byte too small.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len - 1)], &ad,
                                        s_in_out, s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len - 1)], &ad,
                                        &mut in_out).is_err());
        }

        // Nonce is one byte too large.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len + 1)], &ad,
                                        s_in_out, s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len + 1)], &ad,
                                        &mut in_out).is_err());
        }

        // Nonce is half the required size.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len / 2)], &ad,
                                        s_in_out, s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len / 2)], &ad,
                                        &mut in_out).is_err());
        }

        // Nonce is twice the required size.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len * 2)], &ad,
                                        s_in_out, s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len * 2)], &ad,
                                        &mut in_out).is_err());
        }

        // Nonce is empty.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &[], &ad, s_in_out, s_tag)
                        .is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &[], &ad, &mut in_out)
                        .is_err());
        }

        // Nonce is one byte.
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..1], &ad, s_in_out,
                                        s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..1], &ad, &mut in_out)
                        .is_err());
        }

        // Nonce is 128 bits (16 bytes).
        {
            let mut in_out = to_open.clone();
            let (s_in_out, s_tag) = in_out.split_at_mut(to_seal.len());
            assert!(aead::seal_in_place(&s_key, &nonce[..16], &ad, s_in_out,
                                        s_tag).is_err());
        }
        {
            let mut in_out = to_open.clone();
            assert!(aead::open_in_place(&o_key, &nonce[..16], &ad, &mut in_out)
                        .is_err());
        }

        Ok(())
    }
}
