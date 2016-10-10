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

/// A key for authenticating and decrypting (&ldquo;opening&rdquo;)
/// AEAD-protected data.
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

/// Authenticates and decrypts (&ldquo;opens&rdquo;) data in place.
///
/// The input is `in_out[in_prefix_len..]`; i.e. the input is the part of
/// `in_out` after the prefix. When `open` returns `Ok(out_len)`, the decrypted
/// output is `in_out[..out_len]`; i.e. the output has been written over the
/// top of the prefix and the input. To put it a different way, the output
/// overwrites the input, shifted by `in_prefix_len` bytes. To have the output
/// overwrite the input without shifting, pass 0 as `in_prefix_len`. (The
/// input/output buffer is expressed this way because Rust's type system does
/// not allow us to have two slices, one mutable and one immutable, that
/// reference overlapping memory at the same time.)
///
/// C analog: `EVP_AEAD_CTX_open`
///
/// Go analog: [`AEAD.Open`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn open_in_place(key: &OpeningKey, nonce: &[u8], in_prefix_len: usize,
                     in_out: &mut [u8], ad: &[u8])
                     -> Result<usize, error::Unspecified> {
    let nonce = try!(slice_as_array_ref!(nonce, NONCE_LEN));
    let ciphertext_and_tag_len =
        try!(in_out.len().checked_sub(in_prefix_len)
                         .ok_or(error::Unspecified));
    let ciphertext_len =
        try!(ciphertext_and_tag_len.checked_sub(TAG_LEN)
                                   .ok_or(error::Unspecified));
    try!(check_per_nonce_max_bytes(ciphertext_len));
    let (in_out, received_tag) =
        in_out.split_at_mut(in_prefix_len + ciphertext_len);
    let mut calculated_tag = [0u8; TAG_LEN];
    try!((key.key.algorithm.open)(&key.key.ctx_buf, nonce, in_out,
                                  in_prefix_len, &mut calculated_tag, ad));
    try!(constant_time::verify_slices_are_equal(&calculated_tag, received_tag));
    Ok(ciphertext_len) // `ciphertext_len` is also the plaintext length.
}

/// A key for encrypting and signing (&ldquo;sealing&rdquo;) data.
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

/// Encrypts and signs (&ldquo;seals&rdquo;) data in place.
///
/// `nonce` must be unique for every use of the key to seal data.
///
/// The input is `in_out[..(in_out.len() - out_suffix_capacity)]`; i.e. the
/// input is the part of `in_out` that precedes the suffix. When `seal` returns
/// `Ok(out_len)`, the encrypted and signed output is `in_out[..out_len]`; i.e.
/// the output has been written over input and at least part of the data
/// reserved for the suffix. (The input/output buffer is expressed this way
/// because Rust's type system does not allow us to have two slices, one
/// mutable and one immutable, that reference overlapping memory at the same
/// time.)
///
/// `out_suffix_capacity` must be at least `key.algorithm.max_overhead_len()`.
/// See also `MAX_OVERHEAD_LEN`.
///
/// `ad` is the additional authenticated data, if any.
///
/// C analog: `EVP_AEAD_CTX_seal`.
///
/// Go analog: [`AEAD.Seal`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn seal_in_place(key: &SealingKey, nonce: &[u8], in_out: &mut [u8],
                     out_suffix_capacity: usize, ad: &[u8])
                     -> Result<usize, error::Unspecified> {
    if out_suffix_capacity < key.key.algorithm.max_overhead_len() {
        return Err(error::Unspecified);
    }
    let nonce = try!(slice_as_array_ref!(nonce, NONCE_LEN));
    let in_out_len =
        try!(in_out.len().checked_sub(out_suffix_capacity)
                         .ok_or(error::Unspecified));
    try!(check_per_nonce_max_bytes(in_out_len));
    let (in_out, tag_out) = in_out.split_at_mut(in_out_len);
    let tag_out = try!(slice_as_array_ref_mut!(tag_out, TAG_LEN));
    try!((key.key.algorithm.seal)(&key.key.ctx_buf, nonce, in_out, tag_out, ad));
    Ok(in_out_len + TAG_LEN)
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

    seal: fn(ctx: &[u64; KEY_CTX_BUF_ELEMS], nonce: &[u8; NONCE_LEN],
              in_out: &mut [u8], tag_out: &mut [u8; TAG_LEN], ad: &[u8])
              -> Result<(), error::Unspecified>,
    open: fn(ctx: &[u64; KEY_CTX_BUF_ELEMS], nonce: &[u8; NONCE_LEN],
             in_out: &mut [u8], in_prefix_len: usize,
             tag_out: &mut [u8; TAG_LEN], ad: &[u8])
             -> Result<(), error::Unspecified>,

    key_len: usize,
}

impl Algorithm {
    /// The length of the key.
    ///
    /// C analog: `EVP_AEAD_key_length`
    #[inline(always)]
    pub fn key_len(&self) -> usize { self.key_len }

    /// The maximum number of bytes that sealing operations may add to plaintexts.
    /// See also `MAX_OVERHEAD_LEN`.
    ///
    /// C analog: `EVP_AEAD_max_overhead`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.Overhead`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn max_overhead_len(&self) -> usize { TAG_LEN }

    /// The length of the nonces.
    ///
    /// C analog: `EVP_AEAD_nonce_length`
    ///
    /// Go analog:
    ///   [`crypto.cipher.AEAD.NonceSize`](https://golang.org/pkg/crypto/cipher/#AEAD)
    #[inline(always)]
    pub fn nonce_len(&self) -> usize { NONCE_LEN }
}


/// The maximum amount of overhead for the algorithms in this module.
pub const MAX_OVERHEAD_LEN: usize = TAG_LEN;

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

            let max_overhead_len = aead_alg.max_overhead_len();
            let mut s_in_out = plaintext.clone();
            for _ in 0..max_overhead_len {
                s_in_out.push(0);
            }
            let s_key = try!(aead::SealingKey::new(aead_alg, &key_bytes[..]));
            let s_result = aead::seal_in_place(&s_key, &nonce[..],
                                               &mut s_in_out[..],
                                               max_overhead_len, &ad);
            let o_key = try!(aead::OpeningKey::new(aead_alg, &key_bytes[..]));

            ct.extend(tag);

            // In release builds, test all prefix lengths from 0 to 4096 bytes.
            // Debug builds are too slow for this, so for those builds, only
            // test a smaller subset.

            // TLS record headers are 5 bytes long.
            // TLS explicit nonces for AES-GCM are 8 bytes long.
            static MINIMAL_IN_PREFIX_LENS: [usize; 36] = [
                // No input prefix to overwrite; i.e. the opening is exactly
                // "in place."
                0,

                1,
                2,

                // Proposed TLS 1.3 header (no explicit nonce).
                5,

                8,

                // Probably the most common use of a non-zero `in_prefix_len`
                // would be to write a decrypted TLS record over the top of the
                // TLS header and nonce.
                5 /* record header */ + 8 /* explicit nonce */,

                // The stitched AES-GCM x86-64 code works on 6-block (96 byte)
                // units. Some of the ChaCha20 code is even weirder.

                15, // The maximum partial AES block.
                16, // One AES block.
                17, // One byte more than a full AES block.

                31, // 2 AES blocks or 1 ChaCha20 block, minus 1.
                32, // Two AES blocks, one ChaCha20 block.
                33, // 2 AES blocks or 1 ChaCha20 block, plus 1.

                47, // Three AES blocks - 1.
                48, // Three AES blocks.
                49, // Three AES blocks + 1.

                63, // Four AES blocks or two ChaCha20 blocks, minus 1.
                64, // Four AES blocks or two ChaCha20 blocks.
                65, // Four AES blocks or two ChaCha20 blocks, plus 1.

                79, // Five AES blocks, minus 1.
                80, // Five AES blocks.
                81, // Five AES blocks, plus 1.

                95, // Six AES blocks or three ChaCha20 blocks, minus 1.
                96, // Six AES blocks or three ChaCha20 blocks.
                97, // Six AES blocks or three ChaCha20 blocks, plus 1.

                111, // Seven AES blocks, minus 1.
                112, // Seven AES blocks.
                113, // Seven AES blocks, plus 1.

                127, // Eight AES blocks or four ChaCha20 blocks, minus 1.
                128, // Eight AES blocks or four ChaCha20 blocks.
                129, // Eight AES blocks or four ChaCha20 blocks, plus 1.

                143, // Nine AES blocks, minus 1.
                144, // Nine AES blocks.
                145, // Nine AES blocks, plus 1.

                255, // 16 AES blocks or 8 ChaCha20 blocks, minus 1.
                256, // 16 AES blocks or 8 ChaCha20 blocks.
                257, // 16 AES blocks or 8 ChaCha20 blocks, plus 1.
            ];

            let mut more_comprehensive_in_prefix_lenghts = [0; 4096];
            let in_prefix_lengths;
            if cfg!(debug_assertions) {
                in_prefix_lengths = &MINIMAL_IN_PREFIX_LENS[..];
            } else {
                for b in 0..more_comprehensive_in_prefix_lenghts.len() {
                    more_comprehensive_in_prefix_lenghts[b] = b;
                }
                in_prefix_lengths = &more_comprehensive_in_prefix_lenghts[..];
            }
            let mut o_in_out = vec![123u8; 4096];

            for in_prefix_len in in_prefix_lengths.iter() {
                o_in_out.truncate(0);
                for _ in 0..*in_prefix_len {
                    o_in_out.push(123);
                }
                o_in_out.extend_from_slice(&ct[..]);
                let o_result = aead::open_in_place(&o_key, &nonce[..],
                                                   *in_prefix_len,
                                                   &mut o_in_out[..], &ad);
                match error {
                    None => {
                        assert_eq!(Ok(ct.len()), s_result);
                        assert_eq!(&ct[..], &s_in_out[..ct.len()]);
                        assert_eq!(Ok(plaintext.len()), o_result);
                        assert_eq!(&plaintext[..],
                                   &o_in_out[..plaintext.len()]);
                    },
                    Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                        assert_eq!(Err(error::Unspecified), s_result);
                        assert_eq!(Err(error::Unspecified), o_result);
                    },
                    Some(error) => {
                        unreachable!("Unexpected error test case: {}", error);
                    },
                };
            }

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

        let prefix_len = 0;
        let suffix_space = aead_alg.max_overhead_len();
        let ad: [u8; 0] = [];

        // Construct a template input for `seal_in_place`.
        let mut to_seal = b"hello, world".to_vec();
        // Reserve space for tag.
        for _ in 0..suffix_space {
            to_seal.push(0);
        }
        let to_seal = &to_seal[..]; // to_seal is no longer mutable.

        // Construct a template input for `open_in_place`.
        let mut to_open = Vec::from(to_seal);
        let ciphertext_len =
            try!(aead::seal_in_place(&s_key, &nonce[..nonce_len], &mut to_open,
                                     suffix_space, &ad));
        let to_open = &to_open[..ciphertext_len];

        // Nonce is the correct length.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..nonce_len],
                                        &mut in_out, suffix_space, &ad).is_ok());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..nonce_len],
                                        prefix_len, &mut in_out, &ad).is_ok());
        }

        // Nonce is one byte too small.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len - 1)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len - 1)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is one byte too large.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len + 1)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len + 1)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is half the required size.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len / 2)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len / 2)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is twice the required size.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..(nonce_len * 2)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..(nonce_len * 2)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is empty.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &[], &mut in_out, suffix_space,
                                        &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &[], prefix_len, &mut in_out,
                                        &ad).is_err());
        }

        // Nonce is one byte.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..1], &mut in_out,
                                        suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..1], prefix_len,
                                        &mut in_out, &ad).is_err());
        }

        // Nonce is 128 bits (16 bytes).
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[..16], &mut in_out,
                                        suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[..16], prefix_len,
                                        &mut in_out, &ad).is_err());
        }

        Ok(())
    }
}
