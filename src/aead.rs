// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Authenticated Encryption with Associated Data (AEAD).
//!
//! See [Authenticated encryption: relations among notions and analysis of the
//! generic composition
//! paradigm](http://www-cse.ucsd.edu/~mihir/papers/oem.html) for an
//! introduction to the concept of AEADs.
//!
//! C analog: `openssl/aead.h`
//!
//! Go analog: [`crypto.cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)

use libc;
use std;
use super::ffi;

/// A key for authenticating and decrypting (&ldquo;opening&rdquo;)
/// AEAD-protected data.
///
/// C analog: `EVP_AEAD_CTX` with direction `evp_aead_open`
///
/// Go analog: [`crypto.cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub struct OpeningKey {
    key: Key,
}

impl OpeningKey {
    /// C analogs: `EVP_AEAD_CTX_init_with_direction` with direction
    ///            `evp_aead_open`, `EVP_AEAD_CTX_init`.
    ///
    /// Go analog: [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8])
               -> Result<OpeningKey, ()> {
        let mut key = OpeningKey {
            key: Key {
                ctx: EVP_AEAD_CTX {
                    aead: algorithm,
                    aead_state: std::ptr::null_mut()
                }
            }
        };
        try!(key.key.init(Direction::Open, key_bytes));
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
/// output is `in_out[0..out_len]`; i.e. the output has been written over the
/// top of the prefix and the input. To put it a different way, the output
/// overwrites the input, shifted by `in_prefix_len` bytes. To have the output
/// overwrite the input without shifting, pass 0 as `in_prefix_len`. (The input
/// and output buffers are expressed this way because Rust's type system does
/// not allow us to have two slices, one mutable and one immutable, that
/// reference overlapping memory.)
///
/// C analog: `EVP_AEAD_CTX_open`
///
/// Go analog: [`AEAD.Open`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn open_in_place(key: &OpeningKey, nonce: &[u8], in_prefix_len: usize,
                     in_out: &mut [u8], ad: &[u8]) -> Result<usize, ()> {
    if in_out.len() < in_prefix_len {
        return Err(());
    }
    unsafe {
        key.key.open_or_seal_in_place(EVP_AEAD_CTX_open, nonce,
                                      in_out[in_prefix_len..].as_ptr(),
                                      in_out.len() - in_prefix_len, ad, in_out)
    }
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
    /// Go analog: [`crypto.aes.NewCipher`](https://golang.org/pkg/crypto/aes/#NewCipher)
    /// + [`crypto.cipher.NewGCM`](https://golang.org/pkg/crypto/cipher/#NewGCM)
    #[inline]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8])
               -> Result<SealingKey, ()> {
        let mut key = SealingKey {
            key: Key {
                ctx: EVP_AEAD_CTX {
                    aead: algorithm,
                    aead_state: std::ptr::null_mut()
                }
            }
        };
        try!(key.key.init(Direction::Seal, key_bytes));
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
/// The input is `in_out[0..(in_out.len() - out_suffix_capacity]`; i.e. the
/// input is the part of `in_out` that precedes the suffix. When `seal` returns
/// `Ok(out_len)`, the encrypted and signed output is `in_out[0..out_len]`; i.e.
/// the output has been written over input and at least part of the data
/// reserved for the suffix. (This way the input and output buffers are
/// expressed this way because Rust's type system does not allow us to have two
/// slices, one mutable and one immutable, that reference overlapping memory.)
///
/// `out_suffix_capacity` should be at least `key.algorithm.max_overhead_len`.
/// See also `MAX_OVERHEAD_LEN`.
///
/// `ad` is the additional authenticated data, if any.
///
/// C analog: `EVP_AEAD_CTX_seal`.
///
/// Go analog: [`AEAD.Seal`](https://golang.org/pkg/crypto/cipher/#AEAD)
pub fn seal_in_place(key: &SealingKey, nonce: &[u8], in_out: &mut [u8],
                     out_suffix_capacity: usize, ad: &[u8])
                     -> Result<usize, ()> {
    if in_out.len() < out_suffix_capacity {
        return Err(());
    }
    unsafe {
        key.key.open_or_seal_in_place(EVP_AEAD_CTX_seal, nonce, in_out.as_ptr(),
                                      in_out.len() - out_suffix_capacity, ad,
                                      in_out)
    }
}

/// `OpeningKey` and `SealingKey` are type-safety wrappers around `Key`, which
/// does all the actual work via the C AEAD interface.
///
/// C analog: `EVP_AEAD_CTX`
struct Key {
    ctx: EVP_AEAD_CTX
}

impl Key {
    /// XXX: Assumes self.ctx.aead is already filled in.
    ///
    /// C analogs: `EVP_AEAD_CTX_init` or `EVP_AEAD_CTX_init_with_direction`
    fn init(&mut self, direction: Direction, key_bytes: &[u8]) -> Result<(), ()> {
        ffi::map_bssl_result(unsafe {
            EVP_AEAD_CTX_init_with_direction(&mut self.ctx, self.ctx.aead,
                                             key_bytes.as_ptr(),
                                             key_bytes.len() as libc::size_t,
                                             0, // EVP_AEAD_DEFAULT_TAG_LENGTH
                                             direction)
        })
    }

    /// The key's AEAD algorithm.
    #[inline(always)]
    fn algorithm(&self) -> &'static Algorithm { self.ctx.aead }

    unsafe fn open_or_seal_in_place(&self, open_or_seal_fn: OpenOrSealFn,
                                    nonce: &[u8], in_ptr: *const u8,
                                    in_len: usize, ad: &[u8], out: &mut [u8])
                                    -> Result<usize, ()> {
        let mut out_len: libc::size_t = 0;
        match (open_or_seal_fn)(&self.ctx, out.as_mut_ptr(), &mut out_len,
                                out.len() as libc::size_t, nonce.as_ptr(),
                                nonce.len() as libc::size_t, in_ptr,
                                in_len as libc::size_t, ad.as_ptr(),
                                ad.len() as libc::size_t) {
            1 => Ok(out_len as usize),
            _ => Err(())
        }
    }
}

impl Drop for Key {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            EVP_AEAD_CTX_cleanup(&mut self.ctx);
        }
    }
}

#[repr(C)]
struct EVP_AEAD_CTX {
    aead: &'static Algorithm,
    aead_state: *mut libc::c_void
}

/// C analog: `evp_aead_direction_t`
#[repr(C)]
enum Direction {
  /// C analog: `evp_aead_open`
  Open,

  /// C analog: `evp_aead_seal`
  Seal,
}

/// An AEAD Algorithm.
///
/// C analog: `EVP_AEAD`
///
/// Go analog: [`crypto.cipher.AEAD`](https://golang.org/pkg/crypto/cipher/#AEAD)
#[repr(C)]
pub struct Algorithm {
  // Keep the layout of this in sync with the layout of `EVP_AEAD`.

  /// The length of the key.
  ///
  /// C analog: `EVP_AEAD_key_length`
  pub key_len: libc::uint8_t,

  /// The length of the nonces.
  ///
  /// C analog: `EVP_AEAD_nonce_length`
  ///
  /// Go analog: [`crypto.cipher.AEAD.NonceSize`](https://golang.org/pkg/crypto/cipher/#AEAD)
  pub nonce_len: libc::uint8_t,

  /// The maximum number of bytes that sealing operations may add to plaintexts.
  /// See also `MAX_OVERHEAD_LEN`.
  ///
  /// C analog: `EVP_AEAD_max_overhead`
  ///
  /// Go analog: [`crypto.cipher.AEAD.Overhead`](https://golang.org/pkg/crypto/cipher/#AEAD)
  pub max_overhead_len: libc::uint8_t,

  /// The length of the authentication tags or MACs.
  ///
  /// Use `max_overhead_len` or `MAX_OVERHEAD_LEN` when sizing buffers for
  /// sealing operations.
  ///
  /// C analog: `EVP_AEAD_max_tag_len`
  pub tag_len: libc::uint8_t,

  init: Option<unsafe extern fn(ctx: *mut EVP_AEAD_CTX,
                                key: *const libc::uint8_t,
                                key_len: libc::size_t, tag_len: libc::size_t)
                                -> libc::c_int>,

  init_with_direction: Option<unsafe extern fn(ctx: *mut EVP_AEAD_CTX,
                                               key: *const libc::uint8_t,
                                               key_len: libc::size_t,
                                               tag_len: libc::size_t,
                                               direction: Direction)
                                               -> libc::c_int>,

  cleanup: unsafe extern fn(ctx: *mut EVP_AEAD_CTX),

  seal: unsafe extern fn(ctx: *mut EVP_AEAD_CTX, out: *mut libc::uint8_t,
                         out_len: libc::size_t, max_out_len: libc::size_t,
                         nonce: *const libc::uint8_t,
                         in_: *const libc::uint8_t, in_len: libc::size_t,
                         ad: *const libc::uint8_t, ad_len: libc::size_t)
                         -> libc::c_int,

  open: unsafe extern fn(ctx: *mut EVP_AEAD_CTX, out: *mut libc::uint8_t,
                         out_len: libc::size_t, max_out_len: libc::size_t,
                         nonce: *const libc::uint8_t,
                         in_: *const libc::uint8_t, in_len: libc::size_t,
                         ad: *const libc::uint8_t, ad_len: libc::size_t)
                         -> libc::c_int,
}

const AES_128_KEY_LEN: libc::uint8_t = 128 / 8;
const AES_256_KEY_LEN: libc::uint8_t = (256 as usize / 8) as libc::uint8_t;
const AES_GCM_NONCE_LEN: libc::uint8_t = 96 / 8;
const AES_GCM_TAG_LEN: libc::uint8_t = 128 / 8;

/// The maximum value of `Algorithm.max_overhead_len` for the algorithms in
/// this module.
pub const MAX_OVERHEAD_LEN: usize = AES_GCM_TAG_LEN as usize;

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
///
/// C analog: `EVP_aead_aes_128_gcm`
///
/// Go analog: [`crypto.aes`](https://golang.org/pkg/crypto/aes/)
pub static AES_128_GCM: Algorithm = Algorithm {
    key_len: AES_128_KEY_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
    max_overhead_len: AES_GCM_TAG_LEN,
    tag_len: AES_GCM_TAG_LEN,
    init: Some(evp_aead_aes_gcm_init),
    init_with_direction: None,
    cleanup: evp_aead_aes_gcm_cleanup,
    seal: evp_aead_aes_gcm_seal,
    open: evp_aead_aes_gcm_open,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
///
/// C analog: `EVP_aead_aes_256_gcm`
///
/// Go analog: [`crypto.aes`](https://golang.org/pkg/crypto/aes/)
pub static AES_256_GCM: Algorithm = Algorithm {
    key_len: AES_256_KEY_LEN,
    nonce_len: AES_GCM_NONCE_LEN,
    max_overhead_len: AES_GCM_TAG_LEN,
    tag_len: AES_GCM_TAG_LEN,
    init: Some(evp_aead_aes_gcm_init),
    init_with_direction: None,
    cleanup: evp_aead_aes_gcm_cleanup,
    seal: evp_aead_aes_gcm_seal,
    open: evp_aead_aes_gcm_open,
};

type OpenOrSealFn =
    unsafe extern fn(ctx: &EVP_AEAD_CTX, out: *mut libc::uint8_t,
                     out_len: &mut libc::size_t, max_out_len: libc::size_t,
                     nonce: *const libc::uint8_t, nonce_len: libc::size_t,
                     in_: *const libc::uint8_t, in_len: libc::size_t,
                     ad: *const libc::uint8_t, ad_len: libc::size_t)
                     -> libc::c_int;


extern {
    // TODO: C analog documentation

    fn evp_aead_aes_gcm_init(ctx: *mut EVP_AEAD_CTX, key: *const libc::uint8_t,
                             key_len: libc::size_t, tag_len: libc::size_t)
                             -> libc::c_int;

    fn evp_aead_aes_gcm_cleanup(ctx: *mut EVP_AEAD_CTX);

    fn evp_aead_aes_gcm_seal(ctx: *mut EVP_AEAD_CTX, out: *mut libc::uint8_t,
                             out_len: libc::size_t, max_out_len: libc::size_t,
                             nonce: *const libc::uint8_t,
                             in_: *const libc::uint8_t, in_len: libc::size_t,
                             ad: *const libc::uint8_t, ad_len: libc::size_t)
                             -> libc::c_int;

    fn evp_aead_aes_gcm_open(ctx: *mut EVP_AEAD_CTX, out: *mut libc::uint8_t,
                             out_len: libc::size_t, max_out_len: libc::size_t,
                             nonce: *const libc::uint8_t,
                             in_: *const libc::uint8_t, in_len: libc::size_t,
                             ad: *const libc::uint8_t, ad_len: libc::size_t)
                             -> libc::c_int;

    fn EVP_AEAD_CTX_init_with_direction(ctx: &mut EVP_AEAD_CTX,
                                        aead: &Algorithm, key: *const u8,
                                        key_len: libc::size_t,
                                        tag_len: libc::size_t,
                                        direction: Direction) -> libc::c_int;

    fn EVP_AEAD_CTX_seal(ctx: &EVP_AEAD_CTX, out: *mut libc::uint8_t,
                         out_len: &mut libc::size_t, max_out_len: libc::size_t,
                         nonce: *const libc::uint8_t, nonce_len: libc::size_t,
                         in_: *const libc::uint8_t, in_len: libc::size_t,
                         ad: *const libc::uint8_t, ad_len: libc::size_t)
                         -> libc::c_int;

    fn EVP_AEAD_CTX_open(ctx: &EVP_AEAD_CTX, out: *mut libc::uint8_t,
                         out_len: &mut libc::size_t, max_out_len: libc::size_t,
                         nonce: *const libc::uint8_t, nonce_len: libc::size_t,
                         in_: *const libc::uint8_t, in_len: libc::size_t,
                         ad: *const libc::uint8_t, ad_len: libc::size_t)
                         -> libc::c_int;

    fn EVP_AEAD_CTX_cleanup(ctx: &mut EVP_AEAD_CTX);
}

#[cfg(test)]
mod tests {

    use super::super::{aead, file_test};

    #[test]
    pub fn test_aes_gcm_128() {
        test_aead(&aead::AES_128_GCM,
                  "crypto/cipher/test/aes_128_gcm_tests.txt");
    }

    #[test]
    pub fn test_aes_gcm_256() {
        test_aead(&aead::AES_256_GCM,
                  "crypto/cipher/test/aes_256_gcm_tests.txt");
    }

    fn test_aead(aead_alg: &'static aead::Algorithm, file_path: &str) {
        test_aead_key_sizes(aead_alg);
        test_aead_nonce_sizes(aead_alg);

        file_test::run(file_path, |test_case| {
            let key_bytes = test_case.consume_bytes("KEY");
            let nonce = test_case.consume_bytes("NONCE");
            let plaintext = test_case.consume_bytes("IN");
            let ad = test_case.consume_bytes("AD");
            let mut ct = test_case.consume_bytes("CT");
            let tag = test_case.consume_bytes("TAG");
            let error = test_case.consume_optional_string("FAILS");

            ct.extend(tag);

            // TODO: test shifting.

            let max_overhead_len = aead_alg.max_overhead_len as usize;
            let mut s_in_out = plaintext.clone();
            for _ in 0..max_overhead_len {
                s_in_out.push(0);
            }
            let s_key = aead::SealingKey::new(aead_alg, &key_bytes).unwrap();
            let s_result = aead::seal_in_place(&s_key, &nonce,
                                               &mut s_in_out[..],
                                               max_overhead_len, &ad);

            let mut o_in_out = ct.clone();
            let o_key = aead::OpeningKey::new(aead_alg, &key_bytes).unwrap();
            let o_result = aead::open_in_place(&o_key, &nonce, 0,
                                               &mut o_in_out[..], &ad);

            match error {
                None => {
                    assert_eq!(Ok(ct.len()), s_result);
                    assert_eq!(&ct[..], &s_in_out[0..ct.len()]);
                    assert_eq!(Ok(plaintext.len()), o_result);
                    assert_eq!(&plaintext[..], &o_in_out[0..plaintext.len()]);
                },
                Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                    assert_eq!(Err(()), s_result);
                    assert_eq!(Err(()), o_result);
                },
                Some(error) => {
                    unreachable!("Unexpected error test case: {}", error);
                }
            };
        });
    }

    fn test_aead_key_sizes(aead_alg: &'static aead::Algorithm) {
        let key_len = aead_alg.key_len as usize;
        let key_data = vec![0u8; key_len * 2];

        // Key is the right size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[0..key_len])
                    .is_ok());
        assert!(aead::SealingKey::new(aead_alg, &key_data[0..key_len])
                    .is_ok());

        // Key is one byte too small.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[0..(key_len - 1)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[0..(key_len - 1)])
                    .is_err());

        // Key is one byte too large.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[0..(key_len + 1)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[0..(key_len + 1)])
                    .is_err());

        // Key is half the required size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[0..(key_len / 2)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[0..(key_len / 2)])
                    .is_err());

        // Key is twice the required size.
        assert!(aead::OpeningKey::new(aead_alg, &key_data[0..(key_len * 2)])
                    .is_err());
        assert!(aead::SealingKey::new(aead_alg, &key_data[0..(key_len * 2)])
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
    // non-standard nonce sizes. So, when `open_in_place` returns `Err(())`, we
    // don't know if it is because it rejected the non-standard nonce size or
    // because it tried to process the input with the wrong nonce. But at least
    // we're verifying that `open_in_place` won't crash or access out-of-bounds
    // memory (when run under valgrind or similar). The AES-128-GCM tests have
    // one WRONG_NONCE_LENGTH test case that tests this more correctly.
    fn test_aead_nonce_sizes(aead_alg: &'static aead::Algorithm) {
        let key_len = aead_alg.key_len as usize;
        let key_data = vec![0u8; key_len];
        let o_key =
            aead::OpeningKey::new(aead_alg, &key_data[0..key_len]).unwrap();
        let s_key =
            aead::SealingKey::new(aead_alg, &key_data[0..key_len]).unwrap();

        let nonce_len = aead_alg.nonce_len as usize;

        let nonce = vec![0u8; nonce_len * 2];

        let prefix_len = 0;
        let suffix_space = aead_alg.max_overhead_len as usize;
        let ad: [u8; 0] = [];

        // Construct a template input for `seal_in_place`.
        let plaintext = "hello, world".as_bytes();
        let mut to_seal = Vec::from(plaintext);
        // Reserve space for tag.
        for _ in 0..suffix_space {
            to_seal.push(0);
        }
        let to_seal = &to_seal[..]; // to_seal is no longer mutable.

        // Construct a template input for `open_in_place`.
        let mut to_open = Vec::from(to_seal);
        let ciphertext_len = aead::seal_in_place(&s_key, &nonce[0..nonce_len],
                                                 &mut to_open, suffix_space,
                                                 &ad).unwrap();
        let to_open = &to_open[0..ciphertext_len];

        // Nonce is the correct length.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..nonce_len],
                                        &mut in_out, suffix_space, &ad).is_ok());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..nonce_len],
                                        prefix_len, &mut in_out, &ad).is_ok());
        }

        // Nonce is one byte too small.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..(nonce_len - 1)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..(nonce_len - 1)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is one byte too large.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..(nonce_len + 1)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..(nonce_len + 1)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is half the required size.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..(nonce_len / 2)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..(nonce_len / 2)],
                                        prefix_len, &mut in_out, &ad).is_err());
        }

        // Nonce is twice the required size.
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..(nonce_len * 2)],
                                        &mut in_out, suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..(nonce_len * 2)],
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
            assert!(aead::seal_in_place(&s_key, &nonce[0..1], &mut in_out,
                                        suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..1], prefix_len,
                                        &mut in_out, &ad).is_err());
        }

        // Nonce is 128 bits (16 bytes).
        {
            let mut in_out = Vec::from(to_seal);
            assert!(aead::seal_in_place(&s_key, &nonce[0..16], &mut in_out,
                                        suffix_space, &ad).is_err());
        }
        {
            let mut in_out = Vec::from(to_open);
            assert!(aead::open_in_place(&o_key, &nonce[0..16], prefix_len,
                                        &mut in_out, &ad).is_err());
        }
    }
}
