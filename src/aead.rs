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
//! [AEAD]: http://www-cse.ucsd.edu/~mihir/papers/oem.html
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD

use self::block::{Block, BLOCK_LEN};
use crate::{constant_time, cpu, error, hkdf, polyfill};
use core::ops::{Bound, RangeBounds};

pub use self::{
    aes_gcm::{AES_128_GCM, AES_256_GCM},
    chacha20_poly1305::CHACHA20_POLY1305,
    nonce::{Nonce, NONCE_LEN},
};

/// A sequences of unique nonces.
///
/// A given `NonceSequence` must never return the same `Nonce` twice from
/// `advance()`.
///
/// A simple counter is a reasonable (but probably not ideal) `NonceSequence`.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the sequence.
pub trait NonceSequence {
    /// Returns a nonce, and prevents that
    /// This may fail if "too many" nonces have been requested, where how many
    /// is too many is up to the implementation of `NonceSequence`. An
    /// implementation may that enforce a maximum number of records are
    /// sent/received under a key this way. Once `advance()` fails, it must
    /// fail for all subsequent calls.
    fn advance(&mut self) -> Result<Nonce, error::Unspecified>;
}

/// An AEAD key bound to a nonce sequence.
pub trait BoundKey<N: NonceSequence>: core::fmt::Debug {
    /// Constructs a new key from the given `UnboundKey` and `NonceSequence`.
    fn new(key: UnboundKey, nonce_sequence: N) -> Self;

    /// The key's AEAD algorithm.
    #[inline]
    fn algorithm(&self) -> &'static Algorithm;
}

/// An AEAD key for authenticating and decrypting ("opening"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct OpeningKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for OpeningKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl<N: NonceSequence> core::fmt::Debug for OpeningKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("OpeningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> OpeningKey<N> {
    /// Authenticates and decrypts (“opens”) data in place.
    ///
    /// The input is `&in_out[ciphertext_and_tag]`. Use `..` as
    /// `ciphertext_and_tag` if the entirety of `in_out` is the input.
    ///
    /// As the input ciphertext is transformed to plaintext, it is shifted to
    /// the start of `in_out`. When `open_in_place()` returns `Ok(plaintext)`,
    /// the decrypted output is `plaintext`, which is `&mut
    /// in_out[..plaintext.len()]`; the output plaintext is always written to
    /// the beginning of `in_out`, even if the input doesn't start at the
    /// beginning of `in_out`. For example, the following two code fragments
    /// are equivalent:
    ///
    /// ```skip
    /// key.open_in_place(nonce, aad, in_out, in_out, in_prefix_len..)?;
    /// ```
    ///
    /// ```skip
    /// in_out.copy_within(in_prefix_len.., 0);
    /// key.open_in_place(nonce, aad, in_out, in_out, ..(in_out.len() - in_prefix_len))?;
    /// ```
    ///
    /// Similarly, these are equivalent (when `copy_within` doesn't panic):
    ///
    /// ```skip
    /// key.open_in_place(nonce, aad, in_out, in_out, start..end)?;
    /// ```
    ///
    /// ```skip
    /// in_out.copy_within(start..end, 0);
    /// key.open_in_place(nonce, aad, in_out, ..(end - start));
    /// ```
    ///
    /// When `open_in_place()` returns `Err(..)`, `in_out` may have been
    /// overwritten in an unspecified way.
    ///
    /// The shifting feature is useful in the case where multiple packets are
    /// being reassembled in place. Consider this example where the peer has
    /// sent the message “Split stream reassembled in place” split into
    /// three sealed packets:
    ///
    /// ```ascii-art
    ///                 Packet 1                  Packet 2                 Packet 3
    /// Input:  [Header][Ciphertext][Tag][Header][Ciphertext][Tag][Header][Ciphertext][Tag]
    ///                      |         +--------------+                        |
    ///               +------+   +-----+    +----------------------------------+
    ///               v          v          v
    /// Output: [Plaintext][Plaintext][Plaintext]
    ///        “Split stream reassembled in place”
    /// ```
    #[inline]
    pub fn open_in_place<'in_out, A: AsRef<[u8]>, I: RangeBounds<usize>>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: I,
    ) -> Result<&'in_out mut [u8], error::Unspecified> {
        open_in_place_(
            &self.key,
            self.nonce_sequence.advance()?,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }
}

#[inline]
fn open_in_place_<'in_out, A: AsRef<[u8]>, I: RangeBounds<usize>>(
    key: &UnboundKey,
    nonce: Nonce,
    Aad(aad): Aad<A>,
    in_out: &'in_out mut [u8],
    ciphertext_and_tag: I,
) -> Result<&'in_out mut [u8], error::Unspecified> {
    fn open_in_place<'in_out>(
        key: &UnboundKey,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &'in_out mut [u8],
        in_prefix_len: usize,
    ) -> Result<&'in_out mut [u8], error::Unspecified> {
        let ciphertext_and_tag_len = in_out
            .len()
            .checked_sub(in_prefix_len)
            .ok_or(error::Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(TAG_LEN)
            .ok_or(error::Unspecified)?;
        check_per_nonce_max_bytes(key.algorithm, ciphertext_len)?;
        let (in_out, received_tag) = in_out.split_at_mut(in_prefix_len + ciphertext_len);
        let Tag(calculated_tag) = (key.algorithm.open)(
            &key.inner,
            nonce,
            aad,
            in_prefix_len,
            in_out,
            key.cpu_features,
        );
        if constant_time::verify_slices_are_equal(calculated_tag.as_ref(), received_tag).is_err() {
            // Zero out the plaintext so that it isn't accidentally leaked or used
            // after verification fails. It would be safest if we could check the
            // tag before decrypting, but some `open` implementations interleave
            // authentication with decryption for performance.
            for b in &mut in_out[..ciphertext_len] {
                *b = 0;
            }
            return Err(error::Unspecified);
        }
        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    let in_out = match ciphertext_and_tag.end_bound() {
        Bound::Unbounded => in_out,
        Bound::Excluded(end) => in_out.get_mut(..*end).ok_or(error::Unspecified)?,
        Bound::Included(end) => in_out.get_mut(..=*end).ok_or(error::Unspecified)?,
    };
    let in_prefix_len = match ciphertext_and_tag.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(start) => *start,
        Bound::Excluded(start) => (*start).checked_add(1).ok_or(error::Unspecified)?,
    };

    open_in_place(key, nonce, Aad::from(aad.as_ref()), in_out, in_prefix_len)
}

/// An AEAD key for encrypting and signing ("sealing"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct SealingKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for SealingKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl<N: NonceSequence> core::fmt::Debug for SealingKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("SealingKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> SealingKey<N> {
    /// Encrypts and signs (“seals”) data in place.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// The plaintext is given as the input value of `in_out`. `seal_in_place()`
    /// will overwrite the plaintext with the ciphertext and then append the tag
    /// using `in_out.extend()`; the tag will be `self.algorithm.tag_len()` bytes
    /// long.
    ///
    /// `aad` is the additional authenticated data, if any.
    #[inline]
    pub fn seal_in_place<A: AsRef<[u8]>, InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified> {
        seal_in_place_(&self.key, self.nonce_sequence.advance()?, aad, in_out)
    }
}

#[inline]
fn seal_in_place_<A: AsRef<[u8]>, InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>>(
    key: &UnboundKey,
    nonce: Nonce,
    Aad(aad): Aad<A>,
    in_out: &mut InOut,
) -> Result<(), error::Unspecified> {
    fn seal_in_place(
        key: &UnboundKey,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified> {
        check_per_nonce_max_bytes(key.algorithm, in_out.len())?;
        Ok((key.algorithm.seal)(
            &key.inner,
            nonce,
            aad,
            in_out,
            key.cpu_features,
        ))
    }
    let Tag(tag) = seal_in_place(key, nonce, Aad::from(aad.as_ref()), in_out.as_mut())?;
    in_out.extend(tag.as_ref());
    Ok(())
}

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
#[repr(transparent)]
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    pub fn empty() -> Self {
        Self::from([])
    }
}

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    inner: KeyInner,
    algorithm: &'static Algorithm,
    cpu_features: cpu::Features,
}

impl core::fmt::Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[allow(variant_size_differences)]
enum KeyInner {
    AesGcm(aes_gcm::Key),
    ChaCha20Poly1305(chacha20_poly1305::Key),
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    ///
    /// Fails if `key_bytes.len() != ` algorithm.key_len()`.
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let cpu_features = cpu::features();
        Ok(Self {
            inner: (algorithm.init)(key_bytes, cpu_features)?,
            algorithm,
            cpu_features,
        })
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// Immutable keys for use in situations where `Key` and `NonceSequence` cannot
/// reasonably be used.
///
/// Prefer to use `Key` and `NonceSequence` when practical.
pub struct LessSafeKey {
    key: UnboundKey,
}

impl LessSafeKey {
    /// Constructs a `LessSafeKey` from an `UnboundKey`.
    pub fn new(key: UnboundKey) -> Self {
        Self { key }
    }

    /// Like `Key::open_in_place()`, except it accepts an arbitrary nonce.
    #[inline]
    pub fn open_in_place<'in_out, A: AsRef<[u8]>, I: RangeBounds<usize>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: I,
    ) -> Result<&'in_out mut [u8], error::Unspecified> {
        open_in_place_(&self.key, nonce, aad, in_out, ciphertext_and_tag)
    }

    /// Like `Key::seal_in_place()`, except it accepts an arbitrary nonce.
    #[inline]
    pub fn seal_in_place<A: AsRef<[u8]>, InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified> {
        seal_in_place_(&self.key, nonce, aad, in_out)
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        &self.key.algorithm
    }
}

impl core::fmt::Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Key")
            .field("algorithm", self.algorithm())
            .finish()
    }
}

/// An AEAD Algorithm.
pub struct Algorithm {
    init: fn(key: &[u8], cpu_features: cpu::Features) -> Result<KeyInner, error::Unspecified>,

    seal: fn(
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
        cpu_features: cpu::Features,
    ) -> Tag,
    open: fn(
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_prefix_len: usize,
        in_out: &mut [u8],
        cpu_features: cpu::Features,
    ) -> Tag,

    key_len: usize,
    id: AlgorithmID,

    /// Use `max_input_len!()` to initialize this.
    // TODO: Make this `usize`.
    max_input_len: u64,
}

const fn max_input_len(block_len: usize, overhead_blocks_per_nonce: usize) -> u64 {
    // Each of our AEADs use a 32-bit block counter so the maximum is the
    // largest input that will not overflow the counter.
    ((1u64 << 32) - polyfill::u64_from_usize(overhead_blocks_per_nonce))
        * polyfill::u64_from_usize(block_len)
}

impl Algorithm {
    /// The length of the key.
    #[inline(always)]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    #[inline(always)]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

/// An authentication tag.
#[must_use]
#[repr(C)]
struct Tag(Block);

const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = BLOCK_LEN;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

fn check_per_nonce_max_bytes(alg: &Algorithm, in_out_len: usize) -> Result<(), error::Unspecified> {
    if polyfill::u64_from_usize(in_out_len) > alg.max_input_len {
        return Err(error::Unspecified);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Direction {
    Opening { in_prefix_len: usize },
    Sealing,
}

mod aes;
mod aes_gcm;
mod block;
mod chacha;
mod chacha20_poly1305;
pub mod chacha20_poly1305_openssh;
mod gcm;
mod nonce;
mod poly1305;
pub mod quic;
mod shift;
