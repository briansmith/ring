// Copyright 2015-2021 Brian Smith.
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

use crate::{cpu, error, hkdf, polyfill};
use core::ops::RangeFrom;

pub use self::{
    aes_gcm::{AES_128_GCM, AES_256_GCM},
    chacha20_poly1305::CHACHA20_POLY1305,
    less_safe_key::LessSafeKey,
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
    /// Returns the next nonce in the sequence.
    ///
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
    fn algorithm(&self) -> &'static Algorithm;
}

/// An AEAD key for authenticating and decrypting ("opening"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct OpeningKey<N: NonceSequence> {
    key: LessSafeKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for OpeningKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key: key.inner,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
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
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out` must be the ciphertext followed by the tag. When
    /// `open_in_place()` returns `Ok(plaintext)`, the input ciphertext
    /// has been overwritten by the plaintext; `plaintext` will refer to the
    /// plaintext without the tag.
    ///
    /// When `open_in_place()` returns `Err(..)`, `in_out` may have been
    /// overwritten in an unspecified way.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .open_in_place(self.nonce_sequence.advance()?, aad, in_out)
    }

    /// Authenticates and decrypts (“opens”) data in place, with a shift.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out[ciphertext_and_tag]` must be the ciphertext followed
    /// by the tag. When `open_within()` returns `Ok(plaintext)`, the plaintext
    /// will be at `in_out[0..plaintext.len()]`. In other words, the following
    /// two code fragments are equivalent for valid values of
    /// `ciphertext_and_tag`, except `open_within` will often be more efficient:
    ///
    ///
    /// ```skip
    /// let plaintext = key.open_within(aad, in_out, cipertext_and_tag)?;
    /// ```
    ///
    /// ```skip
    /// let ciphertext_and_tag_len = in_out[ciphertext_and_tag].len();
    /// in_out.copy_within(ciphertext_and_tag, 0);
    /// let plaintext = key.open_in_place(aad, &mut in_out[..ciphertext_and_tag_len])?;
    /// ```
    ///
    /// Similarly, `key.open_within(aad, in_out, 0..)` is equivalent to
    /// `key.open_in_place(aad, in_out)`.
    ///
    ///  When `open_in_place()` returns `Err(..)`, `in_out` may have been
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
    ///
    /// This reassembly be accomplished with three calls to `open_within()`.
    #[inline]
    pub fn open_within<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key.open_within(
            self.nonce_sequence.advance()?,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }
}

/// An AEAD key for encrypting and signing ("sealing"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct SealingKey<N: NonceSequence> {
    key: LessSafeKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for SealingKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key: key.inner,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm()
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
    /// Encrypts and signs (“seals”) data in place, appending the tag to the
    /// resulting ciphertext.
    ///
    /// `key.seal_in_place_append_tag(aad, in_out)` is equivalent to:
    ///
    /// ```skip
    /// key.seal_in_place_separate_tag(aad, in_out.as_mut())
    ///     .map(|tag| in_out.extend(tag.as_ref()))
    /// ```
    #[inline]
    pub fn seal_in_place_append_tag<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.key
            .seal_in_place_append_tag(self.nonce_sequence.advance()?, aad, in_out)
    }

    /// Encrypts and signs (“seals”) data in place.
    ///
    /// `aad` is the additional authenticated data (AAD), if any. This is
    /// authenticated but not encrypted. The type `A` could be a byte slice
    /// `&[u8]`, a byte array `[u8; N]` for some constant `N`, `Vec<u8>`, etc.
    /// If there is no AAD then use `Aad::empty()`.
    ///
    /// The plaintext is given as the input value of `in_out`. `seal_in_place()`
    /// will overwrite the plaintext with the ciphertext and return the tag.
    /// For most protocols, the caller must append the tag to the ciphertext.
    /// The tag will be `self.algorithm.tag_len()` bytes long.
    #[inline]
    pub fn seal_in_place_separate_tag<A>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.key
            .seal_in_place_separate_tag(self.nonce_sequence.advance()?, aad, in_out)
    }
}

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
///
/// The type `A` could be a byte slice `&[u8]`, a byte array `[u8; N]`
/// for some constant `N`, `Vec<u8>`, etc.
pub struct Aad<A>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    pub fn empty() -> Self {
        Self::from([])
    }
}

impl<A> Clone for Aad<A>
where
    A: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A> Copy for Aad<A> where A: Copy {}

impl<A> core::fmt::Debug for Aad<A>
where
    A: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Aad").field(&self.0).finish()
    }
}

impl<A> PartialEq for Aad<A>
where
    A: PartialEq,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<A> Eq for Aad<A> where A: Eq {}

/// An AEAD key without a designated role or nonce sequence.
pub struct UnboundKey {
    inner: LessSafeKey,
}

impl core::fmt::Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

#[allow(clippy::large_enum_variant, variant_size_differences)]
enum KeyInner {
    AesGcm(aes_gcm::Key),
    ChaCha20Poly1305(chacha20_poly1305::Key),
}

impl UnboundKey {
    /// Constructs a `UnboundKey`.
    ///
    /// Fails if `key_bytes.len() != algorithm.key_len()`.
    #[inline]
    pub fn new(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            inner: LessSafeKey::new_(algorithm, key_bytes)?,
        })
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.inner.algorithm()
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self {
            inner: LessSafeKey::new_(algorithm, key_bytes).unwrap(),
        }
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
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
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = 16;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

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
mod less_safe_key;
mod nonce;
mod poly1305;
pub mod quic;
mod shift;
