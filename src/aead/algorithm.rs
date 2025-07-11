// Copyright 2015-2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    aes, aes_gcm, chacha20_poly1305,
    nonce::{Nonce, NONCE_LEN},
    overlapping::{IndexError, Overlapping},
    Aad, AuthError, ForgedPlaintext, KeyInner, Tag, TAG_LEN,
};
use crate::{
    cpu,
    error::{self, InputTooLongError},
    hkdf,
};
use core::ops::RangeFrom;

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
    ) -> Result<Tag, InputTooLongError>,
    open: for<'o> fn(
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: Overlapping<'o, u8>,
        received_tag: &Tag,
        cpu_features: cpu::Features,
    ) -> Result<&'o mut [u8], AuthError>,

    key_len: usize,
    id: AlgorithmID,
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

    pub(super) fn new_key(
        &self,
        key_bytes: &[u8],
        cpu_features: cpu::Features,
    ) -> Result<KeyInner, error::Unspecified> {
        (self.init)(key_bytes, cpu_features)
    }

    pub(super) fn open_within<'io>(
        &self,
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        received_tag: Tag,
        in_out_slice: &'io mut [u8],
        src: RangeFrom<usize>,
        cpu_features: cpu::Features,
    ) -> Result<&'io mut [u8], error::Unspecified> {
        let in_out = Overlapping::new(in_out_slice, src).map_err(error::erase::<IndexError>)?;
        (self.open)(key, nonce, aad, in_out, &received_tag, cpu_features)
            .map_err(error::erase::<AuthError>)
    }

    #[inline]
    pub(super) fn seal(
        &self,
        key: &KeyInner,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
        cpu_features: cpu::Features,
    ) -> Result<Tag, InputTooLongError> {
        (self.seal)(key, nonce, aad, in_out, cpu_features)
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq)]
pub(super) enum AlgorithmID {
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

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: Algorithm = Algorithm {
    key_len: aes::AES_128_KEY_LEN,
    init: aes_gcm_init_128,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: AlgorithmID::AES_128_GCM,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: Algorithm = Algorithm {
    key_len: aes::AES_256_KEY_LEN,
    init: aes_gcm_init_256,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: AlgorithmID::AES_256_GCM,
};

fn aes_gcm_init_128(
    key: &[u8],
    cpu_features: cpu::Features,
) -> Result<KeyInner, error::Unspecified> {
    let key = key.try_into().map_err(|_| error::Unspecified)?;
    Ok(KeyInner::AesGcm(aes_gcm::Key::new(
        aes::KeyBytes::AES_128(key),
        cpu_features,
    )))
}

fn aes_gcm_init_256(
    key: &[u8],
    cpu_features: cpu::Features,
) -> Result<KeyInner, error::Unspecified> {
    let key = key.try_into().map_err(|_| error::Unspecified)?;
    Ok(KeyInner::AesGcm(aes_gcm::Key::new(
        aes::KeyBytes::AES_256(key),
        cpu_features,
    )))
}

fn aes_gcm_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    _cpu_features: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    let key = match key {
        KeyInner::AesGcm(key) => key,
        _ => unreachable!(),
    };
    key.seal(nonce, aad, in_out)
}

pub(super) fn aes_gcm_open<'o>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'o, u8>,
    received_tag: &Tag,
    _cpu_features: cpu::Features,
) -> Result<&'o mut [u8], AuthError> {
    let key = match key {
        KeyInner::AesGcm(key) => key,
        _ => unreachable!(),
    };
    key.open_within(nonce, aad, in_out, received_tag, ForgedPlaintext::Zero)
}

/// ChaCha20-Poly1305 as described in [RFC 8439].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 8439]: https://tools.ietf.org/html/rfc8439
pub static CHACHA20_POLY1305: Algorithm = Algorithm {
    key_len: chacha20_poly1305::KEY_LEN,
    init: chacha20_poly1305_init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
    id: AlgorithmID::CHACHA20_POLY1305,
};

/// Copies |key| into |ctx_buf|.
fn chacha20_poly1305_init(
    key: &[u8],
    _cpu_features: cpu::Features,
) -> Result<KeyInner, error::Unspecified> {
    let key: [u8; chacha20_poly1305::KEY_LEN] = key.try_into()?;
    Ok(KeyInner::ChaCha20Poly1305(chacha20_poly1305::Key::new(key)))
}

fn chacha20_poly1305_seal(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Result<Tag, InputTooLongError> {
    let key = match key {
        KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    key.seal(nonce, aad, in_out, cpu_features)
}

fn chacha20_poly1305_open<'o>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'o, u8>,
    received_tag: &Tag,
    cpu_features: cpu::Features,
) -> Result<&'o mut [u8], AuthError> {
    let key = match key {
        KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };
    key.open_within(
        nonce,
        aad,
        in_out,
        received_tag,
        ForgedPlaintext::Zero,
        cpu_features,
    )
}
