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

use super::{Aad, Algorithm, KeyInner, Nonce, Tag, UnboundKey, TAG_LEN};
use crate::{constant_time, cpu, error};
use core::ops::RangeFrom;

/// Immutable keys for use in situations where `OpeningKey`/`SealingKey` and
/// `NonceSequence` cannot reasonably be used.
///
/// Prefer to use `OpeningKey`/`SealingKey` and `NonceSequence` when practical.
#[derive(Clone)]
pub struct LessSafeKey {
    inner: KeyInner,
    algorithm: &'static Algorithm,
}

impl LessSafeKey {
    /// Constructs a `LessSafeKey`.
    #[inline]
    pub fn new(key: UnboundKey) -> Self {
        key.into_inner()
    }

    pub(super) fn new_(
        algorithm: &'static Algorithm,
        key_bytes: &[u8],
    ) -> Result<Self, error::Unspecified> {
        let cpu_features = cpu::features();
        Ok(Self {
            inner: (algorithm.init)(key_bytes, cpu_features)?,
            algorithm,
        })
    }

    /// Like [open_in_place](Self::open_in_place), except the authentication tag is
    /// passed separately.
    #[inline]
    pub fn open_in_place_separate_tag<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        tag: Tag,
        in_out: &'in_out mut [u8],
        ciphertext: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let aad = Aad::from(aad.as_ref());
        open_within_(self, nonce, aad, tag, in_out, ciphertext)
    }

    /// Like [`super::OpeningKey::open_in_place()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(nonce, aad, in_out, 0..)
    }

    /// Like [`super::OpeningKey::open_within()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    #[inline]
    pub fn open_within<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        let tag_offset = in_out
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(error::Unspecified)?;

        // Split the tag off the end of `in_out`.
        let (in_out, received_tag) = in_out.split_at_mut(tag_offset);
        let received_tag = (*received_tag).try_into()?;
        let ciphertext = ciphertext_and_tag;

        self.open_in_place_separate_tag(nonce, aad, received_tag, in_out, ciphertext)
    }

    /// Like [`super::SealingKey::seal_in_place_append_tag()`], except it
    /// accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    #[inline]
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), error::Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_separate_tag(nonce, aad, in_out.as_mut())
            .map(|tag| in_out.extend(tag.as_ref()))
    }

    /// Like `super::SealingKey::seal_in_place_separate_tag()`, except it
    /// accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    #[inline]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, error::Unspecified>
    where
        A: AsRef<[u8]>,
    {
        seal_in_place_separate_tag_(self, nonce, Aad::from(aad.as_ref()), in_out)
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }

    pub(super) fn fmt_debug(
        &self,
        type_name: &'static str,
        f: &mut core::fmt::Formatter,
    ) -> Result<(), core::fmt::Error> {
        f.debug_struct(type_name)
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

fn open_within_<'in_out>(
    key: &LessSafeKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    received_tag: Tag,
    in_out: &'in_out mut [u8],
    src: RangeFrom<usize>,
) -> Result<&'in_out mut [u8], error::Unspecified> {
    let ciphertext_len = in_out.get(src.clone()).ok_or(error::Unspecified)?.len();

    let Tag(calculated_tag) =
        (key.algorithm.open)(&key.inner, nonce, aad, in_out, src, cpu::features())?;

    if constant_time::verify_slices_are_equal(calculated_tag.as_ref(), received_tag.as_ref())
        .is_err()
    {
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

#[inline]
pub(super) fn seal_in_place_separate_tag_(
    key: &LessSafeKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, error::Unspecified> {
    (key.algorithm.seal)(&key.inner, nonce, aad, in_out, cpu::features())
}

impl core::fmt::Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        self.fmt_debug("LessSafeKey", f)
    }
}
