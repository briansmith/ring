// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM4-GCM: SM4 block cipher in Galois/Counter Mode (GB/T 32907 + NIST SP 800-38D).
//!
//! Combines the SM4 block cipher with ring's existing pure-Rust GHASH
//! implementation (`gcm::fallback`) to provide an AEAD compatible with
//! [`crate::aead::Algorithm`].
//!
//! Key length: 128 bits. Nonce: 96 bits. Tag: 128 bits.
//!
//! # Security note
//! This is an unaudited, experimental implementation. Performance is significantly
//! lower than hardware-accelerated AES-GCM.

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    Aad, AuthError, ForgedPlaintext, Nonce, Overlapping, Tag,
    aes::{BLOCK_LEN, Counter, Iv, OverlappingPartialBlock, ZERO_BLOCK},
    gcm,
    overlapping::IndexError,
};
use crate::{error::InputTooLongError, polyfill::sliceutil::overwrite_at_start};

use super::sm4;

/// SM4-GCM combined key: SM4 round keys + GHASH subkey.
#[derive(Clone)]
pub(super) struct Key {
    sm4_key: sm4::Key,
    gcm_key: gcm::fallback::Key,
}

impl Key {
    pub(super) fn new(key_bytes: &[u8; sm4::KEY_LEN]) -> Self {
        let sm4_key = sm4::Key::new(key_bytes);
        // Derive the GHASH H value by encrypting the zero block with SM4.
        // Reason: GCM defines H = E(K, 0^128) per NIST SP 800-38D Section 6.1.
        let h_block = sm4_key.encrypt_block(ZERO_BLOCK);
        let gcm_key = gcm::fallback::Key::new(gcm::KeyValue::new(h_block));
        Self { sm4_key, gcm_key }
    }

    #[inline(never)]
    pub(super) fn seal(
        &self,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &mut [u8],
    ) -> Result<Tag, InputTooLongError> {
        seal(self, nonce, aad, in_out)
    }

    #[inline(never)]
    pub(super) fn open_within<'o>(
        &self,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: Overlapping<'o>,
        received_tag: &Tag,
        forged_plaintext: ForgedPlaintext,
    ) -> Result<&'o mut [u8], AuthError> {
        super::open_within(in_out, received_tag, forged_plaintext, |in_out| {
            open(self, nonce, aad, in_out)
        })
    }
}

// Number of 16-byte blocks per GHASH chunk (~3 KiB, matching aes_gcm's CHUNK_BLOCKS).
const CHUNK_BLOCKS: usize = 3 * 1024 / 16;

fn seal(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, InputTooLongError> {
    // Reason: CTR value 1 is reserved for the final tag encryption (tag_iv).
    // Plaintext encryption starts at counter value 2.
    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment(); // extracts counter=1 as tag_iv, advances ctr to 2

    let mut auth = gcm::Context::new(&key.gcm_key, aad, in_out.len())?;

    // Encrypt all complete 16-byte blocks, then authenticate the resulting ciphertext.
    let (whole, remainder) = in_out.as_chunks_mut::<BLOCK_LEN>();
    for chunk in whole.chunks_mut(CHUNK_BLOCKS) {
        key.sm4_key.ctr32_encrypt_blocks(chunk, &mut ctr);
        auth.update_blocks(chunk.as_ref());
    }

    // Handle the final partial block (if any).
    let remainder = OverlappingPartialBlock::new(remainder.into())
        .unwrap_or_else(|InputTooLongError { .. }| unreachable!());
    Ok(seal_finish(&key.sm4_key, auth, remainder, ctr, tag_iv))
}

fn open(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    mut in_out: Overlapping<'_>,
) -> Result<Tag, InputTooLongError> {
    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment(); // extracts counter=1 as tag_iv, advances ctr to 2

    let mut auth = gcm::Context::new(&key.gcm_key, aad, in_out.len())?;

    // Process whole blocks: authenticate the ciphertext first, then decrypt.
    loop {
        let remaining = in_out.len();
        let whole_remaining = remaining - (remaining % BLOCK_LEN);
        if whole_remaining == 0 {
            break;
        }
        let chunk_len = whole_remaining.min(CHUNK_BLOCKS * BLOCK_LEN);
        in_out = in_out
            .split_at(chunk_len, |chunk| {
                // Authenticate ciphertext before decryption.
                let (ct_blocks, _) = chunk.input().as_chunks::<BLOCK_LEN>();
                auth.update_blocks(ct_blocks);
                // Decrypt via SM4 CTR (Overlapping allows input == output).
                key.sm4_key.ctr32_encrypt_within(chunk, &mut ctr);
            })
            .unwrap_or_else(|IndexError { .. }| unreachable!());
    }

    // Handle the final partial block.
    let in_out = OverlappingPartialBlock::new(in_out)
        .unwrap_or_else(|InputTooLongError { .. }| unreachable!());
    Ok(open_finish(&key.sm4_key, auth, in_out, ctr, tag_iv))
}

/// Encrypt and authenticate the trailing partial block, then produce the authentication tag.
fn seal_finish(
    sm4_key: &sm4::Key,
    mut auth: gcm::Context<'_, gcm::fallback::Key>,
    remainder: OverlappingPartialBlock<'_>,
    ctr: Counter,
    tag_iv: Iv,
) -> Tag {
    let remainder_len = remainder.len();
    if remainder_len > 0 {
        // Zero-pad plaintext to 16 bytes, encrypt with next CTR block, zero-pad ciphertext tail.
        let mut padded_pt = ZERO_BLOCK;
        overwrite_at_start(&mut padded_pt, remainder.input());
        // Reason: `ctr` is the next keystream counter (already past tag_iv); use it for the
        // partial block. Convert to Iv (consumes Counter) per the GCM spec.
        let keystream = sm4_key.encrypt_block(*Iv::from(ctr).as_ref());
        let mut padded_ct = ZERO_BLOCK;
        for (c, (p, k)) in padded_ct
            .iter_mut()
            .zip(padded_pt.iter().zip(keystream.iter()))
        {
            *c = p ^ k;
        }
        padded_ct[remainder_len..].fill(0); // clear keystream leak beyond real ciphertext
        auth.update_block(padded_ct);
        remainder.overwrite_at_start(padded_ct);
    }
    // Finalize: fold lengths into GHASH, then E(K, counter=1) XOR GHASH result = tag.
    auth.pre_finish(|pre_tag| {
        let tag_keystream = sm4_key.encrypt_block(*tag_iv.as_ref());
        let mut tag_bytes = ZERO_BLOCK;
        for (t, (g, k)) in tag_bytes
            .iter_mut()
            .zip(pre_tag.iter().zip(tag_keystream.iter()))
        {
            *t = g ^ k;
        }
        Tag::from(tag_bytes)
    })
}

/// Authenticate the trailing partial ciphertext block, decrypt it, then produce the tag.
fn open_finish(
    sm4_key: &sm4::Key,
    mut auth: gcm::Context<'_, gcm::fallback::Key>,
    remainder: OverlappingPartialBlock<'_>,
    ctr: Counter,
    tag_iv: Iv,
) -> Tag {
    if remainder.len() > 0 {
        // Authenticate the zero-padded ciphertext, then decrypt.
        let mut padded_ct = ZERO_BLOCK;
        overwrite_at_start(&mut padded_ct, remainder.input());
        auth.update_block(padded_ct);
        let keystream = sm4_key.encrypt_block(*Iv::from(ctr).as_ref());
        let mut padded_pt = ZERO_BLOCK;
        for (p, (c, k)) in padded_pt
            .iter_mut()
            .zip(padded_ct.iter().zip(keystream.iter()))
        {
            *p = c ^ k;
        }
        remainder.overwrite_at_start(padded_pt);
    }
    auth.pre_finish(|pre_tag| {
        let tag_keystream = sm4_key.encrypt_block(*tag_iv.as_ref());
        let mut tag_bytes = ZERO_BLOCK;
        for (t, (g, k)) in tag_bytes
            .iter_mut()
            .zip(pre_tag.iter().zip(tag_keystream.iter()))
        {
            *t = g ^ k;
        }
        Tag::from(tag_bytes)
    })
}
