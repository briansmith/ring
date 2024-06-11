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

use super::{
    chacha::{self, Counter, Iv},
    poly1305, Aad, Nonce, Tag,
};
use crate::{
    cpu, error,
    polyfill::{u64_from_usize, usize_from_u64_saturated},
};
use core::ops::RangeFrom;

pub(super) const KEY_LEN: usize = chacha::KEY_LEN;

const MAX_IN_OUT_LEN: usize = super::max_input_len(64, 1);
// https://tools.ietf.org/html/rfc8439#section-2.8
const _MAX_IN_OUT_LEN_BOUNDED_BY_RFC: () =
    assert!(MAX_IN_OUT_LEN == usize_from_u64_saturated(274_877_906_880u64));

#[derive(Clone)]
pub(super) struct Key(chacha::Key);

impl Key {
    pub(super) fn new(value: [u8; KEY_LEN]) -> Self {
        Self(chacha::Key::new(value))
    }
}

pub(super) fn seal(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key(chacha20_key) = key;

    if in_out.len() > MAX_IN_OUT_LEN {
        return Err(error::Unspecified);
    }
    /// RFC 8439 Section 2.8 says the maximum AAD length is 2**64 - 1, which is
    /// never larger than usize::MAX, so we don't need an explicit length
    /// check.
    const _USIZE_BOUNDED_BY_U64: u64 = u64_from_usize(usize::MAX);

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    if has_integrated(cpu_features) {
        // XXX: BoringSSL uses `alignas(16)` on `key` instead of on the
        // structure, but Rust can't do that yet; see
        // https://github.com/rust-lang/rust/issues/73557.
        //
        // Keep in sync with the anonymous struct of BoringSSL's
        // `chacha20_poly1305_seal_data`.
        #[repr(align(16), C)]
        #[derive(Clone, Copy)]
        struct seal_data_in {
            key: [u32; KEY_LEN / 4],
            counter: u32,
            nonce: [u8; super::NONCE_LEN],
            extra_ciphertext: *const u8,
            extra_ciphertext_len: usize,
        }

        let mut data = integrated::InOut {
            input: seal_data_in {
                key: *chacha20_key.words_less_safe(),
                counter: 0,
                nonce: *nonce.as_ref(),
                extra_ciphertext: core::ptr::null(),
                extra_ciphertext_len: 0,
            },
        };

        // Encrypts `plaintext_len` bytes from `plaintext` and writes them to `out_ciphertext`.
        prefixed_extern! {
            fn chacha20_poly1305_seal(
                out_ciphertext: *mut u8,
                plaintext: *const u8,
                plaintext_len: usize,
                ad: *const u8,
                ad_len: usize,
                data: &mut integrated::InOut<seal_data_in>,
            );
        }

        let out = unsafe {
            chacha20_poly1305_seal(
                in_out.as_mut_ptr(),
                in_out.as_ptr(),
                in_out.len(),
                aad.as_ref().as_ptr(),
                aad.as_ref().len(),
                &mut data,
            );
            &data.out
        };

        return Ok(Tag(out.tag));
    }

    let mut counter = Counter::zero(nonce);
    let mut auth = {
        let key = derive_poly1305_key(chacha20_key, counter.increment());
        poly1305::Context::from_key(key, cpu_features)
    };

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    chacha20_key.encrypt_in_place(counter, in_out);
    poly1305_update_padded_16(&mut auth, in_out);
    Ok(finish(auth, aad.as_ref().len(), in_out.len()))
}

pub(super) fn open(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key(chacha20_key) = key;

    let unprefixed_len = in_out
        .len()
        .checked_sub(src.start)
        .ok_or(error::Unspecified)?;
    if unprefixed_len > MAX_IN_OUT_LEN {
        return Err(error::Unspecified);
    }
    // RFC 8439 Section 2.8 says the maximum AAD length is 2**64 - 1, which is
    // never larger than usize::MAX, so we don't need an explicit length
    // check.
    const _USIZE_BOUNDED_BY_U64: u64 = u64_from_usize(usize::MAX);

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    if has_integrated(cpu_features) {
        // XXX: BoringSSL uses `alignas(16)` on `key` instead of on the
        // structure, but Rust can't do that yet; see
        // https://github.com/rust-lang/rust/issues/73557.
        //
        // Keep in sync with the anonymous struct of BoringSSL's
        // `chacha20_poly1305_open_data`.
        #[derive(Copy, Clone)]
        #[repr(align(16), C)]
        struct open_data_in {
            key: [u32; KEY_LEN / 4],
            counter: u32,
            nonce: [u8; super::NONCE_LEN],
        }

        let mut data = integrated::InOut {
            input: open_data_in {
                key: *chacha20_key.words_less_safe(),
                counter: 0,
                nonce: *nonce.as_ref(),
            },
        };

        // Decrypts `plaintext_len` bytes from `ciphertext` and writes them to `out_plaintext`.
        prefixed_extern! {
            fn chacha20_poly1305_open(
                out_plaintext: *mut u8,
                ciphertext: *const u8,
                plaintext_len: usize,
                ad: *const u8,
                ad_len: usize,
                data: &mut integrated::InOut<open_data_in>,
            );
        }

        let out = unsafe {
            chacha20_poly1305_open(
                in_out.as_mut_ptr(),
                in_out.as_ptr().add(src.start),
                unprefixed_len,
                aad.as_ref().as_ptr(),
                aad.as_ref().len(),
                &mut data,
            );
            &data.out
        };

        return Ok(Tag(out.tag));
    }

    let mut counter = Counter::zero(nonce);
    let mut auth = {
        let key = derive_poly1305_key(chacha20_key, counter.increment());
        poly1305::Context::from_key(key, cpu_features)
    };

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    poly1305_update_padded_16(&mut auth, &in_out[src.clone()]);
    chacha20_key.encrypt_within(counter, in_out, src.clone());
    Ok(finish(auth, aad.as_ref().len(), unprefixed_len))
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
#[allow(clippy::needless_return)]
#[inline(always)]
fn has_integrated(cpu_features: cpu::Features) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        return cpu::arm::NEON.available(cpu_features);
    }

    #[cfg(target_arch = "x86_64")]
    {
        return cpu::intel::SSE41.available(cpu_features);
    }
}

fn finish(mut auth: poly1305::Context, aad_len: usize, in_out_len: usize) -> Tag {
    let mut block = [0u8; poly1305::BLOCK_LEN];
    let (alen, clen) = block.split_at_mut(poly1305::BLOCK_LEN / 2);
    alen.copy_from_slice(&u64::to_le_bytes(u64_from_usize(aad_len)));
    clen.copy_from_slice(&u64::to_le_bytes(u64_from_usize(in_out_len)));
    auth.update(&block);
    auth.finish()
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod integrated {
    use super::super::TAG_LEN;

    // Keep in sync with BoringSSL's `chacha20_poly1305_open_data` and
    // `chacha20_poly1305_seal_data`.
    #[repr(C)]
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(super) union InOut<T>
    where
        T: Copy,
    {
        pub(super) input: T,
        pub(super) out: Out,
    }

    // It isn't obvious whether the assembly code works for tags that aren't
    // 16-byte aligned. In practice it will always be 16-byte aligned because it
    // is embedded in a union where the other member of the union is 16-byte
    // aligned.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[derive(Clone, Copy)]
    #[repr(align(16), C)]
    pub(super) struct Out {
        pub(super) tag: [u8; TAG_LEN],
    }
}

#[inline]
fn poly1305_update_padded_16(ctx: &mut poly1305::Context, input: &[u8]) {
    if !input.is_empty() {
        ctx.update(input);
        let remainder_len = input.len() % poly1305::BLOCK_LEN;
        if remainder_len != 0 {
            const ZEROES: [u8; poly1305::BLOCK_LEN] = [0; poly1305::BLOCK_LEN];
            ctx.update(&ZEROES[..(poly1305::BLOCK_LEN - remainder_len)])
        }
    }
}

// Also used by chacha20_poly1305_openssh.
pub(super) fn derive_poly1305_key(chacha_key: &chacha::Key, iv: Iv) -> poly1305::Key {
    let mut key_bytes = [0u8; poly1305::KEY_LEN];
    chacha_key.encrypt_iv_xor_in_place(iv, &mut key_bytes);
    poly1305::Key::new(key_bytes)
}
