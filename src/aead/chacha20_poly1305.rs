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
use crate::{aead, cpu, endian::*, error, polyfill};
use core::{convert::TryInto, ops::RangeFrom};

/// ChaCha20-Poly1305 as described in [RFC 7539].
///
/// The keys are 256 bits long and the nonces are 96 bits long.
///
/// [RFC 7539]: https://tools.ietf.org/html/rfc7539
pub static CHACHA20_POLY1305: aead::Algorithm = aead::Algorithm {
    key_len: chacha::KEY_LEN,
    init: chacha20_poly1305_init,
    seal: chacha20_poly1305_seal,
    open: chacha20_poly1305_open,
    id: aead::AlgorithmID::CHACHA20_POLY1305,
    max_input_len: super::max_input_len(64, 1),
};

/// Copies |key| into |ctx_buf|.
fn chacha20_poly1305_init(
    key: &[u8],
    cpu_features: cpu::Features,
) -> Result<aead::KeyInner, error::Unspecified> {
    let key: [u8; chacha::KEY_LEN] = key.try_into()?;
    Ok(aead::KeyInner::ChaCha20Poly1305(chacha::Key::new(
        key,
        cpu_features,
    )))
}

fn chacha20_poly1305_seal(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Tag {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };

    #[cfg(target_arch = "x86_64")]
    {
        if cpu::intel::SSE41.available(chacha20_key.cpu_features()) {
            // XXX: BoringSSL uses `alignas(16)` on `key` instead of on the
            // structure, but Rust can't do that yet; see
            // https://github.com/rust-lang/rust/issues/73557.
            //
            // Keep in sync with the anonymous struct of BoringSSL's
            // `chacha20_poly1305_seal_data`.
            #[repr(align(16), C)]
            #[derive(Clone, Copy)]
            struct seal_data_in {
                key: [u32; chacha::KEY_LEN / 4],
                counter: u32,
                nonce: [u8; super::NONCE_LEN],
                extra_ciphertext: *const u8,
                extra_ciphertext_len: usize,
            }

            let mut data = InOut {
                input: seal_data_in {
                    key: *chacha20_key.words_less_safe(),
                    counter: 0,
                    nonce: *nonce.as_ref(),
                    extra_ciphertext: core::ptr::null(),
                    extra_ciphertext_len: 0,
                },
            };

            // Encrypts `plaintext_len` bytes from `plaintext` and writes them to `out_ciphertext`.
            extern "C" {
                fn GFp_chacha20_poly1305_seal(
                    out_ciphertext: *mut u8,
                    plaintext: *const u8,
                    plaintext_len: usize,
                    ad: *const u8,
                    ad_len: usize,
                    data: &mut InOut<seal_data_in>,
                );
            }

            let out = unsafe {
                GFp_chacha20_poly1305_seal(
                    in_out.as_mut_ptr(),
                    in_out.as_ptr(),
                    in_out.len(),
                    aad.as_ref().as_ptr(),
                    aad.as_ref().len(),
                    &mut data,
                );
                &data.out
            };

            return Tag(out.tag);
        }
    }

    let mut counter = Counter::zero(nonce);
    let mut auth = {
        let key = derive_poly1305_key(chacha20_key, counter.increment());
        poly1305::Context::from_key(key)
    };

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    chacha20_key.encrypt_in_place(counter, in_out);
    poly1305_update_padded_16(&mut auth, in_out);
    finish(auth, aad.as_ref().len(), in_out.len())
}

fn chacha20_poly1305_open(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
) -> Tag {
    let chacha20_key = match key {
        aead::KeyInner::ChaCha20Poly1305(key) => key,
        _ => unreachable!(),
    };

    #[cfg(target_arch = "x86_64")]
    {
        if cpu::intel::SSE41.available(chacha20_key.cpu_features()) {
            // XXX: BoringSSL uses `alignas(16)` on `key` instead of on the
            // structure, but Rust can't do that yet; see
            // https://github.com/rust-lang/rust/issues/73557.
            //
            // Keep in sync with the anonymous struct of BoringSSL's
            // `chacha20_poly1305_open_data`.
            #[derive(Copy, Clone)]
            #[repr(align(16), C)]
            struct open_data_in {
                key: [u32; chacha::KEY_LEN / 4],
                counter: u32,
                nonce: [u8; super::NONCE_LEN],
            }

            let mut data = InOut {
                input: open_data_in {
                    key: *chacha20_key.words_less_safe(),
                    counter: 0,
                    nonce: *nonce.as_ref(),
                },
            };

            // Decrypts `plaintext_len` bytes from `ciphertext` and writes them to `out_plaintext`.
            extern "C" {
                fn GFp_chacha20_poly1305_open(
                    out_plaintext: *mut u8,
                    ciphertext: *const u8,
                    plaintext_len: usize,
                    ad: *const u8,
                    ad_len: usize,
                    data: &mut InOut<open_data_in>,
                );
            }

            let out = unsafe {
                GFp_chacha20_poly1305_open(
                    in_out.as_mut_ptr(),
                    in_out.as_ptr().add(src.start),
                    in_out.len() - src.start,
                    aad.as_ref().as_ptr(),
                    aad.as_ref().len(),
                    &mut data,
                );
                &data.out
            };

            return Tag(out.tag);
        }
    }

    let mut counter = Counter::zero(nonce);
    let mut auth = {
        let key = derive_poly1305_key(chacha20_key, counter.increment());
        poly1305::Context::from_key(key)
    };

    poly1305_update_padded_16(&mut auth, aad.as_ref());
    poly1305_update_padded_16(&mut auth, &in_out[src.clone()]);
    chacha20_key.encrypt_within(counter, in_out, src.clone());
    finish(auth, aad.as_ref().len(), in_out[src].len())
}

fn finish(mut auth: poly1305::Context, aad_len: usize, in_out_len: usize) -> Tag {
    auth.update(
        [
            LittleEndian::from(polyfill::u64_from_usize(aad_len)),
            LittleEndian::from(polyfill::u64_from_usize(in_out_len)),
        ]
        .as_byte_array(),
    );
    auth.finish()
}

pub type Key = chacha::Key;

// Keep in sync with BoringSSL's `chacha20_poly1305_open_data` and
// `chacha20_poly1305_seal_data`.
#[repr(C)]
#[cfg(target_arch = "x86_64")]
union InOut<T>
where
    T: Copy,
{
    input: T,
    out: Out,
}

// It isn't obvious whether the assembly code works for tags that aren't
// 16-byte aligned. In practice it will always be 16-byte aligned because it
// is embedded in a union where the other member of the union is 16-byte
// aligned.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
#[repr(align(16), C)]
struct Out {
    tag: [u8; super::TAG_LEN],
}

#[inline]
fn poly1305_update_padded_16(ctx: &mut poly1305::Context, input: &[u8]) {
    if input.len() > 0 {
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
    poly1305::Key::new(key_bytes, chacha_key.cpu_features())
}

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // Errata 4858 at https://www.rfc-editor.org/errata_search.php?rfc=7539.
        assert_eq!(super::CHACHA20_POLY1305.max_input_len, 274_877_906_880u64);
    }
}
