// Copyright 2015-2025 Brian Smith.
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
    super::{NONCE_LEN, TAG_LEN},
    chacha::Overlapping,
    check_input_lengths, Aad, InputTooLongError, Key, Nonce, Tag, KEY_LEN,
};
use crate::cpu;
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_endian = "little"))] {
        type RequiredCpuFeatures = cpu::arm::Neon;
    } else {
        type RequiredCpuFeatures = cpu::intel::Sse41;
    }
}

pub(super) fn seal(
    Key(key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    _cpu_features: RequiredCpuFeatures,
) -> Result<Tag, InputTooLongError> {
    check_input_lengths(aad, in_out)?;

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
        nonce: [u8; NONCE_LEN],
        extra_ciphertext: *const u8,
        extra_ciphertext_len: usize,
    }

    let mut data = InOut {
        input: seal_data_in {
            key: *key.words_less_safe(),
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
            data: &mut InOut<seal_data_in>,
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

    Ok(Tag(out.tag))
}

pub(super) fn open(
    Key(key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'_>,
    _cpu: RequiredCpuFeatures,
) -> Result<Tag, InputTooLongError> {
    check_input_lengths(aad, in_out.input())?;

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
        nonce: [u8; NONCE_LEN],
    }

    let mut data = InOut {
        input: open_data_in {
            key: *key.words_less_safe(),
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
            data: &mut InOut<open_data_in>,
        );
    }

    let (input, output, len) = in_out.into_input_output_len();
    let out = unsafe {
        chacha20_poly1305_open(
            output,
            input,
            len,
            aad.as_ref().as_ptr(),
            aad.as_ref().len(),
            &mut data,
        );
        &data.out
    };

    Ok(Tag(out.tag))
}

// Keep in sync with BoringSSL's `chacha20_poly1305_open_data` and
// `chacha20_poly1305_seal_data`.
#[repr(C)]
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
#[derive(Clone, Copy)]
#[repr(align(16), C)]
pub(super) struct Out {
    pub(super) tag: [u8; TAG_LEN],
}
