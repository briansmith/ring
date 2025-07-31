// Copyright 2018-2024 Brian Smith.
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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{KeyBytes, Overlapping, AES_128_KEY_LEN, AES_256_KEY_LEN, BLOCK_LEN};
use crate::{bits::BitLength, c};
use core::{
    ffi::{c_int, c_uint},
    mem::MaybeUninit,
    num::{NonZeroU32, NonZeroUsize},
};

/// nonce || big-endian counter.
#[repr(transparent)]
pub(in super::super) struct Counter(pub(super) [u8; BLOCK_LEN]);

// `AES_KEY` in BoringSSL's aes.h.
#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct AES_KEY {
    rd_key: RdKeys,
    rounds: c_uint,
}

#[derive(Clone, Copy)]
#[repr(C)]
union RdKeys {
    aes128: Aes128RoundKeys,
    aes256: Aes256RoundKeys,
}

pub(super) type Aes128RoundKeys = [RdKey; Rounds::Aes128.into_usize() + 1];
pub(super) type Aes256RoundKeys = [RdKey; Rounds::Aes256.into_usize() + 1];

pub type RdKey = [u32; 4];

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Rounds {
    Aes128 = 10,
    Aes256 = 14,
}

impl Rounds {
    pub(super) const MAX: Self = Self::Aes256;

    pub(super) const fn into_usize(self) -> usize {
        self as usize
    }
}

impl KeyBytes<'_> {
    pub(super) fn as_user_key_and_bits(&self) -> (*const u8, KeyBitLength) {
        match self {
            KeyBytes::AES_128(bytes) => (bytes.as_ptr(), KeyBitLength::_128),
            KeyBytes::AES_256(bytes) => (bytes.as_ptr(), KeyBitLength::_256),
        }
    }
}
#[repr(transparent)]
pub struct KeyBitLength(BitLength<c_int>);

impl KeyBitLength {
    pub const _128: Self = Self(BitLength::from_bits(128));
    pub const _256: Self = Self(BitLength::from_bits(256));
}

#[allow(dead_code)]
pub(super) trait RoundKeys: AsMut<[RdKey]> + Sized {
    const USER_KEY_BITS: KeyBitLength;
    type UserKey: AsRef<[u8]>;
}

impl RoundKeys for Aes128RoundKeys {
    const USER_KEY_BITS: KeyBitLength = KeyBitLength::_128;
    type UserKey = [u8; AES_128_KEY_LEN];
}

impl RoundKeys for Aes256RoundKeys {
    const USER_KEY_BITS: KeyBitLength = KeyBitLength::_256;
    type UserKey = [u8; AES_256_KEY_LEN];
}

#[allow(dead_code)]
#[inline(always)]
pub(super) unsafe fn assume_init<T>(f: impl FnOnce(*mut T)) -> T {
    let mut uninit = MaybeUninit::<T>::uninit();
    unsafe {
        f(uninit.as_mut_ptr());
        uninit.assume_init()
    }
}

impl AES_KEY {
    #[allow(dead_code)]
    #[inline]
    pub(super) unsafe fn new_using_set_encrypt_key(
        bytes: KeyBytes<'_>,
        f: unsafe extern "C" fn(*const u8, KeyBitLength, *mut AES_KEY) -> c_int,
    ) -> Self {
        let (user_key, bits) = bytes.as_user_key_and_bits();
        let mut uninit = MaybeUninit::<AES_KEY>::uninit();
        // Unusually, in this case zero means success and non-zero means failure.
        let r = unsafe { f(user_key, bits, uninit.as_mut_ptr()) };
        debug_assert_eq!(r, 0);
        unsafe { uninit.assume_init() }
    }
}

#[cfg(all(target_arch = "arm", target_endian = "little"))]
impl AES_KEY {
    pub(super) fn rounds(&self) -> u32 {
        self.rounds
    }
}

// SAFETY:
//  * The function `$name` must read `bits` bits from `user_key`; `bits` will
//    always be a valid AES key length, i.e. a whole number of bytes.
//  * `$name` must set `key.rounds` to the value expected by the corresponding
//    encryption/decryption functions.
//  * `$name` must return 1 when given 128 or 256 for `bits`.
//
// In BoringSSL, the C prototypes for these are in
// crypto/fipsmodule/aes/internal.h.
#[allow(unused_macros)]
macro_rules! prefixed_extern_set_encrypt_key {
    { $name:ident } => {
        prefixed_extern! {
            fn $name(user_key: *const u8,
                     bits: $crate::aead::aes::ffi::KeyBitLength,
                     key: *mut crate::aead::aes::ffi::AES_KEY) -> core::ffi::c_int;
        }
    }
}

#[allow(unused_macros)]
macro_rules! prefixed_extern_ctr32_encrypt_blocks {
    { $name:ident } => {
        prefixed_extern! {
            fn $name(
                input: *const [u8; $crate::aead::aes::BLOCK_LEN],
                output: *mut [u8; $crate::aead::aes::BLOCK_LEN],
                blocks: $crate::c::NonZero_size_t,
                key: &$crate::aead::aes::ffi::AES_KEY,
                ivec: &$crate::aead::aes::ffi::Counter,
            );
        }
    }
}

#[allow(unused_macros)]
macro_rules! prefixed_extern_ctr32_encrypt_blocks_with_rd_keys {
    { $name:ident } => {
        prefixed_extern! {
            fn $name(
                input: *const [u8; $crate::aead::aes::BLOCK_LEN],
                output: *mut [u8; $crate::aead::aes::BLOCK_LEN],
                blocks: $crate::c::NonZero_size_t,
                key: *const $crate::aead::aes::ffi::RdKey,
                ivec: &$crate::aead::aes::ffi::Counter,
                rounds: $crate::aead::aes::ffi::Rounds,
            );
        }
    }
}

impl AES_KEY {
    /// SAFETY:
    ///   * The caller must ensure that `self` was initialized with the
    ///     `set_encrypt_key` function corresponding to `f`.
    ///   * `f` must not read more than `blocks` blocks from `input`.
    ///   * `f` must write exactly `block` blocks to `output`.
    ///   * In particular, `f` must handle blocks == 0 without reading from `input`
    ///     or writing to `output`.
    ///   * `f` must support the input overlapping with the output exactly or
    ///     with any nonnegative offset `n` (i.e. `input == output.add(n)`);
    ///     `f` does NOT need to support the cases where input < output.
    ///   * `key` must have been initialized with the `set_encrypt_key`
    ///     function that corresponds to `f`.
    #[allow(dead_code)]
    #[inline]
    pub(super) unsafe fn ctr32_encrypt_blocks(
        &self,
        in_out: Overlapping<'_>,
        ctr: &mut Counter,
        f: unsafe extern "C" fn(
            input: *const [u8; BLOCK_LEN],
            output: *mut [u8; BLOCK_LEN],
            blocks: c::NonZero_size_t,
            key: &AES_KEY,
            ivec: &Counter,
        ),
    ) {
        in_out.with_input_output_len(|input, output, len| {
            debug_assert_eq!(len % BLOCK_LEN, 0);

            let Some(blocks) = NonZeroUsize::new(len / BLOCK_LEN) else {
                return;
            };

            let input = input.cast_array_::<BLOCK_LEN>();
            let output = output.cast_array_::<BLOCK_LEN>();
            let blocks_u32: NonZeroU32 = blocks.try_into().unwrap();

            // SAFETY:
            //  * `input` points to `blocks` blocks.
            //  * `output` points to space for `blocks` blocks to be written.
            //  * input == output.add(n), where n == src.start, and the caller is
            //    responsible for ensuing this sufficient for `f` to work correctly.
            //  * `blocks` is non-zero so `f` doesn't have to work for empty slices.
            //  * The caller is responsible for ensuring `key` was initialized by the
            //    `set_encrypt_key` function that corresponds to `f`.
            unsafe {
                f(input, output, blocks, self, ctr);
            }

            ctr.increment_by_less_safe(blocks_u32);
        });
    }
}

// SAFETY: Like `AES_KEY::ctr32_encrypt_blocks`, except `rd_keys` must point to
// the round keys and `rounds` must be the number of rounds.
#[allow(dead_code)]
#[inline]
pub(super) unsafe fn ctr32_encrypt_blocks(
    in_out: Overlapping<'_>,
    ctr: &mut Counter,
    rd_keys: *const RdKey,
    rounds: Rounds,
    f: unsafe extern "C" fn(
        input: *const [u8; BLOCK_LEN],
        output: *mut [u8; BLOCK_LEN],
        blocks: c::NonZero_size_t,
        rd_keys: *const RdKey,
        ivec: &Counter,
        rounds: Rounds,
    ),
) {
    in_out.with_input_output_len(|input, output, len| {
        debug_assert_eq!(len % BLOCK_LEN, 0);

        let Some(blocks) = NonZeroUsize::new(len / BLOCK_LEN) else {
            return;
        };

        let input = input.cast_array_::<BLOCK_LEN>();
        let output = output.cast_array_::<BLOCK_LEN>();
        let blocks_u32: NonZeroU32 = blocks.try_into().unwrap();

        // SAFETY:
        //  * `input` points to `blocks` blocks.
        //  * `output` points to space for `blocks` blocks to be written.
        //  * input == output.add(n), where n == src.start, and the caller is
        //    responsible for ensuing this sufficient for `f` to work correctly.
        //  * `blocks` is non-zero so `f` doesn't have to work for empty slices.
        //  * The caller is responsible for ensuring `rd_keys` points to
        //    `rounds` round keys in the representation that `f` requires.
        unsafe {
            f(input, output, blocks, rd_keys, ctr, rounds);
        }

        ctr.increment_by_less_safe(blocks_u32);
    });
}
