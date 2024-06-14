// Copyright 2018-2024 Brian Smith.
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

use super::{Block, KeyBytes, BLOCK_LEN};
use crate::{bits::BitLength, c, cpu, error, polyfill::slice};
use core::{num::NonZeroUsize, ops::RangeFrom};

/// nonce || big-endian counter.
#[repr(transparent)]
pub(in super::super) struct Counter(pub(super) [u8; BLOCK_LEN]);

// Keep this in sync with AES_KEY in aes.h.
#[repr(C)]
#[derive(Clone)]
pub(in super::super) struct AES_KEY {
    pub rd_key: [u32; 4 * (MAX_ROUNDS + 1)],
    pub rounds: c::uint,
}

// Keep this in sync with `AES_MAXNR` in aes.h.
const MAX_ROUNDS: usize = 14;

impl AES_KEY {
    #[inline]
    pub(super) unsafe fn new(
        f: unsafe extern "C" fn(*const u8, BitLength<c::int>, *mut AES_KEY) -> c::int,
        bytes: KeyBytes<'_>,
        _cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let mut key = Self {
            rd_key: [0; 4 * (MAX_ROUNDS + 1)],
            rounds: 0,
        };

        let (bytes, key_bits) = match bytes {
            KeyBytes::AES_128(bytes) => (&bytes[..], BitLength::from_bits(128)),
            KeyBytes::AES_256(bytes) => (&bytes[..], BitLength::from_bits(256)),
        };

        // Unusually, in this case zero means success and non-zero means failure.
        if 0 == unsafe { f(bytes.as_ptr(), key_bits, &mut key) } {
            debug_assert_ne!(key.rounds, 0); // Sanity check initialization.
            Ok(key)
        } else {
            Err(error::Unspecified)
        }
    }
}

#[cfg(target_arch = "arm")]
impl AES_KEY {
    pub(super) unsafe fn derive(
        f: for<'a> unsafe extern "C" fn(*mut AES_KEY, &'a AES_KEY),
        src: &Self,
        _cpu_features: cpu::Features,
    ) -> Self {
        let mut r = AES_KEY {
            rd_key: [0u32; 4 * (MAX_ROUNDS + 1)],
            rounds: 0,
        };
        unsafe { f(&mut r, src) };
        r
    }

    pub(super) fn rounds(&self) -> u32 {
        self.rounds
    }
}

// SAFETY:
//  * The function `$name` must read `bits` bits from `user_key`; `bits` will
//    always be a valid AES key length, i.e. a whole number of bytes.
//  * `$name` must set `key.rounds` to the value expected by the corresponding
//    encryption/decryption functions and return 0, or otherwise must return
//    non-zero to indicate failure.
//  * `$name` may inspect CPU features.
//
// In BoringSSL, the C prototypes for these are in
// crypto/fipsmodule/aes/internal.h.
macro_rules! set_encrypt_key {
    ( $name:ident, $key_bytes:expr, $cpu_features:expr $(,)? ) => {{
        use crate::{bits::BitLength, c};
        prefixed_extern! {
            fn $name(user_key: *const u8, bits: BitLength<c::int>, key: *mut AES_KEY) -> c::int;
        }
        $crate::aead::aes::ffi::AES_KEY::new($name, $key_bytes, $cpu_features)
    }};
}

macro_rules! encrypt_block {
    ($name:ident, $block:expr, $key:expr) => {{
        use crate::aead::aes::{ffi::AES_KEY, Block};
        prefixed_extern! {
            fn $name(a: &Block, r: *mut Block, key: &AES_KEY);
        }
        $key.encrypt_block($name, $block)
    }};
}

impl AES_KEY {
    #[inline]
    pub(super) unsafe fn encrypt_block(
        &self,
        f: unsafe extern "C" fn(&Block, *mut Block, &AES_KEY),
        a: Block,
    ) -> Block {
        let mut result = core::mem::MaybeUninit::uninit();
        unsafe {
            f(&a, result.as_mut_ptr(), self);
            result.assume_init()
        }
    }
}

/// SAFETY:
///   * The caller must ensure that `$key` was initialized with the
///     `set_encrypt_key!` invocation that `$name` requires.
///   * The caller must ensure that fhe function `$name` satisfies the conditions
///     for the `f` parameter to `ctr32_encrypt_blocks`.
macro_rules! ctr32_encrypt_blocks {
    ($name:ident, $in_out:expr, $src:expr, $key:expr, $ctr:expr, $cpu_features:expr ) => {{
        use crate::{
            aead::aes::{ffi::AES_KEY, Counter, BLOCK_LEN},
            c,
        };
        prefixed_extern! {
            fn $name(
                input: *const [u8; BLOCK_LEN],
                output: *mut [u8; BLOCK_LEN],
                blocks: c::NonZero_size_t,
                key: &AES_KEY,
                ivec: &Counter,
            );
        }
        $key.ctr32_encrypt_blocks($name, $in_out, $src, $ctr, $cpu_features)
    }};
}

impl AES_KEY {
    /// SAFETY:
    ///   * `f` must not read more than `blocks` blocks from `input`.
    ///   * `f` must write exactly `block` blocks to `output`.
    ///   * In particular, `f` must handle blocks == 0 without reading from `input`
    ///     or writing to `output`.
    ///   * `f` must support the input overlapping with the output exactly or
    ///     with any nonnegative offset `n` (i.e. `input == output.add(n)`);
    ///     `f` does NOT need to support the cases where input < output.
    ///   * `key` must have been initialized with the `set_encrypt_key!` invocation
    ///      that corresponds to `f`.
    ///   * `f` may inspect CPU features.
    #[inline]
    pub(super) unsafe fn ctr32_encrypt_blocks(
        &self,
        f: unsafe extern "C" fn(
            input: *const [u8; BLOCK_LEN],
            output: *mut [u8; BLOCK_LEN],
            blocks: c::NonZero_size_t,
            key: &AES_KEY,
            ivec: &Counter,
        ),
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        ctr: &mut Counter,
        cpu_features: cpu::Features,
    ) {
        let (input, leftover) = slice::as_chunks(&in_out[src]);
        debug_assert_eq!(leftover.len(), 0);

        let blocks = match NonZeroUsize::new(input.len()) {
            Some(blocks) => blocks,
            None => {
                return;
            }
        };

        let blocks_u32: u32 = blocks.get().try_into().unwrap();

        let input = input.as_ptr();
        let output: *mut [u8; BLOCK_LEN] = in_out.as_mut_ptr().cast();

        let _: cpu::Features = cpu_features;

        // SAFETY:
        //  * `input` points to `blocks` blocks.
        //  * `output` points to space for `blocks` blocks to be written.
        //  * input == output.add(n), where n == src.start, and the caller is
        //    responsible for ensuing this sufficient for `f` to work correctly.
        //  * The caller is responsible for ensuring `f` can handle any value of
        //    `blocks` including zero.
        //  * The caller is responsible for ensuring `key` was initialized by the
        //    `set_encrypt_key!` invocation required by `f`.
        //  * CPU feature detection has been done so `f` can inspect
        //    CPU features.
        unsafe {
            f(input, output, blocks, self, ctr);
        }

        ctr.increment_by_less_safe(blocks_u32);
    }
}
