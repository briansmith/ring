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

use super::{KeyBytes, OverlappingBlocks, BLOCK_LEN};
use crate::{bits::BitLength, c, polyfill::nonzero_u32_try_from_nonzero_usize};
use core::{
    ffi::{c_int, c_uint},
    num::NonZeroUsize,
};

/// nonce || big-endian counter.
#[repr(transparent)]
pub(in super::super) struct Counter(pub(super) [u8; BLOCK_LEN]);

// `AES_KEY` in BoringSSL's aes.h.
#[repr(C)]
#[derive(Clone)]
pub(in super::super) struct AES_KEY {
    rd_key: [[u32; 4]; MAX_ROUNDS + 1],
    rounds: c_uint,
}

// `AES_MAXNR` in BoringSSL's aes.h.
const MAX_ROUNDS: usize = 14;

impl AES_KEY {
    #[inline]
    pub(super) unsafe fn new(
        f: unsafe extern "C" fn(*const u8, BitLength<c_int>, *mut AES_KEY) -> c_int,
        bytes: KeyBytes<'_>,
    ) -> Self {
        let mut key = Self::invalid_zero();

        let (bytes, key_bits) = match bytes {
            KeyBytes::AES_128(bytes) => (&bytes[..], BitLength::from_bits(128)),
            KeyBytes::AES_256(bytes) => (&bytes[..], BitLength::from_bits(256)),
        };

        // Unusually, in this case zero means success and non-zero means failure.
        let r = unsafe { f(bytes.as_ptr(), key_bits, &mut key) };
        assert_eq!(r, 0);
        key
    }

    pub(super) fn invalid_zero() -> Self {
        Self {
            rd_key: [[0; 4]; MAX_ROUNDS + 1],
            rounds: 0,
        }
    }
}

#[cfg(all(target_arch = "arm", target_endian = "little"))]
impl AES_KEY {
    pub(super) unsafe fn derive(
        f: for<'a> unsafe extern "C" fn(*mut AES_KEY, &'a AES_KEY),
        src: &Self,
    ) -> Self {
        let mut r = Self::invalid_zero();
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
//    encryption/decryption functions.
//  * `$name` must return 1 when given 128 or 256 for `bits`.
//
// In BoringSSL, the C prototypes for these are in
// crypto/fipsmodule/aes/internal.h.
macro_rules! set_encrypt_key {
    ( $name:ident, $key_bytes:expr $(,)? ) => {{
        use crate::bits::BitLength;
        use core::ffi::c_int;
        prefixed_extern! {
            fn $name(user_key: *const u8, bits: BitLength<c_int>, key: *mut AES_KEY) -> c_int;
        }
        $crate::aead::aes::ffi::AES_KEY::new($name, $key_bytes)
    }};
}

/// SAFETY:
///   * The caller must ensure that `$key` was initialized with the
///     `set_encrypt_key!` invocation that `$name` requires.
///   * The caller must ensure that fhe function `$name` satisfies the conditions
///     for the `f` parameter to `ctr32_encrypt_blocks`.
macro_rules! ctr32_encrypt_blocks {
    ($name:ident, $in_out:expr, $key:expr, $ctr:expr $(,)? ) => {{
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
        $key.ctr32_encrypt_blocks($name, $in_out, $ctr)
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
    ///     that corresponds to `f`.
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
        in_out: OverlappingBlocks<'_>,
        ctr: &mut Counter,
    ) {
        in_out.with_input_output_blocks(|input, output, blocks| {
            let Some(blocks) = NonZeroUsize::new(blocks) else {
                return;
            };
            let blocks_u32 = nonzero_u32_try_from_nonzero_usize(blocks).unwrap();
            let input: *const [u8; BLOCK_LEN] = input.cast();
            let output: *mut [u8; BLOCK_LEN] = output.cast();

            // SAFETY:
            //  * `input` points to `blocks` blocks.
            //  * `output` points to space for `blocks` blocks to be written.
            //  * input == output.add(n), where n == src.start, and the caller is
            //    responsible for ensuing this sufficient for `f` to work correctly.
            //  * `blocks` is non-zero so `f` doesn't have to work for empty slices.
            //  * The caller is responsible for ensuring `key` was initialized by the
            //    `set_encrypt_key!` invocation required by `f`.
            unsafe {
                f(input, output, blocks, self, ctr);
            }

            ctr.increment_by_less_safe(blocks_u32);
        });
    }
}
