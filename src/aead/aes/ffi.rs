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

use super::{Overlapping, BLOCK_LEN};
use crate::c;
use core::num::{NonZeroU32, NonZeroUsize};

/// nonce || big-endian counter.
#[repr(transparent)]
pub(in super::super) struct Counter(pub(super) [u8; BLOCK_LEN]);

macro_rules! define_key_bssl {
    {
        $( #[$t_attr:meta] )*
        $t_vis:vis $T:ident
    } => {
        // Upstream uses a single `AES_KEY` struct with this shape for every
        // representation, but where the values in `rd_key` and `rounds` are
        // specific to the implementation that created the key. Instead we
        // define a new type `$T` for each representation.
        #[repr(C)]
        $( #[$t_attr] )*
        $t_vis struct $T {
            rd_key: [[u32; 4]; $crate::aead::aes::ffi::MAX_ROUNDS + 1],
            rounds: core::ffi::c_uint,
        }

        impl $T {
            #[inline]
            unsafe fn new_with_set_encrypt_key(
                f: unsafe extern "C" fn(
                    *const u8,
                    $crate::bits::BitLength<core::ffi::c_int>,
                    *mut Self
                ) -> core::ffi::c_int,
                bytes: KeyBytes<'_>,
            ) -> Self {
                use $crate::{aead::aes::KeyBytes, bits::BitLength};
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

            fn invalid_zero() -> Self {
                Self {
                    rd_key: [[0; 4]; $crate::aead::aes::ffi::MAX_ROUNDS + 1],
                    rounds: 0,
                }
            }
        }
    }
}

// `AES_MAXNR` in BoringSSL's aes.h.
pub(super) const MAX_ROUNDS: usize = 14;

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
    ( $Key:ty, $name:ident, $key_bytes:expr $(,)? ) => {{
        use crate::bits::BitLength;
        use core::ffi::c_int;
        prefixed_extern! {
            fn $name(user_key: *const u8, bits: BitLength<c_int>, key: *mut $Key) -> c_int;
        }
        <$Key>::new_with_set_encrypt_key($name, $key_bytes)
    }};
}

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
macro_rules! declare_ctr32_encrypt_blocks {
    { $K:ty, $f:ident } => {
        prefixed_extern! {
            fn $f(
                input: *const [u8; $crate::aead::aes::BLOCK_LEN],
                output: *mut [u8; $crate::aead::aes::BLOCK_LEN],
                blocks: crate::c::NonZero_size_t,
                key: &$K,
                ivec: &$crate::aead::aes::Counter,
            );
        }
    };
}

#[inline]
pub(super) fn ctr32_encrypt_blocks(
    in_out: Overlapping<'_>,
    ctr: &mut Counter,
    f: impl FnOnce(
        /*input: */ *const [u8; BLOCK_LEN],
        /*output: */ *mut [u8; BLOCK_LEN],
        /*blocks: */ c::NonZero_size_t,
        /*ivec: */ &Counter,
    ),
) {
    in_out.with_input_output_len(|input, output, len| {
        debug_assert_eq!(len % BLOCK_LEN, 0);

        let blocks = match NonZeroUsize::new(len / BLOCK_LEN) {
            Some(blocks) => blocks,
            None => {
                return;
            }
        };

        let input: *const [u8; BLOCK_LEN] = input.cast();
        let output: *mut [u8; BLOCK_LEN] = output.cast();
        let blocks_u32: NonZeroU32 = blocks.try_into().unwrap();

        f(input, output, blocks, ctr);

        ctr.increment_by_less_safe(blocks_u32);
    });
}
