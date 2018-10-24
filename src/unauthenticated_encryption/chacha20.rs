// Copyright 2018 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
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

use crate::{c, core, error, polyfill, unauthenticated_encryption};
use polyfill::slice::u32_from_le_u8;

/// ChaCha20 unauthenticated stream cipher.
///
/// The keys are 256 bits long and the nonces are 128 bits long, rather then
/// the usual 96 bits. The first 32 bits of the 128-bit nonce represents an
/// explicit initial counter parameter.
pub static CHACHA20: unauthenticated_encryption::Algorithm =
                                        unauthenticated_encryption::Algorithm {
    key_len: KEY_LEN_IN_BYTES,
    init: chacha20_init,
    xor_in_place: chacha20_do_xor_in_place,
    id: unauthenticated_encryption::AlgorithmID::CHACHA20,
    max_input_len: max_input_len!(CHACHA20_BLOCK_LEN,
                                  CHACHA20_OVERHEAD_BLOCKS_PER_NONCE),
};

fn chacha20_do_xor_in_place(ctx: &[u64; unauthenticated_encryption::KEY_CTX_BUF_ELEMS],
                          nonce: &[u8; unauthenticated_encryption::NONCE_LEN],
                          in_out: &mut [u8]) -> Result<(), error::Unspecified> {
    let chacha20_key = ctx_as_key(ctx)?;
    let counter = u32_from_le_u8(slice_as_array_ref!(&nonce[0..4], 4)?);
    let nonce = slice_as_array_ref!(&nonce[4..16], NONCE_LEN)?;
    let counter = make_counter(nonce, counter);
    chacha20_xor_in_place(&chacha20_key, &counter, in_out);
    Ok(())
}

pub fn ctx_as_key(ctx: &[u64; unauthenticated_encryption::KEY_CTX_BUF_ELEMS])
              -> Result<&Key, error::Unspecified> {
    slice_as_array_ref!(
        &polyfill::slice::u64_as_u32(ctx)[..(KEY_LEN_IN_BYTES / 4)],
        KEY_LEN_IN_BYTES / 4)
}

pub(crate) type Key = [u32; KEY_LEN_IN_BYTES / 4];

pub(crate) const CHACHA20_BLOCK_LEN: u64 = 64;
pub(crate) const CHACHA20_OVERHEAD_BLOCKS_PER_NONCE: u64 = 1;

pub(crate) fn key_from_bytes(key_bytes: &[u8; KEY_LEN_IN_BYTES]) -> Key {
    let mut key = [0u32; KEY_LEN_IN_BYTES / 4];
    for (key_u32, key_u8_4) in key.iter_mut().zip(key_bytes.chunks(4)) {
        *key_u32 = u32_from_le_u8(slice_as_array_ref!(key_u8_4, 4).unwrap());
    }
    key
}

/// Copies |key| into |ctx_buf|.
pub(crate) fn chacha20_init(ctx_buf: &mut [u8], key: &[u8])
                              -> Result<(), error::Unspecified> {
    ctx_buf[..key.len()].copy_from_slice(key);
    Ok(())
}

#[inline]
pub(crate) fn chacha20_xor_in_place(key: &Key, counter: &Counter, in_out: &mut [u8]) {
    chacha20_xor_inner(key, counter, in_out.as_ptr(), in_out.len(),
                       in_out.as_mut_ptr());
}

pub(crate) fn chacha20_xor_overlapping(key: &Key, counter: &Counter,
                                in_out: &mut [u8], in_prefix_len: usize) {
    // XXX: The x86 and at least one branch of the ARM assembly language
    // code doesn't allow overlapping input and output unless they are
    // exactly overlapping. TODO: Figure out which branch of the ARM code
    // has this limitation and come up with a better solution.
    //
    // https://rt.openssl.org/Ticket/Display.html?id=4362
    let len = in_out.len() - in_prefix_len;
    if cfg!(any(target_arch = "arm", target_arch = "x86")) &&
            in_prefix_len != 0 {
        unsafe {
            core::ptr::copy(in_out[in_prefix_len..].as_ptr(),
                            in_out.as_mut_ptr(), len);
        }
        chacha20_xor_in_place(key, &counter, &mut in_out[..len]);
    } else {
        chacha20_xor_inner(key, counter, in_out[in_prefix_len..].as_ptr(),
                           len, in_out.as_mut_ptr());
    }
}

#[inline]
fn chacha20_xor_inner(key: &Key, counter: &Counter, input: *const u8,
                          in_out_len: usize, output: *mut u8) {
    debug_assert!(core::mem::align_of_val(key) >= 4);
    debug_assert!(core::mem::align_of_val(counter) >= 4);
    unsafe {
        GFp_ChaCha20_ctr32(output, input, in_out_len, key, counter);
    }
}

pub(crate) type Counter = [u32; 4];

#[inline]
pub(crate) fn make_counter(nonce: &[u8; NONCE_LEN], counter: u32) -> Counter {
    [counter.to_le(),
     u32_from_le_u8(slice_as_array_ref!(&nonce[0..4], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[4..8], 4).unwrap()),
     u32_from_le_u8(slice_as_array_ref!(&nonce[8..12], 4).unwrap())]
}

extern {
    fn GFp_ChaCha20_ctr32(out: *mut u8, in_: *const u8, in_len: c::size_t,
                          key: &Key, counter: &Counter);
}

pub(crate) const KEY_LEN_IN_BYTES: usize = 256 / 8;

pub(crate) const NONCE_LEN: usize = 12; /* 96 bits */

#[cfg(test)]
mod tests {
    use test;
    use super::*;
    use super::GFp_ChaCha20_ctr32;

    // This verifies the encryption functionality provided by ChaCha20_ctr32
    // is successful when either computed on disjoint input/output buffers,
    // or on overlapping input/output buffers. On some branches of the 32-bit
    // x86 and ARM code the in-place operation fails in some situations where
    // the input/output buffers are not exactly overlapping. Such failures are
    // dependent not only on the degree of overlapping but also the length of
    // the data. `open()` works around that by moving the input data to the
    // output location so that the buffers exactly overlap, for those targets.
    // This test exists largely as a canary for detecting if/when that type of
    // problem spreads to other platforms.
    #[test]
    pub fn chacha20_tests() {
        test::from_file("src/chacha_tests.txt", |section, test_case| {
            assert_eq!(section, "");

            let key = test_case.consume_bytes("Key");
            let key = slice_as_array_ref!(&key, KEY_LEN_IN_BYTES)?;
            let key = key_from_bytes(key);

            let ctr = test_case.consume_usize("Ctr");
            let nonce_bytes = test_case.consume_bytes("Nonce");
            let nonce = slice_as_array_ref!(&nonce_bytes, NONCE_LEN).unwrap();
            let ctr = make_counter(&nonce, ctr as u32);
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("Output");

            // Pre-allocate buffer for use in test_cases.
            let mut in_out_buf = vec![0u8; input.len() + 276];

            // Run the test case over all prefixes of the input because the
            // behavior of ChaCha20 implementation changes dependent on the
            // length of the input.
            for len in 0..(input.len() + 1) {
                chacha20_test_case_inner(&key, &ctr, &input[..len],
                                         &output[..len], len, &mut in_out_buf);
            }

            Ok(())
        });
    }

    fn chacha20_test_case_inner(key: &Key, ctr: &Counter, input: &[u8],
                                expected: &[u8], len: usize,
                                in_out_buf: &mut [u8]) {
        // Straightforward encryption into disjoint buffers is computed
        // correctly.
        unsafe {
          GFp_ChaCha20_ctr32(in_out_buf.as_mut_ptr(), input[..len].as_ptr(),
                             len, key, &ctr);
        }
        assert_eq!(&in_out_buf[..len], expected);

        // Do not test offset buffers for x86 and ARM architectures (see above
        // for rationale).
        let max_offset =
            if cfg!(any(target_arch = "x86", target_arch = "arm")) {
                0
            } else {
                259
            };

        // Check that in-place encryption works successfully when the pointers
        // to the input/output buffers are (partially) overlapping.
        for alignment in 0..16 {
            for offset in 0..(max_offset + 1) {
              in_out_buf[alignment+offset..][..len].copy_from_slice(input);
              unsafe {
                  GFp_ChaCha20_ctr32(in_out_buf[alignment..].as_mut_ptr(),
                                     in_out_buf[alignment + offset..].as_ptr(),
                                     len, key, ctr);
                  assert_eq!(&in_out_buf[alignment..][..len], expected);
              }
            }
        }
    }
}
