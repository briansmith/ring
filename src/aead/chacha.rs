// Copyright 2016 Brian Smith.
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

use super::{quic::Sample, Nonce};

#[cfg(any(
    test,
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64"
    ))
))]
mod fallback;

use crate::polyfill::ArraySplitMap;
use core::ops::RangeFrom;

#[derive(Clone)]
pub struct Key {
    words: [u32; KEY_LEN / 4],
}

impl Key {
    pub(super) fn new(value: [u8; KEY_LEN]) -> Self {
        Self {
            words: value.array_split_map(u32::from_le_bytes),
        }
    }
}

impl Key {
    #[inline]
    pub fn encrypt_in_place(&self, counter: Counter, in_out: &mut [u8]) {
        self.encrypt_less_safe(counter, in_out, 0..);
    }

    #[inline]
    pub fn encrypt_iv_xor_in_place(&self, iv: Iv, in_out: &mut [u8; 32]) {
        // It is safe to use `into_counter_for_single_block_less_safe()`
        // because `in_out` is exactly one block long.
        debug_assert!(in_out.len() <= BLOCK_LEN);
        self.encrypt_less_safe(iv.into_counter_for_single_block_less_safe(), in_out, 0..);
    }

    #[inline]
    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let mut out: [u8; 5] = [0; 5];
        let iv = Iv::assume_unique_for_key(sample);

        debug_assert!(out.len() <= BLOCK_LEN);
        self.encrypt_less_safe(iv.into_counter_for_single_block_less_safe(), &mut out, 0..);

        out
    }

    /// Analogous to `slice::copy_within()`.
    pub fn encrypt_within(&self, counter: Counter, in_out: &mut [u8], src: RangeFrom<usize>) {
        // XXX: The x86 and at least one branch of the ARM assembly language
        // code doesn't allow overlapping input and output unless they are
        // exactly overlapping. TODO: Figure out which branch of the ARM code
        // has this limitation and come up with a better solution.
        //
        // https://rt.openssl.org/Ticket/Display.html?id=4362
        if cfg!(any(target_arch = "arm", target_arch = "x86")) && src.start != 0 {
            let len = in_out.len() - src.start;
            in_out.copy_within(src, 0);
            self.encrypt_in_place(counter, &mut in_out[..len]);
        } else {
            self.encrypt_less_safe(counter, in_out, src);
        }
    }

    /// This is "less safe" because it skips the important check that `encrypt_within` does.
    /// Only call this with `src` equal to `0..` or from `encrypt_within`.
    #[inline]
    fn encrypt_less_safe(&self, counter: Counter, in_out: &mut [u8], src: RangeFrom<usize>) {
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        #[inline(always)]
        pub(super) fn ChaCha20_ctr32(
            key: &Key,
            counter: Counter,
            in_out: &mut [u8],
            src: RangeFrom<usize>,
        ) {
            let in_out_len = in_out.len().checked_sub(src.start).unwrap();

            // There's no need to worry if `counter` is incremented because it is
            // owned here and we drop immediately after the call.
            prefixed_extern! {
                fn ChaCha20_ctr32(
                    out: *mut u8,
                    in_: *const u8,
                    in_len: crate::c::size_t,
                    key: &[u32; KEY_LEN / 4],
                    counter: &Counter,
                );
            }
            unsafe {
                ChaCha20_ctr32(
                    in_out.as_mut_ptr(),
                    in_out[src].as_ptr(),
                    in_out_len,
                    key.words_less_safe(),
                    &counter,
                )
            }
        }

        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        )))]
        use fallback::ChaCha20_ctr32;

        ChaCha20_ctr32(self, counter, in_out, src);
    }

    #[inline]
    pub(super) fn words_less_safe(&self) -> &[u32; KEY_LEN / 4] {
        &self.words
    }
}

/// Counter || Nonce, all native endian.
#[repr(transparent)]
pub struct Counter([u32; 4]);

impl Counter {
    pub fn zero(nonce: Nonce) -> Self {
        Self::from_nonce_and_ctr(nonce, 0)
    }

    fn from_nonce_and_ctr(nonce: Nonce, ctr: u32) -> Self {
        let [n0, n1, n2] = nonce.as_ref().array_split_map(u32::from_le_bytes);
        Self([ctr, n0, n1, n2])
    }

    pub fn increment(&mut self) -> Iv {
        let iv = Iv(self.0);
        self.0[0] += 1;
        iv
    }

    /// This is "less safe" because it hands off management of the counter to
    /// the caller.
    #[cfg(any(
        test,
        not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        ))
    ))]
    fn into_words_less_safe(self) -> [u32; 4] {
        self.0
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv([u32; 4]);

impl Iv {
    fn assume_unique_for_key(value: [u8; 16]) -> Self {
        Self(value.array_split_map(u32::from_le_bytes))
    }

    fn into_counter_for_single_block_less_safe(self) -> Counter {
        Counter(self.0)
    }
}

pub const KEY_LEN: usize = 32;

const BLOCK_LEN: usize = 64;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::test;
    use alloc::vec;

    const MAX_ALIGNMENT_AND_OFFSET: (usize, usize) = (15, 259);
    const MAX_ALIGNMENT_AND_OFFSET_SUBSET: (usize, usize) =
        if cfg!(any(debug_assertions = "false", feature = "slow_tests")) {
            MAX_ALIGNMENT_AND_OFFSET
        } else {
            (0, 0)
        };

    #[test]
    fn chacha20_test_default() {
        // Always use `MAX_OFFSET` if we hav assembly code.
        let max_offset = if cfg!(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        )) {
            MAX_ALIGNMENT_AND_OFFSET
        } else {
            MAX_ALIGNMENT_AND_OFFSET_SUBSET
        };
        chacha20_test(max_offset, Key::encrypt_within);
    }

    // Smoketest the fallback implementation.
    #[test]
    fn chacha20_test_fallback() {
        chacha20_test(MAX_ALIGNMENT_AND_OFFSET_SUBSET, fallback::ChaCha20_ctr32);
    }

    // Verifies the encryption is successful when done on overlapping buffers.
    //
    // On some branches of the 32-bit x86 and ARM assembly code the in-place
    // operation fails in some situations where the input/output buffers are
    // not exactly overlapping. Such failures are dependent not only on the
    // degree of overlapping but also the length of the data. `encrypt_within`
    // works around that.
    fn chacha20_test(
        max_alignment_and_offset: (usize, usize),
        f: impl for<'k, 'i> Fn(&'k Key, Counter, &'i mut [u8], RangeFrom<usize>),
    ) {
        // Reuse a buffer to avoid slowing down the tests with allocations.
        let mut buf = vec![0u8; 1300];

        test::run(test_file!("chacha_tests.txt"), move |section, test_case| {
            assert_eq!(section, "");

            let key = test_case.consume_bytes("Key");
            let key: &[u8; KEY_LEN] = key.as_slice().try_into()?;
            let key = Key::new(*key);

            let ctr = test_case.consume_usize("Ctr");
            let nonce = test_case.consume_bytes("Nonce");
            let input = test_case.consume_bytes("Input");
            let output = test_case.consume_bytes("Output");

            // Run the test case over all prefixes of the input because the
            // behavior of ChaCha20 implementation changes dependent on the
            // length of the input.
            for len in 0..=input.len() {
                #[allow(clippy::cast_possible_truncation)]
                chacha20_test_case_inner(
                    &key,
                    &nonce,
                    ctr as u32,
                    &input[..len],
                    &output[..len],
                    &mut buf,
                    max_alignment_and_offset,
                    &f,
                );
            }

            Ok(())
        });
    }

    fn chacha20_test_case_inner(
        key: &Key,
        nonce: &[u8],
        ctr: u32,
        input: &[u8],
        expected: &[u8],
        buf: &mut [u8],
        (max_alignment, max_offset): (usize, usize),
        f: &impl for<'k, 'i> Fn(&'k Key, Counter, &'i mut [u8], RangeFrom<usize>),
    ) {
        const ARBITRARY: u8 = 123;

        for alignment in 0..=max_alignment {
            buf[..alignment].fill(ARBITRARY);
            let buf = &mut buf[alignment..];
            for offset in 0..=max_offset {
                let buf = &mut buf[..(offset + input.len())];
                buf[..offset].fill(ARBITRARY);
                let src = offset..;
                buf[src.clone()].copy_from_slice(input);

                let ctr = Counter::from_nonce_and_ctr(
                    Nonce::try_assume_unique_for_key(nonce).unwrap(),
                    ctr,
                );
                f(key, ctr, buf, src);
                assert_eq!(&buf[..input.len()], expected)
            }
        }
    }
}
