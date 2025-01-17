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

use super::{overlapping, quic::Sample, Nonce};

#[cfg(any(
    test,
    not(any(
        all(target_arch = "aarch64", target_endian = "little"),
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86",
        target_arch = "x86_64"
    ))
))]
mod fallback;

use crate::polyfill::ArraySplitMap;

pub type Overlapping<'o> = overlapping::Overlapping<'o, u8>;

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
        self.encrypt_within(counter, in_out.into())
    }

    // Encrypts `in_out` with the counter 0 and returns counter 1,
    // where the counter is derived from the nonce `nonce`.
    #[inline]
    pub fn encrypt_single_block_with_ctr_0<const N: usize>(
        &self,
        nonce: Nonce,
        in_out: &mut [u8; N],
    ) -> Counter {
        assert!(N <= BLOCK_LEN);
        let (zero, one) = Counter::zero_one_less_safe(nonce);
        self.encrypt_within(zero, in_out.as_mut().into());
        one
    }

    #[inline]
    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let (ctr, nonce) = sample.split_at(4);
        let ctr = u32::from_le_bytes(ctr.try_into().unwrap());
        let nonce = Nonce::assume_unique_for_key(nonce.try_into().unwrap());
        let ctr = Counter::from_nonce_and_ctr(nonce, ctr);

        let mut out: [u8; 5] = [0; 5];
        self.encrypt_within(ctr, out.as_mut().into());
        out
    }

    #[inline(always)]
    pub fn encrypt_within(&self, counter: Counter, in_out: Overlapping<'_>) {
        #[cfg(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))]
        #[inline(always)]
        pub(super) fn ChaCha20_ctr32(key: &Key, counter: Counter, in_out: Overlapping<'_>) {
            // XXX: The x86 and at least one branch of the ARM assembly language
            // code doesn't allow overlapping input and output unless they are
            // exactly overlapping. TODO: Figure out which branch of the ARM code
            // has this limitation and come up with a better solution.
            //
            // https://rt.openssl.org/Ticket/Display.html?id=4362
            #[cfg(not(any(
                all(target_arch = "aarch64", target_endian = "little"),
                target_arch = "x86_64"
            )))]
            let in_out = Overlapping::from(in_out.copy_within());

            let (input, output, len) = in_out.into_input_output_len();

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
            unsafe { ChaCha20_ctr32(output, input, len, key.words_less_safe(), &counter) }
        }

        #[cfg(not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        )))]
        use fallback::ChaCha20_ctr32;

        ChaCha20_ctr32(self, counter, in_out)
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
    // Nonce-reuse: the caller must only use the first counter (0) for at most
    // a single block.
    fn zero_one_less_safe(nonce: Nonce) -> (Self, Self) {
        let ctr0 @ Self([_, n0, n1, n2]) = Self::from_nonce_and_ctr(nonce, 0);
        let ctr1 = Self([1, n0, n1, n2]);
        (ctr0, ctr1)
    }

    fn from_nonce_and_ctr(nonce: Nonce, ctr: u32) -> Self {
        let [n0, n1, n2] = nonce.as_ref().array_split_map(u32::from_le_bytes);
        Self([ctr, n0, n1, n2])
    }

    /// This is "less safe" because it hands off management of the counter to
    /// the caller.
    #[cfg(any(
        test,
        not(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
            target_arch = "x86",
            target_arch = "x86_64"
        ))
    ))]
    fn into_words_less_safe(self) -> [u32; 4] {
        self.0
    }
}

pub const KEY_LEN: usize = 32;

const BLOCK_LEN: usize = 64;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::{super::overlapping::IndexError, *};
    use crate::{error, test};
    use alloc::vec;

    const MAX_ALIGNMENT_AND_OFFSET: (usize, usize) = (15, 259);
    const MAX_ALIGNMENT_AND_OFFSET_SUBSET: (usize, usize) =
        if cfg!(any(not(debug_assertions), feature = "slow_tests")) {
            MAX_ALIGNMENT_AND_OFFSET
        } else {
            (0, 0)
        };

    #[test]
    fn chacha20_test_default() {
        // Always use `MAX_OFFSET` if we hav assembly code.
        let max_offset = if cfg!(any(
            all(target_arch = "aarch64", target_endian = "little"),
            all(target_arch = "arm", target_endian = "little"),
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
        f: impl for<'k, 'o> Fn(&'k Key, Counter, Overlapping<'o>),
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
        f: &impl for<'k, 'o> Fn(&'k Key, Counter, Overlapping<'o>),
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
                let in_out = Overlapping::new(buf, src)
                    .map_err(error::erase::<IndexError>)
                    .unwrap();
                f(key, ctr, in_out);
                assert_eq!(&buf[..input.len()], expected)
            }
        }
    }
}
