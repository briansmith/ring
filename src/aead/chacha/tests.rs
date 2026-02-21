// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
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

extern crate alloc;

use super::super::{chacha::*, overlapping::IndexError};
use crate::error;
use crate::testutil as test;
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
    chacha20_test(max_offset, Key::encrypt);
}

// Smoketest the fallback implementation.
#[test]
fn chacha20_test_fallback() {
    chacha20_test(MAX_ALIGNMENT_AND_OFFSET_SUBSET, |key, ctr, in_out, _cpu| {
        fallback::ChaCha20_ctr32(key, ctr, in_out)
    });
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
    f: impl for<'k, 'o> Fn(&'k Key, Counter, Overlapping<'o>, cpu::Features),
) {
    let cpu = cpu::features();

    // Reuse a buffer to avoid slowing down the tests with allocations.
    let mut buf = vec![0u8; 1300];

    test::run(
        test_vector_file!("chacha_tests.txt"),
        move |section, test_case| {
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
                    cpu,
                    &f,
                );
            }

            Ok(())
        },
    );
}

fn chacha20_test_case_inner(
    key: &Key,
    nonce: &[u8],
    ctr: u32,
    input: &[u8],
    expected: &[u8],
    buf: &mut [u8],
    (max_alignment, max_offset): (usize, usize),
    cpu: cpu::Features,
    f: &impl for<'k, 'o> Fn(&'k Key, Counter, Overlapping<'o>, cpu::Features),
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

            let ctr =
                Counter::from_nonce_and_ctr(Nonce::try_assume_unique_for_key(nonce).unwrap(), ctr);
            let in_out = Overlapping::new(buf, src)
                .map_err(error::erase::<IndexError>)
                .unwrap();
            f(key, ctr, in_out, cpu);
            assert_eq!(&buf[..input.len()], expected)
        }
    }
}
