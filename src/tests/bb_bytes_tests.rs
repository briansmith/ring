// Copyright 2015-2025 Brian Smith.
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

//! Building blocks.

use crate::{
    bb::{BoolMask, xor_assign_at_start_bytes},
    rand,
};

#[test]
fn constant_time_conditional_memcpy() {
    const LEN: usize = 4 * size_of::<u64>();
    test_constant_time_conditional_mem_x::<LEN>(
        |b, out, input| {
            prefixed_extern! {
                unsafe fn bssl_constant_time_test_conditional_memcpy(dst: &mut [u8; LEN], src: &[u8; LEN], b: BoolMask);
            }
            unsafe { bssl_constant_time_test_conditional_memcpy(out, input, b) }
        },
        |b, out, input| {
            if b {
                *out = *input;
            }
        },
    )
}

#[test]
fn constant_time_conditional_memxor() {
    const LEN: usize = 3 * 32;
    test_constant_time_conditional_mem_x::<LEN>(
        |b, out, input| {
            prefixed_extern! {
                unsafe fn bssl_constant_time_test_conditional_memxor(dst: &mut [u8; LEN], src: &[u8; LEN], b: BoolMask);
            }
            unsafe {
                bssl_constant_time_test_conditional_memxor(out, input, b);
            }
        },
        |b, out, input| {
            if b {
                xor_assign_at_start_bytes(out, input)
            }
        },
    )
}

// `f`: The implementation being tested.
// `ref_f`: The reference implementation.
fn test_constant_time_conditional_mem_x<const LEN: usize>(
    f: impl Fn(BoolMask, &mut [u8; LEN], &[u8; LEN]),
    ref_f: impl Fn(bool, &mut [u8; LEN], &[u8; LEN]),
) {
    let rng = rand::SystemRandom::new();
    for b in [BoolMask::false_(), BoolMask::true_()] {
        for _ in 0..256 {
            let mut out = rand::generate::<[u8; LEN]>(&rng).unwrap().expose();
            let input = rand::generate::<[u8; LEN]>(&rng).unwrap().expose();

            let mut ref_out: [u8; LEN] = out;
            let ref_in: [u8; LEN] = input;

            f(b, &mut out, &input);
            ref_f(b.leak(), &mut ref_out, &ref_in);

            assert_eq!(ref_in, input);
            assert_eq!(&ref_out, &out);
        }
    }
}
