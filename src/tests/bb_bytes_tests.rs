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
    bb::{xor_assign_at_start_bytes, BoolMask},
    rand,
};
use core::hint::black_box;

#[test]
fn constant_time_conditional_memcpy() {
    test_constant_time_conditional_mem_x(
        |b, out, input| {
            prefixed_extern! {
                fn bssl_constant_time_test_conditional_memcpy(dst: &mut [u8; 256], src: &[u8; 256], b: BoolMask);
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
    test_constant_time_conditional_mem_x(
        |b, out, input| {
            prefixed_extern! {
                fn bssl_constant_time_test_conditional_memxor(dst: &mut [u8; 256], src: &[u8; 256], b: BoolMask);
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
    for _ in 0..256 {
        let mut out = rand::generate::<[u8; LEN]>(&rng).unwrap().expose();
        let input = rand::generate::<[u8; LEN]>(&rng).unwrap().expose();

        let mut ref_out: [u8; LEN] = out;
        let ref_in: [u8; LEN] = input;

        // Mask to 16 bits to make zero more likely than it would otherwise be.
        let b = if (rand::generate::<[u8; 1]>(&rng).unwrap().expose()[0] & 0x0f) == 0 {
            BoolMask::true_()
        } else {
            BoolMask::false_()
        };

        f(b, &mut out, &input);
        ref_f(black_box(b).leak(), &mut ref_out, &ref_in);
        assert_eq!(ref_in, input);
        assert_eq!(&ref_out, &out);
    }
}
