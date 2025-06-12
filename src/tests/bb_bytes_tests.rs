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
    error, rand,
};

#[test]
fn constant_time_conditional_memcpy() -> Result<(), error::Unspecified> {
    let rng = rand::SystemRandom::new();
    for _ in 0..100 {
        let mut out = rand::generate::<[u8; 256]>(&rng)?.expose();
        let input = rand::generate::<[u8; 256]>(&rng)?.expose();

        // Mask to 16 bits to make zero more likely than it would otherwise be.
        let b = (rand::generate::<[u8; 1]>(&rng)?.expose()[0] & 0x0f) == 0;

        let ref_in = input;
        let ref_out = if b { input } else { out };

        prefixed_extern! {
            fn bssl_constant_time_test_conditional_memcpy(dst: &mut [u8; 256], src: &[u8; 256], b: BoolMask);
        }
        unsafe {
            bssl_constant_time_test_conditional_memcpy(
                &mut out,
                &input,
                if b { BoolMask::TRUE } else { BoolMask::FALSE },
            )
        }
        assert_eq!(ref_in, input);
        assert_eq!(ref_out, out);
    }

    Ok(())
}

#[test]
fn constant_time_conditional_memxor() -> Result<(), error::Unspecified> {
    let rng = rand::SystemRandom::new();
    for _ in 0..256 {
        let mut out = rand::generate::<[u8; 256]>(&rng)?.expose();
        let input = rand::generate::<[u8; 256]>(&rng)?.expose();

        // Mask to 16 bits to make zero more likely than it would otherwise be.
        let b = (rand::generate::<[u8; 1]>(&rng)?.expose()[0] & 0x0f) != 0;

        let ref_in = input;
        let mut ref_out = out;
        if b {
            xor_assign_at_start_bytes(&mut ref_out, &ref_in)
        };

        prefixed_extern! {
            fn bssl_constant_time_test_conditional_memxor(dst: &mut [u8; 256], src: &[u8; 256], b: BoolMask);
        }
        unsafe {
            bssl_constant_time_test_conditional_memxor(
                &mut out,
                &input,
                if b { BoolMask::TRUE } else { BoolMask::FALSE },
            );
        }

        assert_eq!(ref_in, input);
        assert_eq!(ref_out, out);
    }

    Ok(())
}
