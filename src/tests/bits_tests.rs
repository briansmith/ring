// Copyright 2024 Brian Smith.
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

use crate::{
    polyfill::u64_from_usize,
    {
        bits::{BitLength, FromByteLen as _},
        error,
    },
};

#[test]
fn test_from_byte_len_overflow() {
    const USIZE_MAX_VALID_BYTES: usize = usize::MAX / 8;

    // Maximum valid input for BitLength<usize>.
    {
        let bits = BitLength::<usize>::from_byte_len(USIZE_MAX_VALID_BYTES).unwrap();
        assert_eq!(bits.as_usize_bytes_rounded_up(), USIZE_MAX_VALID_BYTES);
        assert_eq!(bits.as_bits(), usize::MAX & !0b111);
    }

    // Minimum invalid usize input for BitLength<usize>.
    assert_eq!(
        BitLength::<usize>::from_byte_len(USIZE_MAX_VALID_BYTES + 1),
        Err(error::Unspecified)
    );

    // Minimum invalid usize input for BitLength<u64> on 64-bit targets.
    {
        let bits = BitLength::<u64>::from_byte_len(USIZE_MAX_VALID_BYTES + 1);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(bits, Err(error::Unspecified));
        } else {
            let bits = bits.unwrap();
            assert_eq!(
                bits.as_bits(),
                (u64_from_usize(USIZE_MAX_VALID_BYTES) + 1) * 8
            );
        }
    }

    const U64_MAX_VALID_BYTES: u64 = u64::MAX / 8;

    // Maximum valid u64 input for BitLength<u64>.
    {
        let bits = BitLength::<u64>::from_byte_len(U64_MAX_VALID_BYTES).unwrap();
        assert_eq!(bits.as_bits(), u64::MAX & !0b111);
    }

    // Minimum invalid usize input for BitLength<u64> on 64-bit targets.
    {
        let bits = BitLength::<u64>::from_byte_len(U64_MAX_VALID_BYTES + 1);
        assert_eq!(bits, Err(error::Unspecified));
    }
}
