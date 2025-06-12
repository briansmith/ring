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

use crate::bb::BoolMask;

fn leak_in_test(a: BoolMask) -> bool {
    a.leak()
}

#[test]
fn test_bool_mask_bitwise_and_is_logical_and() {
    assert!(leak_in_test(BoolMask::TRUE & BoolMask::TRUE));
    assert!(!leak_in_test(BoolMask::TRUE & BoolMask::FALSE));
    assert!(!leak_in_test(BoolMask::FALSE & BoolMask::TRUE));
    assert!(!leak_in_test(BoolMask::FALSE & BoolMask::FALSE));
}
