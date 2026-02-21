// Copyright (c) 2014, Google Inc.
// Portions Copyright 2015-2025 Brian Smith.
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

// This implementation of poly1305 is by Andrew Moon
// (https://github.com/floodyberry/poly1305-donna) and released as public
// domain.

use super::super::{poly1305::*, Tag};
use crate::cpu;
use crate::testutil as test;

// Adapted from BoringSSL's crypto/poly1305/poly1305_test.cc.
#[test]
pub fn test_poly1305() {
    let cpu_features = cpu::features();
    test::run(
        test_vector_file!("poly1305_test.txt"),
        |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let key: &[u8; KEY_LEN] = key.as_slice().try_into().unwrap();
            let input = test_case.consume_bytes("Input");
            let expected_mac = test_case.consume_bytes("MAC");
            let key = Key::new(*key);
            let Tag(actual_mac) = sign(key, &input, cpu_features);
            assert_eq!(expected_mac, actual_mac.as_ref());

            Ok(())
        },
    )
}
