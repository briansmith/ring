// Copyright 2018-2024 Brian Smith.
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

use super::super::*;
use crate::cpu;
use crate::testutil as test;

#[test]
pub fn test_aes() {
    test::run(test_vector_file!("aes_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let key = consume_key(test_case, "Key");
        let input = test_case.consume_bytes("Input");
        let block: Block = input.as_slice().try_into()?;
        let expected_output = test_case.consume_bytes("Output");

        let output = key.encrypt_block(block);
        assert_eq!(output.as_ref(), &expected_output[..]);

        Ok(())
    })
}

fn consume_key(test_case: &mut test::TestCase, name: &str) -> Key {
    let key = test_case.consume_bytes(name);
    let key = &key[..];
    let key = match key.len() {
        16 => KeyBytes::AES_128(key.try_into().unwrap()),
        32 => KeyBytes::AES_256(key.try_into().unwrap()),
        _ => unreachable!(),
    };
    Key::new(key, cpu::features())
}
