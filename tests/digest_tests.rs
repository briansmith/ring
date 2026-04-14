// Copyright 2015-2017 Brian Smith.
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

#![allow(missing_docs)]

use ring::digest;
#[allow(deprecated)]
use ring::{test, test_file};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
wasm_bindgen_test_configure!(run_in_browser);

/// Test vectors from BoringSSL, Go, and other sources.
#[test]
fn digest_misc() {
    test::run(test_file!("digest_tests.txt"), |section, test_case| {
        assert_eq!(section, "");
        let digest_alg = test_case.consume_digest_alg("Hash").unwrap();
        let input = test_case.consume_bytes("Input");
        let repeat = test_case.consume_usize("Repeat");
        let expected = test_case.consume_bytes("Output");

        let mut ctx = digest::Context::new(digest_alg);
        let mut data = Vec::new();
        for _ in 0..repeat {
            ctx.update(&input);
            data.extend(&input);
        }
        let actual_from_chunks = ctx.finish();
        assert_eq!(&expected, &actual_from_chunks.as_ref());

        let actual_from_one_shot = digest::digest(digest_alg, &data);
        assert_eq!(&expected, &actual_from_one_shot.as_ref());

        Ok(())
    });
}

/// Test some ways in which `Context::update` and/or `Context::finish`
/// could go wrong by testing every combination of updating three inputs
/// that vary from zero bytes to one byte larger than the block length.
///
/// These are not run in dev (debug) builds because they are too slow.
macro_rules! test_i_u_f {
    ( $test_name:ident, $alg:expr) => {
        #[cfg(not(debug_assertions))]
        #[test]
        fn $test_name() {
            let mut input = [0; (digest::MAX_BLOCK_LEN + 1) * 3];
            let max = $alg.block_len() + 1;
            for i in 0..(max * 3) {
                input[i] = (i & 0xff) as u8;
            }

            for i in 0..max {
                for j in 0..max {
                    for k in 0..max {
                        let part1 = &input[..i];
                        let part2 = &input[i..(i + j)];
                        let part3 = &input[(i + j)..(i + j + k)];

                        let mut ctx = digest::Context::new(&$alg);
                        ctx.update(part1);
                        ctx.update(part2);
                        ctx.update(part3);
                        let i_u_f = ctx.finish();

                        let one_shot = digest::digest(&$alg, &input[..(i + j + k)]);

                        assert_eq!(i_u_f.as_ref(), one_shot.as_ref());
                    }
                }
            }
        }
    };
}
test_i_u_f!(digest_test_i_u_f_sha1, digest::SHA1_FOR_LEGACY_USE_ONLY);
test_i_u_f!(digest_test_i_u_f_sha256, digest::SHA256);
test_i_u_f!(digest_test_i_u_f_sha384, digest::SHA384);
test_i_u_f!(digest_test_i_u_f_sha512, digest::SHA512);

#[test]
fn test_fmt_algorithm() {
    assert_eq!("SHA1", &format!("{:?}", digest::SHA1_FOR_LEGACY_USE_ONLY));
    assert_eq!("SHA256", &format!("{:?}", digest::SHA256));
    assert_eq!("SHA384", &format!("{:?}", digest::SHA384));
    assert_eq!("SHA512", &format!("{:?}", digest::SHA512));
    assert_eq!("SHA512_256", &format!("{:?}", digest::SHA512_256));
}

#[test]
fn digest_test_fmt() {
    assert_eq!(
        "SHA1:b7e23ec29af22b0b4e41da31e868d57226121c84",
        &format!(
            "{:?}",
            digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, b"hello, world")
        )
    );
    assert_eq!(
        "SHA256:09ca7e4eaa6e8ae9c7d261167129184883644d\
         07dfba7cbfbc4c8a2e08360d5b",
        &format!("{:?}", digest::digest(&digest::SHA256, b"hello, world"))
    );
    assert_eq!(
        "SHA384:1fcdb6059ce05172a26bbe2a3ccc88ed5a8cd5\
         fc53edfd9053304d429296a6da23b1cd9e5c9ed3bb34f0\
         0418a70cdb7e",
        &format!("{:?}", digest::digest(&digest::SHA384, b"hello, world"))
    );
    assert_eq!(
        "SHA512:8710339dcb6814d0d9d2290ef422285c9322b7\
         163951f9a0ca8f883d3305286f44139aa374848e4174f5\
         aada663027e4548637b6d19894aec4fb6c46a139fbf9",
        &format!("{:?}", digest::digest(&digest::SHA512, b"hello, world"))
    );

    assert_eq!(
        "SHA512_256:11f2c88c04f0a9c3d0970894ad2472505e\
         0bc6e8c7ec46b5211cd1fa3e253e62",
        &format!("{:?}", digest::digest(&digest::SHA512_256, b"hello, world"))
    );
}

/// SM3 test vectors from GB/T 32905-2016 Annex A.
#[cfg(feature = "sm")]
#[test]
fn sm3_standard_test_vectors() {
    // Annex A.1: SM3("abc") = 66c7f0f4...
    let actual = digest::digest(&digest::SM3, b"abc");
    assert_eq!(
        actual.as_ref(),
        &[
            0x66u8, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ]
    );

    // Annex A.2: SM3("abcd" repeated 16 times = 64 bytes total)
    let mut ctx = digest::Context::new(&digest::SM3);
    for _ in 0..16 {
        ctx.update(b"abcd");
    }
    let actual = ctx.finish();
    assert_eq!(
        actual.as_ref(),
        &[
            0xdeu8, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e,
            0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3,
            0x9c, 0x0c, 0x57, 0x32,
        ]
    );
}
