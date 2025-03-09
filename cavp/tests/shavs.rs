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

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test_configure;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
wasm_bindgen_test_configure!(run_in_browser);

mod digest_shavs {
    use ring::digest;
    #[allow(deprecated)]
    use ring::test;

    fn run_known_answer_test(digest_alg: &'static digest::Algorithm, test_file: test::File) {
        let section_name = &format!("L = {}", digest_alg.output_len());
        test::run(test_file, |section, test_case| {
            assert_eq!(section_name, section);
            let len_bits = test_case.consume_usize("Len");

            let mut msg = test_case.consume_bytes("Msg");
            // The "msg" field contains the dummy value "00" when the
            // length is zero.
            if len_bits == 0 {
                assert_eq!(msg, &[0u8]);
                msg.truncate(0);
            }

            assert_eq!(msg.len() * 8, len_bits);
            let expected = test_case.consume_bytes("MD");
            let actual = digest::digest(digest_alg, &msg);
            assert_eq!(&expected, &actual.as_ref());

            Ok(())
        });
    }

    macro_rules! shavs_tests {
        ( $file_name:ident, $algorithm_name:ident ) => {
            #[allow(non_snake_case)]
            mod $algorithm_name {
                use super::run_known_answer_test;
                use ring::digest;
                #[allow(deprecated)]
                use ring::test_file;

                #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
                use wasm_bindgen_test::wasm_bindgen_test as test;

                #[test]
                fn short_msg_known_answer_test() {
                    run_known_answer_test(
                        &digest::$algorithm_name,
                        test_file!(concat!(
                            "../third_party/NIST/SHAVS/",
                            stringify!($file_name),
                            "ShortMsg.rsp"
                        )),
                    );
                }

                #[test]
                fn long_msg_known_answer_test() {
                    run_known_answer_test(
                        &digest::$algorithm_name,
                        test_file!(concat!(
                            "../third_party/NIST/SHAVS/",
                            stringify!($file_name),
                            "LongMsg.rsp"
                        )),
                    );
                }
            }
        };
    }

    shavs_tests!(SHA1, SHA1_FOR_LEGACY_USE_ONLY);
    shavs_tests!(SHA256, SHA256);
    shavs_tests!(SHA384, SHA384);
    shavs_tests!(SHA512, SHA512);
}
