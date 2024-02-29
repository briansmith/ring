// Copyright 2015-2017 Brian Smith.
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

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
wasm_bindgen_test_configure!(run_in_browser);

mod digest_shavs {
    use ring::{digest, test};

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
                use super::{run_known_answer_test, run_monte_carlo_test};
                use ring::{digest, test_file};

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

                #[test]
                fn monte_carlo_test() {
                    run_monte_carlo_test(
                        &digest::$algorithm_name,
                        test_file!(concat!(
                            "../third_party/NIST/SHAVS/",
                            stringify!($file_name),
                            "Monte.rsp"
                        )),
                    );
                }
            }
        };
    }

    fn run_monte_carlo_test(digest_alg: &'static digest::Algorithm, test_file: test::File) {
        let section_name = &format!("L = {}", digest_alg.output_len());

        let mut expected_count: isize = -1;
        let mut seed = Vec::with_capacity(digest_alg.output_len());

        test::run(test_file, |section, test_case| {
            assert_eq!(section_name, section);

            if expected_count == -1 {
                seed.extend(test_case.consume_bytes("Seed"));
                expected_count = 0;
                return Ok(());
            }

            assert!(expected_count >= 0);
            let actual_count = test_case.consume_usize("COUNT");
            assert_eq!(expected_count as usize, actual_count);
            expected_count += 1;

            let expected_md = test_case.consume_bytes("MD");

            let mut mds = Vec::with_capacity(4);
            mds.push(seed.clone());
            mds.push(seed.clone());
            mds.push(seed.clone());
            for _ in 0..1000 {
                let mut ctx = digest::Context::new(digest_alg);
                ctx.update(&mds[0]);
                ctx.update(&mds[1]);
                ctx.update(&mds[2]);
                let md_i = ctx.finish();
                let _ = mds.remove(0);
                mds.push(Vec::from(md_i.as_ref()));
            }
            let md_j = mds.last().unwrap();
            assert_eq!(&expected_md, md_j);
            seed = md_j.clone();

            Ok(())
        });

        assert_eq!(expected_count, 100);
    }

    shavs_tests!(SHA1, SHA1_FOR_LEGACY_USE_ONLY);
    shavs_tests!(SHA256, SHA256);
    shavs_tests!(SHA384, SHA384);
    shavs_tests!(SHA512, SHA512);
}
