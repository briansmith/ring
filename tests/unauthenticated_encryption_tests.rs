// Copyright 2018 Brian Smith.
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

#![forbid(
    anonymous_parameters,
    box_pointers,
    legacy_directory_ownership,
    missing_copy_implementations,
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results,
    variant_size_differences,
    warnings,
)]

#[macro_use]
extern crate ring;

use ring::{error, test, unauthenticated_encryption};

#[test]
fn unauthenticated_encryption_chacha20() {
    test_encryption(&unauthenticated_encryption::CHACHA20,
                    "tests/unauthenticated_encryption_chacha20_tests.txt");
}


fn test_encryption(stream_alg: &'static unauthenticated_encryption::Algorithm,
                                                            file_path: &str) {
    test_encryption_key_sizes(stream_alg);
    test_encryption_nonce_sizes(stream_alg).unwrap();

    test::from_file(file_path, |section, test_case| {
        assert_eq!(section, "");
        let key_bytes = test_case.consume_bytes("KEY");
        let nonce = test_case.consume_bytes("NONCE");
        let plaintext = test_case.consume_bytes("IN");
        let ct = test_case.consume_bytes("CT");
        let error = test_case.consume_optional_string("FAILS");

        let mut s_in_out = plaintext.clone();
        let s_key = unauthenticated_encryption::EncryptingKey::new(stream_alg,
                                                               &key_bytes[..])?;

        let s_result =
            unauthenticated_encryption::encrypt_in_place(&s_key, &nonce[..],
                                                     &mut s_in_out[..]);

        let mut o_in_out = vec![123u8; 4096];
        o_in_out.truncate(0);
        o_in_out.extend_from_slice(&ct[..]);
        let o_key = unauthenticated_encryption::DecryptingKey::new(stream_alg,
                                                              &key_bytes[..])?;

        let o_result =
            unauthenticated_encryption::decrypt_in_place(&o_key, &nonce[..],
                                                      &mut o_in_out);

        match error {
            None => {
                assert_eq!(Ok(ct.len()), s_result);
                assert_eq!(&ct[..], &s_in_out[..ct.len()]);
                assert_eq!(&plaintext[..], o_result.unwrap());
            },
            Some(ref error) if error == "WRONG_NONCE_LENGTH" => {
                assert_eq!(Err(error::Unspecified), s_result);
                assert_eq!(Err(error::Unspecified), o_result);
            },
            Some(error) => {
                unreachable!("Unexpected error test case: {}", error);
            },
        };

        Ok(())
    });
}

fn test_encryption_key_sizes(alg: &'static unauthenticated_encryption::Algorithm) {
    encryption_key_sizes_tests!(alg, unauthenticated_encryption::DecryptingKey,
                                     unauthenticated_encryption::EncryptingKey);
}

// Test that we reject non-standard nonce sizes.
//
// XXX: This test isn't that great in terms of how it tests
// `open_in_place`. It should be constructing a valid ciphertext using the
// unsupported nonce size using a different implementation that supports
// non-standard nonce sizes. So, when `open_in_place` returns
// `Err(error::Unspecified)`, we don't know if it is because it rejected
// the non-standard nonce size or because it tried to process the input
// with the wrong nonce. But at least we're verifying that `open_in_place`
// won't crash or access out-of-bounds memory (when run under valgrind or
// similar). The AES-128-GCM tests have some WRONG_NONCE_LENGTH test cases
// that tests this more correctly.
fn test_encryption_nonce_sizes(stream_alg: &'static unauthenticated_encryption::Algorithm)
                         -> Result<(), error::Unspecified> {
    let key_len = stream_alg.key_len();
    let key_data = vec![0u8; key_len];
    let s_key = unauthenticated_encryption::EncryptingKey::new(stream_alg,
                                                           &key_data[..key_len])?;
    let o_key = unauthenticated_encryption::DecryptingKey::new(stream_alg,
                                                           &key_data[..key_len])?;

    let nonce_len = stream_alg.nonce_len();

    let nonce = vec![0u8; nonce_len * 2];

    // Construct a template input for `encrypt_in_place`.
    let to_encrypt = b"hello, world".to_vec();
    let to_encrypt = &to_encrypt[..];

    // Construct a template input for `decrypt_in_place`.
    let mut to_decrypt = Vec::from(to_encrypt);
    let ciphertext_len =
        unauthenticated_encryption::encrypt_in_place(&s_key, &nonce[..nonce_len],
                                                 &mut to_decrypt)?;
    let to_decrypt = &to_decrypt[..ciphertext_len];

    // Nonce is the correct length.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
                &nonce[..nonce_len], &mut in_out).is_ok());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
                &nonce[..nonce_len], &mut in_out).is_ok());
    }

    // Nonce is one byte too small.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
                &nonce[..(nonce_len - 1)], &mut in_out).is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
                &nonce[..(nonce_len - 1)], &mut in_out).is_err());
    }

    // Nonce is one byte too large.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
            &nonce[..(nonce_len + 1)], &mut in_out).is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
            &nonce[..(nonce_len + 1)], &mut in_out).is_err());
    }

    // Nonce is half the required size.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
            &nonce[..(nonce_len / 2)], &mut in_out).is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
            &nonce[..(nonce_len / 2)], &mut in_out).is_err());
    }

    // Nonce is twice the required size.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
            &nonce[..(nonce_len * 2)], &mut in_out).is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
            &nonce[..(nonce_len * 2)], &mut in_out).is_err());
    }

    // Nonce is empty.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key, &[],
            &mut in_out) .is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key, &[],
            &mut in_out) .is_err());
    }

    // Nonce is one byte.
    {
        let mut in_out = Vec::from(to_encrypt);
        assert!(unauthenticated_encryption::encrypt_in_place(&s_key,
            &nonce[..1], &mut in_out).is_err());
    }
    {
        let mut in_out = Vec::from(to_decrypt);
        assert!(unauthenticated_encryption::decrypt_in_place(&o_key,
            &nonce[..1], &mut in_out).is_err());
    }

    Ok(())
}
