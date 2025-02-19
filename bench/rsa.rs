// Copyright 2023 Brian Smith.
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

use criterion::{criterion_group, criterion_main, Criterion};
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

macro_rules! verify_case {
    ( $modulus_bits:expr, $exponent_value:expr ) => {
        TestCase {
            modulus_bits: $modulus_bits,
            exponent_value: $exponent_value,
            public_key: include_bytes!(concat!(
                "data/rsa-",
                stringify!($modulus_bits),
                "-",
                stringify!($exponent_value),
                "-public-key.der"
            )),
            signature: include_bytes!(concat!(
                "data/rsa-",
                stringify!($modulus_bits),
                "-",
                stringify!($exponent_value),
                "-signature.bin"
            )),
        }
    };
}

fn verify(c: &mut Criterion) {
    struct TestCase {
        modulus_bits: usize,
        exponent_value: usize,
        public_key: &'static [u8],
        signature: &'static [u8],
    }
    static TEST_CASES: &[TestCase] = &[
        verify_case!(2048, 65537),
        verify_case!(2048, 3),
        verify_case!(3072, 3),
        verify_case!(4096, 3),
        verify_case!(8192, 3),
    ];

    for TestCase {
        modulus_bits,
        exponent_value,
        public_key,
        signature,
    } in TEST_CASES
    {
        c.bench_function(
            &format!("rsa_verify_{modulus_bits}_{exponent_value}"),
            |b| {
                const MESSAGE: &[u8] = &[];

                b.iter(|| {
                    let public_key =
                        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key);
                    public_key.verify(MESSAGE, signature).unwrap();
                });
            },
        );
    }
}

criterion_group!(rsa, verify);
criterion_main!(rsa);
