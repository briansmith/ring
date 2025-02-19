// Copyright 2015-2023 Brian Smith.
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

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ring::{
    rand,
    signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, KeyPair},
};

static ALGORITHMS: &[(&str, &EcdsaSigningAlgorithm, &EcdsaVerificationAlgorithm)] = &[
    (
        "p256",
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &signature::ECDSA_P256_SHA256_ASN1,
    ),
    (
        "p384",
        &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        &signature::ECDSA_P384_SHA384_ASN1,
    ),
];

fn sign(c: &mut Criterion) {
    for (alg_name, alg, _) in ALGORITHMS {
        c.bench_function(&format!("ecdsa_{alg_name}_sign"), |b| {
            let rng = rand::SystemRandom::new();
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8_bytes.as_ref(), &rng).unwrap();

            b.iter(|| {
                key_pair.sign(&rng, black_box(&[])).unwrap();
            })
        });
    }
}

fn verify(c: &mut Criterion) {
    for (alg_name, sign_alg, verify_alg) in ALGORITHMS {
        c.bench_function(&format!("ecdsa_{alg_name}_verify"), |b| {
            let rng = rand::SystemRandom::new();
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(sign_alg, &rng).unwrap();
            let key_pair = EcdsaKeyPair::from_pkcs8(sign_alg, pkcs8_bytes.as_ref(), &rng).unwrap();

            let public_key =
                signature::UnparsedPublicKey::new(*verify_alg, key_pair.public_key().as_ref());

            b.iter_batched(
                || key_pair.sign(&rng, &[]).unwrap(),
                |signature| {
                    public_key
                        .verify(black_box(&[]), black_box(signature.as_ref()))
                        .unwrap();
                },
                BatchSize::LargeInput,
            )
        });
    }
}

criterion_group!(ecdsa, sign, verify);
criterion_main!(ecdsa);
