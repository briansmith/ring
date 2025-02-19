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
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey},
    rand,
};

static ALGORITHMS: &[(&str, &agreement::Algorithm)] = &[
    ("p256", &agreement::ECDH_P256),
    ("p384", &&agreement::ECDH_P384),
    ("x25519", &&agreement::X25519),
];

fn generate_key(c: &mut Criterion) {
    for (alg_name, alg) in ALGORITHMS {
        c.bench_function(&bench_name(alg_name, "generate_key"), |b| {
            let rng = rand::SystemRandom::new();
            b.iter(|| {
                let private_key = EphemeralPrivateKey::generate(alg, &rng).unwrap();
                let _r = black_box(private_key);
            })
        });
    }
}

fn compute_public_key(c: &mut Criterion) {
    for (alg_name, alg) in ALGORITHMS {
        c.bench_function(&bench_name(alg_name, "compute_public_key"), |b| {
            let rng = rand::SystemRandom::new();
            let my_private_key = EphemeralPrivateKey::generate(alg, &rng).unwrap();
            b.iter(|| {
                let public_key = my_private_key.compute_public_key();
                let _r = black_box(public_key);
            })
        });
    }
}

fn agree_ephemeral(c: &mut Criterion) {
    for (alg_name, alg) in ALGORITHMS {
        c.bench_function(&bench_name(alg_name, "agree_ephemeral"), |b| {
            let rng = rand::SystemRandom::new();
            let peer_public_key = {
                let peer_private_key =
                    agreement::EphemeralPrivateKey::generate(&alg, &rng).unwrap();
                peer_private_key.compute_public_key().unwrap()
            };
            let peer_public_key: &[u8] = peer_public_key.as_ref();

            b.iter_batched(
                || EphemeralPrivateKey::generate(alg, &rng).unwrap(),
                |my_private_key| {
                    let peer_public_key = UnparsedPublicKey::new(alg, peer_public_key);
                    agreement::agree_ephemeral(my_private_key, &peer_public_key, |key_material| {
                        black_box(key_material);
                    })
                    .unwrap();
                },
                BatchSize::LargeInput,
            )
        });
    }
}

fn bench_name(alg_name: &str, bench_name: &str) -> String {
    format!("{}_{}", alg_name, bench_name)
}

criterion_group!(agreement, generate_key, compute_public_key, agree_ephemeral);
criterion_main!(agreement);
