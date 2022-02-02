// Copyright 2015-2023 Brian Smith.
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
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ring::{
    agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519},
    rand,
};

fn generate_key(c: &mut Criterion) {
    c.bench_function("x25519_generate_key", |b| {
        let rng = rand::SystemRandom::new();
        b.iter(|| {
            let private_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
            let _r = black_box(private_key);
        })
    });
}

fn compute_public_key(c: &mut Criterion) {
    c.bench_function("x25519_compute_public_key", |b| {
        let rng = rand::SystemRandom::new();
        let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng).unwrap();
        b.iter(|| {
            let public_key = my_private_key.compute_public_key();
            let _r = black_box(public_key);
        })
    });
}

fn agree_ephemeral(c: &mut Criterion) {
    c.bench_function("x25519_agree_ephemeral", |b| {
        let rng = rand::SystemRandom::new();
        let peer_public_key: [u8; 32] = rand::generate(&rng).unwrap().expose();

        b.iter_batched(
            || EphemeralPrivateKey::generate(&X25519, &rng).unwrap(),
            |my_private_key| {
                let peer_public_key = UnparsedPublicKey::new(&X25519, &peer_public_key);
                agreement::agree_ephemeral(my_private_key, &peer_public_key, |key_material| {
                    black_box(<[u8; 32]>::try_from(key_material).unwrap())
                })
                .unwrap();
            },
            BatchSize::LargeInput,
        )
    });
}

criterion_group!(x25519, generate_key, compute_public_key, agree_ephemeral);
criterion_main!(x25519);
