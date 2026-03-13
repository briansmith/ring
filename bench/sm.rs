// Copyright 2026 The ring Authors.
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

//! Benchmarks for Chinese National Standard (GB/T) cryptographic algorithms:
//! SM3 (hash), SM4-GCM (AEAD), and SM2 (signature/ECDH).
//!
//! Run with: `cargo bench -p ring-bench --features sm --bench sm`
//!
//! **Note**: SM3 and SM4 are pure-Rust implementations without hardware
//! acceleration. Performance will be lower than SHA-256 (AES-NI) and
//! AES-128-GCM (AES-NI + CLMUL). SM2 point arithmetic is also pure-Rust.

#![allow(missing_docs)]

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ring::{
    aead::{self, BoundKey},
    digest, error,
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};

// ── SM3 vs SHA-256 ────────────────────────────────────────────────────────────

static DIGEST_ALGORITHMS: &[(&str, &digest::Algorithm)] =
    &[("sm3", &digest::SM3), ("sha256", &digest::SHA256)];

const INPUT_LENGTHS: &[usize] = &[0, 64, 256, 1024, 8192, 1024 * 1024];

fn sm3_vs_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("digest");

    for &(alg_name, algorithm) in DIGEST_ALGORITHMS {
        for &input_len in INPUT_LENGTHS {
            group.throughput(criterion::Throughput::Bytes(input_len as u64));
            group.bench_with_input(
                BenchmarkId::new(alg_name, input_len),
                &input_len,
                |b, &input_len| {
                    let input = vec![0u8; input_len];
                    b.iter(|| -> usize {
                        let d = digest::digest(algorithm, black_box(&input));
                        black_box(d.as_ref().len())
                    })
                },
            );
        }
    }

    group.finish();
}

// ── SM4-GCM vs AES-128-GCM ───────────────────────────────────────────────────

static AEAD_ALGORITHMS: &[(&str, &aead::Algorithm)] = &[
    ("sm4_128_gcm", &aead::SM4_128_GCM),
    ("aes_128_gcm", &aead::AES_128_GCM),
];

// Record lengths representative of TLS traffic.
static RECORD_LENGTHS: &[usize] = &[64, 256, 1024, 8192, 16384];

const NONCE_BYTES: [u8; 12] = [0u8; 12];

struct NonceSequence(u64);

impl NonceSequence {
    const fn new() -> Self {
        Self(0)
    }
}

impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        let mut n = [0u8; aead::NONCE_LEN];
        n[4..].copy_from_slice(&self.0.to_be_bytes());
        self.0 = self.0.checked_add(1).ok_or(error::Unspecified)?;
        Ok(aead::Nonce::assume_unique_for_key(n))
    }
}

fn sm4_gcm_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_seal");
    let rng = SystemRandom::new();

    for &(alg_name, algorithm) in AEAD_ALGORITHMS {
        for &record_len in RECORD_LENGTHS {
            group.throughput(criterion::Throughput::Bytes(record_len as u64));
            group.bench_with_input(
                BenchmarkId::new(alg_name, record_len),
                &record_len,
                |b, &record_len| {
                    let mut key_bytes = vec![0u8; algorithm.key_len()];
                    rng.fill(&mut key_bytes).unwrap();
                    let unbound = aead::UnboundKey::new(algorithm, &key_bytes).unwrap();
                    let mut key = aead::SealingKey::new(unbound, NonceSequence::new());
                    let mut in_out = vec![0u8; record_len];

                    b.iter(|| {
                        let aad = aead::Aad::empty();
                        key.seal_in_place_separate_tag(aad, &mut in_out).unwrap()
                    })
                },
            );
        }
    }

    group.finish();
}

fn sm4_gcm_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_open");
    let rng = SystemRandom::new();

    for &(alg_name, algorithm) in AEAD_ALGORITHMS {
        for &record_len in RECORD_LENGTHS {
            group.throughput(criterion::Throughput::Bytes(record_len as u64));
            group.bench_with_input(
                BenchmarkId::new(alg_name, record_len),
                &record_len,
                |b, &record_len| {
                    let mut key_bytes = vec![0u8; algorithm.key_len()];
                    rng.fill(&mut key_bytes).unwrap();

                    // Pre-encrypt a ciphertext to open.
                    let unbound_seal = aead::UnboundKey::new(algorithm, &key_bytes).unwrap();
                    let key_seal = aead::LessSafeKey::new(unbound_seal);
                    let nonce = aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                    let mut ciphertext = vec![0u8; record_len];
                    key_seal
                        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
                        .unwrap();

                    let unbound_open = aead::UnboundKey::new(algorithm, &key_bytes).unwrap();
                    let key_open = aead::LessSafeKey::new(unbound_open);

                    b.iter_batched(
                        || ciphertext.clone(),
                        |mut ct| {
                            let nonce = aead::Nonce::assume_unique_for_key(NONCE_BYTES);
                            key_open
                                .open_in_place(nonce, aead::Aad::empty(), &mut ct)
                                .unwrap()
                                .len()
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }

    group.finish();
}

// ── SM2 vs ECDSA P-256 ────────────────────────────────────────────────────────

fn sm2_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let rng = SystemRandom::new();

    // SM2 signing
    group.bench_function("sm2_sign", |b| {
        let pkcs8 =
            signature::Sm2KeyPair::generate_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, &rng).unwrap();
        let key_pair = signature::Sm2KeyPair::from_pkcs8(
            &signature::SM2_SM3_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        b.iter(|| {
            key_pair
                .sign(&rng, black_box(b"benchmark message"))
                .unwrap()
        })
    });

    // ECDSA P-256 signing for comparison
    group.bench_function("ecdsa_p256_sign", |b| {
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        b.iter(|| {
            key_pair
                .sign(&rng, black_box(b"benchmark message"))
                .unwrap()
        })
    });

    group.finish();
}

fn sm2_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let rng = SystemRandom::new();

    // SM2 verification
    group.bench_function("sm2_verify", |b| {
        let pkcs8 =
            signature::Sm2KeyPair::generate_pkcs8(&signature::SM2_SM3_FIXED_SIGNING, &rng).unwrap();
        let key_pair = signature::Sm2KeyPair::from_pkcs8(
            &signature::SM2_SM3_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let public_key = signature::UnparsedPublicKey::new(
            &signature::SM2_SM3_FIXED,
            key_pair.public_key().as_ref(),
        );
        b.iter_batched(
            || key_pair.sign(&rng, b"benchmark message").unwrap(),
            |sig| {
                public_key
                    .verify(black_box(b"benchmark message"), black_box(sig.as_ref()))
                    .unwrap()
            },
            BatchSize::LargeInput,
        )
    });

    // ECDSA P-256 verification for comparison
    group.bench_function("ecdsa_p256_verify", |b| {
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            key_pair.public_key().as_ref(),
        );
        b.iter_batched(
            || key_pair.sign(&rng, b"benchmark message").unwrap(),
            |sig| {
                public_key
                    .verify(black_box(b"benchmark message"), black_box(sig.as_ref()))
                    .unwrap()
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

criterion_group!(
    sm_benches,
    sm3_vs_sha256,
    sm4_gcm_seal,
    sm4_gcm_open,
    sm2_sign,
    sm2_verify
);
criterion_main!(sm_benches);
