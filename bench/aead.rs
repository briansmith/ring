// Copyright 2015-2021 Brian Smith.
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

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use ring::{
    aead::{self, BoundKey},
    error,
    rand::{SecureRandom, SystemRandom},
};

static ALGORITHMS: &[(&str, &aead::Algorithm)] = &[
    ("aes128_gcm", &aead::AES_128_GCM),
    ("aes256_gcm", &aead::AES_256_GCM),
    ("chacha20_poly1305", &aead::CHACHA20_POLY1305),
];

static RECORD_LENGTHS: &[usize] = &[
    TLS12_FINISHED_LEN,
    16,
    TLS13_FINISHED_LEN,
    64,
    128,
    256,
    512,
    1024,
    // ~1 packet of data in TLS.
    1350,
    2048,
    4096,
    8192,
    16384,
];

// All the AEADs we're testing use 96-bit nonces.
pub const NONCE: [u8; 96 / 8] = [0u8; 96 / 8];

// A TLS 1.2 finished message is always 12 bytes long.
const TLS12_FINISHED_LEN: usize = 12;

// A TLS 1.3 finished message is "[t]he size of the HMAC output for the
// Hash used for the handshake," which is usually SHA-256.
const TLS13_FINISHED_LEN: usize = 32;

// In TLS, 13 bytes of additional data are used for AEAD cipher suites.
const TLS_AD: &[u8; 13] = &[
    23, // Type: application_data
    3, 3, // Version = TLS 1.2.
    0x12, 0x34, // Length = 0x1234.
    0, 0, 0, 0, 0, 0, 0, 1, // Record #1
];

struct NonceSequence(u64);
impl NonceSequence {
    const fn new() -> Self {
        Self(0)
    }
}

impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        let mut result = [0u8; aead::NONCE_LEN];
        result[4..].copy_from_slice(&u64::to_be_bytes(self.0));
        self.0 = self.0.checked_add(1).ok_or(error::Unspecified)?;
        Ok(aead::Nonce::assume_unique_for_key(result))
    }
}

fn seal_in_place_separate_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    let rng = SystemRandom::new();

    for &(alg_name, algorithm) in ALGORITHMS {
        for record_len in RECORD_LENGTHS {
            group.throughput(criterion::Throughput::BytesDecimal(*record_len as _));
            group.bench_with_input(
                bench_id("seal_in_place_separate_tag", alg_name, *record_len),
                record_len,
                |b, record_len| {
                    let mut key_bytes = vec![0u8; algorithm.key_len()];
                    rng.fill(&mut key_bytes).unwrap();
                    let unbound_key = aead::UnboundKey::new(algorithm, &key_bytes).unwrap();
                    let mut key = aead::SealingKey::new(unbound_key, NonceSequence::new());

                    let mut in_out = vec![0u8; *record_len];

                    b.iter(|| -> Result<(), ring::error::Unspecified> {
                        let aad = aead::Aad::from(black_box(TLS_AD));
                        let _tag = key.seal_in_place_separate_tag(aad, &mut in_out).unwrap();
                        Ok(())
                    })
                },
            );
        }
    }
}

fn open_in_place(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    let rng = SystemRandom::new();

    for &(alg_name, algorithm) in ALGORITHMS {
        for record_len in RECORD_LENGTHS {
            group.throughput(criterion::Throughput::BytesDecimal(*record_len as _));
            group.bench_with_input(
                bench_id("open_in_place", alg_name, *record_len),
                record_len,
                |b, _record_len| {
                    let mut key_bytes = vec![0u8; algorithm.key_len()];
                    rng.fill(&mut key_bytes).unwrap();
                    let unbound_key = aead::UnboundKey::new(algorithm, &key_bytes).unwrap();
                    let key = aead::LessSafeKey::new(unbound_key);

                    let ciphertext = {
                        let nonce = aead::Nonce::assume_unique_for_key(NONCE);
                        let aad = aead::Aad::from(&TLS_AD);
                        let mut in_out = vec![0u8; *record_len];
                        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                            .unwrap();
                        in_out
                    };
                    let num_batches = 1.max(8192 / (ciphertext.len() as u64) * 10);

                    b.iter_batched(
                        || ciphertext.clone(),
                        |mut ciphertext| -> Result<(), ring::error::Unspecified> {
                            // Optimizes out
                            let nonce = aead::Nonce::assume_unique_for_key(NONCE);

                            let aad = aead::Aad::from(black_box(&TLS_AD));
                            let _result = key.open_in_place(nonce, aad, &mut ciphertext)?;

                            Ok(())
                        },
                        BatchSize::NumBatches(num_batches),
                    )
                },
            );
        }
    }
}

fn bench_id(func_name: &str, alg_name: &str, record_len: usize) -> BenchmarkId {
    BenchmarkId::new(format!("{}::{}", alg_name, func_name), record_len)
}

criterion_group!(aead, seal_in_place_separate_tag, open_in_place);

criterion_main!(aead);
