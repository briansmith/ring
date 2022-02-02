// Copyright 2015-2021 Brian Smith.
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

use criterion::criterion_main;
use ring::{aead, error};

// All the AEADs we're testing use 96-bit nonces.
pub const NONCE: [u8; 96 / 8] = [0u8; 96 / 8];

// A TLS 1.2 finished message is always 12 bytes long.
const TLS12_FINISHED_LEN: usize = 12;

// A TLS 1.3 finished message is "[t]he size of the HMAC output for the
// Hash used for the handshake," which is usually SHA-256.
const TLS13_FINISHED_LEN: usize = 32;

// In TLS 1.2, 13 bytes of additional data are used for AEAD cipher suites.
const TLS12_AD: [u8; 13] = [
    23, // Type: application_data
    3, 3, // Version = TLS 1.2.
    0x12, 0x34, // Length = 0x1234.
    0, 0, 0, 0, 0, 0, 0, 1, // Record #1
];

// In TLS 1.3, 5 bytes of additional data are used for AEAD cihper suites.
const TLS13_AD: [u8; 5] = [
    0x17, // app data type
    0x3,  // version
    0x3,  // ..
    0x0,  // Length
    0x7,  // ..
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

macro_rules! function_bench_name {
    ( $benchmark_name:ident, $algorithm:expr, $operation:ident) => {{
        const FUNC_NAME_BASE: &str = concat!(
            "aead_",
            stringify!($operation),
            "_",
            stringify!($benchmark_name),
            "_",
            stringify!($algorithm)
        );

        FUNC_NAME_BASE.replace("&aead::", "")
    }};
}

macro_rules! bench {
    ( $benchmark_name:ident, $algorithm:expr, $chunk_len:expr, $ad:expr ) => {
        pub(super) fn $benchmark_name(c: &mut criterion::Criterion) {
            use super::{NonceSequence, NONCE};
            use criterion::{black_box, BatchSize};
            use ring::{
                aead::{self, BoundKey},
                rand::{SecureRandom, SystemRandom},
            };

            let rng = SystemRandom::new();

            let mut key_bytes = vec![0u8; $algorithm.key_len()];
            rng.fill(&mut key_bytes).unwrap();

            {
                let key = aead::UnboundKey::new($algorithm, &key_bytes).unwrap();
                let mut key = aead::SealingKey::new(key, NonceSequence::new());

                let mut in_out = black_box(vec![0u8; $chunk_len + $algorithm.tag_len()]);

                c.bench_function(
                    &function_bench_name!($benchmark_name, $algorithm, seal),
                    |b| {
                        b.iter(|| -> Result<(), ring::error::Unspecified> {
                            let aad = aead::Aad::from(black_box($ad));
                            let _tag = key.seal_in_place_separate_tag(aad, &mut in_out)?;
                            Ok(())
                        })
                    },
                );
            }

            {
                let key =
                    aead::LessSafeKey::new(aead::UnboundKey::new($algorithm, &key_bytes).unwrap());

                let ciphertext = {
                    let nonce = aead::Nonce::assume_unique_for_key(NONCE);
                    let mut in_out = vec![0u8; $chunk_len + $algorithm.tag_len()];
                    let aad = aead::Aad::from($ad);
                    key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                        .unwrap();
                    in_out
                };

                let num_batches = (std::cmp::max(1, 8192 / ciphertext.len()) * 10) as u64;

                c.bench_function(
                    &function_bench_name!($benchmark_name, $algorithm, open),
                    |b| {
                        b.iter_batched(
                            || ciphertext.clone(),
                            |mut ciphertext| -> Result<(), ring::error::Unspecified> {
                                // Optimizes out
                                let nonce = aead::Nonce::assume_unique_for_key(NONCE);

                                let aad = aead::Aad::from(black_box($ad));
                                let _result = key.open_in_place(nonce, aad, &mut ciphertext)?;

                                Ok(())
                            },
                            BatchSize::NumBatches(num_batches),
                        )
                    },
                );
            }
        }
    };
}

macro_rules! benches {
    ( $name:ident, $algorithm:expr ) => {
        mod $name {
            use criterion::criterion_group;

            // A TLS 1.2 finished message.
            bench!(
                tls12_finished,
                $algorithm,
                super::TLS12_FINISHED_LEN,
                super::TLS12_AD
            );

            // A TLS 1.3 finished message.
            bench!(
                tls13_finished,
                $algorithm,
                super::TLS13_FINISHED_LEN,
                super::TLS13_AD
            );

            // For comparison with BoringSSL.
            bench!(tls12_16, $algorithm, 16, super::TLS12_AD);

            // ~1 packet of data in TLS.
            bench!(tls12_1350, $algorithm, 1350, super::TLS12_AD);
            bench!(tls13_1350, $algorithm, 1350, super::TLS13_AD);

            // For comparison with BoringSSL.
            bench!(tls12_8192, $algorithm, 8192, super::TLS12_AD);
            bench!(tls13_8192, $algorithm, 8192, super::TLS13_AD);

            criterion_group!(
                $name,
                tls12_finished,
                tls13_finished,
                tls12_16,
                tls12_1350,
                tls13_1350,
                tls12_8192,
                tls13_8192
            );
        }

        // Export Criterion benchmark groups
        pub use $name::*;
    };
}

benches!(aes_128_gcm, &aead::AES_128_GCM);
benches!(aes_256_gcm, &aead::AES_256_GCM);
benches!(chacha20_poly1305, &aead::CHACHA20_POLY1305);

criterion_main!(aes_128_gcm, aes_256_gcm, chacha20_poly1305);
