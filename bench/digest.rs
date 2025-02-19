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

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ring::digest;

static ALGORITHMS: &[(&str, &digest::Algorithm)] = &[
    ("sha256", &digest::SHA256),
    ("sha384", &digest::SHA384),
    ("sha512", &digest::SHA512),
];

const INPUT_LENGTHS: &[usize] = &[
    // Benchmark that emphasizes overhead.
    0,
    32,
    64,
    128,
    1024,
    2048,
    4096,
    8192,
    1024 * 1024,
];

const SMALL_MAX: usize = 8192;

#[repr(align(64))]
struct Small([u8; SMALL_MAX]);

fn oneshot(c: &mut Criterion) {
    for &(alg_name, algorithm) in ALGORITHMS {
        for input_len in INPUT_LENGTHS {
            c.bench_with_input(
                BenchmarkId::new(format!("digest::oneshot::{alg_name}"), input_len),
                input_len,
                |b, &input_len| {
                    let small;
                    let v;
                    let input = if input_len <= SMALL_MAX {
                        // Use an aligned buffer to minimize alignment-related variance.
                        small = Small([0; SMALL_MAX]);
                        &small.0[..input_len]
                    } else {
                        // TODO: Align this similarly.
                        v = vec![0u8; input_len];
                        &v[..]
                    };
                    b.iter(|| -> usize {
                        let digest = digest::digest(algorithm, &input);
                        black_box(digest.as_ref().len())
                    })
                },
            );
        }
    }
}

criterion_group!(digest, oneshot);
criterion_main!(digest);
