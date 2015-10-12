// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Derived from the CC0-licensed implementation by Joseph Birr-Pixton at
// https://github.com/ctz/rust-fastpbkdf2/blob/master/pbkdf2-bench/src/main.rs
// commit b000c72c7b3beb0bee761bebcf07ac3f0875d1ad. This version only measures
// *ring*.

extern crate ring;
extern crate time;

use ring::pbkdf2;
use time::SteadyTime;

const ITERATIONS: usize = 1 << 20;
const PASSWORD: &'static [u8] = b"password";
const SALT: &'static [u8] = b"salt";

fn bench<F>(name: &'static str, f: F) where F: FnOnce() {
  let start = SteadyTime::now();
  f();
  let duration = SteadyTime::now() - start;
  println!("{} = {}ms", name, duration.num_milliseconds());
}

fn ring_sha1() {
  let mut out = [0u8; 20];
  pbkdf2::derive(&pbkdf2::HMAC_SHA1, ITERATIONS, PASSWORD, SALT, &mut out);
}

fn ring_sha256() {
  let mut out = [0u8; 32];
  pbkdf2::derive(&pbkdf2::HMAC_SHA256, ITERATIONS, PASSWORD, SALT, &mut out);
}

fn ring_sha512() {
  let mut out = [0u8; 64];
  pbkdf2::derive(&pbkdf2::HMAC_SHA512, ITERATIONS, PASSWORD, SALT, &mut out);
}

fn main() {
  bench("ring-sha1", ring_sha1);
  bench("ring-sha256", ring_sha256);
  bench("ring-sha512", ring_sha512);
}
