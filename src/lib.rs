// Copyright 2015-2016 Brian Smith.
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

//! Safe, fast, small crypto using Rust with BoringSSL's cryptography
//! primitives.
//!
//! <code>git clone https://github.com/briansmith/ring</code>
//!
//! # Feature Flags
//!
//! <table>
//! <tr><th>Feature
//!     <th>Description
//! <tr><td><code>dev_urandom_fallback (default)</code>
//!     <td>This is only applicable to Linux. On Linux, by default,
//!         <code>ring::rand::SystemRandom</code> will fall back to reading
//!         from <code>/dev/urandom</code> if the <code>getrandom()</code>
//!         syscall isn't supported at runtime. When the
//!         <code>dev_urandom_fallback</code> feature is disabled, such
//!         fallbacks will not occur. See the documentation for
//!         <code>rand::SystemRandom</code> for more details.
//! <tr><td><code>rsa_signing</code>
//!     <td>Enable RSA signing (<code>RSAKeyPair</code> and related things).
//! </table>

#![doc(html_root_url="https://briansmith.org/rustdoc/")]

#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    non_camel_case_types,
    non_snake_case,
    unsafe_code,
)]

// `#[derive(...)]` uses `trivial_numeric_casts` and `unused_qualifications`
// internally.
#![deny(
    missing_docs,
    trivial_numeric_casts,
    unstable_features, // Used by `internal_benches`
    unused_qualifications,
)]

#![forbid(
    anonymous_parameters,
    trivial_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    variant_size_differences,
    warnings,
)]

#![no_std]

#![cfg_attr(feature = "internal_benches", allow(unstable_features))]
#![cfg_attr(feature = "internal_benches", feature(test))]

#[cfg(target_os = "linux")]
extern crate libc;

#[cfg(feature = "internal_benches")]
extern crate test as bench;

#[cfg(any(target_os = "redox",
          all(unix,
              not(any(target_os = "macos", target_os = "ios")),
              any(not(target_os = "linux"),
                  feature = "dev_urandom_fallback"))))]
#[macro_use]
extern crate lazy_static;

#[macro_use]
mod debug;

// `ring::test` uses the formatting & printing stuff in non-test mode.
#[macro_use]
extern crate std;

extern crate untrusted;

#[no_link]
#[macro_use]
extern crate native_versioning;

mod arithmetic;

#[macro_use]
mod bssl;

#[macro_use]
mod polyfill;

pub mod aead;
pub mod agreement;

#[cfg(feature = "use_heap")]
mod bits;

mod c;
mod chacha;
pub mod constant_time;

#[doc(hidden)]
pub mod der;

pub mod digest;
mod ec;
pub mod error;
pub mod hkdf;
pub mod hmac;
mod init;
mod limb;
pub mod pbkdf2;
mod pkcs8;
mod poly1305;
pub mod rand;

#[cfg(feature = "use_heap")]
mod rsa;

pub mod signature;
mod signature_impl;

#[cfg(any(feature = "use_heap", test))]
pub mod test;

mod private {
    /// Traits that are designed to only be implemented internally in *ring*.
    //
    // Usage:
    // ```
    // use private;
    //
    // pub trait MyType : private::Sealed {
    //     // [...]
    // }
    //
    // impl private::Sealed for MyType { }
    // ```
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    bssl_test!(test_constant_time, bssl_constant_time_test_main);
}
