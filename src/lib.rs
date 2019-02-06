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
//! <tr><td><code>use_heap (default)</code>
//!     <td>Enable features that require use of the heap, RSA in particular.
//! </table>

#![doc(html_root_url = "https://briansmith.org/rustdoc/")]
#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    non_camel_case_types,
    non_snake_case,
    unsafe_code
)]
// `#[derive(...)]` uses `trivial_numeric_casts` and `unused_qualifications`
// internally.
#![deny(
    missing_docs,
    trivial_numeric_casts,
    unstable_features, // Used by `internal_benches`
    unused_qualifications,
    variant_size_differences,
)]
#![forbid(
    anonymous_parameters,
    trivial_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    warnings
)]
#![cfg_attr(
    any(
        target_os = "redox",
        all(
            not(test),
            not(feature = "use_heap"),
            unix,
            not(any(target_os = "macos", target_os = "ios")),
            any(not(target_os = "linux"), feature = "dev_urandom_fallback")
        )
    ),
    no_std
)]
#![cfg_attr(feature = "internal_benches", allow(unstable_features))]
#![cfg_attr(feature = "internal_benches", feature(test))]

#[macro_use]
mod debug;

#[macro_use]
mod bssl;

#[macro_use]
mod polyfill;

#[cfg(any(test, feature = "use_heap"))]
#[macro_use]
pub mod test;

mod arithmetic;

pub mod aead;
pub mod agreement;

mod bits;

pub mod constant_time;

pub mod io;

mod cpu;
pub mod digest;
mod ec;
mod endian;
pub mod error;
pub mod hkdf;
pub mod hmac;
mod limb;
pub mod pbkdf2;
mod pkcs8;
pub mod rand;

#[cfg(feature = "use_heap")]
mod rsa;

pub mod signature;

mod sealed {
    /// Traits that are designed to only be implemented internally in *ring*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}
