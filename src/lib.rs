// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Safe, fast, small crypto using Rust with BoringSSL's cryptography primitives.
//!
//! # Feature Flags
//!
//! <table>
//! <tr><th>Feature
//!     <th>Description
//! <tr><td><code>disable_dev_urandom_fallback</code>
//!     <td>On Linux, by default, `ring::rand::SystemRandom` will fall back
//!         to reading from `/dev/urandom` if the `getrandom()` syscall isn't
//!         supported at runtime. When the `disable_dev_urandom_fallback`
//!         feature is enabled, such fallback will not occur. See the
//!         documentation for `rand::SystemRandom` for more details.
//! <tr><td><code>no_heap</code>
//!     <td>Disable all functionality that uses the heap. This is useful for
//!         code running in kernel space and some embedded applications. The
//!         goal is to enable as much functionality as is practical in
//!         <code>no_heap</code> mode, but for now some RSA, ECDH, and ECDSA
//!         functionality still uses the heap.
//! <tr><td><code>test_logging</code>
//!     <td>Print out additional logging information, in particular the
//!          contents of the test input files, as tests execute. When a test
//!          fails, the most recently-logged stuff indicates which test vectors
//!          failed. This isn't enabled by default because it uses too much
//!          memory on small targets, due to the way that Rust buffers the
//!          output until (unless) the test fails. For small (embedded)
//!          targets, use
//!          `cargo test --release --no-run --features=test_logging` to build
//!          the tests, and then run the tests on the target with
//!          `<executable-name> --nocapture' to see the log.
//! </table>

#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    drop_with_repr_extern,
    exceeding_bitshifts,
    fat_ptr_transmutes,
    improper_ctypes,
    match_of_unit_variant_via_paren_dotdot,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_snake_case,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unknown_lints,
    unreachable_code,
    unsafe_code,
    unstable_features,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_qualifications,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true,
)]

#![no_std]

#[cfg(test)]
extern crate rustc_serialize;

#[cfg(test)]
#[macro_use(format, print, println, vec)]
extern crate std;

#[macro_use] mod bssl;
#[macro_use] mod polyfill;

#[path = "aead/aead.rs"] pub mod aead;
pub mod agreement;
mod c;
pub mod constant_time;

#[doc(hidden)]
pub mod der;

#[path = "digest/digest.rs"] pub mod digest;
mod ecc;
pub mod hkdf;
pub mod hmac;
mod init;
pub mod input;
pub mod pbkdf2;

pub mod rand;
pub mod signature;

#[cfg(test)]
mod file_test;

#[cfg(test)]
mod tests {
    bssl_test_rng!(test_bn, bssl_bn_test_main);
    bssl_test!(test_bytestring, bssl_bytestring_test_main);
    bssl_test!(test_constant_time, bssl_constant_time_test_main);
}
