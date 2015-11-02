// Copyright 2015 Brian Smith.
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

//! SHA-2 and the legacy SHA-1 digest algorithm.
//!
//! If all the data is available in a single contiguous slice then the `digest`
//! function should be used. Otherwise, the digest can be calculated in
//! multiple steps using `Context`.

// Note on why are we doing things the hard way: It would be easy to implement
// this using the C `EVP_MD`/`EVP_MD_CTX` interface. However, if we were to do
// things that way, we'd have a hard dependency on `malloc` and other overhead.
// The goal for this implementation is to drive the overhead as close to zero
// as possible.

use std::mem;
use super::c;

/// A context for multi-step (Init-Update-Finish) digest calculations.
///
/// C analog: `EVP_MD_CTX`.
///
/// # Examples
///
/// ```
/// use ring::digest;
///
/// let one_shot = digest::digest(&digest::SHA384, "hello, world".as_bytes());
///
/// let mut ctx = digest::Context::new(&digest::SHA384);
/// ctx.update("hello".as_bytes());
/// ctx.update(", ".as_bytes());
/// ctx.update("world".as_bytes());
/// let multi_part = ctx.finish();
///
/// assert_eq!(&one_shot.as_ref(), &multi_part.as_ref());
/// ```
#[derive(Clone)]
pub struct Context {
    pub algorithm: &'static Algorithm,

    // We use u64 to try to ensure 64-bit alignment/padding.
    // XXX: Test this, and also test that DIGEST_CONTEXT_U64_COUNT is enough
    // by having the build system verify with the C part of the build system.
    state: [u64; DIGEST_CONTEXT_STATE_U64_COUNT],
}

impl Context {
    /// Constructs a new context.
    ///
    /// C analogs: `EVP_DigestInit`, `EVP_DigestInit_ex`
    pub fn new(algorithm: &'static Algorithm) -> Context {
        let mut ctx = Context {
            algorithm: algorithm,
            state: [0u64; DIGEST_CONTEXT_STATE_U64_COUNT],
        };
        let _ = unsafe { (algorithm.init)(ctx.state.as_mut_ptr()) };
        ctx
    }

    /// Updates the digest with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called. It must not be called
    /// after `finish` has been called.
    ///
    /// C analog: `EVP_DigestUpdate`
    pub fn update(&mut self, data: &[u8]) {
        let _ = unsafe {
            (self.algorithm.update)(self.state.as_mut_ptr(), data.as_ptr(),
                                    data.len())
        };
    }

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// consumes the context so it cannot be (mis-)used after `finish` has been
    /// called.
    ///
    /// C analogs: `EVP_DigestFinal`, `EVP_DigestFinal_ex`
    pub fn finish(mut self) -> Digest {
        let mut digest = Digest {
            algorithm: self.algorithm,
            value: unsafe { mem::uninitialized() },
        };
        let _ = unsafe {
            (self.algorithm.final_)(digest.value.as_mut_ptr(),
                                    self.state.as_mut_ptr())
        };
        digest
    }

    /// The algorithm that this context is using.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

/// Returns the digest of `data` using the given digest algorithm.
///
/// C analog: `EVP_Digest`
///
/// # Examples:
///
/// ```
/// extern crate ring;
/// extern crate rustc_serialize;
///
/// # fn main() {
/// use ring::digest;
/// use rustc_serialize::hex::FromHex;
///
/// let expected_hex = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
/// let expected: Vec<u8> = expected_hex.from_hex().unwrap();
/// let actual = digest::digest(&digest::SHA256, "hello, world".as_bytes());
///
/// assert_eq!(&expected, &actual.as_ref());
/// # }
/// ```
pub fn digest(algorithm: &'static Algorithm, data: &[u8]) -> Digest {
    let mut ctx = Context::new(algorithm);
    ctx.update(data);
    ctx.finish()
}

/// A calculated digest value.
///
/// Use `as_ref` to get the value as a `&[u8]`.
pub struct Digest {
    algorithm: &'static Algorithm,
    value: [u8; MAX_OUTPUT_LEN],
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] { &self.value[0..self.algorithm.output_len] }
}

/// A digest algorithm.
///
/// C analog: `EVP_MD`
pub struct Algorithm {
    /// C analog: `EVP_MD_size`
    pub output_len: usize,

    /// The size of the chaining value of the digest function, in bytes. For
    /// non-truncated algorithms (SHA-1, SHA-256, SHA-512), this is equal to
    /// `output_len`. For truncated algorithms (e.g. SHA-384, SHA-512/256),
    /// this is equal to the length before truncation. This is mostly helpful
    /// for determining the size of an HMAC key that is appropriate for the
    /// digest algorithm.
    pub chaining_len: usize,

    /// C analog: `EVP_MD_block_size`
    pub block_len: usize,

    init: unsafe extern fn(ctx_state: *mut u64) -> c::int,
    update: unsafe extern fn(ctx_state: *mut u64, data: *const u8,
                             len: c::size_t) -> c::int,
    final_: unsafe extern fn(out: *mut u8, ctx_state: *mut u64) -> c::int,

    // XXX: This is required because the signature verification functions
    // require a NID. But, really they don't need a NID, but just the OID of
    // the digest function, perhaps with an `EVP_MD` if it wants to validate
    // the properties of the digest like the length. XXX: This has to be public
    // because it is accessed from the signature modules.
    pub nid: c::int,
}

#[cfg(test)]
pub mod test_util {
    use super::super::digest;

    pub static ALL_ALGORITHMS: [&'static digest::Algorithm; 4] = [
        &digest::SHA1,
        &digest::SHA256,
        &digest::SHA384,
        &digest::SHA512,
    ];
}

macro_rules! impl_Digest {
    ($XXX:ident, $output_len_in_bits:expr, $chaining_len_in_bits:expr,
     $block_len_in_bits:expr, $xxx_Init:ident, $xxx_Update:ident,
     $xxx_Final:ident, $NID_xxx:expr) => {

        pub static $XXX: Algorithm = Algorithm {
            output_len: $output_len_in_bits / 8,
            chaining_len: $chaining_len_in_bits / 8,
            block_len: $block_len_in_bits / 8,

            init: $xxx_Init,
            update: $xxx_Update,
            final_: $xxx_Final,

            nid: $NID_xxx,
        };

        // Although the called functions all specify a return value, in
        // BoringSSL they are always guaranteed to return 1 according to the
        // documentation in the header files, so we can safely ignore their
        // return values.
        //
        // XXX: As of Rust 1.4, the compiler will no longer warn about the use
        // of `usize` and `isize` in FFI declarations. Remove the
        // `allow(improper_ctypes)` when Rust 1.4 is released.
        #[allow(improper_ctypes)]
        extern {
            fn $xxx_Init(ctx_state: *mut u64) -> c::int;
            fn $xxx_Update(ctx_state: *mut u64, data: *const u8, len: c::size_t)
                           -> c::int;
            fn $xxx_Final(out: *mut u8, ctx_state: *mut u64) -> c::int;
        }
    }
}

impl_Digest!(SHA1, 160, 160, 512, SHA1_Init, SHA1_Update, SHA1_Final,
             64 /*NID_sha1*/);
impl_Digest!(SHA256, 256, 256, 512, SHA256_Init, SHA256_Update, SHA256_Final,
             672 /*NID_sha256*/);
impl_Digest!(SHA384, 384, 512, 1024, SHA384_Init, SHA384_Update, SHA384_Final,
             673 /*NID_sha384*/);
impl_Digest!(SHA512, 512, 512, 1024, SHA512_Init, SHA512_Update, SHA512_Final,
             674 /*NID_sha512*/);

/// The maximum block length (`Algorithm::block_len`) of all the algorithms in
/// this module.
pub const MAX_BLOCK_LEN: usize = 1024 / 8;

/// The maximum output length (`Algorithm::output_len`) of all the algorithms
/// in this module.
pub const MAX_OUTPUT_LEN: usize = 512 / 8;

// The number of u64-sized words needed to store the largest digest context
// state.
const DIGEST_CONTEXT_STATE_U64_COUNT: usize = 28;

#[cfg(test)]
mod tests {
    use super::super::{digest, file_test};

    #[test]
    fn test_digests() {
        file_test::run("src/digest_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let digest_alg = test_case.consume_digest_alg("Hash").unwrap();
            let input = test_case.consume_bytes("Input");
            let repeat = test_case.consume_usize("Repeat");
            let expected = test_case.consume_bytes("Output");

            let mut ctx = digest::Context::new(digest_alg);
            let mut data = Vec::new();
            for _ in 0..repeat {
                ctx.update(&input);
                data.extend(&input);
            }
            let actual_from_chunks = ctx.finish();
            assert_eq!(&expected, &actual_from_chunks.as_ref());

            let actual_from_one_shot = digest::digest(digest_alg, &data);
            assert_eq!(&expected, &actual_from_one_shot.as_ref());
        });
    }

    /// Test some ways in which `Context::update` and/or `Context::finish`
    /// could go wrong by testing every combination of updating three inputs
    /// that vary from zero bytes to twice the size of the block length.
    ///
    /// This is not run in dev (debug) builds because it is too slow.
    macro_rules! test_i_u_f {
        ( $test_name:ident, $alg:expr) => {
            #[cfg(not(debug_assertions))]
            #[test]
            fn $test_name() {
                let mut input = vec![0u8; $alg.block_len * 2];
                for i in 0..input.len() {
                    input[i] = i as u8;
                }

                for i in 0..input.len() {
                    for j in 0..input.len() {
                        for k in 0..input.len() {
                            let part1 = &input[0..i];
                            let part2 = &input[0..j];
                            let part3 = &input[0..k];

                            let mut ctx = digest::Context::new(&$alg);
                            ctx.update(part1);
                            ctx.update(part2);
                            ctx.update(part3);
                            let i_u_f = ctx.finish();

                            let mut combined = Vec::<u8>::new();
                            combined.extend(part1);
                            combined.extend(part2);
                            combined.extend(part3);
                            let one_shot = digest::digest(&$alg, &combined);

                            assert_eq!(i_u_f.as_ref(), one_shot.as_ref());
                        }
                    }
                }
            }
        }
    }
    test_i_u_f!(test_i_u_f_sha1, digest::SHA1);
    test_i_u_f!(test_i_u_f_sha256, digest::SHA256);
    test_i_u_f!(test_i_u_f_sha384, digest::SHA384);
    test_i_u_f!(test_i_u_f_sha512, digest::SHA512);

    /// See https://bugzilla.mozilla.org/show_bug.cgi?id=610162. This tests the
    /// calculation of 8GB of the byte 123.
    ///
    /// You can verify the expected values in many ways. One way is
    /// `python ~/p/write_big.py`, where write_big.py is:
    ///
    /// ```python
    /// chunk = bytearray([123] * (16 * 1024))
    /// with open('tempfile', 'w') as f:
    /// for i in xrange(0, 8 * 1024 * 1024 * 1024, len(chunk)):
    ///     f.write(chunk)
    /// ```
    /// Then:
    ///
    /// ```sh
    /// sha1sum -b tempfile
    /// sha256sum -b tempfile
    /// sha384sum -b tempfile
    /// sha512sum -b tempfile
    /// ```
    ///
    /// This is not run in dev (debug) builds because it is too slow.
    macro_rules! test_large_digest {
        ( $test_name:ident, $alg:expr, $len:expr, $expected:expr) => {
            #[cfg(not(debug_assertions))]
            #[test]
            fn $test_name() {
                let chunk = vec![123u8; 16 * 1024];
                let chunk_len = chunk.len() as u64;
                let mut ctx = digest::Context::new(&$alg);
                let mut hashed = 0u64;
                loop {
                    ctx.update(&chunk);
                    hashed += chunk_len;
                    if hashed >= 8u64 * 1024 * 1024 * 1024 {
                        break;
                    }
                }
                let calculated = ctx.finish();
                let expected: [u8; $len] = $expected;
                assert_eq!(&expected[..], calculated.as_ref());
            }
        }
    }
    test_large_digest!(test_large_digest_sha1, digest::SHA1, 160 / 8, [
        0xCA, 0xC3, 0x4C, 0x31, 0x90, 0x5B, 0xDE, 0x3B,
        0xE4, 0x0D, 0x46, 0x6D, 0x70, 0x76, 0xAD, 0x65,
        0x3C, 0x20, 0xE4, 0xBD
    ]);
    test_large_digest!(test_large_digest_sha256, digest::SHA256, 256 / 8, [
        0x8D, 0xD1, 0x6D, 0xD8, 0xB2, 0x5A, 0x29, 0xCB,
        0x7F, 0xB9, 0xAE, 0x86, 0x72, 0xE9, 0xCE, 0xD6,
        0x65, 0x4C, 0xB6, 0xC3, 0x5C, 0x58, 0x21, 0xA7,
        0x07, 0x97, 0xC5, 0xDD, 0xAE, 0x5C, 0x68, 0xBD
    ]);
    test_large_digest!(test_large_digest_sha384, digest::SHA384, 384 / 8, [
        0x3D, 0xFE, 0xC1, 0xA9, 0xD0, 0x9F, 0x08, 0xD5,
        0xBB, 0xE8, 0x7C, 0x9E, 0xE0, 0x0A, 0x87, 0x0E,
        0xB0, 0xEA, 0x8E, 0xEA, 0xDB, 0x82, 0x36, 0xAE,
        0x74, 0xCF, 0x9F, 0xDC, 0x86, 0x1C, 0xE3, 0xE9,
        0xB0, 0x68, 0xCD, 0x19, 0x3E, 0x39, 0x90, 0x02,
        0xE1, 0x58, 0x5D, 0x66, 0xC4, 0x55, 0x11, 0x9B
    ]);
    test_large_digest!(test_large_digest_sha512, digest::SHA512, 512 / 8, [
        0xFC, 0x8A, 0x98, 0x20, 0xFC, 0x82, 0xD8, 0x55,
        0xF8, 0xFF, 0x2F, 0x6E, 0xAE, 0x41, 0x60, 0x04,
        0x08, 0xE9, 0x49, 0xD7, 0xCD, 0x1A, 0xED, 0x22,
        0xEB, 0x55, 0xE1, 0xFD, 0x80, 0x50, 0x3B, 0x01,
        0x2F, 0xC6, 0xF4, 0x33, 0x86, 0xFB, 0x60, 0x75,
        0x2D, 0xA5, 0xA9, 0x93, 0xE7, 0x00, 0x45, 0xA8,
        0x49, 0x1A, 0x6B, 0xEC, 0x9C, 0x98, 0xC8, 0x19,
        0xA6, 0xA9, 0x88, 0x3E, 0x2F, 0x09, 0xB9, 0x9A
    ]);
}
