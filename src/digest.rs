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

use libc;
use std::mem;

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
    /// C analog: `EVP_DigestInit`
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
                                    data.len() as libc::size_t)
        };
    }

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// consumes the context so it cannot be (mis-)used after `finish` has been
    /// called.
    ///
    /// C analog: `EVP_DigestFinal`
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
    value: [u8; MAX_DIGEST_LEN],
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] { &self.value[0..self.algorithm.digest_len] }
}

/// A digest algorithm.
///
/// C analog: `EVP_MD`
#[repr(C)]
pub struct Algorithm {
    /// C analog: `EVP_MD_size`
    pub digest_len: usize,

    /// C analog: `EVP_MD_block_size`
    pub block_len: usize,

    init: unsafe extern fn(ctx_state: *mut u64) -> libc::c_int,
    update: unsafe extern fn(ctx_state: *mut u64, data: *const u8,
                             len: libc::size_t) -> libc::c_int,
    final_: unsafe extern fn(out: *mut u8, ctx_state: *mut u64) -> libc::c_int,

    // XXX: This is required because the signature verification functions
    // require a NID. But, really they don't need a NID, but just the OID of
    // the digest function, perhaps with an `EVP_MD` if it wants to validate
    // the properties of the digest like the length. XXX: This has to be public
    // because it is accessed from the signature modules.
    pub nid: libc::c_int,
}

#[cfg(test)]
mod tests {
    use super::super::{digest, file_test};

    #[test]
    fn test_digests() {
        fn test_case(test_case: &mut file_test::TestCase) {
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
        }

        file_test::run("src/digest_tests.txt", test_case);
    }
}

macro_rules! impl_Digest {
    ($XXX:ident, $digest_len_in_bits:expr, $block_len_in_bits:expr,
     $xxx_Init:ident, $xxx_Update:ident, $xxx_Final:ident, $NID_xxx:expr) => {

        pub static $XXX: Algorithm = Algorithm {
            digest_len: $digest_len_in_bits / 8,
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
        extern {
            fn $xxx_Init(ctx_state: *mut u64) -> libc::c_int;
            fn $xxx_Update(ctx_state: *mut u64, data: *const u8,
                           len: libc::size_t) -> libc::c_int;
            fn $xxx_Final(out: *mut u8, ctx_state: *mut u64) -> libc::c_int;
        }
    }
}

impl_Digest!(SHA1, 160, 512, SHA1_Init, SHA1_Update, SHA1_Final,
             64 /*NID_sha1*/);
impl_Digest!(SHA256, 256, 512, SHA256_Init, SHA256_Update, SHA256_Final,
             672 /*NID_sha256*/);
impl_Digest!(SHA384, 384, 1024, SHA384_Init, SHA384_Update, SHA384_Final,
             673 /*NID_sha384*/);
impl_Digest!(SHA512, 512, 1024, SHA512_Init, SHA512_Update, SHA512_Final,
             674 /*NID_sha512*/);

pub const MAX_DIGEST_LEN: usize = 512 / 8;

// The number of u64-sized words needed to store the largest digest context
// state.
const DIGEST_CONTEXT_STATE_U64_COUNT: usize = 28;
