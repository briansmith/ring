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

//! SHA-2 and legacy SHA-1 and MD5 digest algorithms.
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
/// use ring::*;
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
/// use ring::*;
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
    use super::*;

    fn test_digest_alg(algorithm: &'static Algorithm,
                       test_cases: &[(&'static str, u32, &'static str)]) {
        use rustc_serialize::hex::FromHex;

        for &(data_chunk, repeat, expected_hex) in test_cases {
            let expected = expected_hex.from_hex().unwrap();

            let mut ctx = Context::new(algorithm);
            let mut data = Vec::new();
            for _ in 0..repeat {
                ctx.update(data_chunk.as_bytes());
                data.extend(data_chunk.as_bytes());
            }
            let actual_from_chunks = ctx.finish();
            assert_eq!(&expected, &actual_from_chunks.as_ref());

            let actual_from_one_shot = digest(algorithm, &data);
            assert_eq!(&expected, &actual_from_one_shot.as_ref());
        }
    }

    #[test]
    fn test_md5() {
        test_digest_alg(&MD5, &[
            // From RFC 1321.
            ("", 1, "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", 1, "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", 1, "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", 1, "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", 1, "c3fcd3d76192e4007dfb496cca67e13b"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
             "d174ab98d277d9f5a5611c2c9f419d9f"),
            ("1234567890", 8, "57edf4a22be3c955ac49da2e2107b67a"),
        ]);
    }

    #[test]
    fn test_sha1() {
         test_digest_alg(&SHA1, &[
            // From RFC 3174.
            ("abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
             "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            ("a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
            ("0123456701234567012345670123456701234567012345670123456701234567", 10,
             "dea356a2cddd90c7a7ecedc5ebb563934f460452"),
        ]);
    }

    #[test]
    fn test_sha256() {
        test_digest_alg(&SHA256, &[
            // From NIST.
            ("abc", 1,
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ]);
    }

    #[test]
    fn test_sha384() {
        test_digest_alg(&SHA384, &[
            // From NIST.
            ("abc", 1,
             "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
              8086072ba1e7cc2358baeca134c825a7"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
             "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
              fcc7c71a557e2db966c3e9fa91746039"),
        ]);
    }

    #[test]
    fn test_sha512() {
        test_digest_alg(&SHA512, &[
            // From NIST.
            ("abc", 1,
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
             "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
              501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
        ]);
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

impl_Digest!(MD5, 128, 512, MD5_Init, MD5_Update, MD5_Final, 4 /*NID_md5*/);
impl_Digest!(SHA1, 160, 512, SHA1_Init, SHA1_Update, SHA1_Final,
             64 /*NID_sha1*/);
impl_Digest!(SHA256, 256, 512, SHA256_Init, SHA256_Update, SHA256_Final,
             672 /*NID_sha256*/);
impl_Digest!(SHA384, 384, 1024, SHA384_Init, SHA384_Update, SHA384_Final,
             673 /*NID_sha384*/);
impl_Digest!(SHA512, 512, 1024, SHA512_Init, SHA512_Update, SHA512_Final,
             674 /*NID_sha512*/);

const MAX_DIGEST_LEN: usize = 512 / 8;

// The number of u64-sized words needed to store the largest digest context
// state.
const DIGEST_CONTEXT_STATE_U64_COUNT: usize = 28;
