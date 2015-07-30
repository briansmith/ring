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

// Note on why are we doing things the hard way: It would be easy to implement
// this using the C `EVP_MD`/`EVP_MD_CTX` interface. However, if we were to do
// things that way, we'd have a hard dependency on `malloc` and other overhead.
// The goal for this implementation is to drive the overhead as close to zero
// as possible.

// XXX: Double-check conversions between |usize| and |libc::size_t|, and try to
// find some way to statically assert that they have the same range.

use libc;
use std::mem;

/// A context for digest calculations. If all the data is available in a single
/// contiguous slice, then the `digest` function should be used. Otherwise, the
/// digest can be calculated in parts.
///
/// ```ignore
/// use ring::{digest, SHA384};
///
/// let one_shot = digest::<SHA384>("hello, world".as_bytes());
///
/// let mut ctx = SHA384::new();
/// ctx.update("hello".as_bytes());
/// ctx.update(", ".as_bytes());
/// ctx.update("world".as_bytes());
/// let multi_part = ctx.finish();
///
/// assert_eq!(&one_shot[..], &multi_part[..]);
/// ```
pub trait Digest {
    /// The sized array type for the digest's size. For example, for SHA-256
    /// this is `[u8; 32]` (256 / 8 == 32).
    type Value;

    /// Constructs a new context.
    ///
    /// C analog: `EVP_DigestInit`
    fn new() -> Self;

    /// Updates the digest with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called. It must not be called
    /// after `finish` has been called.
    ///
    /// C analog: `EVP_DigestUpdate`
    fn update(&mut self, data: &[u8]);

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// must not be called more than once.
    ///
    /// C analog: `EVP_DigestFinal`
    fn finish(&mut self) -> <Self as Digest>::Value;
}

/// Returns the digest of `data` using the given digest function.
///
/// # Examples:
///
/// ```ignore
/// use ring::{digest, SHA256};
/// use rustc_serialize::hex::FromHex;
///
/// let expected_hex = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
/// let expected: Vec<u8> = expected_hex.from_hex().unwrap();
/// let actual = digest::<SHA256>("hello, world".as_bytes());
///
/// assert_eq!(&expected[..], &actual[..]);
/// ```
///
/// C analog: `EVP_Digest`
pub fn digest<D: Digest>(data: &[u8]) -> <D as Digest>::Value {
    let mut ctx = D::new();
    ctx.update(data);
    ctx.finish()
}

macro_rules! impl_Digest {
    ($A_name:expr, $a_name:expr, $XXX:ident, $length_in_bits:expr,
     $xxx_state_st:ident, $xxx_Init:ident, $xxx_Update:ident, $xxx_Final:ident,
     $xxx_DIGEST_LEN:ident, $xxx_tests:ident, $test_xxx:ident,
     $xxx_num_test_cases:expr, $xxx_test_cases:expr) => {

        #[doc="The length, in bytes, of "]
        #[doc=$a_name]
        #[doc=" digest."]
        pub const $xxx_DIGEST_LEN: usize = $length_in_bits / 8;

        #[doc=$A_name]
        #[doc=" digest context that implements the `Digest` trait."]
        pub struct $XXX { state: $xxx_state_st }

        impl Digest for $XXX {
            type Value = [u8; $xxx_DIGEST_LEN];

            /// Constructs a new, initialized `$XXX`.
            fn new() -> $XXX {
                let mut ctx;
                unsafe {
                    ctx = $XXX { state: mem::uninitialized() };
                    let _ = $xxx_Init(&mut ctx.state);
                }
                ctx
            }

            fn update(&mut self, data: &[u8]) {
                unsafe {
                    let _ = $xxx_Update(&mut self.state, data.as_ptr(),
                                        data.len() as libc::size_t);
                }
            }

            fn finish(&mut self) -> <$XXX as Digest>::Value {
                let mut result: <$XXX as Digest>::Value;
                unsafe {
                    result = mem::uninitialized();
                    let _ = $xxx_Final(result.as_mut_ptr(), &mut self.state);
                }
                result
            }
        }

        #[cfg(test)]
        mod $xxx_tests {
            use super::{Digest, digest, $XXX};

            #[test]
            fn $test_xxx() {
                use rustc_serialize::hex::FromHex;

                // From NIST:
                const TEST_CASES: [(&'static str, u32, &'static str);
                                   $xxx_num_test_cases] =
                    $xxx_test_cases;

                for &(data_chunk, repeat, expected_hex) in TEST_CASES.iter() {
                    let expected = expected_hex.from_hex().unwrap();

                    let mut ctx = $XXX::new();
                    let mut data = Vec::new();
                    for _ in 0..repeat {
                        ctx.update(data_chunk.as_bytes());
                        data.extend(data_chunk.as_bytes());
                    }
                    let actual_from_chunks = ctx.finish();
                    assert_eq!(&expected[..], &actual_from_chunks[..]);

                    let actual_from_one_shot = digest::<$XXX>(&data);
                    assert_eq!(&expected[..], &actual_from_one_shot[..]);
                }
            }
        }

        extern {
            // Although these functions all return a return value, in BoringSSL
            // they are always guaranteed to return 1 according to the
            // documentation in the header files, so we can safely ignore their
            // return values.
            fn $xxx_Init(md5: *mut $xxx_state_st) -> libc::c_int;
            fn $xxx_Update(md5: *mut $xxx_state_st, data: *const u8,
                           len: libc::size_t) -> libc::c_int;
            fn $xxx_Final(md: *mut u8, md5: *mut $xxx_state_st) -> libc::c_int;
        }
    }
}

impl_Digest!("An MD5", "an MD5", MD5, 128, md5_state_st, MD5_Init, MD5_Update,
             MD5_Final, MD5_DIGEST_LEN, md5_tests, test_md5, 7, [
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

impl_Digest!("A SHA-1", "a SHA-1", SHA1, 160, sha_state_st, SHA1_Init,
             SHA1_Update, SHA1_Final, SHA1_DIGEST_LEN, sha1_tests, test_sha1,
             4, [
    // From RFC 3174.
    ("abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    ("a", 1000000, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"),
    ("0123456701234567012345670123456701234567012345670123456701234567", 10,
     "dea356a2cddd90c7a7ecedc5ebb563934f460452"),
]);

impl_Digest!("A SHA-256", "a SHA-256", SHA256, 256, sha256_state_st,
             SHA256_Init, SHA256_Update, SHA256_Final, SHA256_DIGEST_LEN,
             sha256_tests, test_sha256, 2, [
    // From NIST.
    ("abc", 1,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]);

impl_Digest!("A SHA-384", "a SHA-384", SHA384, 384, sha512_state_st,
             SHA384_Init, SHA384_Update, SHA384_Final, SHA384_DIGEST_LEN,
             sha384_tests, test_sha384, 2, [
    // From NIST.
    ("abc", 1,
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
      8086072ba1e7cc2358baeca134c825a7"),
    ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
      hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
     "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
      fcc7c71a557e2db966c3e9fa91746039"),
]);

impl_Digest!("A SHA-512", "a SHA-512", SHA512, 512, sha512_state_st,
             SHA512_Init, SHA512_Update, SHA512_Final, SHA512_DIGEST_LEN,
             sha512_tests, test_sha512, 2, [
    // From NIST.
    ("abc", 1,
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
      2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
      hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
     "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
      501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),

]);

// TODO: find a better way to keep the C and Rust struct definitions in sync.

#[allow(non_snake_case)]
#[repr(C)]
struct md5_state_st {
    A: libc::uint32_t,
    B: libc::uint32_t,
    C: libc::uint32_t,
    D: libc::uint32_t,
    Nl: libc::uint32_t,
    Nh: libc::uint32_t,
    data: [libc::uint32_t; 16],
    num: libc::c_uint
}

#[allow(non_snake_case)]
#[repr(C)]
struct sha_state_st {
    h0: libc::uint32_t,
    h1: libc::uint32_t,
    h2: libc::uint32_t,
    h3: libc::uint32_t,
    h4: libc::uint32_t,
    Nl: libc::uint32_t,
    Nh: libc::uint32_t,
    data: [libc::uint32_t; 16],
    num: libc::c_uint
}

#[repr(C)]
#[allow(non_snake_case)]
struct sha256_state_st {
    h: [libc::uint32_t; 8],
    Nl: libc::uint32_t,
    Nh: libc::uint32_t,
    data: [libc::uint32_t; 16],
    num: libc::c_uint,
    md_len: libc::c_uint,
}

#[repr(C)]
#[allow(non_snake_case)]
struct sha512_state_st {
    h: [libc::uint64_t; 8],
    Nl: libc::uint64_t,
    Nh: libc::uint64_t,
    u_d: [libc::uint64_t; 16], // union { uint64_t d[16]; uint8_t p[128]; } u;
    num: libc::c_uint,
    md_len: libc::c_uint,
}
