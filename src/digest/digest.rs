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

#![allow(unsafe_code)]

use {c, init, polyfill};
use core;

// XXX: Replace with `const fn` when `const fn` is stable:
// https://github.com/rust-lang/rust/issues/24111
#[cfg(target_endian = "little")]
macro_rules! u32x2 {
    ( $first:expr, $second:expr ) =>
    ( ((($second as u64) << 32) | ($first as u64)) )
}

mod sha1;

/// A context for multi-step (Init-Update-Finish) digest calculations.
///
/// C analog: `EVP_MD_CTX`.
///
/// # Examples
///
/// ```
/// use ring::digest;
///
/// let one_shot = digest::digest(&digest::SHA384, b"hello, world");
///
/// let mut ctx = digest::Context::new(&digest::SHA384);
/// ctx.update(b"hello");
/// ctx.update(b", ");
/// ctx.update(b"world");
/// let multi_part = ctx.finish();
///
/// assert_eq!(&one_shot.as_ref(), &multi_part.as_ref());
/// ```
pub struct Context {
    // We use u64 to try to ensure 64-bit alignment/padding.
    state: [u64; MAX_CHAINING_LEN / 8],

    // Note that SHA-512 has a 128-bit input bit counter, but this
    // implementation only supports up to 2^64-1 input bits for all algorithms,
    // so a 64-bit counter is more than sufficient.
    completed_data_blocks: u64,

    // TODO: More explicitly force 64-bit alignment for |pending|.
    pending: [u8; MAX_BLOCK_LEN],
    num_pending: usize,

    /// The context's algorithm.
    pub algorithm: &'static Algorithm,
}

impl Context {
    /// Constructs a new context.
    ///
    /// C analogs: `EVP_DigestInit`, `EVP_DigestInit_ex`
    pub fn new(algorithm: &'static Algorithm) -> Context {
        init::init_once();

        Context {
            algorithm: algorithm,
            state: algorithm.initial_state,
            completed_data_blocks: 0,
            pending: [0u8; MAX_BLOCK_LEN],
            num_pending: 0,
        }
    }

    /// Updates the digest with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called. It must not be called
    /// after `finish` has been called.
    ///
    /// C analog: `EVP_DigestUpdate`
    pub fn update(&mut self, data: &[u8]) {
        if data.len() < self.algorithm.block_len - self.num_pending {
            polyfill::slice::fill_from_slice(
                &mut self.pending[self.num_pending..
                                  (self.num_pending + data.len())],
                data);
            self.num_pending += data.len();
            return;
        }

        let mut remaining = data;
        if self.num_pending > 0 {
            let to_copy = self.algorithm.block_len - self.num_pending;
            polyfill::slice::fill_from_slice(
                &mut self.pending[self.num_pending..self.algorithm.block_len],
                &data[..to_copy]);

            unsafe {
                (self.algorithm.block_data_order)(&mut self.state,
                                                  self.pending.as_ptr(), 1);
            }
            self.completed_data_blocks =
                self.completed_data_blocks.checked_add(1).unwrap();

            remaining = &remaining[to_copy..];
            self.num_pending = 0;
        }

        let num_blocks = remaining.len() / self.algorithm.block_len;
        let num_to_save_for_later = remaining.len() % self.algorithm.block_len;
        if num_blocks > 0 {
            unsafe {
                (self.algorithm.block_data_order)(&mut self.state,
                                                  remaining.as_ptr(),
                                                  num_blocks);
            }
            self.completed_data_blocks =
                self.completed_data_blocks.checked_add(widen_u64(num_blocks))
                                          .unwrap();
        }
        if num_to_save_for_later > 0 {
            polyfill::slice::fill_from_slice(
                &mut self.pending[..num_to_save_for_later],
                &remaining[(remaining.len() - num_to_save_for_later)..]);
            self.num_pending = num_to_save_for_later;
        }
    }

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// consumes the context so it cannot be (mis-)used after `finish` has been
    /// called.
    ///
    /// C analogs: `EVP_DigestFinal`, `EVP_DigestFinal_ex`
    pub fn finish(mut self) -> Digest {
        // We know |num_pending < self.algorithm.block_len|, because we would
        // have processed the block otherwise.

        let mut padding_pos = self.num_pending;
        self.pending[padding_pos] = 0x80;
        padding_pos += 1;

        if padding_pos > self.algorithm.block_len - self.algorithm.len_len {
            polyfill::slice::fill(
                &mut self.pending[padding_pos..self.algorithm.block_len], 0);
            unsafe {
                (self.algorithm.block_data_order)(&mut self.state,
                                                  self.pending.as_ptr(), 1);
            }
            // We don't increase |self.completed_data_blocks| because the
            // padding isn't data, and so it isn't included in the data length.
            padding_pos = 0;
        }

        polyfill::slice::fill(
            &mut self.pending[padding_pos..(self.algorithm.block_len - 8)], 0);

        // Output the length, in bits, in big endian order.
        let mut completed_data_bits: u64 =
            self.completed_data_blocks
                .checked_mul(widen_u64(self.algorithm.block_len)).unwrap()
                .checked_add(widen_u64(self.num_pending)).unwrap()
                .checked_mul(8).unwrap();

        for b in (&mut self.pending[(self.algorithm.block_len - 8)..
                                    self.algorithm.block_len]).into_iter().rev() {
            *b = completed_data_bits as u8;
            completed_data_bits /= 0x100;
        }
        unsafe {
            (self.algorithm.block_data_order)(&mut self.state,
                                              self.pending.as_ptr(), 1);
        }

        Digest {
            algorithm: self.algorithm,
            value: (self.algorithm.format_output)(&self.state),
        }
    }

    /// The algorithm that this context is using.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

// XXX: This should just be `#[derive(Clone)]` but that doesn't work because
// `[u8; 128]` doesn't implement `Clone`.
impl Clone for Context {
   fn clone(&self) -> Context {
        Context {
            state: self.state,
            pending: self.pending,
            completed_data_blocks: self.completed_data_blocks,
            num_pending: self.num_pending,
            algorithm: self.algorithm
        }
   }
}

/// Returns the digest of `data` using the given digest algorithm.
///
/// C analog: `EVP_Digest`
///
/// # Examples:
///
/// ```
/// # #[cfg(feature = "use_heap")]
/// # fn main() {
/// use ring::{digest, test};
///
/// let expected_hex = "09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b";
/// let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
/// let actual = digest::digest(&digest::SHA256, b"hello, world");
///
/// assert_eq!(&expected, &actual.as_ref());
/// # }
///
/// # #[cfg(not(feature = "use_heap"))]
/// # fn main() { }
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
    value: [u64; MAX_OUTPUT_LEN / 8],
    algorithm: &'static Algorithm,
}

impl Digest {
    /// The algorithm that was used to calculate the digest value.
    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm { self.algorithm }
}

impl AsRef<[u8]> for Digest {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &(polyfill::slice::u64_as_u8(&self.value))[..self.algorithm.output_len]
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        try!(write!(fmt, "{:?}:", self.algorithm));
        for byte in self.as_ref() {
            try!(write!(fmt, "{:02x}", byte));
        }
        Ok(())
    }
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

    /// The length of the length in the padding.
    len_len: usize,

    block_data_order: unsafe extern fn(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                       data: *const u8, num: c::size_t),
    format_output: fn (input: &[u64; MAX_CHAINING_LEN / 8]) ->
                       [u64; MAX_OUTPUT_LEN / 8],

    initial_state: [u64; MAX_CHAINING_LEN / 8],
}

impl core::fmt::Debug for Algorithm {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        // This would have to change if/when we add other algorithms with the
        // same output lengths.
        let n = if self.output_len == 20 { 1 } else { self.output_len * 8 };
        write!(fmt, "SHA-{:?}", n)
    }
}

/// SHA-1 as specified in [FIPS 180-4]. Deprecated.
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA1: Algorithm = Algorithm {
    output_len: 160 / 8,
    chaining_len: sha1::CHAINING_LEN,
    block_len: sha1::BLOCK_LEN,
    len_len: 64 / 8,
    block_data_order: sha1::block_data_order,
    format_output: sha256_format_output,
    initial_state: [
        u32x2!(0x67452301u32, 0xefcdab89u32),
        u32x2!(0x98badcfeu32, 0x10325476u32),
        u32x2!(0xc3d2e1f0u32, 0u32),
        0, 0, 0, 0, 0,
    ],
};

/// SHA-256 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA256: Algorithm = Algorithm {
    output_len: 256 / 8,
    chaining_len: 256 / 8,
    block_len: 512 / 8,
    len_len: 64 / 8,
    block_data_order: sha256_block_data_order,
    format_output: sha256_format_output,
    initial_state: [
        u32x2!(0x6a09e667u32, 0xbb67ae85u32),
        u32x2!(0x3c6ef372u32, 0xa54ff53au32),
        u32x2!(0x510e527fu32, 0x9b05688cu32),
        u32x2!(0x1f83d9abu32, 0x5be0cd19u32),
        0, 0, 0, 0,
    ],
};

/// SHA-384 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA384: Algorithm = Algorithm {
    output_len: 384 / 8,
    chaining_len: 512 / 8,
    block_len: 1024 / 8,
    len_len: 128 / 8,
    block_data_order: sha512_block_data_order,
    format_output: sha512_format_output,
    initial_state: [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ],
};

/// SHA-512 as specified in [FIPS 180-4].
///
/// [FIPS 180-4]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub static SHA512: Algorithm = Algorithm {
    output_len: 512 / 8,
    chaining_len: 512 / 8,
    block_len: 1024 / 8,
    len_len: 128 / 8,
    block_data_order: sha512_block_data_order,
    format_output: sha512_format_output,
    initial_state: [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ],
};

#[inline(always)]
fn widen_u64(x: usize) -> u64 { x as u64 }

/// The maximum block length (`Algorithm::block_len`) of all the algorithms in
/// this module.
pub const MAX_BLOCK_LEN: usize = 1024 / 8;

/// The maximum output length (`Algorithm::output_len`) of all the algorithms
/// in this module.
pub const MAX_OUTPUT_LEN: usize = 512 / 8;

/// The maximum chaining length (`Algorithm::chaining_len`) of all the
/// algorithms in this module.
pub const MAX_CHAINING_LEN: usize = MAX_OUTPUT_LEN;

fn sha256_format_output(input: &[u64; MAX_CHAINING_LEN / 8])
                        -> [u64; MAX_OUTPUT_LEN / 8] {
    let in32 = &polyfill::slice::u64_as_u32(input)[..8];
    [
        u32x2!(in32[0].to_be(), in32[1].to_be()),
        u32x2!(in32[2].to_be(), in32[3].to_be()),
        u32x2!(in32[4].to_be(), in32[5].to_be()),
        u32x2!(in32[6].to_be(), in32[7].to_be()),
        0,
        0,
        0,
        0,
    ]
}

fn sha512_format_output(input: &[u64; MAX_CHAINING_LEN / 8])
                        -> [u64; MAX_OUTPUT_LEN / 8] {
    [
        input[0].to_be(),
        input[1].to_be(),
        input[2].to_be(),
        input[3].to_be(),
        input[4].to_be(),
        input[5].to_be(),
        input[6].to_be(),
        input[7].to_be(),
    ]
}

/// SHA512_4 calculates the SHA-512 digest of the concatenation of |part1|
/// through |part4|. Any part<N> may be null if and only if the corresponding
/// part<N>_len is zero. This ugliness exists in order to allow some of the
/// C ECC code to calculate SHA-512 digests.
#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub extern fn SHA512_4(out: *mut u8, out_len: c::size_t,
                       part1: *const u8, part1_len: c::size_t,
                       part2: *const u8, part2_len: c::size_t,
                       part3: *const u8, part3_len: c::size_t,
                       part4: *const u8, part4_len: c::size_t) {
    fn maybe_update(ctx: &mut Context, part: *const u8, part_len: c::size_t) {
        if part_len != 0 {
            assert!(!part.is_null());
            ctx.update(unsafe { core::slice::from_raw_parts(part, part_len) });
        }
    }

    let mut ctx = Context::new(&SHA512);
    maybe_update(&mut ctx, part1, part1_len);
    maybe_update(&mut ctx, part2, part2_len);
    maybe_update(&mut ctx, part3, part3_len);
    maybe_update(&mut ctx, part4, part4_len);
    let digest = ctx.finish();
    let digest = digest.as_ref();
    let out = unsafe { core::slice::from_raw_parts_mut(out, out_len) };
    polyfill::slice::fill_from_slice(out, digest);
}

extern {
    fn sha256_block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                               data: *const u8, num: c::size_t);
    fn sha512_block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                               data: *const u8, num: c::size_t);
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

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use super::super::{digest, test};

    /// Test vectors from BoringSSL.
    #[test]
    fn test_bssl() {
        test::from_file("src/digest/digest_tests.txt", |section, test_case| {
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

            Ok(())
        });
    }

    mod shavs {
        use std::vec::Vec;
        use super::super::super::{digest, test};

        macro_rules! shavs_tests {
            ( $algorithm_name:ident ) => {
                #[allow(non_snake_case)]
                mod $algorithm_name {
                    use super::{run_known_answer_test, run_monte_carlo_test};
                    use super::super::super::super::digest;

                    #[test]
                    fn short_msg_known_answer_test() {
                        run_known_answer_test(
                            &digest::$algorithm_name,
                            &format!("third-party/NIST/SHAVS/{}ShortMsg.rsp",
                                     stringify!($algorithm_name)));
                    }

                    #[test]
                    fn long_msg_known_answer_test() {
                        run_known_answer_test(
                            &digest::$algorithm_name,
                            &format!("third-party/NIST/SHAVS/{}LongMsg.rsp",
                                     stringify!($algorithm_name)));
                    }

                    #[test]
                    fn monte_carlo_test() {
                        run_monte_carlo_test(
                            &digest::$algorithm_name,
                            &format!("third-party/NIST/SHAVS/{}Monte.rsp",
                                     stringify!($algorithm_name)));
                    }
                }
            }
        }

        fn run_known_answer_test(digest_alg: &'static digest::Algorithm,
                                 file_name: &str, ) {
            let section_name = &format!("L = {}", digest_alg.output_len);
            test::from_file(file_name, |section, test_case| {
                assert_eq!(section_name, section);
                let len_bits = test_case.consume_usize("Len");

                let mut msg = test_case.consume_bytes("Msg");
                // The "msg" field contains the dummy value "00" when the
                // length is zero.
                if len_bits == 0 {
                    assert_eq!(msg, &[0u8]);
                    msg.truncate(0);
                }

                assert_eq!(msg.len() * 8, len_bits);
                let expected = test_case.consume_bytes("MD");
                let actual = digest::digest(digest_alg, &msg);
                assert_eq!(&expected, &actual.as_ref());

                Ok(())
            });
        }

        fn run_monte_carlo_test(digest_alg: &'static digest::Algorithm,
                                file_name: &str) {
            let section_name = &format!("L = {}", digest_alg.output_len);

            let mut expected_count: isize = -1;
            let mut seed = Vec::with_capacity(digest_alg.output_len);

            test::from_file(file_name, |section, test_case| {
                assert_eq!(section_name, section);

                if expected_count == -1 {
                    seed.extend(test_case.consume_bytes("Seed"));
                    expected_count = 0;
                    return Ok(());
                }

                assert!(expected_count >= 0);
                let actual_count = test_case.consume_usize("COUNT");
                assert_eq!(expected_count as usize, actual_count);
                expected_count += 1;

                let expected_md = test_case.consume_bytes("MD");

                let mut mds = Vec::with_capacity(4);
                mds.push(seed.clone());
                mds.push(seed.clone());
                mds.push(seed.clone());
                for _ in 0..1000 {
                    let mut ctx = digest::Context::new(digest_alg);
                    ctx.update(&mds[0]);
                    ctx.update(&mds[1]);
                    ctx.update(&mds[2]);
                    let md_i = ctx.finish();
                    let _ = mds.remove(0);
                    mds.push(Vec::from(md_i.as_ref()));
                }
                let md_j = mds.last().unwrap();
                assert_eq!(&expected_md, md_j);
                seed = md_j.clone();

                Ok(())
            });

            assert_eq!(expected_count, 100);
        }

        shavs_tests!(SHA1);
        shavs_tests!(SHA256);
        shavs_tests!(SHA384);
        shavs_tests!(SHA512);
    }

    /// Test some ways in which `Context::update` and/or `Context::finish`
    /// could go wrong by testing every combination of updating three inputs
    /// that vary from zero bytes to one byte larger than the block length.
    ///
    /// These are not run in dev (debug) builds because they are too slow.
    macro_rules! test_i_u_f {
        ( $test_name:ident, $alg:expr) => {
            #[cfg(not(debug_assertions))]
            #[test]
            fn $test_name() {
                let mut input = [0; (super::MAX_BLOCK_LEN + 1) * 3];
                let max = $alg.block_len + 1;
                for i in 0..(max * 3) {
                    input[i] = (i & 0xff) as u8;
                }

                for i in 0..max {
                    for j in 0..max {
                        for k in 0..max {
                            let part1 = &input[..i];
                            let part2 = &input[i..(i+j)];
                            let part3 = &input[(i+j)..(i+j+k)];

                            let mut ctx = digest::Context::new(&$alg);
                            ctx.update(part1);
                            ctx.update(part2);
                            ctx.update(part3);
                            let i_u_f = ctx.finish();

                            let one_shot =
                                digest::digest(&$alg, &input[..(i + j + k)]);

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

    #[test]
    fn test_fmt_algorithm() {
        assert_eq!("SHA-1", &format!("{:?}", digest::SHA1));
        assert_eq!("SHA-256", &format!("{:?}", digest::SHA256));
        assert_eq!("SHA-384", &format!("{:?}", digest::SHA384));
        assert_eq!("SHA-512", &format!("{:?}", digest::SHA512));
    }

    #[test]
    fn test_fmt_digest() {
        assert_eq!("SHA-1:b7e23ec29af22b0b4e41da31e868d57226121c84",
                   &format!("{:?}",
                            digest::digest(&digest::SHA1, b"hello, world")));
        assert_eq!("SHA-256:09ca7e4eaa6e8ae9c7d261167129184883644d\
                    07dfba7cbfbc4c8a2e08360d5b",
                   &format!("{:?}",
                            digest::digest(&digest::SHA256, b"hello, world")));
        assert_eq!("SHA-384:1fcdb6059ce05172a26bbe2a3ccc88ed5a8cd5\
                    fc53edfd9053304d429296a6da23b1cd9e5c9ed3bb34f0\
                    0418a70cdb7e",
                   &format!("{:?}",
                            digest::digest(&digest::SHA384, b"hello, world")));
        assert_eq!("SHA-512:8710339dcb6814d0d9d2290ef422285c9322b7\
                    163951f9a0ca8f883d3305286f44139aa374848e4174f5\
                    aada663027e4548637b6d19894aec4fb6c46a139fbf9",
                   &format!("{:?}",
                            digest::digest(&digest::SHA512, b"hello, world")));

    }
}
