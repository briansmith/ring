// Copyright 2018 Brian Smith.
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

use super::{
    block::{Block, BLOCK_LEN},
    nonce::Nonce,
    quic::Sample,
};
use crate::{
    bits::BitLength,
    c, cpu,
    endian::{ArrayEncoding, BigEndian},
    error,
    polyfill::{self, ChunksFixed},
};
use core::ops::RangeFrom;

pub(crate) struct Key {
    inner: AES_KEY,
    cpu_features: cpu::Features,
}

macro_rules! set_encrypt_key {
    ( $name:ident, $bytes:expr, $key_bits:expr, $key:expr ) => {{
        extern "C" {
            fn $name(user_key: *const u8, bits: c::uint, key: &mut AES_KEY) -> c::int;
        }
        set_encrypt_key($name, $bytes, $key_bits, $key)
    }};
}

#[inline]
fn set_encrypt_key(
    f: unsafe extern "C" fn(*const u8, c::uint, &mut AES_KEY) -> c::int,
    bytes: &[u8],
    key_bits: BitLength,
    key: &mut AES_KEY,
) -> Result<(), error::Unspecified> {
    // Unusually, in this case zero means success and non-zero means failure.
    if 0 == unsafe { f(bytes.as_ptr(), key_bits.as_usize_bits() as c::uint, key) } {
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}

macro_rules! encrypt_block {
    ($name:ident, $block:expr, $key:expr) => {{
        extern "C" {
            fn $name(a: &Block, r: *mut Block, key: &AES_KEY);
        }
        encrypt_block_($name, $block, $key)
    }};
}

#[inline]
fn encrypt_block_(
    f: unsafe extern "C" fn(&Block, *mut Block, &AES_KEY),
    a: Block,
    key: &Key,
) -> Block {
    let mut result = core::mem::MaybeUninit::uninit();
    unsafe {
        f(&a, result.as_mut_ptr(), &key.inner);
        result.assume_init()
    }
}

macro_rules! ctr32_encrypt_blocks {
    ($name:ident, $in_out:expr, $src:expr, $key:expr, $ivec:expr ) => {{
        extern "C" {
            fn $name(
                input: *const u8,
                output: *mut u8,
                blocks: c::size_t,
                key: &AES_KEY,
                ivec: &Counter,
            );
        }
        ctr32_encrypt_blocks_($name, $in_out, $src, $key, $ivec)
    }};
}

#[inline]
fn ctr32_encrypt_blocks_(
    f: unsafe extern "C" fn(
        input: *const u8,
        output: *mut u8,
        blocks: c::size_t,
        key: &AES_KEY,
        ivec: &Counter,
    ),
    in_out: &mut [u8],
    src: RangeFrom<usize>,
    key: &AES_KEY,
    ctr: &mut Counter,
) {
    let in_out_len = in_out[src.clone()].len();
    assert_eq!(in_out_len % BLOCK_LEN, 0);

    let blocks = in_out_len / BLOCK_LEN;
    let blocks_u32 = blocks as u32;
    assert_eq!(blocks, polyfill::usize_from_u32(blocks_u32));

    let input = in_out[src].as_ptr();
    let output = in_out.as_mut_ptr();

    unsafe {
        f(input, output, blocks, &key, ctr);
    }
    ctr.increment_by_less_safe(blocks_u32);
}

impl Key {
    #[inline]
    pub fn new(
        bytes: &[u8],
        variant: Variant,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let key_bits = match variant {
            Variant::AES_128 => BitLength::from_usize_bits(128),
            Variant::AES_256 => BitLength::from_usize_bits(256),
        };
        if BitLength::from_usize_bytes(bytes.len())? != key_bits {
            return Err(error::Unspecified);
        }

        let mut key = AES_KEY {
            rd_key: [0u32; 4 * (MAX_ROUNDS + 1)],
            rounds: 0,
        };

        match detect_implementation(cpu_features) {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::HWAES => {
                set_encrypt_key!(GFp_aes_hw_set_encrypt_key, bytes, key_bits, &mut key)?
            }

            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::VPAES_BSAES => {
                set_encrypt_key!(GFp_vpaes_set_encrypt_key, bytes, key_bits, &mut key)?
            }

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::NOHW => {
                set_encrypt_key!(GFp_aes_nohw_set_encrypt_key, bytes, key_bits, &mut key)?
            }
        };

        Ok(Self {
            inner: key,
            cpu_features,
        })
    }

    #[inline]
    pub fn encrypt_block(&self, a: Block) -> Block {
        match detect_implementation(self.cpu_features) {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::HWAES => encrypt_block!(GFp_aes_hw_encrypt, a, self),

            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::VPAES_BSAES => encrypt_block!(GFp_vpaes_encrypt, a, self),

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::NOHW => encrypt_block!(GFp_aes_nohw_encrypt, a, self),
        }
    }

    #[inline]
    pub fn encrypt_iv_xor_block(&self, iv: Iv, input: Block) -> Block {
        let encrypted_iv = self.encrypt_block(Block::from(iv.as_bytes_less_safe()));
        encrypted_iv ^ input
    }

    #[inline]
    pub(super) fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        ctr: &mut Counter,
    ) {
        let in_out_len = in_out[src.clone()].len();

        assert_eq!(in_out_len % BLOCK_LEN, 0);

        match detect_implementation(self.cpu_features) {
            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            Implementation::HWAES => ctr32_encrypt_blocks!(
                GFp_aes_hw_ctr32_encrypt_blocks,
                in_out,
                src,
                &self.inner,
                ctr
            ),

            #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
            Implementation::VPAES_BSAES => {
                // 8 blocks is the cut-off point where it's faster to use BSAES.
                #[cfg(target_arch = "arm")]
                let in_out = if in_out_len >= 8 * BLOCK_LEN {
                    let remainder = in_out_len % (8 * BLOCK_LEN);
                    let bsaes_in_out_len = if remainder < (4 * BLOCK_LEN) {
                        in_out_len - remainder
                    } else {
                        in_out_len
                    };

                    let mut bsaes_key = AES_KEY {
                        rd_key: [0u32; 4 * (MAX_ROUNDS + 1)],
                        rounds: 0,
                    };
                    extern "C" {
                        fn GFp_vpaes_encrypt_key_to_bsaes(
                            bsaes_key: &mut AES_KEY,
                            vpaes_key: &AES_KEY,
                        );
                    }
                    unsafe {
                        GFp_vpaes_encrypt_key_to_bsaes(&mut bsaes_key, &self.inner);
                    }
                    ctr32_encrypt_blocks!(
                        GFp_bsaes_ctr32_encrypt_blocks,
                        &mut in_out[src.clone()][bsaes_in_out_len..],
                        src.clone(),
                        &bsaes_key,
                        ctr
                    );

                    &mut in_out[src.clone()][bsaes_in_out_len..]
                } else {
                    in_out
                };

                ctr32_encrypt_blocks!(
                    GFp_vpaes_ctr32_encrypt_blocks,
                    in_out,
                    src,
                    &self.inner,
                    ctr
                )
            }

            #[cfg(any(target_arch = "x86"))]
            Implementation::VPAES_BSAES => {
                super::shift::shift_full_blocks(in_out, src, |input| {
                    self.encrypt_iv_xor_block(ctr.increment(), Block::from(input))
                });
            }

            #[cfg(not(target_arch = "aarch64"))]
            Implementation::NOHW => ctr32_encrypt_blocks!(
                GFp_aes_nohw_ctr32_encrypt_blocks,
                in_out,
                src,
                &self.inner,
                ctr
            ),
        }
    }

    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let block = self.encrypt_block(Block::from(&sample));

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&block.as_ref()[..5]);

        out
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn is_aes_hw(&self) -> bool {
        matches!(
            detect_implementation(self.cpu_features),
            Implementation::HWAES
        )
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub(super) fn inner_less_safe(&self) -> &AES_KEY {
        &self.inner
    }
}

// Keep this in sync with AES_KEY in aes.h.
#[repr(C)]
pub(super) struct AES_KEY {
    pub rd_key: [u32; 4 * (MAX_ROUNDS + 1)],
    pub rounds: c::uint,
}

// Keep this in sync with `AES_MAXNR` in aes.h.
const MAX_ROUNDS: usize = 14;

pub enum Variant {
    AES_128,
    AES_256,
}

/// Nonce || Counter, all big-endian.
#[repr(transparent)]
pub(super) struct Counter([BigEndian<u32>; 4]);

impl Counter {
    pub fn one(nonce: Nonce) -> Self {
        let nonce = nonce.as_ref().chunks_fixed();
        Self([nonce[0].into(), nonce[1].into(), nonce[2].into(), 1.into()])
    }

    pub fn increment(&mut self) -> Iv {
        let iv = Iv(self.0);
        self.increment_by_less_safe(1);
        iv
    }

    fn increment_by_less_safe(&mut self, increment_by: u32) {
        let old_value: u32 = self.0[3].into();
        self.0[3] = (old_value + increment_by).into();
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv([BigEndian<u32>; 4]);

impl From<Counter> for Iv {
    fn from(counter: Counter) -> Self {
        Self(counter.0)
    }
}

impl Iv {
    pub(super) fn as_bytes_less_safe(&self) -> &[u8; 16] {
        self.0.as_byte_array()
    }
}

#[repr(C)] // Only so `Key` can be `#[repr(C)]`
#[derive(Clone, Copy)]
pub enum Implementation {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    HWAES = 1,

    // On "arm" only, this indicates that the bsaes implementation may be used.
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    VPAES_BSAES = 2,

    #[cfg(not(target_arch = "aarch64"))]
    NOHW = 3,
}

fn detect_implementation(cpu_features: cpu::Features) -> Implementation {
    // `cpu_features` is only used for specific platforms.
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    let _cpu_features = cpu_features;

    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    {
        if cpu::intel::AES.available(cpu_features) || cpu::arm::AES.available(cpu_features) {
            return Implementation::HWAES;
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if cpu::intel::SSSE3.available(cpu_features) {
            return Implementation::VPAES_BSAES;
        }
    }

    #[cfg(target_arch = "arm")]
    {
        if cpu::arm::NEON.available(cpu_features) {
            return Implementation::VPAES_BSAES;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        Implementation::VPAES_BSAES
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        Implementation::NOHW
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use core::convert::TryInto;

    #[test]
    pub fn test_aes() {
        test::run(test_file!("aes_tests.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = consume_key(test_case, "Key");
            let input = test_case.consume_bytes("Input");
            let input: &[u8; BLOCK_LEN] = input.as_slice().try_into()?;
            let expected_output = test_case.consume_bytes("Output");

            let block = Block::from(input);
            let output = key.encrypt_block(block);
            assert_eq!(output.as_ref(), &expected_output[..]);

            Ok(())
        })
    }

    fn consume_key(test_case: &mut test::TestCase, name: &str) -> Key {
        let key = test_case.consume_bytes(name);
        let variant = match key.len() {
            16 => Variant::AES_128,
            32 => Variant::AES_256,
            _ => unreachable!(),
        };
        Key::new(&key[..], variant, cpu::features()).unwrap()
    }
}
