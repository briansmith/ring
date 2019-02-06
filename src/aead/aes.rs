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
    nonce::{self, Iv},
    shift, Block, Direction, BLOCK_LEN,
};
use crate::{bits::BitLength, cpu, endian::*, error, polyfill};
use libc::size_t;

pub(crate) struct Key {
    inner: AES_KEY,
    cpu_features: cpu::Features,
}

impl Key {
    #[inline]
    pub fn new(
        bytes: &[u8], variant: Variant, cpu_features: cpu::Features,
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
            Implementation::HWAES => {
                extern "C" {
                    fn GFp_aes_hw_set_encrypt_key(
                        user_key: *const u8, bits: libc::c_uint, key: &mut AES_KEY,
                    ) -> ZeroMeansSuccess;
                }
                Result::from(unsafe {
                    GFp_aes_hw_set_encrypt_key(
                        bytes.as_ptr(),
                        key_bits.as_usize_bits() as libc::c_uint,
                        &mut key,
                    )
                })?;
            },

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Implementation::VPAES => {
                extern "C" {
                    fn GFp_vpaes_set_encrypt_key(
                        user_key: *const u8, bits: libc::c_uint, key: &mut AES_KEY,
                    ) -> ZeroMeansSuccess;
                }
                Result::from(unsafe {
                    GFp_vpaes_set_encrypt_key(
                        bytes.as_ptr(),
                        key_bits.as_usize_bits() as libc::c_uint,
                        &mut key,
                    )
                })?;
            },

            _ => {
                extern "C" {
                    fn GFp_aes_nohw_set_encrypt_key(
                        user_key: *const u8, bits: libc::c_uint, key: &mut AES_KEY,
                    ) -> ZeroMeansSuccess;
                }
                Result::from(unsafe {
                    GFp_aes_nohw_set_encrypt_key(
                        bytes.as_ptr(),
                        key_bits.as_usize_bits() as libc::c_uint,
                        &mut key,
                    )
                })?;
            },
        };

        Ok(Key {
            inner: key,
            cpu_features,
        })
    }

    #[inline]
    pub fn encrypt_block(&self, mut a: Block) -> Block {
        let aliasing_const: *const Block = &a;
        let aliasing_mut: *mut Block = &mut a;

        match detect_implementation(self.cpu_features) {
            Implementation::HWAES => {
                extern "C" {
                    fn GFp_aes_hw_encrypt(a: *const Block, r: *mut Block, key: &AES_KEY);
                }
                unsafe {
                    GFp_aes_hw_encrypt(aliasing_const, aliasing_mut, &self.inner);
                }
            },

            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            Implementation::VPAES => {
                extern "C" {
                    fn GFp_vpaes_encrypt(a: *const Block, r: *mut Block, key: &AES_KEY);
                }
                unsafe {
                    GFp_vpaes_encrypt(aliasing_const, aliasing_mut, &self.inner);
                }
            },

            _ => {
                extern "C" {
                    fn GFp_aes_nohw_encrypt(a: *const Block, r: *mut Block, key: &AES_KEY);
                }
                unsafe {
                    GFp_aes_nohw_encrypt(aliasing_const, aliasing_mut, &self.inner);
                }
            },
        }

        a
    }

    #[inline]
    pub fn encrypt_iv_xor_block(&self, iv: Iv, input: Block) -> Block {
        let mut output = self.encrypt_block(iv.into_block_less_safe());
        output.bitxor_assign(input);
        output
    }

    #[inline]
    pub(super) fn ctr32_encrypt_blocks(
        &self, in_out: &mut [u8], direction: Direction, ctr: &mut Counter,
    ) {
        let output: *mut u8 = in_out.as_mut_ptr();
        let in_prefix_len = match direction {
            Direction::Opening { in_prefix_len } => in_prefix_len,
            Direction::Sealing => 0,
        };
        let input: *const u8 = in_out[in_prefix_len..].as_ptr();

        let in_out_len = in_out.len().checked_sub(in_prefix_len).unwrap();

        assert_eq!(in_out_len % BLOCK_LEN, 0);
        let blocks = in_out_len / BLOCK_LEN;
        let blocks_u32 = blocks as u32;
        assert_eq!(blocks, polyfill::usize_from_u32(blocks_u32));

        match detect_implementation(self.cpu_features) {
            Implementation::HWAES => {
                extern "C" {
                    fn GFp_aes_hw_ctr32_encrypt_blocks(
                        input: *const u8, output: *mut u8, blocks: size_t, key: &AES_KEY,
                        ivec: &Counter,
                    );
                }
                unsafe {
                    GFp_aes_hw_ctr32_encrypt_blocks(input, output, blocks, &self.inner, ctr);
                }
                ctr.increment_by_less_safe(blocks_u32);
            },

            #[cfg(target_arch = "arm")]
            Implementation::BSAES => {
                extern "C" {
                    fn GFp_bsaes_ctr32_encrypt_blocks(
                        input: *const u8, output: *mut u8, blocks: size_t, key: &AES_KEY,
                        ivec: &Counter,
                    );
                }
                unsafe {
                    GFp_bsaes_ctr32_encrypt_blocks(input, output, blocks, &self.inner, ctr);
                }
                ctr.increment_by_less_safe(blocks_u32);
            },

            _ => {
                shift::shift_full_blocks(in_out, in_prefix_len, |input| {
                    self.encrypt_iv_xor_block(ctr.increment(), Block::from(input))
                });
            },
        }
    }

    pub fn new_mask(&self, sample: Block) -> [u8; 5] {
        let block = self.encrypt_block(sample);

        let mut out: [u8; 5] = [0; 5];
        out.copy_from_slice(&block.as_ref()[..5]);

        out
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn is_aes_hw(&self) -> bool {
        match detect_implementation(self.cpu_features) {
            Implementation::HWAES => true,
            _ => false,
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub(super) fn inner_less_safe(&self) -> &AES_KEY { &self.inner }
}

// Keep this in sync with AES_KEY in aes.h.
#[repr(C)]
pub(super) struct AES_KEY {
    pub rd_key: [u32; 4 * (MAX_ROUNDS + 1)],
    pub rounds: libc::c_uint,
}

// Keep this in sync with `AES_MAXNR` in aes.h.
const MAX_ROUNDS: usize = 14;

pub enum Variant {
    AES_128,
    AES_256,
}

pub type Counter = nonce::Counter<BigEndian<u32>>;

#[repr(C)] // Only so `Key` can be `#[repr(C)]`
#[derive(Clone, Copy)]
pub enum Implementation {
    HWAES = 1,

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    VPAES = 2,

    #[cfg(target_arch = "arm")]
    BSAES = 3,

    Fallback = 4,
}

fn detect_implementation(cpu_features: cpu::Features) -> Implementation {
    if cpu::intel::AES.available(cpu_features) || cpu::arm::AES.available(cpu_features) {
        return Implementation::HWAES;
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if cpu::intel::SSSE3.available(cpu_features) {
            return Implementation::VPAES;
        }
    }

    #[cfg(target_arch = "arm")]
    {
        if cpu::arm::NEON.available(cpu_features) {
            return Implementation::BSAES;
        }
    }

    Implementation::Fallback
}

#[must_use]
#[repr(transparent)]
pub struct ZeroMeansSuccess(libc::c_int);

impl From<ZeroMeansSuccess> for Result<(), error::Unspecified> {
    fn from(ZeroMeansSuccess(value): ZeroMeansSuccess) -> Self {
        if value == 0 {
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::BLOCK_LEN, *};
    use crate::{polyfill::convert::*, test};

    #[test]
    pub fn test_aes() {
        test::run(test_file!("aes_tests.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = consume_key(test_case, "Key");
            let input = test_case.consume_bytes("Input");
            let input: &[u8; BLOCK_LEN] = input.as_slice().try_into_()?;
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
