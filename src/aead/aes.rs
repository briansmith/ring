// Copyright 2018-2024 Brian Smith.
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

use super::{nonce::Nonce, quic::Sample, InOut, NONCE_LEN};
use crate::{
    constant_time,
    cpu::{self, GetFeature as _},
    error,
};
use cfg_if::cfg_if;

pub(super) use ffi::Counter;

#[macro_use]
mod ffi;

mod bs;
pub(super) mod fallback;
pub(super) mod hw;
pub(super) mod vp;

cfg_if! {
    if #[cfg(all(perlasm, any(target_arch = "aarch64", target_arch = "x86_64")))] {
        pub(super) use ffi::AES_KEY;
    } else {
        use ffi::AES_KEY;
    }
}

#[derive(Clone)]
pub(super) enum Key {
    #[cfg(all(
        perlasm,
        any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86")
    ))]
    Hw(hw::Key),

    #[cfg(all(
        perlasm,
        any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        )
    ))]
    Vp(vp::Key),

    Fallback(fallback::Key),
}

impl Key {
    #[inline]
    pub fn new(
        bytes: KeyBytes<'_>,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        #[cfg(all(
            perlasm,
            any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")
        ))]
        if let Some(hw_features) = cpu_features.get_feature() {
            return Ok(Self::Hw(hw::Key::new(bytes, hw_features)?));
        }

        #[cfg(all(
            perlasm,
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            )
        ))]
        if let Some(vp_features) = cpu_features.get_feature() {
            return Ok(Self::Vp(vp::Key::new(bytes, vp_features)?));
        }

        let _ = cpu_features;

        Ok(Self::Fallback(fallback::Key::new(bytes)?))
    }

    #[inline]
    fn encrypt_block(&self, a: Block) -> Block {
        match self {
            #[cfg(all(
                perlasm,
                any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86")
            ))]
            Key::Hw(inner) => inner.encrypt_block(a),

            #[cfg(all(
                perlasm,
                any(
                    target_arch = "aarch64",
                    target_arch = "arm",
                    target_arch = "x86",
                    target_arch = "x86_64"
                )
            ))]
            Key::Vp(inner) => inner.encrypt_block(a),

            Key::Fallback(inner) => inner.encrypt_block(a),
        }
    }

    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let [b0, b1, b2, b3, b4, ..] = self.encrypt_block(sample);
        [b0, b1, b2, b3, b4]
    }
}

pub const AES_128_KEY_LEN: usize = 128 / 8;
pub const AES_256_KEY_LEN: usize = 256 / 8;

pub enum KeyBytes<'a> {
    AES_128(&'a [u8; AES_128_KEY_LEN]),
    AES_256(&'a [u8; AES_256_KEY_LEN]),
}

// `Counter` is `ffi::Counter` as its representation is dictated by its use in
// the FFI.
impl Counter {
    pub fn one(nonce: Nonce) -> Self {
        let mut value = [0u8; BLOCK_LEN];
        value[..NONCE_LEN].copy_from_slice(nonce.as_ref());
        value[BLOCK_LEN - 1] = 1;
        Self(value)
    }

    pub fn increment(&mut self) -> Iv {
        let iv = Iv(self.0);
        self.increment_by_less_safe(1);
        iv
    }

    fn increment_by_less_safe(&mut self, increment_by: u32) {
        let [.., c0, c1, c2, c3] = &mut self.0;
        let old_value: u32 = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        let new_value = old_value + increment_by;
        [*c0, *c1, *c2, *c3] = u32::to_be_bytes(new_value);
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv(Block);

impl From<Counter> for Iv {
    fn from(counter: Counter) -> Self {
        Self(counter.0)
    }
}

pub(super) type Block = [u8; BLOCK_LEN];
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const ZERO_BLOCK: Block = [0u8; BLOCK_LEN];

pub(super) trait EncryptBlock {
    fn encrypt_block(&self, block: Block) -> Block;
    fn encrypt_iv_xor_block(&self, iv: Iv, block: Block) -> Block;
}

pub(super) trait EncryptCtr32 {
    fn ctr32_encrypt_within(&self, in_out: InOut<'_>, ctr: &mut Counter);
}

#[allow(dead_code)]
fn encrypt_block_using_encrypt_iv_xor_block(key: &impl EncryptBlock, block: Block) -> Block {
    key.encrypt_iv_xor_block(Iv(block), ZERO_BLOCK)
}

fn encrypt_iv_xor_block_using_encrypt_block(
    key: &impl EncryptBlock,
    iv: Iv,
    block: Block,
) -> Block {
    let encrypted_iv = key.encrypt_block(iv.0);
    constant_time::xor_16(encrypted_iv, block)
}

#[allow(dead_code)]
fn encrypt_iv_xor_block_using_ctr32(key: &impl EncryptCtr32, iv: Iv, mut block: Block) -> Block {
    let mut ctr = Counter(iv.0); // This is OK because we're only encrypting one block.
    key.ctr32_encrypt_within(InOut::in_place(&mut block), &mut ctr);
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;

    #[test]
    pub fn test_aes() {
        test::run(test_file!("aes_tests.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = consume_key(test_case, "Key");
            let input = test_case.consume_bytes("Input");
            let block: Block = input.as_slice().try_into()?;
            let expected_output = test_case.consume_bytes("Output");

            let output = key.encrypt_block(block);
            assert_eq!(output.as_ref(), &expected_output[..]);

            Ok(())
        })
    }

    fn consume_key(test_case: &mut test::TestCase, name: &str) -> Key {
        let key = test_case.consume_bytes(name);
        let key = &key[..];
        let key = match key.len() {
            16 => KeyBytes::AES_128(key.try_into().unwrap()),
            32 => KeyBytes::AES_256(key.try_into().unwrap()),
            _ => unreachable!(),
        };
        Key::new(key, cpu::features()).unwrap()
    }
}
