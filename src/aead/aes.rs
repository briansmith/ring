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

use super::{nonce::Nonce, quic::Sample, NONCE_LEN};
use crate::{constant_time, cpu, error};
use cfg_if::cfg_if;
use core::ops::RangeFrom;

pub(super) use ffi::Counter;
#[macro_use]
mod ffi;

cfg_if! {
    if #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))] {
        pub(super) use ffi::AES_KEY;
    } else {
        use ffi::AES_KEY;
    }
}

#[derive(Clone)]
pub(super) struct Key {
    inner: AES_KEY,
}

impl Key {
    #[inline]
    pub fn new(
        bytes: KeyBytes<'_>,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let key = match detect_implementation(cpu_features) {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            // SAFETY: `aes_hw_set_encrypt_key` satisfies the `set_encrypt_key!`
            // contract for these target architectures.
            Implementation::HWAES => unsafe {
                set_encrypt_key!(aes_hw_set_encrypt_key, bytes, cpu_features)
            },

            #[cfg(any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "x86_64",
                target_arch = "x86"
            ))]
            // SAFETY: `vpaes_set_encrypt_key` satisfies the `set_encrypt_key!`
            // contract for these target architectures.
            Implementation::VPAES_BSAES => unsafe {
                set_encrypt_key!(vpaes_set_encrypt_key, bytes, cpu_features)
            },

            // SAFETY: `aes_nohw_set_encrypt_key` satisfies the `set_encrypt_key!`
            // contract.
            Implementation::NOHW => unsafe {
                set_encrypt_key!(aes_nohw_set_encrypt_key, bytes, cpu_features)
            },
        }?;

        Ok(Self { inner: key })
    }

    #[inline]
    pub fn encrypt_block(&self, a: Block, cpu_features: cpu::Features) -> Block {
        match detect_implementation(cpu_features) {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            Implementation::HWAES => self.encrypt_iv_xor_block(Iv(a), ZERO_BLOCK, cpu_features),

            #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
            Implementation::VPAES_BSAES => {
                self.encrypt_iv_xor_block(Iv(a), ZERO_BLOCK, cpu_features)
            }

            // `encrypt_iv_xor_block` calls `encrypt_block` on `target_arch = "x86"`.
            #[cfg(target_arch = "x86")]
            Implementation::VPAES_BSAES => unsafe { encrypt_block!(vpaes_encrypt, a, &self.inner) },

            Implementation::NOHW => unsafe { encrypt_block!(aes_nohw_encrypt, a, &self.inner) },
        }
    }

    pub fn encrypt_iv_xor_block(
        &self,
        iv: Iv,
        mut block: Block,
        cpu_features: cpu::Features,
    ) -> Block {
        let use_ctr32 = match detect_implementation(cpu_features) {
            // These have specialized one-block implementations.
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            Implementation::HWAES => true,
            // `ctr32_encrypt_within` calls `encrypt_iv_xor_block` on `target_arch = "x86"`.
            #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
            Implementation::VPAES_BSAES => true,
            _ => false,
        };
        if use_ctr32 {
            let mut ctr = Counter(iv.0); // We're only doing one block so this is OK.
            self.ctr32_encrypt_within(&mut block, 0.., &mut ctr, cpu_features);
            block
        } else {
            let encrypted_iv = self.encrypt_block(iv.into_block_less_safe(), cpu_features);
            constant_time::xor_16(encrypted_iv, block)
        }
    }

    #[inline]
    pub(super) fn ctr32_encrypt_within(
        &self,
        in_out: &mut [u8],
        src: RangeFrom<usize>,
        ctr: &mut Counter,
        cpu_features: cpu::Features,
    ) {
        match detect_implementation(cpu_features) {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
            // SAFETY:
            //  * self.inner was initialized with `aes_hw_set_encrypt_key` above,
            //    as required by `aes_hw_ctr32_encrypt_blocks`.
            //  * `aes_hw_ctr32_encrypt_blocks` satisfies the contract for
            //    `ctr32_encrypt_blocks`.
            Implementation::HWAES => unsafe {
                ctr32_encrypt_blocks!(
                    aes_hw_ctr32_encrypt_blocks,
                    in_out,
                    src,
                    &self.inner,
                    ctr,
                    cpu_features
                )
            },

            #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
            Implementation::VPAES_BSAES => {
                #[cfg(target_arch = "arm")]
                let in_out = {
                    let blocks = in_out[src.clone()].len() / BLOCK_LEN;

                    // bsaes operates in batches of 8 blocks.
                    let bsaes_blocks = if blocks >= 8 && (blocks % 8) < 6 {
                        // It's faster to use bsaes for all the full batches and then
                        // switch to vpaes for the last partial batch (if any).
                        blocks - (blocks % 8)
                    } else if blocks >= 8 {
                        // It's faster to let bsaes handle everything including
                        // the last partial batch.
                        blocks
                    } else {
                        // It's faster to let vpaes handle everything.
                        0
                    };
                    let bsaes_in_out_len = bsaes_blocks * BLOCK_LEN;

                    // SAFETY:
                    //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
                    //    as required by `bsaes_ctr32_encrypt_blocks_with_vpaes_key`.
                    unsafe {
                        bsaes_ctr32_encrypt_blocks_with_vpaes_key(
                            &mut in_out[..(src.start + bsaes_in_out_len)],
                            src.clone(),
                            &self.inner,
                            ctr,
                            cpu_features,
                        );
                    }

                    &mut in_out[bsaes_in_out_len..]
                };

                // SAFETY:
                //  * self.inner was initialized with `vpaes_set_encrypt_key` above,
                //    as required by `vpaes_ctr32_encrypt_blocks`.
                //  * `vpaes_ctr32_encrypt_blocks` satisfies the contract for
                //    `ctr32_encrypt_blocks`.
                unsafe {
                    ctr32_encrypt_blocks!(
                        vpaes_ctr32_encrypt_blocks,
                        in_out,
                        src,
                        &self.inner,
                        ctr,
                        cpu_features
                    )
                }
            }

            #[cfg(target_arch = "x86")]
            Implementation::VPAES_BSAES => {
                super::shift::shift_full_blocks(in_out, src, |input| {
                    self.encrypt_iv_xor_block(ctr.increment(), *input, cpu_features)
                });
            }

            // SAFETY:
            //  * self.inner was initialized with `aes_nohw_set_encrypt_key`
            //    above, as required by `aes_nohw_ctr32_encrypt_blocks`.
            //  * `aes_nohw_ctr32_encrypt_blocks` satisfies the contract for
            //    `ctr32_encrypt_blocks`.
            Implementation::NOHW => unsafe {
                ctr32_encrypt_blocks!(
                    aes_nohw_ctr32_encrypt_blocks,
                    in_out,
                    src,
                    &self.inner,
                    ctr,
                    cpu_features
                )
            },
        }
    }

    pub fn new_mask(&self, sample: Sample) -> [u8; 5] {
        let [b0, b1, b2, b3, b4, ..] = self.encrypt_block(sample, cpu::features());
        [b0, b1, b2, b3, b4]
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[must_use]
    pub fn is_aes_hw(&self, cpu_features: cpu::Features) -> bool {
        matches!(detect_implementation(cpu_features), Implementation::HWAES)
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[must_use]
    pub(super) fn inner_less_safe(&self) -> &AES_KEY {
        &self.inner
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

impl Iv {
    /// "Less safe" because it defeats attempts to use the type system to prevent reuse of the IV.
    #[inline]
    pub(super) fn into_block_less_safe(self) -> Block {
        self.0
    }
}

pub(super) type Block = [u8; BLOCK_LEN];
pub(super) const BLOCK_LEN: usize = 16;
pub(super) const ZERO_BLOCK: Block = [0u8; BLOCK_LEN];

#[derive(Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum Implementation {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
    HWAES,

    // On "arm" only, this indicates that the bsaes implementation may be used.
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    ))]
    VPAES_BSAES,

    NOHW,
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

    #[cfg(target_arch = "aarch64")]
    {
        if cpu::arm::AES.available(cpu_features) {
            return Implementation::HWAES;
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if cpu::intel::AES.available(cpu_features) {
            return Implementation::HWAES;
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if cpu::intel::SSSE3.available(cpu_features) {
            return Implementation::VPAES_BSAES;
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        if cpu::arm::NEON.available(cpu_features) {
            return Implementation::VPAES_BSAES;
        }
    }

    {
        Implementation::NOHW
    }
}

/// SAFETY:
///   * The caller must ensure that if blocks > 0 then either `input` and
///     `output` do not overlap at all, or input == output.add(n) for some
///     (nonnegative) n.
///   * if blocks > 0, The caller must ensure `input` points to `blocks` blocks
///     and that `output` points to writable space for `blocks` blocks.
///   * The caller must ensure that `vpaes_key` was initialized with
///     `vpaes_set_encrypt_key`.
///   * Upon returning, `blocks` blocks will have been read from `input` and
///     written to `output`.
#[cfg(target_arch = "arm")]
unsafe fn bsaes_ctr32_encrypt_blocks_with_vpaes_key(
    in_out: &mut [u8],
    src: RangeFrom<usize>,
    vpaes_key: &AES_KEY,
    ctr: &mut Counter,
    cpu_features: cpu::Features,
) {
    prefixed_extern! {
        // bsaes_ctr32_encrypt_blocks requires transformation of an existing
        // VPAES key; there is no `bsaes_set_encrypt_key`.
        fn vpaes_encrypt_key_to_bsaes(bsaes_key: *mut AES_KEY, vpaes_key: &AES_KEY);
    }

    // SAFETY:
    //   * The caller ensures `vpaes_key` was initialized by
    //     `vpaes_set_encrypt_key`.
    //   * `bsaes_key was zeroed above, and `vpaes_encrypt_key_to_bsaes`
    //     is assumed to initialize `bsaes_key`.
    let bsaes_key =
        unsafe { AES_KEY::derive(vpaes_encrypt_key_to_bsaes, &vpaes_key, cpu_features) };

    // The code for `vpaes_encrypt_key_to_bsaes` notes "vpaes stores one
    // fewer round count than bsaes, but the number of keys is the same,"
    // so use this as a sanity check.
    debug_assert_eq!(bsaes_key.rounds(), vpaes_key.rounds() + 1);

    // SAFETY:
    //  * `bsaes_key` is in bsaes format after calling
    //    `vpaes_encrypt_key_to_bsaes`.
    //  * `bsaes_ctr32_encrypt_blocks` satisfies the contract for
    //    `ctr32_encrypt_blocks`.
    unsafe {
        ctr32_encrypt_blocks!(
            bsaes_ctr32_encrypt_blocks,
            in_out,
            src,
            &bsaes_key,
            ctr,
            cpu_features
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;

    #[test]
    pub fn test_aes() {
        let cpu_features = cpu::features();
        test::run(test_file!("aes_tests.txt"), |section, test_case| {
            assert_eq!(section, "");
            let key = consume_key(test_case, "Key");
            let input = test_case.consume_bytes("Input");
            let block: Block = input.as_slice().try_into()?;
            let expected_output = test_case.consume_bytes("Output");

            let output = key.encrypt_block(block, cpu_features);
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
