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

use super::{
    aes::{self, Counter, BLOCK_LEN, ZERO_BLOCK},
    gcm, shift, Aad, Nonce, Tag,
};
use crate::{
    constant_time, cpu, error,
    polyfill::{slice, sliceutil::overwrite_at_start, usize_from_u64_saturated},
};
use core::ops::RangeFrom;

#[derive(Clone)]
pub struct Key {
    gcm_key: gcm::Key, // First because it has a large alignment requirement.
    aes_key: aes::Key,
}

impl Key {
    pub(super) fn new(
        key: aes::KeyBytes,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let aes_key = aes::Key::new(key, cpu_features)?;
        let gcm_key = gcm::Key::new(
            aes_key.encrypt_block(ZERO_BLOCK, cpu_features),
            cpu_features,
        );
        Ok(Self { gcm_key, aes_key })
    }
}

const CHUNK_BLOCKS: usize = 3 * 1024 / 16;

pub(super) fn seal(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key { gcm_key, aes_key } = key;

    let mut auth = gcm::Context::new(gcm_key, aad, in_out.len(), cpu_features)?;

    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment();

    #[cfg(target_arch = "x86_64")]
    let in_out = {
        if !aes_key.is_aes_hw(cpu_features) || !auth.is_avx() {
            in_out
        } else {
            use crate::c;
            let (htable, xi) = auth.inner();
            prefixed_extern! {
                // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
                // assembly says it needs just nine values in that array.
                fn aesni_gcm_encrypt(
                    input: *const u8,
                    output: *mut u8,
                    len: c::size_t,
                    key: &aes::AES_KEY,
                    ivec: &mut Counter,
                    Htable: &gcm::HTable,
                    Xi: &mut gcm::Xi) -> c::size_t;
            }
            let processed = unsafe {
                aesni_gcm_encrypt(
                    in_out.as_ptr(),
                    in_out.as_mut_ptr(),
                    in_out.len(),
                    aes_key.inner_less_safe(),
                    &mut ctr,
                    htable,
                    xi,
                )
            };

            &mut in_out[processed..]
        }
    };

    let (whole, remainder) = slice::as_chunks_mut(in_out);

    #[cfg(target_arch = "aarch64")]
    let whole = {
        if !aes_key.is_aes_hw(cpu_features) || !auth.is_clmul() {
            whole
        } else {
            use crate::bits::BitLength;

            let whole_block_bits = auth.in_out_whole_block_bits();
            let whole_block_bits_u64: BitLength<u64> = whole_block_bits.into();
            if let Ok(whole_block_bits) = whole_block_bits_u64.try_into() {
                use core::num::NonZeroU64;

                let (htable, xi) = auth.inner();
                prefixed_extern! {
                    fn aes_gcm_enc_kernel(
                        input: *const [u8; BLOCK_LEN],
                        in_bits: BitLength<NonZeroU64>,
                        output: *mut [u8; BLOCK_LEN],
                        Xi: &mut gcm::Xi,
                        ivec: &mut Counter,
                        key: &aes::AES_KEY,
                        Htable: &gcm::HTable);
                }
                unsafe {
                    aes_gcm_enc_kernel(
                        whole.as_ptr(),
                        whole_block_bits,
                        whole.as_mut_ptr(),
                        xi,
                        &mut ctr,
                        aes_key.inner_less_safe(),
                        htable,
                    )
                }
            }

            &mut []
        }
    };

    for chunk in whole.chunks_mut(CHUNK_BLOCKS) {
        aes_key.ctr32_encrypt_within(slice::flatten_mut(chunk), 0.., &mut ctr, cpu_features);
        auth.update_blocks(chunk);
    }

    if !remainder.is_empty() {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder);
        let mut output = aes_key.encrypt_iv_xor_block(ctr.into(), input, cpu_features);
        output[remainder.len()..].fill(0);
        auth.update_block(output);
        overwrite_at_start(remainder, &output);
    }

    Ok(finish(aes_key, auth, tag_iv))
}

pub(super) fn open(
    key: &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key { gcm_key, aes_key } = key;

    let mut auth = {
        let unprefixed_len = in_out
            .len()
            .checked_sub(src.start)
            .ok_or(error::Unspecified)?;
        gcm::Context::new(gcm_key, aad, unprefixed_len, cpu_features)
    }?;

    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment();

    let in_prefix_len = src.start;

    #[cfg(target_arch = "x86_64")]
    let in_out = {
        if !aes_key.is_aes_hw(cpu_features) || !auth.is_avx() {
            in_out
        } else {
            use crate::c;
            let (htable, xi) = auth.inner();
            prefixed_extern! {
                // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
                // assembly says it needs just nine values in that array.
                fn aesni_gcm_decrypt(
                    input: *const u8,
                    output: *mut u8,
                    len: c::size_t,
                    key: &aes::AES_KEY,
                    ivec: &mut Counter,
                    Htable: &gcm::HTable,
                    Xi: &mut gcm::Xi) -> c::size_t;
            }

            let processed = unsafe {
                aesni_gcm_decrypt(
                    in_out[src.clone()].as_ptr(),
                    in_out.as_mut_ptr(),
                    in_out.len() - src.start,
                    aes_key.inner_less_safe(),
                    &mut ctr,
                    htable,
                    xi,
                )
            };
            &mut in_out[processed..]
        }
    };

    #[cfg(target_arch = "aarch64")]
    let in_out = {
        if !aes_key.is_aes_hw(cpu_features) || !auth.is_clmul() {
            in_out
        } else {
            use crate::bits::BitLength;

            let whole_block_bits = auth.in_out_whole_block_bits();
            let whole_block_bits_u64: BitLength<u64> = whole_block_bits.into();
            if let Ok(whole_block_bits) = whole_block_bits_u64.try_into() {
                use core::num::NonZeroU64;

                let (htable, xi) = auth.inner();
                prefixed_extern! {
                    fn aes_gcm_dec_kernel(
                        input: *const u8,
                        in_bits: BitLength<NonZeroU64>,
                        output: *mut u8,
                        Xi: &mut gcm::Xi,
                        ivec: &mut Counter,
                        key: &aes::AES_KEY,
                        Htable: &gcm::HTable);
                }

                unsafe {
                    aes_gcm_dec_kernel(
                        in_out[src.clone()].as_ptr(),
                        whole_block_bits,
                        in_out.as_mut_ptr(),
                        xi,
                        &mut ctr,
                        aes_key.inner_less_safe(),
                        htable,
                    )
                }
            }

            &mut in_out[whole_block_bits.as_usize_bytes_rounded_up()..]
        }
    };

    let whole_len = {
        let in_out_len = in_out.len() - in_prefix_len;
        in_out_len - (in_out_len % BLOCK_LEN)
    };
    {
        let mut chunk_len = CHUNK_BLOCKS * BLOCK_LEN;
        let mut output = 0;
        let mut input = in_prefix_len;
        loop {
            if whole_len - output < chunk_len {
                chunk_len = whole_len - output;
            }

            let ciphertext = &in_out[input..][..chunk_len];
            let (ciphertext, leftover) = slice::as_chunks(ciphertext);
            debug_assert_eq!(leftover.len(), 0);
            if ciphertext.is_empty() {
                break;
            }
            auth.update_blocks(ciphertext);

            aes_key.ctr32_encrypt_within(
                &mut in_out[output..][..(chunk_len + in_prefix_len)],
                in_prefix_len..,
                &mut ctr,
                cpu_features,
            );
            output += chunk_len;
            input += chunk_len;
        }
    }

    let remainder = &mut in_out[whole_len..];
    shift::shift_partial((in_prefix_len, remainder), |remainder| {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder);
        auth.update_block(input);
        aes_key.encrypt_iv_xor_block(ctr.into(), input, cpu_features)
    });

    Ok(finish(aes_key, auth, tag_iv))
}

fn finish(aes_key: &aes::Key, gcm_ctx: gcm::Context, tag_iv: aes::Iv) -> Tag {
    // Finalize the tag and return it.
    gcm_ctx.pre_finish(|pre_tag, cpu_features| {
        let encrypted_iv = aes_key.encrypt_block(tag_iv.into_block_less_safe(), cpu_features);
        Tag(constant_time::xor_16(pre_tag, encrypted_iv))
    })
}

pub(super) const MAX_IN_OUT_LEN: usize = super::max_input_len(BLOCK_LEN, 2);

// [NIST SP800-38D] Section 5.2.1.1. Note that [RFC 5116 Section 5.1] and
// [RFC 5116 Section 5.2] have an off-by-one error in `P_MAX`.
//
// [NIST SP800-38D]:
//    http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// [RFC 5116 Section 5.1]: https://tools.ietf.org/html/rfc5116#section-5.1
// [RFC 5116 Section 5.2]: https://tools.ietf.org/html/rfc5116#section-5.2
const _MAX_INPUT_LEN_BOUNDED_BY_NIST: () =
    assert!(MAX_IN_OUT_LEN == usize_from_u64_saturated(((1u64 << 39) - 256) / 8));
