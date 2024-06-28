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
    aes::{
        self, Counter, CounterOverflowError, InOutLenInconsistentWithIvBlockLenError, BLOCK_LEN,
        ZERO_BLOCK,
    },
    gcm, shift, Aad, Nonce, Tag,
};
use crate::{
    cpu, error,
    polyfill::{slice, sliceutil::overwrite_at_start, usize_from_u64_saturated},
};
use core::{num::NonZeroUsize, ops::RangeFrom};

#[cfg(target_arch = "x86_64")]
use aes::EncryptCtr32 as _;

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
))]
use cpu::GetFeature as _;

#[derive(Clone)]
pub(super) struct Key(DynKey);

impl Key {
    pub(super) fn new(
        key: aes::KeyBytes,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        Ok(Self(DynKey::new(key, cpu_features)?))
    }
}

#[derive(Clone)]
enum DynKey {
    #[cfg(target_arch = "x86_64")]
    AesHwClMulAvxMovbe(Combo<aes::hw::Key, gcm::clmulavxmovbe::Key>),

    #[cfg(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64"))]
    AesHwClMul(Combo<aes::hw::Key, gcm::clmul::Key>),

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    Simd(Combo<aes::vp::Key, gcm::neon::Key>),

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Simd(Combo<aes::vp::Key, gcm::fallback::Key>),

    Fallback(Combo<aes::fallback::Key, gcm::fallback::Key>),
}

impl DynKey {
    fn new(key: aes::KeyBytes, cpu_features: cpu::Features) -> Result<Self, error::Unspecified> {
        #[cfg(target_arch = "x86_64")]
        if let (Some(aes), Some(gcm)) = (cpu_features.get_feature(), cpu_features.get_feature()) {
            let aes_key = aes::hw::Key::new(key, aes)?;
            let gcm_key_value = derive_gcm_key_value(&aes_key);
            let gcm_key = gcm::clmulavxmovbe::Key::new(gcm_key_value, gcm);
            return Ok(Self::AesHwClMulAvxMovbe(Combo { aes_key, gcm_key }));
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"))]
        if let (Some(aes), Some(gcm)) = (cpu_features.get_feature(), cpu_features.get_feature()) {
            let aes_key = aes::hw::Key::new(key, aes)?;
            let gcm_key_value = derive_gcm_key_value(&aes_key);
            let gcm_key = gcm::clmul::Key::new(gcm_key_value, gcm);
            return Ok(Self::AesHwClMul(Combo { aes_key, gcm_key }));
        }

        #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
        if let (Some(aes), Some(gcm)) = (cpu_features.get_feature(), cpu_features.get_feature()) {
            let aes_key = aes::vp::Key::new(key, aes)?;
            let gcm_key_value = derive_gcm_key_value(&aes_key);
            let gcm_key = gcm::neon::Key::new(gcm_key_value, gcm);
            return Ok(Self::Simd(Combo { aes_key, gcm_key }));
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Some(aes) = cpu_features.get_feature() {
            let aes_key = aes::vp::Key::new(key, aes)?;
            let gcm_key_value = derive_gcm_key_value(&aes_key);
            let gcm_key = gcm::fallback::Key::new(gcm_key_value);
            return Ok(Self::Simd(Combo { aes_key, gcm_key }));
        }

        let _ = cpu_features;

        let aes_key = aes::fallback::Key::new(key)?;
        let gcm_key_value = derive_gcm_key_value(&aes_key);
        let gcm_key = gcm::fallback::Key::new(gcm_key_value);
        Ok(Self::Fallback(Combo { aes_key, gcm_key }))
    }
}

fn derive_gcm_key_value(aes_key: &impl aes::EncryptBlock) -> gcm::KeyValue {
    gcm::KeyValue::new(aes_key.encrypt_block(ZERO_BLOCK))
}

const CHUNK_BLOCKS: usize = 3 * 1024 / 16;

#[inline(never)]
pub(super) fn seal(
    Key(key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, SealError> {
    let (tag_iv, ctr) = Counter::one_two(nonce);

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    let mut ctr = ctr;

    match key {
        #[cfg(target_arch = "x86_64")]
        DynKey::AesHwClMulAvxMovbe(Combo { aes_key, gcm_key }) => {
            use crate::c;
            let mut auth =
                gcm::Context::new(gcm_key, aad, in_out.len()).map_err(SealError::from_gcm_error)?;
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

            let ramaining = match in_out.get_mut(processed..) {
                Some(remaining) => remaining,
                None => {
                    // This can't happen. If it did, then the assembly already
                    // caused a buffer overflow.
                    unreachable!()
                }
            };
            let (whole, remainder) = slice::as_chunks_mut(ramaining);
            if let Some(whole_len) = NonZeroUsize::new(whole.len()) {
                let iv_block = ctr
                    .increment_by(whole_len)
                    .map_err(SealError::counter_overflow)?;
                match aes_key.ctr32_encrypt_within(slice::flatten_mut(whole), 0.., iv_block) {
                    Ok(()) => {}
                    Result::<_, InOutLenInconsistentWithIvBlockLenError>::Err(_) => unreachable!(),
                }
                auth.update_blocks(whole);
            }
            seal_finish(aes_key, auth, remainder, ctr, tag_iv)
        }

        #[cfg(target_arch = "aarch64")]
        DynKey::AesHwClMul(Combo { aes_key, gcm_key }) => {
            use crate::bits::BitLength;

            let mut auth =
                gcm::Context::new(gcm_key, aad, in_out.len()).map_err(SealError::from_gcm_error)?;

            let (whole, remainder) = slice::as_chunks_mut(in_out);
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
            seal_finish(aes_key, auth, remainder, ctr, tag_iv)
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        DynKey::AesHwClMul(c) => seal_strided(c, aad, in_out, ctr, tag_iv),

        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86_64",
            target_arch = "x86"
        ))]
        DynKey::Simd(c) => seal_strided(c, aad, in_out, ctr, tag_iv),

        DynKey::Fallback(c) => seal_strided(c, aad, in_out, ctr, tag_iv),
    }
}

#[cfg_attr(
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64"
    ),
    inline(never)
)]
#[cfg_attr(any(target_arch = "aarch64", target_arch = "x86_64"), cold)]
fn seal_strided<A: aes::EncryptBlock + aes::EncryptCtr32, G: gcm::UpdateBlocks + gcm::Gmult>(
    Combo { aes_key, gcm_key }: &Combo<A, G>,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    mut ctr: Counter,
    tag_iv: aes::Iv,
) -> Result<Tag, SealError> {
    let mut auth =
        gcm::Context::new(gcm_key, aad, in_out.len()).map_err(SealError::from_gcm_error)?;

    let (whole, remainder) = slice::as_chunks_mut(in_out);

    for chunk in whole.chunks_mut(CHUNK_BLOCKS) {
        let chunk_len = NonZeroUsize::new(chunk.len()).unwrap(); // Guaranteed by chunks_mut
        let iv_block = ctr
            .increment_by(chunk_len)
            .map_err(SealError::counter_overflow)?;
        match aes_key.ctr32_encrypt_within(slice::flatten_mut(chunk), 0.., iv_block) {
            Ok(_) => {}
            Err(_) => unreachable!(),
        }
        auth.update_blocks(chunk);
    }

    seal_finish(aes_key, auth, remainder, ctr, tag_iv)
}

fn seal_finish<A: aes::EncryptBlock, G: gcm::Gmult>(
    aes_key: &A,
    mut auth: gcm::Context<G>,
    remainder: &mut [u8],
    ctr: Counter,
    tag_iv: aes::Iv,
) -> Result<Tag, SealError> {
    if !remainder.is_empty() {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder);
        let iv = ctr.try_into_iv().map_err(SealError::counter_overflow)?;
        let mut output = aes_key.encrypt_iv_xor_block(iv, input);
        output[remainder.len()..].fill(0);
        auth.update_block(output);
        overwrite_at_start(remainder, &output);
    }

    Ok(finish(aes_key, auth, tag_iv))
}

#[non_exhaustive]
pub(super) enum SealError {
    #[allow(dead_code)]
    InputTooLong(gcm::Error),
    CounterOverflow(CounterOverflowError),
}

impl SealError {
    #[cold]
    #[inline(never)]
    fn from_gcm_error(error: gcm::Error) -> Self {
        Self::InputTooLong(error)
    }

    #[cold]
    #[inline(never)]
    fn counter_overflow(counter_overflow_error: CounterOverflowError) -> Self {
        Self::CounterOverflow(counter_overflow_error)
    }
}

#[inline(never)]
pub(super) fn open(
    Key(key): &Key,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
) -> Result<Tag, OpenError> {
    // Check that `src` is in bounds.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    let input = in_out.get(src.clone()).ok_or_else(OpenError::invalid_src)?;

    let (tag_iv, ctr) = Counter::one_two(nonce);

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    let mut ctr = ctr;

    match key {
        #[cfg(target_arch = "x86_64")]
        DynKey::AesHwClMulAvxMovbe(Combo { aes_key, gcm_key }) => {
            use crate::c;

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

            let mut auth =
                gcm::Context::new(gcm_key, aad, input.len()).map_err(OpenError::from_gcm_error)?;
            let (htable, xi) = auth.inner();
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
            let in_out = match in_out.get_mut(processed..) {
                Some(remaining) => remaining,
                None => {
                    // This can't happen. If it did, then the assembly already
                    // caused a buffer overflow.
                    unreachable!()
                }
            };

            let input = match in_out.get(src.clone()) {
                Some(remaining_input) => remaining_input,
                None => unreachable!(),
            };

            let (whole, _) = slice::as_chunks(input);
            let whole_len = if let Some(whole_len) = NonZeroUsize::new(whole.len()) {
                let iv_block = ctr
                    .increment_by(whole_len)
                    .map_err(OpenError::counter_overflow)?;
                auth.update_blocks(whole);
                let whole_len = slice::flatten(whole).len();
                match aes_key.ctr32_encrypt_within(
                    &mut in_out[..(src.start + whole_len)],
                    src.clone(),
                    iv_block,
                ) {
                    Ok(()) => {}
                    Result::<_, InOutLenInconsistentWithIvBlockLenError>::Err(_) => unreachable!(),
                }
                whole_len
            } else {
                0
            };

            let in_out = match in_out.get_mut(whole_len..) {
                Some(partial) => partial,
                None => unreachable!(),
            };
            open_finish(aes_key, auth, in_out, src, ctr, tag_iv)
        }

        #[cfg(target_arch = "aarch64")]
        DynKey::AesHwClMul(Combo { aes_key, gcm_key }) => {
            use crate::bits::BitLength;

            let input_len = input.len();
            let mut auth =
                gcm::Context::new(gcm_key, aad, input_len).map_err(OpenError::from_gcm_error)?;

            let remainder_len = input_len % BLOCK_LEN;
            let whole_len = input_len - remainder_len;

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
            let remainder = &mut in_out[whole_len..];
            open_finish(aes_key, auth, remainder, src, ctr, tag_iv)
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        DynKey::AesHwClMul(c) => open_strided(c, aad, in_out, src, ctr, tag_iv),

        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86_64",
            target_arch = "x86"
        ))]
        DynKey::Simd(c) => open_strided(c, aad, in_out, src, ctr, tag_iv),

        DynKey::Fallback(c) => open_strided(c, aad, in_out, src, ctr, tag_iv),
    }
}

#[cfg_attr(
    any(
        all(
            any(target_arch = "aarch64", target_arch = "arm"),
            target_feature = "neon"
        ),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse"
        )
    ),
    inline(never)
)]
#[cfg_attr(any(target_arch = "aarch64", target_arch = "x86_64"), cold)]
fn open_strided<A: aes::EncryptBlock + aes::EncryptCtr32, G: gcm::UpdateBlocks + gcm::Gmult>(
    Combo { aes_key, gcm_key }: &Combo<A, G>,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
    mut ctr: Counter,
    tag_iv: aes::Iv,
) -> Result<Tag, OpenError> {
    let input = in_out.get(src.clone()).ok_or_else(OpenError::invalid_src)?;
    let input_len = input.len();

    let mut auth = gcm::Context::new(gcm_key, aad, input_len).map_err(OpenError::from_gcm_error)?;

    let remainder_len = input_len % BLOCK_LEN;
    let whole_len = input_len - remainder_len;
    let in_prefix_len = src.start;

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
            let num_blocks = match NonZeroUsize::new(ciphertext.len()) {
                Some(blocks) => blocks,
                None => break,
            };
            let iv_block = ctr
                .increment_by(num_blocks)
                .map_err(OpenError::counter_overflow)?;

            auth.update_blocks(ciphertext);

            match aes_key.ctr32_encrypt_within(
                &mut in_out[output..][..(chunk_len + in_prefix_len)],
                in_prefix_len..,
                iv_block,
            ) {
                Ok(()) => {}
                Result::<_, InOutLenInconsistentWithIvBlockLenError>::Err(_) => unreachable!(),
            }
            output += chunk_len;
            input += chunk_len;
        }
    }

    open_finish(aes_key, auth, &mut in_out[whole_len..], src, ctr, tag_iv)
}

fn open_finish<A: aes::EncryptBlock, G: gcm::Gmult>(
    aes_key: &A,
    mut auth: gcm::Context<G>,
    remainder: &mut [u8],
    src: RangeFrom<usize>,
    ctr: Counter,
    tag_iv: aes::Iv,
) -> Result<Tag, OpenError> {
    let iv = ctr.try_into_iv().map_err(OpenError::counter_overflow)?;
    shift::shift_partial((src.start, remainder), |remainder| {
        let mut input = ZERO_BLOCK;
        overwrite_at_start(&mut input, remainder);
        auth.update_block(input);
        aes_key.encrypt_iv_xor_block(iv, input)
    });

    Ok(finish(aes_key, auth, tag_iv))
}

fn finish<A: aes::EncryptBlock, G: gcm::Gmult>(
    aes_key: &A,
    gcm_ctx: gcm::Context<G>,
    tag_iv: aes::Iv,
) -> Tag {
    // Finalize the tag and return it.
    gcm_ctx.pre_finish(|pre_tag| Tag(aes_key.encrypt_iv_xor_block(tag_iv, pre_tag)))
}

#[non_exhaustive]
pub(super) enum OpenError {
    #[allow(dead_code)]
    InputTooLong(gcm::Error),
    InvalidSrc,
    CounterOverflow(CounterOverflowError),
}

impl OpenError {
    #[cold]
    #[inline(never)]
    fn from_gcm_error(error: gcm::Error) -> Self {
        Self::InputTooLong(error)
    }

    #[cold]
    #[inline(never)]
    fn counter_overflow(counter_overflow_error: CounterOverflowError) -> Self {
        Self::CounterOverflow(counter_overflow_error)
    }

    #[cold]
    #[inline(never)]
    fn invalid_src() -> Self {
        Self::InvalidSrc
    }
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

#[derive(Copy, Clone)]
pub(super) struct Combo<Aes, Gcm> {
    pub(super) aes_key: Aes,
    pub(super) gcm_key: Gcm,
}
