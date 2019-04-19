// Copyright 2019 Amazon.com, Inc. or its affiliates.
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

use super::{aes, aes::Variant, nonce};
use crate::aead::{
    aes::Variant::{AES_128, AES_256},
    block::Block,
    block::BLOCK_LEN,
    gcm::PolyValContext,
    Nonce, TAG_LEN,
};

use crate::{bits::BitLength, cpu, endian::BigEndian, endian::LittleEndian, error};
use std::convert::TryInto;

#[repr(C, align(16))]
pub struct Key {
    pub aes_asm_key: Option<AES_ASM_KEY>,
    aes_key: Option<aes::Key>,
    pub variant: Variant,
}

#[repr(C, align(16))]
pub struct AES_ASM_KEY(pub [u8; 15 * 16]);

impl Drop for AES_ASM_KEY {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct KeyMaterial([u64; 12]);

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

impl Key {
    pub(super) fn new(
        user_key: &[u8],
        variant: Variant,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::Unspecified> {
        let key_bits = match variant {
            AES_128 => BitLength::from_usize_bits(128),
            AES_256 => BitLength::from_usize_bits(256),
        };
        if BitLength::from_usize_bytes(user_key.len())? != key_bits {
            return Err(error::Unspecified);
        }
        let mut key;

        match detect_implementation(cpu_features) {
            Implementation::AVX_AESNI => {
                key = Key {
                    aes_asm_key: Some(AES_ASM_KEY({ unsafe { std::mem::uninitialized() } })),
                    aes_key: None,
                    variant: variant.clone(),
                };
                let aes_asm_key = key.aes_asm_key.as_mut().ok_or(error::Unspecified)?;

                match variant {
                    AES_128 => {
                        extern "C" {
                            fn aes128gcmsiv_aes_ks(
                                user_key: *const u8,
                                expanded_key: *mut AES_ASM_KEY,
                            );
                        }
                        unsafe {
                            aes128gcmsiv_aes_ks(user_key.as_ptr(), aes_asm_key);
                        }
                    }
                    AES_256 => {
                        extern "C" {
                            fn aes256gcmsiv_aes_ks(
                                user_key: *const u8,
                                expanded_key: *mut AES_ASM_KEY,
                            );
                        }
                        unsafe {
                            aes256gcmsiv_aes_ks(user_key.as_ptr(), aes_asm_key);
                        }
                    }
                }
            }
            Implementation::FALLBACK => {
                key = Key {
                    aes_asm_key: None,
                    aes_key: Some(aes::Key::new(user_key, variant.clone(), cpu_features)?),
                    variant: variant.clone(),
                }
            }
        }
        Ok(key)
    }
}

pub struct GcmSivAsmContext;

impl GcmSivAsmContext {
    pub fn new() -> Self {
        GcmSivAsmContext
    }

    pub fn kdf(
        &self,
        nonce: &Nonce,
        key: &Key,
        auth_key: &mut Auth_Key,
        enc_key: &mut Encryption_Key,
    ) {
        let aes_asm_key = key.aes_asm_key.as_ref().expect("Missing AES ASM KEY");

        let mut key_material: KeyMaterial;
        key_material = { unsafe { std::mem::uninitialized() } };
        let nonce = nonce.as_ref();
        let nonce = Nonce::try_assume_unique_for_key(nonce).expect("Nonce expected");
        let counter: nonce::Counter<BigEndian<u32>> = nonce::Counter::zero(nonce);

        match key.variant {
            AES_128 => {
                extern "C" {
                    fn aes128gcmsiv_kdf(
                        ctr: *const nonce::Counter<BigEndian<u32>>,
                        key_material: *mut KeyMaterial,
                        user_key: *const AES_ASM_KEY,
                    );
                }
                unsafe {
                    aes128gcmsiv_kdf(&counter, &mut key_material, aes_asm_key);
                }
            }
            AES_256 => {
                extern "C" {
                    fn aes256gcmsiv_kdf(
                        ctr: *const nonce::Counter<BigEndian<u32>>,
                        key_material: *mut KeyMaterial,
                        user_key: *const AES_ASM_KEY,
                    );
                }
                unsafe {
                    aes256gcmsiv_kdf(&counter, &mut key_material, aes_asm_key);
                }
            }
        }
        // The key material array contains auth key at index 0 and 2
        auth_key.key = [key_material.0[0], key_material.0[2]];
        // The key material array contains encryption key at index 4, 6, 8, 10
        // Note that in a 128 version of AES_GCM_SIV only the 4th and 6th index is used to compute
        // the encryption key where as 256 version uses all of them
        enc_key.key = [
            key_material.0[4],
            key_material.0[6],
            key_material.0[8],
            key_material.0[10],
        ];
    }

    pub fn gcm_siv_asm_polyval(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        input: &[u8],
        auth_key: &Auth_Key,
    ) -> Out_Tag {
        let tag = [0u8; TAG_LEN];
        let mut out_tag = Out_Tag { tag };

        let ad_blocks = ad.len() / BLOCK_LEN;
        let in_blocks = input.len() / BLOCK_LEN;

        let mut htable_init = false;
        let htable: Htable;
        htable = { unsafe { std::mem::uninitialized() } };

        if ad_blocks > 8 || in_blocks > 8 {
            htable_init = true;
            extern "C" {
                fn aesgcmsiv_htable_init(out_htable: *const Htable, auth_key: *const Auth_Key);
            }
            unsafe {
                aesgcmsiv_htable_init(&htable, auth_key);
            }
        }

        let whole_ad_len = ad.len() - (ad.len() % BLOCK_LEN);
        let remaining_ad_len = ad.len() % BLOCK_LEN;
        if htable_init {
            extern "C" {
                fn aesgcmsiv_htable_polyval(
                    out_htable: *const Htable,
                    input: *const u8,
                    input_len: libc::c_uint,
                    in_out_poly: *mut Out_Tag,
                );
            }
            unsafe {
                aesgcmsiv_htable_polyval(
                    &htable,
                    ad.as_ptr(),
                    whole_ad_len as libc::c_uint,
                    &mut out_tag,
                );
            }
        } else {
            extern "C" {
                fn aesgcmsiv_polyval_horner(
                    in_out_poly: *mut Out_Tag,
                    auth_key: *const Auth_Key,
                    ad: *const u8,
                    ad_blocks: libc::c_uint,
                );
            }
            unsafe {
                aesgcmsiv_polyval_horner(
                    &mut out_tag,
                    auth_key,
                    ad.as_ptr(),
                    ad_blocks as libc::c_uint,
                );
            }
        }

        let mut scratch = [0u8; BLOCK_LEN];
        if (ad.len() & remaining_ad_len) != 0 {
            let left = &mut scratch[..ad.len() & remaining_ad_len];
            left.copy_from_slice(&ad[whole_ad_len..ad.len()]);

            extern "C" {
                fn aesgcmsiv_polyval_horner(
                    in_out_poly: *mut Out_Tag,
                    key: *const Auth_Key,
                    scratch: *const u8,
                    scratch_blocks: libc::c_uint,
                );
            }
            unsafe {
                aesgcmsiv_polyval_horner(&mut out_tag, auth_key, scratch.as_ptr(), 1);
            }
        }

        let whole_in_len = input.len() - (input.len() % BLOCK_LEN);
        let remaining_in_len = input.len() % BLOCK_LEN;
        if htable_init {
            extern "C" {
                fn aesgcmsiv_htable_polyval(
                    out_htable: *const Htable,
                    input: *const u8,
                    input_len: libc::c_uint,
                    in_out_poly: *mut Out_Tag,
                );
            }
            unsafe {
                aesgcmsiv_htable_polyval(
                    &htable,
                    input.as_ptr(),
                    whole_in_len as libc::c_uint,
                    &mut out_tag,
                );
            }
        } else {
            extern "C" {
                fn aesgcmsiv_polyval_horner(
                    in_out_poly: *mut Out_Tag,
                    auth_key: *const Auth_Key,
                    input: *const u8,
                    in_blocks: libc::c_uint,
                );
            }
            unsafe {
                aesgcmsiv_polyval_horner(
                    &mut out_tag,
                    auth_key,
                    input.as_ptr(),
                    in_blocks as libc::c_uint,
                );
            }
        }

        let mut scratch = [0u8; BLOCK_LEN];
        if remaining_in_len != 0 {
            let left = &mut scratch[..remaining_in_len];
            left.copy_from_slice(&input[whole_in_len..input.len()]);

            extern "C" {
                fn aesgcmsiv_polyval_horner(
                    in_out_poly: *mut Out_Tag,
                    key: *const Auth_Key,
                    scratch: *const u8,
                    scratch_blocks: libc::c_uint,
                );
            }
            unsafe {
                aesgcmsiv_polyval_horner(&mut out_tag, auth_key, scratch.as_ptr(), 1);
            }
        }

        let length_block = [ad.len() as u64 * 8, input.len() as u64 * 8];
        extern "C" {
            fn aesgcmsiv_polyval_horner(
                out_tag: *mut Out_Tag,
                auth_key: *const Auth_Key,
                length_block: *const u64,
                length_blocks: libc::c_uint,
            );
        }
        unsafe {
            aesgcmsiv_polyval_horner(&mut out_tag, auth_key, length_block.as_ptr(), 1);
        }

        for i in 0..nonce.len() {
            out_tag.tag[i] ^= nonce[i];
        }
        out_tag.tag[15] &= 0x7f;

        out_tag
    }
}

#[repr(C, align(16))]
pub struct Htable {
    htable: [u8; 16 * 8],
}

impl Drop for Htable {
    fn drop(&mut self) {
        for byte in self.htable.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct Out_Tag {
    pub tag: [u8; TAG_LEN],
}

impl Drop for Out_Tag {
    fn drop(&mut self) {
        for byte in self.tag.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct Encryption_Key {
    pub key: [u64; 4],
}

impl Drop for Encryption_Key {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct Auth_Key {
    pub key: [u64; 2],
}

impl Drop for Auth_Key {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub(super) struct GcmSivContext;

impl GcmSivContext {
    pub fn new() -> Self {
        GcmSivContext
    }

    pub fn kdf(
        &self,
        auth_key: &mut [u8; 16],
        enc_key: &mut [u8],
        variant: Variant,
        nonce: &Nonce,
        key: &Key,
    ) {
        let aes_key = match &key.aes_key {
            Some(aes_key) => aes_key,
            None => unreachable!(),
        };

        // 128 is Auth_key bits and 256 is enc key bits
        let mut key_material = [0u8; (128 + 256) / 8];

        let blocks_needed = match variant {
            AES_128 => 4,
            AES_256 => 6,
        };

        let mut counter = [0u8; BLOCK_LEN];
        let left = &mut counter[4..BLOCK_LEN];
        left.copy_from_slice(nonce.as_ref());

        for i in 0..blocks_needed {
            let nonce = nonce.as_ref();
            let nonce = Nonce::try_assume_unique_for_key(nonce).expect("Nonce expected");
            let mut ctr: nonce::Counter<LittleEndian<u32>> = Counter::zero(nonce);

            ctr.increment_by_less_safe(i as u32);
            let output = aes_key.encrypt_block(Block::from(ctr));
            key_material[(i * 8) as usize..(8 + (i * 8)) as usize]
                .copy_from_slice(&output.u64s_native()[0].to_ne_bytes());
        }

        // The first 16 bytes contains the auth_key
        auth_key.copy_from_slice(&key_material[0..16]);
        // the last 16-48 bytes contains the enc_key
        enc_key.copy_from_slice(&key_material[16..16 + 32]);
    }

    pub(super) fn update_blocks(input: &[u8], polyval_ctx: &mut PolyValContext) {
        let whole_len = input.len() - (input.len() % BLOCK_LEN);
        polyval_ctx.update_blocks(&input[..whole_len]);
        let mut scratch = [0u8; BLOCK_LEN];
        if input.len() % BLOCK_LEN != 0 {
            let left = &mut scratch[..input.len() & (input.len() % 16)];
            left.copy_from_slice(&input[whole_len..input.len()]);
            polyval_ctx.update_blocks(&scratch);
        }
    }

    pub(super) fn gcm_siv_polyval(
        &self,
        input: &[u8],
        ad: &[u8],
        nonce: &Nonce,
        auth_key: &Block,
        cpu_features: cpu::Features,
    ) -> Block {
        let mut polyval_ctx = PolyValContext::new(auth_key, cpu_features);

        // update ad blocks
        GcmSivContext::update_blocks(&ad, &mut polyval_ctx);
        // update input blocks
        GcmSivContext::update_blocks(&input, &mut polyval_ctx);

        // initialization vector is 8 bytes ad_len and 8 bytes input_len
        let mut len_block = [0u8; BLOCK_LEN];
        len_block[0..BLOCK_LEN / 2]
            .copy_from_slice(&((ad.len() * (BLOCK_LEN / 2)) as u64).to_ne_bytes());
        len_block[BLOCK_LEN / 2..BLOCK_LEN]
            .copy_from_slice(&((input.len() * (BLOCK_LEN / 2)) as u64).to_ne_bytes());
        polyval_ctx.update_blocks(&len_block);

        let mut tag_block = polyval_ctx.pre_finish();
        let tag = tag_block.as_mut();

        let nonce = nonce.as_ref();
        for i in 0..nonce.len() {
            tag[i] ^= nonce[i];
        }
        tag[15] &= 0x7f;

        let (first, second) = tag.split_at(std::mem::size_of::<u64>());

        Block::from_u64_be(
            BigEndian::from(u64::from_be_bytes(first.try_into().unwrap())),
            BigEndian::from(u64::from_be_bytes(second.try_into().unwrap())),
        )
    }

    pub(super) fn gcm_siv_crypt(
        &self,
        in_out: &mut [u8],
        in_prefix_len: usize,
        tag: &Block,
        enc_key: &aes::Key,
    ) {
        let in_out_len = in_out.len() - in_prefix_len;

        let mut ctr = [0u8; TAG_LEN];
        ctr.copy_from_slice(tag.as_ref());
        ctr[15] |= 0x80;

        let mut done = 0;
        for _ in (0..in_out_len).step_by(BLOCK_LEN) {
            let todo = std::cmp::min(BLOCK_LEN, in_out_len - done);

            let key_stream = enc_key.encrypt_block(Block::from(&ctr));
            let key_stream = key_stream.as_ref();

            let last_val = u32::from_le_bytes(ctr[0..4].try_into().unwrap()).wrapping_add(1);
            ctr[0..4].copy_from_slice(&last_val.to_le_bytes());

            let mut count = 0;
            for i in done..(done + todo) {
                in_out[i] = key_stream[count] ^ in_out[done + count + in_prefix_len];
                count += 1;
            }
            done += todo;
        }
    }
}

pub enum Implementation {
    #[allow(dead_code)]
    AVX_AESNI,
    FALLBACK,
}

pub(super) fn detect_implementation(_cpu_features: cpu::Features) -> Implementation {
    #[cfg(target_arch = "x86_64")]
    {
        if (cpu::intel::AES.available(_cpu_features)) && (cpu::intel::AVX.available(_cpu_features))
        {
            return Implementation::AVX_AESNI;
        }
    }
    return Implementation::FALLBACK;
}

pub type Counter = nonce::Counter<LittleEndian<u32>>;
