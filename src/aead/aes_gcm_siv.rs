// Copyright 2019 Brian Smith.
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

// TODO: Switch to MaybeUninit instead of std::mem::uninitialized once stabilized (see https://github.com/rust-lang/rust/issues/53491)

use super::{
    aes::{
        Variant,
        Variant::{AES_128, AES_256},
    },
    gcm_siv::{
        self, Auth_Key, Encryption_Key, GcmSivAsmContext,
        Implementation::{AVX_AESNI, FALLBACK},
        Out_Tag, AES_ASM_KEY,
    },
    Aad, Block, Nonce, Tag, BLOCK_LEN,
};
use crate::{aead, aead::TAG_LEN, cpu, error};

/// AES-GCM-SIV as described in https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-03.
///
/// There are two implementations in this file(asm and non-asm), the ASM version is for x86_64
/// architecture wchich supports AES acceleration and AVX instruction sets.
///
/// The keys are 128/256 bits long and the nonces are 96 bits long.
///
///
/// AES-128 in GCM-SIV mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM_SIV: aead::Algorithm = aead::Algorithm {
    key_len: 16,
    init: init_128,
    seal: aes_gcm_siv_seal,
    open: aes_gcm_siv_open,
    id: aead::AlgorithmID::AES_128_GCM_SIV,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

const AES_GCM_MAX_INPUT_LEN: u64 = super::max_input_len(BLOCK_LEN, 2);

/// AES-256 in GCM-SIV mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM_SIV: aead::Algorithm = aead::Algorithm {
    key_len: 32,
    init: init_256,
    seal: aes_gcm_siv_seal,
    open: aes_gcm_siv_open,
    id: aead::AlgorithmID::AES_256_GCM_SIV,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

fn init_128(key: &[u8], cpu_features: cpu::Features) -> Result<aead::KeyInner, error::Unspecified> {
    init(key, AES_128, cpu_features)
}

fn init_256(key: &[u8], cpu_features: cpu::Features) -> Result<aead::KeyInner, error::Unspecified> {
    init(key, AES_256, cpu_features)
}

fn init(
    key: &[u8],
    variant: Variant,
    cpu_features: cpu::Features,
) -> Result<aead::KeyInner, error::Unspecified> {
    Ok(aead::KeyInner::AesGcmSiv(super::gcm_siv::Key::new(
        key,
        variant,
        cpu_features,
    )?))
}

fn aes_gcm_siv_seal(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Tag {
    match gcm_siv::detect_implementation(cpu_features) {
        FALLBACK => {
            unimplemented!();
        }
        AVX_AESNI => {
            let asm_key = match key {
                aead::KeyInner::AesGcmSiv(key) => key,
                key_type => panic!("Unexpected key type {:?}", key_type),
            };

            let aes_asm_key = asm_key.aes_asm_key.as_ref().expect("Missing AES ASM KEY");

            let (mut auth_key, mut enc_key) = get_default_auth_enc_keys();
            let gcm_siv_asm_ctx = GcmSivAsmContext::new();
            gcm_siv_asm_ctx.kdf(&nonce, &asm_key, &mut auth_key, &mut enc_key);
            let mut out_tag =
                gcm_siv_asm_ctx.gcm_siv_asm_polyval(nonce.as_ref(), aad.0, in_out, &auth_key);
            let whole_in_out_len = in_out.len() - (in_out.len() % BLOCK_LEN);

            match asm_key.variant {
                AES_128 => {
                    extern "C" {
                        fn aes128gcmsiv_aes_ks_enc_x1(
                            input: *const Out_Tag,
                            output: *mut Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            enc_key: *const Encryption_Key,
                        );
                        fn aes128gcmsiv_enc_msg_x4(
                            input: *const u8,
                            output: *mut u8,
                            tag: *const Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            input_len: libc::c_uint,
                        );
                        fn aes128gcmsiv_enc_msg_x8(
                            input: *const u8,
                            output: *mut u8,
                            tag: *const Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            input_len: libc::c_uint,
                        );
                    }
                    unsafe {
                        aes128gcmsiv_aes_ks_enc_x1(&out_tag, &mut out_tag, aes_asm_key, &enc_key);

                        if in_out.len() < 128 {
                            aes128gcmsiv_enc_msg_x4(
                                in_out.as_ptr(),
                                in_out.as_mut_ptr(),
                                &out_tag,
                                aes_asm_key,
                                whole_in_out_len as libc::c_uint,
                            );
                        } else {
                            aes128gcmsiv_enc_msg_x8(
                                in_out.as_ptr(),
                                in_out.as_mut_ptr(),
                                &out_tag,
                                aes_asm_key,
                                whole_in_out_len as libc::c_uint,
                            );
                        }
                    }
                }
                AES_256 => {
                    extern "C" {
                        fn aes256gcmsiv_aes_ks_enc_x1(
                            input: *const Out_Tag,
                            output: *mut Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            enc_key: *const Encryption_Key,
                        );
                        fn aes256gcmsiv_enc_msg_x4(
                            input: *const u8,
                            output: *mut u8,
                            tag: *const Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            input_len: libc::c_uint,
                        );
                        fn aes256gcmsiv_enc_msg_x8(
                            input: *const u8,
                            output: *mut u8,
                            tag: *const Out_Tag,
                            expanded_key: *const AES_ASM_KEY,
                            input_len: libc::c_uint,
                        );
                    }
                    unsafe {
                        aes256gcmsiv_aes_ks_enc_x1(&out_tag, &mut out_tag, aes_asm_key, &enc_key);

                        if in_out.len() < 128 {
                            aes256gcmsiv_enc_msg_x4(
                                in_out.as_ptr(),
                                in_out.as_mut_ptr(),
                                &out_tag,
                                aes_asm_key,
                                whole_in_out_len as libc::c_uint,
                            );
                        } else {
                            aes256gcmsiv_enc_msg_x8(
                                in_out.as_ptr(),
                                in_out.as_mut_ptr(),
                                &out_tag,
                                aes_asm_key,
                                whole_in_out_len as libc::c_uint,
                            );
                        }
                    }
                }
            }
            if in_out.len() % BLOCK_LEN != 0 {
                crypt_last_block(
                    &out_tag.tag,
                    in_out,
                    &aes_asm_key,
                    &asm_key.variant,
                    in_out.len(),
                    0,
                );
            }

            return Tag(Block::from(&out_tag.tag));
        }
    }
}

const CALCULATED_TAG_LEN: usize = 16 * 8;

#[repr(C, align(16))]
pub struct CalculatedTag {
    tag: [u8; CALCULATED_TAG_LEN],
}

impl Drop for CalculatedTag {
    fn drop(&mut self) {
        for byte in self.tag.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct HTable {
    htable: [u8; 16 * 6],
}

impl Drop for HTable {
    fn drop(&mut self) {
        for byte in self.htable.iter_mut() {
            *byte = 0;
        }
    }
}

#[repr(C, align(16))]
pub struct Counter {
    counter: [u8; BLOCK_LEN],
}

fn crypt_last_block(
    tag: &[u8],
    in_out: &mut [u8],
    expanded_key: &AES_ASM_KEY,
    variant: &Variant,
    in_out_len: usize,
    in_prefix_len: usize,
) {
    let mut counter = [0u8; BLOCK_LEN];
    counter.copy_from_slice(tag);
    counter[15] |= 0x80;

    let mut last_word = [0u8; 4];
    // TODO: use tryInto https://doc.rust-lang.org/std/convert/trait.TryInto.html
    last_word.copy_from_slice(&counter[0..4]);
    let last_word = u32::from_le_bytes(last_word);
    let last_word = last_word.wrapping_add((in_out_len / BLOCK_LEN) as u32);
    counter[0..4].copy_from_slice(&last_word.to_le_bytes());
    let mut counter = Counter { counter };

    match variant {
        AES_128 => {
            extern "C" {
                fn aes128gcmsiv_ecb_enc_block(
                    input: *const Counter,
                    output: *mut Counter,
                    expanded_key: *const AES_ASM_KEY,
                );
            }
            unsafe {
                aes128gcmsiv_ecb_enc_block(&counter, &mut counter, expanded_key);
            }
        }
        AES_256 => {
            extern "C" {
                fn aes256gcmsiv_ecb_enc_block(
                    input: *const Counter,
                    output: *mut Counter,
                    expanded_key: &AES_ASM_KEY,
                );
            }
            unsafe {
                aes256gcmsiv_ecb_enc_block(&counter, &mut counter, expanded_key);
            }
        }
    }

    let last_bytes_offset = (in_out_len - (in_out_len % BLOCK_LEN)) + in_prefix_len;
    let last_bytes_len = in_out_len % BLOCK_LEN;

    for i in last_bytes_offset..(last_bytes_offset + last_bytes_len) {
        // Since in_prefix_len is ignored we have to do in_out[i-in_prefix_len] to store bytes at the right offsets
        in_out[i - in_prefix_len] = in_out[i] ^ counter.counter[i - last_bytes_offset];
    }
}

fn get_default_auth_enc_keys() -> (Auth_Key, Encryption_Key) {
    (
        Auth_Key {
            key: { unsafe { std::mem::uninitialized() } },
        },
        Encryption_Key {
            key: { unsafe { std::mem::uninitialized() } },
        },
    )
}

fn aes_gcm_siv_open(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad,
    in_prefix_len: usize,
    in_out: &mut [u8],
    cpu_features: cpu::Features,
) -> Tag {
    match gcm_siv::detect_implementation(cpu_features) {
        FALLBACK => {
            unimplemented!();
        }
        AVX_AESNI => {
            let asm_key = match key {
                aead::KeyInner::AesGcmSiv(key) => key,
                key_type => panic!("Expected AesGcmSiv key Found: {:?}", key_type),
            };

            let (mut auth_key, mut enc_key) = get_default_auth_enc_keys();
            let gcm_siv_asm_ctx = GcmSivAsmContext::new();
            gcm_siv_asm_ctx.kdf(&nonce, &asm_key, &mut auth_key, &mut enc_key);
            let mut expanded_key: AES_ASM_KEY;
            expanded_key = { unsafe { std::mem::uninitialized() } };

            match &asm_key.variant {
                AES_128 => {
                    extern "C" {
                        fn aes128gcmsiv_aes_ks(
                            enc_key: *const Encryption_Key,
                            expanded_key: *mut AES_ASM_KEY,
                        );
                    }
                    unsafe {
                        aes128gcmsiv_aes_ks(&enc_key, &mut expanded_key);
                    }
                }
                AES_256 => {
                    extern "C" {
                        fn aes256gcmsiv_aes_ks(
                            enc_key: *const Encryption_Key,
                            expanded_key: *mut AES_ASM_KEY,
                        );
                    }
                    unsafe {
                        aes256gcmsiv_aes_ks(&enc_key, &mut expanded_key);
                    }
                }
            }

            // calculated_tag is 16*8 bytes, rather than 16 bytes, because
            // aes[128|256]gcmsiv_dec uses the extra as scratch space.
            // Note: ASM code expects the CalgulatedTag to be zeroized before using it.
            let mut calculated_tag = CalculatedTag {
                tag: [0u8; CALCULATED_TAG_LEN],
            };
            extern "C" {
                fn aesgcmsiv_polyval_horner(
                    calculated_tag: *mut CalculatedTag,
                    record_auth_key: *const Auth_Key,
                    ad: *const u8,
                    ad_blocks: libc::c_uint,
                );
            }
            unsafe {
                aesgcmsiv_polyval_horner(
                    &mut calculated_tag,
                    &auth_key,
                    aad.0.as_ptr(),
                    (aad.0.len() / BLOCK_LEN) as libc::c_uint,
                );
            }

            let mut scratch = [0u8; BLOCK_LEN];
            if (aad.0.len() % BLOCK_LEN) != 0 {
                let left = &mut scratch[..aad.0.len() % BLOCK_LEN];
                left.copy_from_slice(&aad.0[aad.0.len() - (aad.0.len() % BLOCK_LEN)..aad.0.len()]);

                extern "C" {
                    fn aesgcmsiv_polyval_horner(
                        calculated_tag: *mut CalculatedTag,
                        auth_key: *const Auth_Key,
                        scratch: *const u8,
                        scratch_blocks: libc::c_uint,
                    );
                }
                unsafe {
                    aesgcmsiv_polyval_horner(&mut calculated_tag, &auth_key, scratch.as_ptr(), 1);
                }
            }

            let mut htable: HTable;
            htable = unsafe { std::mem::uninitialized() };
            extern "C" {
                fn aesgcmsiv_htable6_init(htable: *mut HTable, auth_key: *const Auth_Key);
            }
            unsafe {
                aesgcmsiv_htable6_init(&mut htable, &auth_key);
            }

            let in_out_len = in_out.len() - TAG_LEN - in_prefix_len;
            match &asm_key.variant {
                AES_128 => {
                    extern "C" {
                        fn aes128gcmsiv_dec(
                            input: *const u8,
                            output: *mut u8,
                            calculated_tag: *mut CalculatedTag,
                            htable: *const HTable,
                            expanded_key: *const AES_ASM_KEY,
                            plaintext_len: libc::c_uint,
                        );
                    }
                    unsafe {
                        aes128gcmsiv_dec(
                            in_out[in_prefix_len..].as_ptr(),
                            in_out.as_mut_ptr(),
                            &mut calculated_tag,
                            &htable,
                            &expanded_key,
                            in_out_len as libc::c_uint,
                        );
                    }
                }
                AES_256 => {
                    extern "C" {
                        fn aes256gcmsiv_dec(
                            input: *const u8,
                            output: *mut u8,
                            calculated_tag: *mut CalculatedTag,
                            htable: *const HTable,
                            expanded_key: *const AES_ASM_KEY,
                            plaintext_len: libc::c_uint,
                        );
                    }
                    unsafe {
                        aes256gcmsiv_dec(
                            in_out[in_prefix_len..].as_ptr(),
                            in_out.as_mut_ptr(),
                            &mut calculated_tag,
                            &htable,
                            &expanded_key,
                            in_out_len as libc::c_uint,
                        );
                    }
                }
            }

            if in_out_len % BLOCK_LEN != 0 {
                let mut tag = [0u8; TAG_LEN];
                tag.copy_from_slice(&in_out[(in_prefix_len + in_out_len)..in_out.len()]);

                crypt_last_block(
                    &tag,
                    in_out,
                    &expanded_key,
                    &asm_key.variant,
                    in_out_len,
                    in_prefix_len,
                );
                let mut scratch = [0u8; BLOCK_LEN];
                let left = &mut scratch[..in_out_len % BLOCK_LEN];

                left.copy_from_slice(&in_out[in_out_len - (in_out_len % BLOCK_LEN)..in_out_len]);
                extern "C" {
                    fn aesgcmsiv_polyval_horner(
                        calculated_tag: *mut CalculatedTag,
                        auth_key: *const Auth_Key,
                        scratch: *const u8,
                        scratch_blocks: libc::c_uint,
                    );
                }
                unsafe {
                    aesgcmsiv_polyval_horner(&mut calculated_tag, &auth_key, scratch.as_ptr(), 1);
                }
            }

            let length_block = [
                (aad.0.len() as u64 * 8).to_le(),
                (in_out_len as u64 * 8).to_le(),
            ];
            {
                extern "C" {
                    fn aesgcmsiv_polyval_horner(
                        calculated_tag: *mut CalculatedTag,
                        record_auth_key: *const Auth_Key,
                        len_block: *const u64,
                        len_block_len: libc::c_uint,
                    );
                }
                unsafe {
                    aesgcmsiv_polyval_horner(
                        &mut calculated_tag,
                        &auth_key,
                        length_block.as_ptr(),
                        1,
                    );
                }
            }

            let nonce = nonce.as_ref();
            for i in 0..nonce.len() {
                calculated_tag.tag[i] ^= nonce[i];
            }
            calculated_tag.tag[15] &= 0x7f;

            match &asm_key.variant {
                AES_128 => {
                    extern "C" {
                        fn aes128gcmsiv_ecb_enc_block(
                            input: *const CalculatedTag,
                            output: *mut CalculatedTag,
                            expanded_key: *const AES_ASM_KEY,
                        );
                    }
                    unsafe {
                        aes128gcmsiv_ecb_enc_block(
                            &calculated_tag,
                            &mut calculated_tag,
                            &expanded_key,
                        );
                    }
                }
                AES_256 => {
                    extern "C" {
                        fn aes256gcmsiv_ecb_enc_block(
                            input: *const CalculatedTag,
                            output: *mut CalculatedTag,
                            expanded_key: *const AES_ASM_KEY,
                        );
                    }
                    unsafe {
                        aes256gcmsiv_ecb_enc_block(
                            &calculated_tag,
                            &mut calculated_tag,
                            &expanded_key,
                        );
                    }
                }
            }
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&calculated_tag.tag[0..TAG_LEN]);
            return Tag(Block::from(&tag));
        }
    }
}

pub type Key = gcm_siv::Key;

#[cfg(test)]
mod tests {
    use crate::aead::aes::Variant;
    use crate::aead::aes_gcm_siv::{aes_gcm_siv_open, aes_gcm_siv_seal, init};
    use crate::aead::{Aad, Nonce};
    use crate::cpu;

    #[test]
    fn test_data_alignments() {
        // KEY: ee8e1ed9ff2540ae8f2ba9f50bc2f27c
        // NONCE: 752abad3e0afb5f434dc4310
        // IN: "Hello world"
        // AD: "example"
        // CT: 5d349ead175ef6b1def6fd
        // TAG: 4fbcdeb7e4793f4a1d7e4faa70100af1

        // SEAL
        let key: u128 = 0xee8e1ed9ff2540ae8f2ba9f50bc2f27c;
        let mut user_key: [u8; 18] = [0u8; 18]; // padded with left 0 and right 0 in the key
        user_key[1..17].copy_from_slice(&key.to_be_bytes());
        let key = init(&user_key[1..17], Variant::AES_128, cpu::features()).unwrap();

        let nonce: u128 = 0x752abad3e0afb5f434dc4310; // padding with garbage from 0..4 bytes
        let nonce = nonce.to_be_bytes();
        let nonce = Nonce::try_assume_unique_for_key(&nonce[4..16]).unwrap();

        let aad = String::from("00example00");
        let aad = aad.as_bytes();
        let aad = Aad(&aad[2..9]);

        let mut input = String::from("00Hello world00");
        let in_out: &mut [u8];
        unsafe {
            in_out = input.as_bytes_mut();
        }
        let tag = aes_gcm_siv_seal(&key, nonce, aad, &mut in_out[2..13], cpu::features());
        let result_tag: u128 = 0x4fbcdeb7e4793f4a1d7e4faa70100af1;
        let result_cipher_text: u128 = 0x5d349ead175ef6b1def6fd;

        // Tag is equal
        assert_eq!(&result_tag.to_be_bytes(), tag.0.as_ref());
        // Cipher text is equal
        assert_eq!(&result_cipher_text.to_be_bytes()[5..16], &in_out[2..13]);

        // OPEN
        let key = init(&user_key[1..17], Variant::AES_128, cpu::features()).unwrap();
        let cipher_text = &mut result_cipher_text.to_be_bytes()[5..16];
        let aad = String::from("00example00");
        let aad = aad.as_bytes();
        let aad = Aad(&aad[2..9]);

        let nonce: u128 = 0x752abad3e0afb5f434dc4310; // padding with garbage from 0..4 bytes
        let nonce = nonce.to_be_bytes();
        let nonce = Nonce::try_assume_unique_for_key(&nonce[4..16]).unwrap();
        let mut in_out = [0u8; 27]; // in_out is 11 + tag is 16
        in_out[0..11].copy_from_slice(&cipher_text);
        in_out[11..27].copy_from_slice(tag.0.as_ref());
        let tag = aes_gcm_siv_open(&key, nonce, aad, 0, &mut in_out, cpu::features());
        let result_plain_text = String::from("Hello world");

        // Tag is equal
        assert_eq!(&result_tag.to_be_bytes(), tag.0.as_ref());
        // Cipher text is equal
        assert_eq!(&result_plain_text.as_bytes(), &in_out[0..11]);
    }

}
