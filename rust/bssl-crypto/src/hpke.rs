/* Copyright (c) 2024, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

//! Hybrid Public Key Encryption
//!
//! HPKE provides a variant of public key encryption of arbitrary-sized plaintexts
//! for a recipient public key. It works for any combination of an asymmetric key
//! encapsulation mechanism (KEM), key derivation function (KDF), and authenticated
//! encryption with additional data (AEAD) function.
//!
//! See RFC 9180 for more details.
//!
//! Note that key generation is currently not supported.
//!
//! ```
//! use bssl_crypto::hpke::{Params, RecipientContext, SenderContext};
//!
//! let params = Params::new_from_rfc_ids(32, 1, 1).unwrap();
//! let recipient_pub_key = ...;
//! let info = ...;
//! let mut sender_ctx =
//!     SenderContext::new(&params, &recipient_pub_key, &info).unwrap();
//!
//! let pt = b"plaintext";
//! let ad = b"associated_data";
//! let ct = sender_ctx.seal(pt, ad);
//!
//! let recipient_priv_key = ...;
//! let mut recipient_ctx = RecipientContext::new(
//!     &params,
//!     &recipient_priv_key,
//!     &sender_ctx.encapsulated_key(),
//!     &info,
//! ).unwrap();
//!
//! let got_pt = recipient_ctx.open(&ct, ad);
//! ```

use crate::{scoped, with_output_vec, with_output_vec_fallible, FfiSlice};
use alloc::vec::Vec;

/// Supported KEM algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum Kem {
    X25519HkdfSha256 = 32,
}

/// Supported KDF algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum Kdf {
    HkdfSha256 = 1,
}

/// Supported AEAD algorithms with values detailed in RFC 9180.
#[derive(PartialEq)]
#[allow(missing_docs)]
pub enum Aead {
    Aes128Gcm = 1,
}

/// Maximum length of the encapsulated key for all currently supported KEMs.
const MAX_ENCAPSULATED_KEY_LEN: usize = bssl_sys::EVP_HPKE_MAX_ENC_LENGTH as usize;

/// HPKE parameters, including KEM, KDF, and AEAD.
pub struct Params {
    kem: *const bssl_sys::EVP_HPKE_KEM,
    kdf: *const bssl_sys::EVP_HPKE_KDF,
    aead: *const bssl_sys::EVP_HPKE_AEAD,
}

impl Params {
    /// New Params from KEM, KDF, and AEAD enums.
    pub fn new(kem: Kem, kdf: Kdf, aead: Aead) -> Option<Self> {
        if kem != Kem::X25519HkdfSha256 || kdf != Kdf::HkdfSha256 || aead != Aead::Aes128Gcm {
            return None;
        }
        // Safety: EVP_hpke_x25519_hkdf_sha256, EVP_hpke_hkdf_sha256, and EVP_hpke_aes_128_gcm
        // initialize structs containing constants and cannot return an error.
        unsafe {
            Some(Self {
                kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KEM,
                kdf: bssl_sys::EVP_hpke_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KDF,
                aead: bssl_sys::EVP_hpke_aes_128_gcm() as *const bssl_sys::EVP_HPKE_AEAD,
            })
        }
    }

    /// New Params from KEM, KDF, and AEAD IDs as detailed in RFC 9180.
    pub fn new_from_rfc_ids(kem: u16, kdf: u16, aead: u16) -> Option<Self> {
        if kem != Kem::X25519HkdfSha256 as u16
            || kdf != Kdf::HkdfSha256 as u16
            || aead != Aead::Aes128Gcm as u16
        {
            return None;
        }
        // Safety: EVP_hpke_x25519_hkdf_sha256, EVP_hpke_hkdf_sha256, and EVP_hpke_aes_128_gcm
        // initialize structs containing constants and cannot return an error.
        unsafe {
            Some(Self {
                kem: bssl_sys::EVP_hpke_x25519_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KEM,
                kdf: bssl_sys::EVP_hpke_hkdf_sha256() as *const bssl_sys::EVP_HPKE_KDF,
                aead: bssl_sys::EVP_hpke_aes_128_gcm() as *const bssl_sys::EVP_HPKE_AEAD,
            })
        }
    }
}

/// HPKE recipient context. Callers may use `open()` to decrypt messages from the sender.
pub struct RecipientContext {
    ctx: scoped::EvpHpkeCtx,
}

/// HPKE sender context. Callers may use `seal()` to encrypt messages for the recipient.
pub struct SenderContext {
    ctx: RecipientContext,
    encapsulated_key: Vec<u8>,
}

impl SenderContext {
    /// New implements the SetupBaseS HPKE operation, which encapsulates a shared secret for
    /// `recipient_pub_key` and sets up a sender context. These are stored and returned in the
    /// newly created SenderContext.
    ///
    /// Note that `recipient_pub_key` may be invalid, in which case this function will return an
    /// error.
    ///
    /// On success, callers may use `seal()` to encrypt messages for the recipient.
    pub fn new(params: &Params, recipient_pub_key: &[u8], info: &[u8]) -> Option<Self> {
        let mut ctx = scoped::EvpHpkeCtx::new();
        unsafe {
            with_output_vec_fallible(MAX_ENCAPSULATED_KEY_LEN, |enc_key_buf| {
                let mut enc_key_len = 0usize;
                // Safety: EVP_HPKE_CTX_setup_sender
                // - is called with context created from EVP_HPKE_CTX_new,
                // - is called with valid buffers with corresponding pointer and length, and
                // - returns 0 on error.
                let result = bssl_sys::EVP_HPKE_CTX_setup_sender(
                    ctx.as_mut_ffi_ptr(),
                    enc_key_buf,
                    &mut enc_key_len,
                    MAX_ENCAPSULATED_KEY_LEN,
                    params.kem,
                    params.kdf,
                    params.aead,
                    recipient_pub_key.as_ffi_ptr(),
                    recipient_pub_key.len(),
                    info.as_ffi_ptr(),
                    info.len(),
                );
                if result == 1 {
                    Some(enc_key_len)
                } else {
                    None
                }
            })
        }
        .map(|enc_key| Self {
            ctx: RecipientContext { ctx },
            encapsulated_key: enc_key,
        })
    }

    /// Seal encrypts `pt` and returns the resulting ciphertext, which is authenticated with `aad`.
    ///
    /// Note that HPKE encryption is stateful and ordered. The sender's first call to `seal()` must
    /// correspond to the recipient's first call to `open()`, etc.
    ///
    /// This function panics if adding the `pt` length and bssl_sys::EVP_HPKE_CTX_max_overhead
    /// overflows.
    pub fn seal(&mut self, pt: &[u8], aad: &[u8]) -> Vec<u8> {
        self.ctx.seal(pt, aad)
    }

    #[allow(missing_docs)]
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }
}

impl RecipientContext {
    /// New implements the SetupBaseR HPKE operation, which decapsulates the shared secret in
    /// `encapsulated_key` with `recipient_priv_key` and sets up a recipient context. These are
    /// stored and returned in the newly created RecipientContext.
    ///
    /// Note that `encapsulated_key` may be invalid, in which case this function will return an
    /// error.
    ///
    /// On success, callers may use `open()` to decrypt messages from the sender.
    pub fn new(
        params: &Params,
        recipient_priv_key: &[u8],
        encapsulated_key: &[u8],
        info: &[u8],
    ) -> Option<Self> {
        let mut hpke_key = scoped::EvpHpkeKey::new();

        // Safety: EVP_HPKE_KEY_init returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_KEY_init(
                hpke_key.as_mut_ffi_ptr(),
                params.kem,
                recipient_priv_key.as_ffi_ptr(),
                recipient_priv_key.len(),
            )
        };
        if result != 1 {
            return None;
        }

        let mut ctx = scoped::EvpHpkeCtx::new();

        // Safety: EVP_HPKE_CTX_setup_recipient
        // - is called with context created from EVP_HPKE_CTX_new,
        // - is called with HPKE key created from EVP_HPKE_KEY_init,
        // - is called with valid buffers with corresponding pointer and length, and
        // - returns 0 on error.
        let result = unsafe {
            bssl_sys::EVP_HPKE_CTX_setup_recipient(
                ctx.as_mut_ffi_ptr(),
                hpke_key.as_ffi_ptr(),
                params.kdf,
                params.aead,
                encapsulated_key.as_ffi_ptr(),
                encapsulated_key.len(),
                info.as_ffi_ptr(),
                info.len(),
            )
        };
        if result == 1 {
            Some(Self { ctx })
        } else {
            None
        }
    }

    /// Seal encrypts `pt` and returns the resulting ciphertext, which is authenticated with `aad`.
    ///
    /// Note that HPKE encryption is stateful and ordered. The sender's first call to `seal()` must
    /// correspond to the recipient's first call to `open()`, etc.
    ///
    /// This function panics if adding the `pt` length and bssl_sys::EVP_HPKE_CTX_max_overhead
    /// overflows.
    pub fn seal(&mut self, pt: &[u8], aad: &[u8]) -> Vec<u8> {
        // Safety: EVP_HPKE_CTX_max_overhead panics if ctx is not set up as a sender.
        #[allow(clippy::expect_used)]
        let max_out_len = pt
            .len()
            .checked_add(unsafe { bssl_sys::EVP_HPKE_CTX_max_overhead(self.ctx.as_mut_ffi_ptr()) })
            .expect("Maximum output length calculation overflow");
        unsafe {
            with_output_vec(max_out_len, |out_buf| {
                let mut out_len = 0usize;
                // Safety: EVP_HPKE_CTX_seal
                // - is called with context created from EVP_HPKE_CTX_new and
                // - is called with valid buffers with corresponding pointer and length.
                let result = bssl_sys::EVP_HPKE_CTX_seal(
                    self.ctx.as_mut_ffi_ptr(),
                    out_buf,
                    &mut out_len,
                    max_out_len,
                    pt.as_ffi_ptr(),
                    pt.len(),
                    aad.as_ffi_ptr(),
                    aad.len(),
                );
                assert_eq!(result, 1);
                out_len
            })
        }
    }

    /// Open authenticates `aad` and decrypts `ct`. It returns an error on failure.
    ///
    /// Note that HPKE encryption is stateful and ordered. The sender's first call to `seal()` must
    /// correspond to the recipient's first call to `open()`, etc.
    pub fn open(&mut self, ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let max_out_len = ct.len();
        unsafe {
            with_output_vec_fallible(max_out_len, |out_buf| {
                let mut out_len = 0usize;
                // Safety: EVP_HPKE_CTX_open
                // - is called with context created from EVP_HPKE_CTX_new and
                // - is called with valid buffers with corresponding pointer and length.
                let result = bssl_sys::EVP_HPKE_CTX_open(
                    self.ctx.as_mut_ffi_ptr(),
                    out_buf,
                    &mut out_len,
                    max_out_len,
                    ct.as_ffi_ptr(),
                    ct.len(),
                    aad.as_ffi_ptr(),
                    aad.len(),
                );
                if result == 1 {
                    Some(out_len)
                } else {
                    None
                }
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_helpers::decode_hex;

    struct TestVector {
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: [u8; 20],
        seed_for_testing: [u8; 32],   // skEm
        recipient_pub_key: [u8; 32],  // pkRm
        recipient_priv_key: [u8; 32], // skRm
        encapsulated_key: [u8; 32],   // enc
        plaintext: [u8; 29],          // pt
        associated_data: [u8; 7],     // aad
        ciphertext: [u8; 45],         // ct
    }

    // https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
    fn x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm() -> TestVector {
        TestVector {
            kem_id: 32,
            kdf_id: 1,
            aead_id: 1,
            info: decode_hex("4f6465206f6e2061204772656369616e2055726e"),
            seed_for_testing: decode_hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"),
            recipient_pub_key: decode_hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"),
            recipient_priv_key: decode_hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"),
            encapsulated_key: decode_hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
            plaintext: decode_hex("4265617574792069732074727574682c20747275746820626561757479"),
            associated_data: decode_hex("436f756e742d30"),
            ciphertext: decode_hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        }
    }

    #[test]
    fn seal_and_open() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut sender_ctx =
            SenderContext::new(&params, &vec.recipient_pub_key, &vec.info).unwrap();

        let mut recipient_ctx = RecipientContext::new(
            &params,
            &vec.recipient_priv_key,
            &sender_ctx.encapsulated_key(),
            &vec.info,
        )
        .unwrap();

        let pt = b"plaintext";
        let ad = b"associated_data";
        let mut prev_ct: Vec<u8> = Vec::new();
        for _ in 0..10 {
            let ct = sender_ctx.seal(pt, ad);
            assert_ne!(ct, prev_ct);
            prev_ct = ct.clone();

            let got_pt = recipient_ctx.open(&ct, ad).unwrap();
            assert_eq!(got_pt, pt);
        }
    }

    fn new_sender_context_for_testing(
        params: &Params,
        recipient_pub_key: &[u8],
        info: &[u8],
        seed_for_testing: &[u8],
    ) -> Option<SenderContext> {
        let mut ctx = scoped::EvpHpkeCtx::new();

        unsafe {
            with_output_vec_fallible(MAX_ENCAPSULATED_KEY_LEN, |enc_key_buf| {
                let mut enc_key_len = 0usize;
                // Safety: EVP_HPKE_CTX_setup_sender_with_seed_for_testing
                // - is called with context created from EVP_HPKE_CTX_new,
                // - is called with valid buffers with corresponding pointer and length, and
                // - returns 0 on error.
                let result = bssl_sys::EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
                    ctx.as_mut_ffi_ptr(),
                    enc_key_buf,
                    &mut enc_key_len,
                    MAX_ENCAPSULATED_KEY_LEN,
                    params.kem,
                    params.kdf,
                    params.aead,
                    recipient_pub_key.as_ffi_ptr(),
                    recipient_pub_key.len(),
                    info.as_ffi_ptr(),
                    info.len(),
                    seed_for_testing.as_ffi_ptr(),
                    seed_for_testing.len(),
                );
                if result == 1 {
                    Some(enc_key_len)
                } else {
                    None
                }
            })
        }
        .map(|enc_key| SenderContext {
            ctx: RecipientContext { ctx },
            encapsulated_key: enc_key,
        })
    }

    #[test]
    fn seal_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut ctx = new_sender_context_for_testing(
            &params,
            &vec.recipient_pub_key,
            &vec.info,
            &vec.seed_for_testing,
        )
        .unwrap();

        assert_eq!(ctx.encapsulated_key, vec.encapsulated_key.to_vec());

        let ciphertext = ctx.seal(&vec.plaintext, &vec.associated_data);
        assert_eq!(ciphertext, vec.ciphertext.to_vec());
    }

    #[test]
    fn open_with_vector() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        let mut ctx = RecipientContext::new(
            &params,
            &vec.recipient_priv_key,
            &vec.encapsulated_key,
            &vec.info,
        )
        .unwrap();

        let plaintext = ctx.open(&vec.ciphertext, &vec.associated_data).unwrap();
        assert_eq!(plaintext, vec.plaintext.to_vec());
    }

    #[test]
    fn params_new() {
        assert!(Params::new(Kem::X25519HkdfSha256, Kdf::HkdfSha256, Aead::Aes128Gcm).is_some());
    }

    #[test]
    fn params_new_from_rfc_ids() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        assert!(Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).is_some());
    }

    #[test]
    fn disallowed_params_fail() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();

        assert!(Params::new_from_rfc_ids(0, vec.kdf_id, vec.aead_id).is_none());
        assert!(Params::new_from_rfc_ids(vec.kem_id, 0, vec.aead_id).is_none());
        assert!(Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, 0).is_none());
        assert!(Params::new_from_rfc_ids(
            vec.kem_id,
            vec.kdf_id,
            bssl_sys::EVP_HPKE_AES_256_GCM as u16
        )
        .is_none());
    }

    #[test]
    fn bad_recipient_pub_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        assert!(SenderContext::new(&params, b"", &vec.info).is_none());
    }

    #[test]
    fn bad_recipient_priv_key_fails() {
        let vec: TestVector = x25519_hkdf_sha256_hkdf_sha256_aes_128_gcm();
        let params = Params::new_from_rfc_ids(vec.kem_id, vec.kdf_id, vec.aead_id).unwrap();

        assert!(RecipientContext::new(&params, b"", &vec.encapsulated_key, &vec.info).is_none());
    }
}
