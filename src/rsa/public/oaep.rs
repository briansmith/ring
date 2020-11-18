//! RSA OAEP encryption.

use super::super::{padding, public, PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN};
use crate::{error, rand};
use alloc::boxed::Box;

impl public::Key {
    /// OAEP Encrypts `plaintext`, returning the ciphertext.
    pub fn encrypt_oaep_bytes_less_safe(
        &self,
        encoding: &'static padding::OaepEncoding,
        plaintext: &[u8],
        rng: &dyn rand::SecureRandom,
    ) -> Result<Box<[u8]>, error::Unspecified> {
        let padded = padding::oaep_encode(encoding, plaintext, self.n().len_bits(), rng)?;
        let mut ciphertext = [0u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN];
        let ciphertext = self.exponentiate(untrusted::Input::from(&padded), &mut ciphertext)?;
        Ok(ciphertext.into())
    }
}
