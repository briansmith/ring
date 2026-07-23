//! Implementation of the Hybrid Public Key Encryption (HPKE) standard specified by RFC 9810.

use crate::hkdf::KeyType;
use crate::{aead, agreement, cpu, digest, ec, error, hkdf, hmac, rand};
use core::convert::TryFrom;

static VERSION: &[u8] = "HPKE-v1".as_bytes();
const MAX_PRIVATE_KEY_LEN: usize = ec::SCALAR_MAX_BYTES;
const MAX_PUBLIC_KEY_LEN: usize = 1 + (2 * ec::ELEM_MAX_BYTES);
const MAX_AEAD_KEY_LEN: usize = 32;
const MAX_DIGEST_LEN: usize = digest::MAX_OUTPUT_LEN;

/// Mode refers to different HPKE variants, which provide varying levels of authentication.
/// All modes require a receiver key pair.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Mode {
    /// Base: base case of encrypting to the receiver's public key.
    Base = 0x00,
    /// Psk: enables sender authentication, by requiring possession of a pre-shared key.
    /// (not yet implemented)
    Psk = 0x01,
    /// Auth: enables sender authentication, by requiring possession of sender key pair.
    /// (not yet implemented)
    Auth = 0x02,
    /// AuthPsk: enables sender authentication, by requiring both sender key pair and a pre-shared key.
    /// (not yet implemented)
    AuthPsk = 0x03,
}

/// KemId is the Key Encapsulation Mechanism (KEM) algorithm identifier.
/// It is used to derive and efficiently transport the shared symmetric key(s) over the wire.
/// It consists of the encapsulation algorithm and the key derivation function.
///
/// The encapsulation algorithm generates a fresh ephemeral DH key pair. A shared secret is computed
/// between the ephemeral key pair and the receiver key pair. Next, it is passed through the associated
/// KDF to compute the final shared secret.
///
/// NOTE that the KDF used in KEM can be different from the KDF used later.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum KemId {
    /// DHKEM(P-256, HKDF-SHA256)
    P256Sha256 = 0x0010,
    /// DHKEM(P-384, HKDF-SHA384)
    P384Sha384 = 0x0011,
    /// DHKEM(P-521, HKDF-SHA512) -- unimplemented
    P521Sha512 = 0x0012,
    /// DHKEM(X25519, HKDF-SHA256)
    X25519Sha256 = 0x0020,
    /// DHKEM(X448, HKDF-SHA512) -- unimplemented
    X448Sha512 = 0x0021,
}

impl TryFrom<u16> for KemId {
    type Error = error::Unspecified;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0010 if 0x0010 == KemId::P256Sha256 as u16 => Ok(KemId::P256Sha256),
            0x0011 if 0x0011 == KemId::P384Sha384 as u16 => Ok(KemId::P384Sha384),
            0x0012 if 0x0012 == KemId::P521Sha512 as u16 => Ok(KemId::P521Sha512),
            0x0020 if 0x0020 == KemId::X25519Sha256 as u16 => Ok(KemId::X25519Sha256),
            0x0021 if 0x0021 == KemId::X448Sha512 as u16 => Ok(KemId::X448Sha512),
            _ => Err(error::Unspecified),
        }
    }
}

/// KdfId is the Hmac Key Derivation Function (HKDF) identifier.
/// The HKDF scheme is used for deriving shared secrets for export.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum KdfId {
    /// HKDF-SHA256
    Sha256 = 0x0001,
    /// HKDF-SHA384
    Sha384 = 0x0002,
    /// HKDF-SHA512 -- unimplemented
    Sha512 = 0x0003,
}

impl TryFrom<u16> for KdfId {
    type Error = error::Unspecified;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 if 0x0001 == KdfId::Sha256 as u16 => Ok(KdfId::Sha256),
            0x0002 if 0x0002 == KdfId::Sha384 as u16 => Ok(KdfId::Sha384),
            0x0003 if 0x0003 == KdfId::Sha512 as u16 => Ok(KdfId::Sha512),
            _ => Err(error::Unspecified),
        }
    }
}

/// AeadId is the Authenticated Encryption with Associated Data algorithm identifier.
/// Aead is used for encrypting messages.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum AeadId {
    /// AES-128-GCM
    Aes128Gcm = 0x0001,
    /// AES-256-GCM
    Aes256Gcm = 0x0002,
    /// ChaCha20Poly1305
    ChaCha20Poly1305 = 0x0003,
    // TODO: Implement ExportOnly
}

impl TryFrom<u16> for AeadId {
    type Error = error::Unspecified;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 if 0x0001 == AeadId::Aes128Gcm as u16 => Ok(AeadId::Aes128Gcm),
            0x0002 if 0x0002 == AeadId::Aes256Gcm as u16 => Ok(AeadId::Aes256Gcm),
            0x0003 if 0x0003 == AeadId::ChaCha20Poly1305 as u16 => Ok(AeadId::ChaCha20Poly1305),
            _ => Err(error::Unspecified),
        }
    }
}

/// KeyPair
pub struct KeyPair {
    secret_key: ec::Seed,
    public_key: [u8; MAX_PUBLIC_KEY_LEN],
    /// public key length
    pub public_key_len: u16,
    /// secret key length
    pub secret_key_len: u16,
}

impl KeyPair {
    /// Returns the public key as a byte slice
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key[..self.public_key_len as usize]
    }
}

/// Suite
pub struct Suite {
    suite_id_context: [u8; 10],
    hash: &'static hkdf::Algorithm,
    aead: &'static aead::Algorithm,
    kem: Kem,
}

fn get_suite_id_kem(kem_id: KemId) -> [u8; 5] {
    let mut kem = [0u8; 5];
    kem[0..3].copy_from_slice("KEM".as_bytes());
    kem[3..5].copy_from_slice(&(kem_id as u16).to_be_bytes());
    kem
}

fn get_suite_id_context(kem_id: KemId, kdf_id: KdfId, aead_id: AeadId) -> [u8; 10] {
    let mut suite = [0u8; 10];
    suite[..4].copy_from_slice("HPKE".as_bytes());
    let mut i = 4;
    for id in [kem_id as u16, kdf_id as u16, aead_id as u16] {
        suite[i..i + 2].copy_from_slice(&id.to_be_bytes());
        i += 2;
    }
    suite
}

/// Kem
pub struct Kem {
    suite_id_kem: [u8; 5],
    kem_id: KemId,
    hash: &'static hkdf::Algorithm,
    agreement: &'static agreement::Algorithm,
}

impl Kem {
    /// Instantiate a new KEM struct from a given [KemId]
    pub fn new(kem_id: KemId) -> Result<Self, error::Unspecified> {
        match kem_id {
            KemId::P256Sha256 => Ok(Kem {
                suite_id_kem: get_suite_id_kem(kem_id),
                kem_id,
                hash: &hkdf::HKDF_SHA256,
                agreement: &agreement::ECDH_P256,
            }),
            KemId::P384Sha384 => Ok(Kem {
                suite_id_kem: get_suite_id_kem(kem_id),
                kem_id,
                hash: &hkdf::HKDF_SHA384,
                agreement: &agreement::ECDH_P384,
            }),
            KemId::P521Sha512 => {
                // unimplemented suite
                Err(error::Unspecified)
            }
            KemId::X25519Sha256 => Ok(Kem {
                suite_id_kem: get_suite_id_kem(kem_id),
                kem_id,
                hash: &hkdf::HKDF_SHA256,
                agreement: &agreement::X25519,
            }),
            KemId::X448Sha512 => {
                // unimplemented suite
                Err(error::Unspecified)
            }
        }
    }

    /// Instantiate a new KEM from an `u16` argument `kem_id`.
    /// `kem_id` should be a valid variant of [KemId].
    pub fn from_u16(kem_id: u16) -> Result<Self, error::Unspecified> {
        let kem_id = KemId::try_from(kem_id)?;
        Self::new(kem_id)
    }

    /// Length of an encoded public key for this KEM
    pub fn public_key_length(&self) -> usize {
        self.agreement.curve.public_key_len
    }

    /// Length of an encoded private key for this KEM
    pub fn private_key_length(&self) -> usize {
        self.agreement.curve.elem_scalar_seed_len
    }

    /// Write the serialized public key bytes into output buffer `buf`
    fn public_key_bytes(&self, secret_key: &ec::Seed, buf: &mut [u8]) -> Result<(), error::Unspecified> {
        if buf.len() != self.public_key_length() {
            return Err(error::Unspecified);
        }
        let public_key = secret_key.compute_public_key()?;
        buf.copy_from_slice(public_key.as_ref());
        Ok(())
    }

    /// Randomized algorithm to generate a key pair.
    /// If `rng` is None, then `rand::SystemRandom` will be used as the rng.
    pub fn generate_key_pair(
        &self,
        rng: Option<&dyn rand::SecureRandom>,
    ) -> Result<KeyPair, error::Unspecified> {
        let secret_key;
        if let Some(rng) = rng {
            secret_key = ec::Seed::generate(self.agreement.curve, rng, cpu::features())?;
        } else {
            secret_key = ec::Seed::generate(self.agreement.curve, &rand::SystemRandom::new(), cpu::features())?;
        };
        let mut public_key = [0u8; MAX_PUBLIC_KEY_LEN];
        let public_key_len = self.public_key_length() as u16;
        let secret_key_len = self.private_key_length() as u16;
        self.public_key_bytes(&secret_key, &mut public_key[..self.public_key_length()])?;
        Ok(KeyPair {
            secret_key,
            public_key,
            public_key_len,
            secret_key_len,
        })
    }

    /// Deterministic algorithm to derive a key pair from an initial `seed`
    pub fn derive_key_pair(&self, seed: &[u8]) -> Result<KeyPair, error::Unspecified> {
        let prk = labeled_extract(&self.suite_id_kem, &[], "dkp_prk", seed, self.hash);
        let mut out = [0u8; MAX_PRIVATE_KEY_LEN];
        let mut public_key = [0u8; MAX_PUBLIC_KEY_LEN];
        let public_key_len = self.public_key_length() as u16;
        let secret_key_len = self.private_key_length() as u16;
        match self.kem_id {
            KemId::X25519Sha256 => {
                labeled_expand(
                    &self.suite_id_kem,
                    self.hash,
                    prk.as_ref(),
                    "sk",
                    &[],
                    self.private_key_length() as u16,
                    &mut out[..self.private_key_length()],
                )?;
                let secret_key = ec::Seed::from_bytes(
                    self.agreement.curve,
                    untrusted::Input::from(&out[..self.private_key_length()]),
                    cpu::features(),
                )?;
                self.public_key_bytes(&secret_key, &mut public_key[..self.public_key_length()])?;
                Ok(KeyPair {
                    secret_key,
                    public_key,
                    public_key_len,
                    secret_key_len,
                })
            }
            KemId::P256Sha256 | KemId::P384Sha384 => {
                for counter in 0u8..=255 {
                    labeled_expand(
                        &self.suite_id_kem,
                        self.hash,
                        prk.as_ref(),
                        "candidate",
                        &[counter],
                        self.private_key_length() as u16,
                        &mut out[..self.private_key_length()],
                    )?;
                    let candidate_key = ec::Seed::from_bytes(
                        self.agreement.curve,
                        untrusted::Input::from(&out[..self.private_key_length()]),
                        cpu::features(),
                    );
                    if let Ok(k) = candidate_key {
                        self.public_key_bytes(&k, &mut public_key[..self.public_key_length()])?;
                        return Ok(KeyPair {
                            secret_key: k,
                            public_key,
                            public_key_len,
                            secret_key_len,
                        });
                    }
                }
                Err(error::Unspecified)
            }
            _ => {
                // unimplemented
                Err(error::Unspecified)
            }
        }
    }

    /// Non interactive DH key exchange to derive shared secret
    fn dh_kex(
        &mut self,
        public_key_receiver: &[u8],
        shared_secret: &mut [u8],
        encapped_key: &mut [u8],
        rng: &dyn rand::SecureRandom,
        seed: Option<&[u8]>,
    ) -> Result<(), error::Unspecified> {
        let keypair = match seed {
            Some(s) => self.derive_key_pair(s)?,
            None => self.generate_key_pair(Some(rng))?,
        };
        let fixed_rng = FixedSliceRandom {
            bytes: keypair.secret_key.bytes_less_safe(),
        };
        let secret_key = agreement::EphemeralPrivateKey::generate(self.agreement, &fixed_rng)?;
        let public_key = secret_key.compute_public_key()?;
        let peer_public_key =
            agreement::UnparsedPublicKey::new(self.agreement, public_key_receiver);
        agreement::agree_ephemeral(secret_key, &peer_public_key, |key_material| {
            shared_secret.copy_from_slice(key_material)
        })?;
        encapped_key.copy_from_slice(public_key.as_ref());
        Ok(())
    }

    fn extract_and_expand(
        &self,
        kex_result: &[u8],
        context: &[&[u8]; 2],
        out: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        let prk = labeled_extract(&self.suite_id_kem, &[], "eae_prk", kex_result, self.hash);
        let mut kem_ctx = [0u8; MAX_PUBLIC_KEY_LEN * 2];
        kem_ctx[..context[0].len()].copy_from_slice(context[0]);
        kem_ctx[context[0].len()..context[0].len() + context[1].len()].copy_from_slice(context[1]);
        labeled_expand(
            &self.suite_id_kem,
            self.hash,
            prk.as_ref(),
            "shared_secret",
            &kem_ctx[..context[0].len() + context[1].len()],
            self.private_key_length() as u16,
            out,
        )
    }

    /// Randomized algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared
    /// secret) and a fixed-length encapsulation of that key that can be decapsulated by the receiver.
    fn encap(
        &self,
        pk_receiver: &[u8],
        encapped_key: &mut [u8],
        shared_secret: &mut [u8],
        rng: &dyn rand::SecureRandom,
        seed: Option<&[u8]>,
    ) -> Result<(), error::Unspecified> {
        let mut kem = Kem::new(self.kem_id)?;
        let mut kex_result = [0u8; MAX_PRIVATE_KEY_LEN];
        kem.dh_kex(
            pk_receiver,
            &mut kex_result[..self.private_key_length()],
            encapped_key,
            rng,
            seed,
        )?;
        kem.extract_and_expand(
            &kex_result[..self.private_key_length()],
            &[encapped_key, pk_receiver],
            shared_secret,
        )?;
        Ok(())
    }

    /// Deterministic algorithm using the private key of the receiver to recover the ephemeral
    /// symmetric key (the KEM shared secret) from its encapsulated representation `enc`.
    fn decap(
        &self,
        keypair: &KeyPair,
        encapped_key: &[u8],
        shared_secret: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        let public_key_ephemeral = agreement::UnparsedPublicKey::new(self.agreement, encapped_key);
        let kem = Kem::new(self.kem_id)?;
        let mut kex_result = [0u8; MAX_PRIVATE_KEY_LEN];
        (kem.agreement.ecdh)(
            &mut kex_result[..self.private_key_length()],
            &keypair.secret_key,
            untrusted::Input::from(public_key_ephemeral.bytes()),
        )?;
        kem.extract_and_expand(
            &kex_result[..self.private_key_length()],
            &[
                encapped_key,
                &keypair.public_key[..keypair.public_key_len as usize],
            ],
            shared_secret,
        )?;
        Ok(())
    }
}

impl Suite {
    /// Instantiate a new suite with a given [KemId], [KdfId] and [AeadId].
    pub fn new(kem_id: KemId, kdf_id: KdfId, aead_id: AeadId) -> Result<Self, error::Unspecified> {
        let kem = Kem::new(kem_id)?;
        Self::with_existing_kem(kem, kdf_id, aead_id)
    }

    /// Instantiate a new `Suite` from `u16` arguments `kem_id`, `kdf_id` and `aead_id`.
    /// `kem_id`, `kdf_id` and `aead_id` should be valid variants of [KemId], [KdfId] and [AeadId].
    pub fn from_u16(kem_id: u16, kdf_id: u16, aead_id: u16) -> Result<Self, error::Unspecified> {
        let kem_id = KemId::try_from(kem_id)?;
        let kdf_id = KdfId::try_from(kdf_id)?;
        let aead_id = AeadId::try_from(aead_id)?;
        Self::new(kem_id, kdf_id, aead_id)
    }

    /// Instantiate a new suite with an existing [Kem], [KdfId] and [AeadId].
    pub fn with_existing_kem(kem: Kem, kdf_id: KdfId, aead_id: AeadId) -> Result<Self, error::Unspecified> {
        let h = match kdf_id {
            KdfId::Sha256 => &hkdf::HKDF_SHA256,
            KdfId::Sha384 => &hkdf::HKDF_SHA384,
            KdfId::Sha512 => &hkdf::HKDF_SHA512,
        };
        let a = match aead_id {
            AeadId::Aes128Gcm => &aead::AES_128_GCM,
            AeadId::Aes256Gcm => &aead::AES_256_GCM,
            AeadId::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        };
        Ok(Suite {
            suite_id_context: get_suite_id_context(kem.kem_id, kdf_id, aead_id),
            hash: h,
            kem,
            aead: a,
        })
    }

    /// Instantiate a new `Suite` with an existing [Kem] and `u16` arguments `kdf_id` and `aead_id`.
    /// `kdf_id` and `aead_id` should be valid variants of [KdfId] and [AeadId].
    pub fn from_u16_with_existing_kem(kem: Kem, kdf_id: u16, aead_id: u16) -> Result<Self, error::Unspecified> {
        let kdf_id = KdfId::try_from(kdf_id)?;
        let aead_id = AeadId::try_from(aead_id)?;
        Self::with_existing_kem(kem, kdf_id, aead_id)
    }

    /// Length of the authentication tag of the associated AEAD algorithm.
    pub fn aead_tag_len(&self) -> usize {
        self.aead.tag_len()
    }

    /// This function combines the KEM shared secret, an info slice that can be chosen by the
    /// application, and an optional pre-shared key to generate the key schedule.
    fn key_schedule(
        &self,
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
    ) -> Result<InnerContext, error::Unspecified> {
        let (psk_id_used, psk_used) = match psk_id {
            Some(p) => (p, psk.unwrap()),
            None => (&[][..], &[][..]),
        };

        let psk_id_hash = labeled_extract(
            &self.suite_id_context,
            &[],
            "psk_id_hash",
            psk_id_used,
            self.hash,
        );
        let info_hash = labeled_extract(&self.suite_id_context, &[], "info_hash", info, self.hash);
        let mut key_schedule_ctx = [0u8; 1 + MAX_DIGEST_LEN * 2];
        key_schedule_ctx[0] = mode as u8;
        key_schedule_ctx[1..self.hash.len() + 1].copy_from_slice(psk_id_hash.as_ref());
        key_schedule_ctx[self.hash.len() + 1..self.hash.len() * 2 + 1]
            .copy_from_slice(info_hash.as_ref());
        let key_schedule_ctx_spliced = &key_schedule_ctx[..self.hash.len() * 2 + 1];
        let secret = labeled_extract(
            &self.suite_id_context,
            shared_secret,
            "secret",
            psk_used,
            self.hash,
        );
        let mut key_out = [0u8; MAX_AEAD_KEY_LEN];
        labeled_expand(
            &self.suite_id_context,
            self.hash,
            secret.as_ref(),
            "key",
            key_schedule_ctx_spliced,
            self.aead.key_len() as u16,
            &mut key_out[..self.aead.key_len()],
        )?;
        let mut nonce_out = [0u8; aead::NONCE_LEN];
        labeled_expand(
            &self.suite_id_context,
            self.hash,
            secret.as_ref(),
            "base_nonce",
            key_schedule_ctx_spliced,
            self.aead.nonce_len() as u16,
            &mut nonce_out,
        )?;
        let mut exporter_secret = [0u8; MAX_DIGEST_LEN];
        labeled_expand(
            &self.suite_id_context,
            self.hash,
            secret.as_ref(),
            "exp",
            key_schedule_ctx_spliced,
            self.hash.len() as u16,
            &mut exporter_secret[..self.hash.len()],
        )?;
        Ok(InnerContext {
            suite_id_context: self.suite_id_context,
            hash: self.hash,
            aead_ctx: AeadContext {
                sealing_key: make_key(
                    self.aead,
                    &key_out[..self.aead.key_len()],
                    &HpkeNonce {
                        base_nonce: nonce_out,
                        nonce_counter: [0u8; aead::NONCE_LEN],
                    },
                ),
                opening_key: make_key(
                    self.aead,
                    &key_out[..self.aead.key_len()],
                    &HpkeNonce {
                        base_nonce: nonce_out,
                        nonce_counter: [0u8; aead::NONCE_LEN],
                    },
                ),
                raw_key: key_out,
                base_nonce: nonce_out,
            },
            exporter_secret,
            aead_algorithm: self.aead,
            peer_aead_ctx: None,
        })
    }

    /// Instantiate a new [SenderContext] that can be used to encrypt. This function takes as input
    /// all the long term key material involved, and an application specific string.
    /// This binds the context to the sender and receiver and the application it is being used for.
    ///
    /// `pk_receiver`: encoded public key of the receiver.
    /// `info`: application specific slice chosen by user.
    /// `encapped_key`: buffer to which the encapsulated key will be written.
    pub fn new_sender_context(
        &self,
        pk_receiver: &[u8],
        info: &[u8],
        encapped_key: &mut [u8],
    ) -> Result<SenderContext, error::Unspecified> {
        let mut shared_secret = [0u8; MAX_PRIVATE_KEY_LEN];
        self.kem.encap(
            pk_receiver,
            encapped_key,
            &mut shared_secret[..self.kem.private_key_length()],
            &rand::SystemRandom::new(),
            None,
        )?;

        Ok(SenderContext {
            inner: self.key_schedule(
                Mode::Base,
                &shared_secret[..self.kem.private_key_length()],
                info,
                None,
                None,
            )?,
        })
    }

    /// NOTE: Only use for testing
    /// Instantiate a new [SenderContext] that can be used to encrypt. This function takes as input
    /// all the long term key material involved, and an application specific string.
    /// This binds the context to the sender and receiver and the application it is being used for.
    ///
    /// `pk_receiver`: encoded public key of the receiver.
    /// `info`: application specific slice chosen by user.
    /// `rng`: optional rng for randomized vs deterministic context. If not test, this is required.
    /// `seed`: optional seed can be specified for deterministic context generation.
    /// `encapped_key`: buffer to which the encapsulated key will be written.
    #[doc(hidden)]
    pub fn new_deterministic_sender_context(
        &self,
        pk_receiver: &[u8],
        info: &[u8],
        seed: &[u8],
        encapped_key: &mut [u8],
    ) -> Result<SenderContext, error::Unspecified> {
        let mut shared_secret = [0u8; MAX_PRIVATE_KEY_LEN];
        self.kem.encap(
            pk_receiver,
            encapped_key,
            &mut shared_secret[..self.kem.private_key_length()],
            &rand::SystemRandom::new(),
            Some(seed),
        )?;

        Ok(SenderContext {
            inner: self.key_schedule(
                Mode::Base,
                &shared_secret[..self.kem.private_key_length()],
                info,
                None,
                None,
            )?,
        })
    }

    /// Instantiate a new [ReceiverContext] that can be used to decrypt. This function takes as input
    /// the encapsulated key and the application specific info slice.
    pub fn new_receiver_context(
        &self,
        keypair: &KeyPair,
        encapped_key: &[u8],
        info: &[u8],
    ) -> Result<ReceiverContext, error::Unspecified> {
        let mut shared_secret = [0u8; MAX_PRIVATE_KEY_LEN];
        self.kem.decap(
            keypair,
            encapped_key,
            &mut shared_secret[..self.kem.private_key_length()],
        )?;
        Ok(ReceiverContext {
            inner: self.key_schedule(
                Mode::Base,
                &shared_secret[..self.kem.private_key_length()],
                info,
                None,
                None,
            )?,
        })
    }
}

/// InnerContext stores the state required to encrypt and decrypt messages.
struct InnerContext {
    suite_id_context: [u8; 10],
    hash: &'static hkdf::Algorithm,
    exporter_secret: [u8; MAX_DIGEST_LEN],
    aead_algorithm: &'static aead::Algorithm,
    aead_ctx: AeadContext,
    peer_aead_ctx: Option<AeadContext>,
}

/// SenderContext stores the state required to encrypt messages.
pub struct SenderContext {
    inner: InnerContext,
}

/// ReceiverContext stores the state required to decrypt messages.
pub struct ReceiverContext {
    inner: InnerContext,
}

impl InnerContext {
    /// Enables AEAD encryption from recipient to sender by deriving a key and nonce
    /// from the current context. It follows guidelines for bidirectional communication as
    /// mentioned in the RFC: https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html#section-9.8
    fn response_state(&mut self) -> Result<AeadContext, error::Unspecified> {
        let mut key = [0u8; MAX_AEAD_KEY_LEN];
        self.export(
            "response key".as_bytes(),
            self.aead_algorithm.key_len() as u16,
            &mut key[..self.aead_algorithm.key_len()],
        )?;
        let mut base_nonce = [0u8; aead::NONCE_LEN];
        self.export(
            "response nonce".as_bytes(),
            self.aead_algorithm.nonce_len() as u16,
            &mut base_nonce,
        )?;
        Ok(AeadContext {
            sealing_key: make_key(
                self.aead_algorithm,
                &key[..self.aead_algorithm.key_len()],
                &HpkeNonce {
                    base_nonce,
                    nonce_counter: [0u8; aead::NONCE_LEN],
                },
            ),
            opening_key: make_key(
                self.aead_algorithm,
                &key[..self.aead_algorithm.key_len()],
                &HpkeNonce {
                    base_nonce,
                    nonce_counter: [0u8; aead::NONCE_LEN],
                },
            ),
            raw_key: key,
            base_nonce,
        })
    }

    /// `export` generates a secret of `length` bytes from `exporter_context`, which is a
    /// secret known by the sender and receiver. It writes the generated secret into the
    /// buffer `exported`.
    fn export(
        &self,
        exporter_context: &[u8],
        length: u16,
        exported: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        labeled_expand(
            &self.suite_id_context,
            self.hash,
            &self.exporter_secret[..self.hash.len()],
            "sec",
            exporter_context,
            length,
            exported,
        )
    }
}

impl SenderContext {
    /// Performs in-place encryption of the message `msg` with additional data `aad` to the receiver.
    /// The resulting ciphertext + tag is written to `msg`.
    pub fn encrypt_to_receiver(
        &mut self,
        msg: &mut [u8],
        aad: &[u8],
    ) -> Result<(), error::Unspecified> {
        let msg_len = msg.len() - self.inner.aead_algorithm.tag_len();
        let out = self
            .inner
            .aead_ctx
            .sealing_key
            .seal_in_place_separate_tag(aead::Aad::from(aad), &mut msg[..msg_len])?;
        msg[msg_len..].copy_from_slice(out.as_ref());
        Ok(())
    }

    /// Performs in-place decryption of the `ciphertext` received, with additional data `aad`.
    /// `ciphertext` should contain the `ciphertext` followed by `tag`.
    /// The resulting plaintext (without the tag) is written to `ciphertext`.
    pub fn decrypt_from_receiver(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        if self.inner.peer_aead_ctx.is_none() {
            self.inner.peer_aead_ctx = Some(self.inner.response_state()?);
        }
        let _ = self
            .inner
            .peer_aead_ctx
            .as_mut()
            .unwrap()
            .opening_key
            .open_in_place(aead::Aad::from(aad), ciphertext)?;
        Ok(())
    }

    /// `export` generates a secret of `length` bytes from `exporter_context`, which is a
    /// secret known by the sender and receiver. It writes the generated secret into the
    /// buffer `exported`.
    pub fn export(
        &self,
        exporter_context: &[u8],
        length: u16,
        exported: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        self.inner.export(exporter_context, length, exported)
    }
}

impl ReceiverContext {
    /// Performs in-place decryption of the `ciphertext` received, with additional data `aad`.
    /// `ciphertext` should contain the `ciphertext` followed by `tag`.
    /// The resulting plaintext (without the tag) is written to `ciphertext`.
    pub fn decrypt_from_sender(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        let _ = self
            .inner
            .aead_ctx
            .opening_key
            .open_in_place(aead::Aad::from(aad), ciphertext)?;
        Ok(())
    }

    /// Performs in-place encryption of the message `msg` with additional data `aad` to the sender.
    /// The resulting ciphertext + tag is written to `msg`.
    /// NOTE: In Base Mode, using this method means there is no authentication of the remote.
    /// For more information, see [Bidirectional Encryption](https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html#section-9.8)
    pub fn encrypt_to_sender(
        &mut self,
        msg: &mut [u8],
        aad: &[u8],
    ) -> Result<(), error::Unspecified> {
        if self.inner.peer_aead_ctx.is_none() {
            self.inner.peer_aead_ctx = Some(self.inner.response_state()?);
        }
        let msg_len = msg.len() - self.inner.aead_algorithm.tag_len();
        let out = self
            .inner
            .peer_aead_ctx
            .as_mut()
            .unwrap()
            .sealing_key
            .seal_in_place_separate_tag(aead::Aad::from(aad), &mut msg[..msg_len])?;
        msg[msg_len..].copy_from_slice(out.as_ref());
        Ok(())
    }

    /// `export` generates a secret of `length` bytes from `exporter_context`, which is a
    /// secret known by the sender and receiver. It writes the generated secret into the
    /// buffer `exported`.
    pub fn export(
        &self,
        exporter_context: &[u8],
        length: u16,
        exported: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        self.inner.export(exporter_context, length, exported)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct HpkeNonce {
    base_nonce: [u8; aead::NONCE_LEN],
    nonce_counter: [u8; aead::NONCE_LEN],
}

/// `AeadContext` contains the symmetric key and nonce necessary for encryption and decryption.
#[derive(Debug)]
struct AeadContext {
    sealing_key: aead::SealingKey<HpkeNonce>,
    opening_key: aead::OpeningKey<HpkeNonce>,
    raw_key: [u8; MAX_AEAD_KEY_LEN],
    base_nonce: [u8; 12],
}

impl aead::NonceSequence for HpkeNonce {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        let mut new_nonce = [0u8; aead::NONCE_LEN];
        for (i, (&x1, &x2)) in self
            .base_nonce
            .iter()
            .zip(self.nonce_counter.iter())
            .enumerate()
        {
            new_nonce[i] = x1 ^ x2;
        }
        self.increment_bytes()?;
        aead::Nonce::try_assume_unique_for_key(&new_nonce)
    }
}

impl HpkeNonce {
    /// Increments the bytes by 1, assuming the most significant bit is first.
    /// Returns an error in case of overflow.
    fn increment_bytes(&mut self) -> Result<(), error::Unspecified> {
        let mut carry = 1 as u16;
        for i in (0..self.nonce_counter.len()).rev() {
            let d = (self.nonce_counter[i] as u16) + carry;
            self.nonce_counter[i] = (d & 0xff) as u8;
            carry = d >> 8;
        }
        if carry != 0 {
            // Overflow error
            return Err(error::Unspecified)
        }
        Ok(())
    }
}

fn make_key<K: aead::BoundKey<HpkeNonce>>(
    algorithm: &'static aead::Algorithm,
    key: &[u8],
    nonce: &HpkeNonce,
) -> K {
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = HpkeNonce {
        base_nonce: nonce.base_nonce,
        nonce_counter: nonce.nonce_counter,
    };
    K::new(key, nonce_sequence)
}

/// Generic newtype wrapper that lets us implement traits for externally-defined
/// types.
#[derive(Debug, PartialEq)]
struct HpkeWrap<T: core::fmt::Debug + PartialEq>(T);

impl KeyType for HpkeWrap<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, HpkeWrap<usize>>> for HpkeWrap<[u8; MAX_DIGEST_LEN]> {
    fn from(okm: hkdf::Okm<HpkeWrap<usize>>) -> Self {
        let mut r = [0u8; MAX_DIGEST_LEN];
        okm.fill(&mut r).unwrap();
        Self(r)
    }
}

/// KDF function to extract a PRK from an initial seed `ikm` with context specific information
pub fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &str,
    ikm: &[u8],
    hash: &'static hkdf::Algorithm,
) -> hmac::Tag {
    let key = hmac::Key::new(hash.hmac_algorithm(), salt);
    let mut ctx = crate::hmac::Context::with_key(&key);
    ctx.update(VERSION);
    ctx.update(suite_id);
    ctx.update(label.as_bytes());
    ctx.update(ikm);
    ctx.sign()
}

/// KDF function that allows expanding a `prk` with context specific information
/// The user must specify the buffer `out` with `length` bytes
pub fn labeled_expand<'a>(
    suite_id: &'a [u8],
    hash: &'static hkdf::Algorithm,
    prk: &'a [u8],
    label: &'a str,
    info: &[u8],
    length: u16,
    out: &'a mut [u8],
) -> Result<(), error::Unspecified> {
    let be_len = length.to_be_bytes();
    let prk = hkdf::Prk::new_less_safe(*hash, prk);
    let labeled_info = [&be_len[0..2], VERSION, suite_id, label.as_bytes(), info];
    let okm = prk.expand(&labeled_info, HpkeWrap(length as usize))?;
    okm.fill(out)?;
    Ok(())
}

/// An implementation of `SecureRandom` that always fills the output slice
/// with the slice in `bytes`. The length of the slice given to `slice`
/// must match exactly.
#[derive(Debug)]
struct FixedSliceRandom<'a> {
    pub bytes: &'a [u8],
}

impl rand::sealed::SecureRandom for FixedSliceRandom<'_> {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        dest.copy_from_slice(self.bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::hpke::*;
    use crate::rand;

    #[test]
    fn generate_kp() {
        let kem = Kem::new(KemId::X25519Sha256).unwrap();
        let _ = kem.generate_key_pair(None).unwrap();
    }

    #[test]
    fn derive_kp() {
        let kem = Kem::new(KemId::X25519Sha256).unwrap();
        let initial: [u8; 32] = rand::generate(&rand::SystemRandom::new()).unwrap().expose();
        let _ = kem.derive_key_pair(&initial).unwrap();
    }

    #[test]
    fn test_setup_context() {
        let receiver_kem = Kem::new(KemId::X25519Sha256).unwrap();
        let kp = receiver_kem.generate_key_pair(None).unwrap();
        let suite = Suite::with_existing_kem(receiver_kem, KdfId::Sha256, AeadId::ChaCha20Poly1305).unwrap();
        let mut encapped_key = [0u8; 32];
        let _ = suite
            .new_sender_context(kp.public_key_bytes(), "test".as_bytes(), &mut encapped_key)
            .unwrap();
        let _ = suite
            .new_receiver_context(&kp, &encapped_key, "test".as_bytes())
            .unwrap();
    }

    #[test]
    fn test_encrypt_to_recv() {
        let receiver_kem = Kem::new(KemId::X25519Sha256).unwrap();
        let kp = receiver_kem.generate_key_pair(None).unwrap();
        let suite = Suite::with_existing_kem(receiver_kem, KdfId::Sha256, AeadId::ChaCha20Poly1305).unwrap();
        let mut encapped_key = [0u8; 32];
        let mut sender_ctx = suite
            .new_sender_context(kp.public_key_bytes(), "test".as_bytes(), &mut encapped_key)
            .unwrap();
        let mut receiver_ctx = suite
            .new_receiver_context(&kp, &encapped_key, "test".as_bytes())
            .unwrap();
        let mut msg = b"jinx".to_vec();
        msg.resize(suite.aead_tag_len() + 4, 0);
        sender_ctx.encrypt_to_receiver(&mut msg, &[]).unwrap();
        let mut ciphertext = msg.clone();
        assert_eq!(ciphertext.len(), 20);
        let res = receiver_ctx.decrypt_from_sender(&[], &mut ciphertext);
        assert_eq!(res.is_err(), false);
        assert_eq!(&ciphertext[0..4], "jinx".as_bytes());
    }

    #[test]
    fn test_encrypt_to_sender() {
        let receiver_kem = Kem::new(KemId::X25519Sha256).unwrap();
        let kp = receiver_kem.generate_key_pair(None).unwrap();
        let suite = Suite::with_existing_kem(receiver_kem, KdfId::Sha256, AeadId::ChaCha20Poly1305).unwrap();
        let mut encapped_key = [0u8; 32];
        let mut sender_ctx = suite
            .new_sender_context(&kp.public_key[..kp.public_key_len as usize], "test".as_bytes(), &mut encapped_key)
            .unwrap();
        let mut receiver_ctx = suite
            .new_receiver_context(&kp, &encapped_key, "test".as_bytes())
            .unwrap();
        let mut msg = b"jinx".to_vec();
        msg.resize(suite.aead_tag_len() + 4, 0);
        sender_ctx.encrypt_to_receiver(&mut msg, &[]).unwrap();
        let mut ciphertext = msg.clone();
        assert_eq!(ciphertext.len(), 20);
        let res = receiver_ctx.decrypt_from_sender(&[], &mut ciphertext);
        assert_eq!(res.is_err(), false);
        assert_eq!(&ciphertext[0..4], "jinx".as_bytes());

        // encrypt to sender
        let mut recv_msg = b"silco".to_vec();
        recv_msg.resize(suite.aead_tag_len() + 5, 0);
        receiver_ctx.encrypt_to_sender(&mut recv_msg, &[]).unwrap();
        let mut new_ct = recv_msg.clone();
        assert_eq!(new_ct.len(), 21);
        let new_res = sender_ctx.decrypt_from_receiver(&[], &mut new_ct);
        assert_eq!(new_res.is_err(), false);
        assert_eq!(&new_ct[0..5], "silco".as_bytes());
    }
}
