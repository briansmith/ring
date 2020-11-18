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

use super::super::{keypair, padding::RsaEncoding, public};

/// RSA PKCS#1 1.5 signatures.
use crate::{
    digest,
    error::{self, KeyRejected},
    io::{self, der, der_writer},
    rand, signature,
};
use alloc::boxed::Box;
use core::convert::TryFrom;

/// An RSA key pair, used for signing.
pub struct RsaKeyPair {
    inner: keypair::RsaKeyPair,
    public_key: RsaSubjectPublicKey,
}

impl core::fmt::Debug for RsaKeyPair {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        self.inner.fmt(fmt)
    }
}

impl RsaKeyPair {
    /// Parses an unencrypted PKCS#8-encoded RSA private key.
    ///
    /// Only two-prime (not multi-prime) keys are supported. The public modulus
    /// (n) must be at least 2047 bits. The public modulus must be no larger
    /// than 4096 bits. It is recommended that the public modulus be exactly
    /// 2048 or 3072 bits. The public exponent must be at least 65537.
    ///
    /// This will generate a 2048-bit RSA private key of the correct form using
    /// OpenSSL's command line tool:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:2048 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-2048-private-key.pk8
    /// ```
    ///
    /// This will generate a 3072-bit RSA private key of the correct form:
    ///
    /// ```sh
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:3072 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-3072-private-key.pk8
    /// ```
    ///
    /// Often, keys generated for use in OpenSSL-based software are stored in
    /// the Base64 “PEM” format without the PKCS#8 wrapper. Such keys can be
    /// converted to binary PKCS#8 form using the OpenSSL command line tool like
    /// this:
    ///
    /// ```sh
    /// openssl pkcs8 -topk8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// Base64 (“PEM”) PKCS#8-encoded keys can be converted to the binary PKCS#8
    /// form like this:
    ///
    /// ```sh
    /// openssl pkcs8 -nocrypt -outform der \
    ///     -in rsa-2048-private-key.pem > rsa-2048-private-key.pk8
    /// ```
    ///
    /// The private key is validated according to [NIST SP-800-56B rev. 1]
    /// section 6.4.1.4.3, crt_pkv (Intended Exponent-Creation Method Unknown),
    /// with the following exceptions:
    ///
    /// * Section 6.4.1.2.1, Step 1: Neither a target security level nor an
    ///   expected modulus length is provided as a parameter, so checks
    ///   regarding these expectations are not done.
    /// * Section 6.4.1.2.1, Step 3: Since neither the public key nor the
    ///   expected modulus length is provided as a parameter, the consistency
    ///   check between these values and the private key's value of n isn't
    ///   done.
    /// * Section 6.4.1.2.1, Step 5: No primality tests are done, both for
    ///   performance reasons and to avoid any side channels that such tests
    ///   would provide.
    /// * Section 6.4.1.2.1, Step 6, and 6.4.1.4.3, Step 7:
    ///     * *ring* has a slightly looser lower bound for the values of `p`
    ///     and `q` than what the NIST document specifies. This looser lower
    ///     bound matches what most other crypto libraries do. The check might
    ///     be tightened to meet NIST's requirements in the future. Similarly,
    ///     the check that `p` and `q` are not too close together is skipped
    ///     currently, but may be added in the future.
    ///     - The validity of the mathematical relationship of `dP`, `dQ`, `e`
    ///     and `n` is verified only during signing. Some size checks of `d`,
    ///     `dP` and `dQ` are performed at construction, but some NIST checks
    ///     are skipped because they would be expensive and/or they would leak
    ///     information through side channels. If a preemptive check of the
    ///     consistency of `dP`, `dQ`, `e` and `n` with each other is
    ///     necessary, that can be done by signing any message with the key
    ///     pair.
    ///
    ///     * `d` is not fully validated, neither at construction nor during
    ///     signing. This is OK as far as *ring*'s usage of the key is
    ///     concerned because *ring* never uses the value of `d` (*ring* always
    ///     uses `p`, `q`, `dP` and `dQ` via the Chinese Remainder Theorem,
    ///     instead). However, *ring*'s checks would not be sufficient for
    ///     validating a key pair for use by some other system; that other
    ///     system must check the value of `d` itself if `d` is to be used.
    ///
    /// In addition to the NIST requirements, *ring* requires that `p > q` and
    /// that `e` must be no more than 33 bits.
    ///
    /// See [RFC 5958] and [RFC 3447 Appendix A.1.2] for more details of the
    /// encoding of the key.
    ///
    /// [NIST SP-800-56B rev. 1]:
    ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    ///
    /// [RFC 5958]:
    ///     https://tools.ietf.org/html/rfc5958
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        keypair::RsaKeyPair::from_pkcs8(pkcs8).map(From::from)
    }

    /// Parses an RSA private key that is not inside a PKCS#8 wrapper.
    ///
    /// The private key must be encoded as a binary DER-encoded ASN.1
    /// `RSAPrivateKey` as described in [RFC 3447 Appendix A.1.2]). In all other
    /// respects, this is just like `from_pkcs8()`. See the documentation for
    /// `from_pkcs8()` for more details.
    ///
    /// It is recommended to use `from_pkcs8()` (with a PKCS#8-encoded key)
    /// instead.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    ///
    /// [NIST SP-800-56B rev. 1]:
    ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf
    pub fn from_der(input: &[u8]) -> Result<Self, KeyRejected> {
        keypair::RsaKeyPair::from_der(input).map(From::from)
    }

    /// Returns a reference to the public key.
    #[inline]
    pub fn public(&self) -> &public::Key {
        self.inner.public()
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    #[inline]
    pub fn public_modulus_len(&self) -> usize {
        self.public().n().len()
    }
}

impl From<keypair::RsaKeyPair> for RsaKeyPair {
    fn from(inner: keypair::RsaKeyPair) -> Self {
        let public_key = RsaSubjectPublicKey::from(inner.public());
        Self { inner, public_key }
    }
}

impl<Public, Private> TryFrom<&keypair::Components<Public, Private>> for RsaKeyPair
where
    Public: AsRef<[u8]> + core::fmt::Debug,
    Private: AsRef<[u8]>,
{
    type Error = KeyRejected;

    fn try_from(components: &keypair::Components<Public, Private>) -> Result<Self, Self::Error> {
        keypair::RsaKeyPair::try_from(components).map(From::from)
    }
}

impl signature::KeyPair for RsaKeyPair {
    type PublicKey = RsaSubjectPublicKey;

    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

/// A serialized RSA public key.
#[derive(Clone)]
pub struct RsaSubjectPublicKey(Box<[u8]>);

impl AsRef<[u8]> for RsaSubjectPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

derive_debug_self_as_ref_hex_bytes!(RsaSubjectPublicKey);

impl From<&public::Key> for RsaSubjectPublicKey {
    fn from(key: &public::Key) -> Self {
        // The public key `n` and `e` are always positive.
        fn positive(bytes: &[u8]) -> io::Positive {
            io::Positive::new_non_empty_without_leading_zeros(untrusted::Input::from(bytes))
                .unwrap()
        }

        let n = key.n().to_be_bytes();
        let e = key.e().to_be_bytes();

        let bytes = der_writer::write_all(der::Tag::Sequence, &|output| {
            der_writer::write_positive_integer(output, &positive(&n));
            der_writer::write_positive_integer(output, &positive(&e));
        });
        RsaSubjectPublicKey(bytes)
    }
}

impl RsaSubjectPublicKey {
    /// The public modulus (n).
    pub fn modulus(&self) -> io::Positive {
        // Parsing won't fail because we serialized it ourselves.
        let (public_key, _exponent) =
            super::super::parse_public_key(untrusted::Input::from(self.as_ref())).unwrap();
        public_key
    }

    /// The public exponent (e).
    pub fn exponent(&self) -> io::Positive {
        // Parsing won't fail because we serialized it ourselves.
        let (_public_key, exponent) =
            super::super::parse_public_key(untrusted::Input::from(self.as_ref())).unwrap();
        exponent
    }
}

impl RsaKeyPair {
    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` may be used to randomize the padding
    /// (e.g. for PSS).
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly.
    pub fn sign(
        &self,
        padding_alg: &'static dyn RsaEncoding,
        rng: &dyn rand::SecureRandom,
        msg: &[u8],
        signature: &mut [u8],
    ) -> Result<(), error::Unspecified> {
        let m_hash = digest::digest(padding_alg.digest_alg(), msg);
        padding_alg.encode(m_hash, signature, self.public().n().len_bits(), rng)?;
        self.inner.rsa_private_in_place(signature)
    }
}

#[cfg(test)]
mod tests {
    // We intentionally avoid `use super::*` so that we are sure to use only
    // the public API; this ensures that enough of the API is public.
    use crate::{rand, signature};
    use alloc::vec;

    // `KeyPair::sign` requires that the output buffer is the same length as
    // the public key modulus. Test what happens when it isn't the same length.
    #[test]
    fn test_signature_rsa_pkcs1_sign_output_buffer_len() {
        // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
        // SHA256 digest algorithm.
        const MESSAGE: &[u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &[u8] = include_bytes!("signature_rsa_example_private_key.der");
        let key_pair = signature::RsaKeyPair::from_der(PRIVATE_KEY_DER).unwrap();

        // The output buffer is one byte too short.
        let mut signature = vec![0; key_pair.public().n().len() - 1];

        assert!(key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature)
            .is_err());

        // The output buffer is the right length.
        signature.push(0);
        assert!(key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature)
            .is_ok());

        // The output buffer is one byte too long.
        signature.push(0);
        assert!(key_pair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE, &mut signature)
            .is_err());
    }
}
