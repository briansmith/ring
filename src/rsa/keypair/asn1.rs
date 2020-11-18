//! Construction of `RsaKeyPair` from ASN1.

use super::super::{keypair, public};
use crate::{
    error::{self, KeyRejected},
    io::der,
    pkcs8,
};
use core::convert::TryFrom;

impl keypair::RsaKeyPair {
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
        const RSA_ENCRYPTION: &[u8] = include_bytes!("../../data/alg-rsa-encryption.der");
        let (der, _) = pkcs8::unwrap_key_(
            untrusted::Input::from(&RSA_ENCRYPTION),
            pkcs8::Version::V1Only,
            untrusted::Input::from(pkcs8),
        )?;
        Self::from_der(der.as_slice_less_safe())
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
        untrusted::Input::from(input).read_all(KeyRejected::invalid_encoding(), |input| {
            der::nested(
                input,
                der::Tag::Sequence,
                KeyRejected::invalid_encoding(),
                Self::from_der_reader,
            )
        })
    }

    fn from_der_reader(input: &mut untrusted::Reader) -> Result<Self, KeyRejected> {
        let version = der::small_nonnegative_integer(input)
            .map_err(|error::Unspecified| KeyRejected::invalid_encoding())?;
        if version != 0 {
            return Err(KeyRejected::version_not_supported());
        }

        fn nonnegative_integer<'a>(
            input: &mut untrusted::Reader<'a>,
        ) -> Result<&'a [u8], KeyRejected> {
            der::nonnegative_integer(input, 0)
                .map(|input| input.as_slice_less_safe())
                .map_err(|error::Unspecified| KeyRejected::invalid_encoding())
        }

        let n = nonnegative_integer(input)?;
        let e = nonnegative_integer(input)?;
        let d = nonnegative_integer(input)?;
        let p = nonnegative_integer(input)?;
        let q = nonnegative_integer(input)?;
        let dP = nonnegative_integer(input)?;
        let dQ = nonnegative_integer(input)?;
        let qInv = nonnegative_integer(input)?;

        let components = keypair::Components {
            public_key: public::Components { n, e },
            d,
            p,
            q,
            dP,
            dQ,
            qInv,
        };

        Self::try_from(&components)
    }
}
