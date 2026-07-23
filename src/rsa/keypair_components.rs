use super::PublicKeyComponents;
use crate::error;
use crate::error::KeyRejected;
use crate::io::der;

/// RSA key pair components.
#[derive(Clone, Copy)]
pub struct KeyPairComponents<Public, Private = Public> {
    /// The public key components.
    pub public_key: PublicKeyComponents<Public>,

    /// The private exponent.
    pub d: Private,

    /// The first prime factor of `d`.
    pub p: Private,

    /// The second prime factor of `d`.
    pub q: Private,

    /// `p`'s public Chinese Remainder Theorem exponent.
    pub dP: Private,

    /// `q`'s public Chinese Remainder Theorem exponent.
    pub dQ: Private,

    /// `q**-1 mod p`.
    pub qInv: Private,
}

impl<'a> KeyPairComponents<&'a [u8], &'a [u8]> {
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
    /// See [`Self::from_components()`] for more details on how the input is
    /// validated.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    ///
    /// [NIST SP-800-56B rev. 1]:
    ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf
    pub fn from_der(input: &'a [u8]) -> Result<Self, KeyRejected> {
        untrusted::Input::from(input).read_all(KeyRejected::invalid_encoding(), |input| {
            der::nested(
                input,
                der::Tag::Sequence,
                KeyRejected::invalid_encoding(),
                Self::from_der_reader,
            )
        })
    }

    fn from_der_reader(input: &mut untrusted::Reader<'a>) -> Result<Self, KeyRejected> {
        let version = der::small_nonnegative_integer(input)
            .map_err(|error::Unspecified| KeyRejected::invalid_encoding())?;
        if version != 0 {
            return Err(KeyRejected::version_not_supported());
        }

        fn nonnegative_integer<'a>(
            input: &mut untrusted::Reader<'a>,
        ) -> Result<&'a [u8], KeyRejected> {
            der::nonnegative_integer(input)
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

        Ok(Self {
            public_key: PublicKeyComponents { n, e },
            d,
            p,
            q,
            dP,
            dQ,
            qInv,
        })
    }
}

impl<Public, Private> core::fmt::Debug for KeyPairComponents<Public, Private>
where
    PublicKeyComponents<Public>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        // Non-public components are intentionally skipped
        f.debug_struct("KeyPairComponents")
            .field("public_key", &self.public_key)
            .finish()
    }
}
