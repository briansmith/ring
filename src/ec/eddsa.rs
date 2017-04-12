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

//! EdDSA Signatures.

use {bssl, c, digest, error, private, rand, signature};
use untrusted;

/// Parameters for EdDSA signing and verification.
pub struct EdDSAParameters;

/// An Ed25519 key pair, for signing.
pub struct Ed25519KeyPair {
    // RFC 8032 Section 5.1.6 calls this *s*.
    private_scalar: Scalar,

    // RFC 8032 Section 5.1.6 calls this *prefix*.
    private_prefix: Prefix,

    // RFC 8032 Section 5.1.5 calls this *A*.
    public_key: PublicKey,
}

/// The raw bytes of the Ed25519 key pair, for serialization.
pub struct Ed25519KeyPairBytes {
    /// Private key (seed) bytes.
    pub private_key: [u8; SEED_LEN],

    /// Public key bytes.
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

impl<'a> Ed25519KeyPair {
    /// Generates a new random key pair. There is no way to extract the private
    /// key bytes to save them. If you need to save the private key bytes for
    /// future use then use `generate_serializable()` instead.
    pub fn generate(rng: &rand::SecureRandom)
                    -> Result<Ed25519KeyPair, error::Unspecified> {
        Ed25519KeyPair::generate_serializable(rng).map(|(key_pair, _)| key_pair)
    }

    /// Generates a new key pair and returns the key pair as both an
    /// `Ed25519KeyPair` and a `Ed25519KeyPairBytes`. There is no way to
    /// extract the private key bytes from an `Ed25519KeyPair`, so extracting
    /// the values from the `Ed25519KeyPairBytes` is the only way to get them.
    pub fn generate_serializable(rng: &rand::SecureRandom)
            -> Result<(Ed25519KeyPair, Ed25519KeyPairBytes),
                      error::Unspecified> {
        let mut seed = [0u8; SEED_LEN];
        try!(rng.fill(&mut seed));

        let key_pair = Ed25519KeyPair::from_seed(&seed);
        let bytes = Ed25519KeyPairBytes {
            private_key: seed,
            public_key: key_pair.public_key,
        };

        Ok((key_pair, bytes))
    }

    /// Copies key data from the given slices to create a new key pair. The
    /// first slice must hold the private key and the second slice must hold
    /// the public key. Both slices must contain 32 little-endian-encoded
    /// bytes.
    ///
    /// This is intended for use by code that deserializes key pairs.
    ///
    /// The private and public keys will be verified to be consistent. This
    /// helps protect, for example, against the accidental swapping of the
    /// public and private components of the key pair. This also detects
    /// corruption that might have occurred during storage of the key pair.
    pub fn from_bytes(seed: &[u8], public_key: &[u8])
                      -> Result<Ed25519KeyPair, error::Unspecified> {
        let seed = try!(slice_as_array_ref!(seed, SEED_LEN));
        let pair = Ed25519KeyPair::from_seed(seed);

        // This implicitly verifies that `public_key` is the right length.
        if public_key != &pair.public_key[..] {
            return Err(error::Unspecified);
        }

        Ok(pair)
    }

    fn from_seed(seed: &Seed) -> Ed25519KeyPair {
        let h = digest::digest(&digest::SHA512, seed);
        let (scalar_encoded, prefix_encoded) = h.as_ref().split_at(SCALAR_LEN);

        let mut scalar = [0u8; SCALAR_LEN];
        scalar.copy_from_slice(&scalar_encoded);
        unsafe { GFp_ed25519_scalar_mask(&mut scalar) };

        let mut prefix = [0u8; PREFIX_LEN];
        prefix.copy_from_slice(prefix_encoded);

        let mut a = ExtPoint::new_at_infinity();
        unsafe {
            GFp_x25519_ge_scalarmult_base(&mut a, &scalar);
        }
        let mut public_key = [0; PUBLIC_KEY_LEN];
        unsafe {
            GFp_ge_p3_tobytes(&mut public_key, &a);
        }

        Ed25519KeyPair {
            private_scalar: scalar,
            private_prefix: prefix,
            public_key: public_key,
        }
    }

    /// Returns a reference to the little-endian-encoded public key bytes.
    pub fn public_key_bytes(&'a self) -> &'a [u8] {
        &self.public_key
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        let mut signature_bytes = [0u8; SIGNATURE_LEN];
        { // Borrow `signature_bytes`.
            let (signature_r, signature_s) =
                signature_bytes.split_at_mut(ELEM_LEN);
            let signature_r =
                slice_as_array_ref_mut!(signature_r, ELEM_LEN).unwrap();
            let signature_s =
                slice_as_array_ref_mut!(signature_s, SCALAR_LEN).unwrap();

            let nonce = {
                let mut ctx = digest::Context::new(&digest::SHA512);
                ctx.update(&self.private_prefix);
                ctx.update(msg);
                ctx.finish()
            };
            let nonce = digest_scalar(nonce);

            let mut r = ExtPoint::new_at_infinity();
            unsafe {
                GFp_x25519_ge_scalarmult_base(&mut r, &nonce);
                GFp_ge_p3_tobytes(signature_r, &r);
            }

            let hram_digest = eddsa_digest(signature_r, &self.public_key, msg);
            let hram = digest_scalar(hram_digest);
            unsafe {
                GFp_x25519_sc_muladd(signature_s, &hram, &self.private_scalar,
                                     &nonce);
            }
        }
        signature::Signature::new(signature_bytes)
    }
}


/// Verification of [Ed25519] signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
///
/// [Ed25519]: https://ed25519.cr.yp.to/
pub static ED25519: EdDSAParameters = EdDSAParameters {};

impl signature::VerificationAlgorithm for EdDSAParameters {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(error::Unspecified);
        }
        let public_key = public_key.as_slice_less_safe();
        let public_key = slice_as_array_ref!(public_key, ELEM_LEN).unwrap();

        let (signature_r, signature_s) =
                try!(signature.read_all(error::Unspecified, |input| {
            let r = try!(input.skip_and_get_input(ELEM_LEN));
            let r = r.as_slice_less_safe();
            // `r` is only used as a slice, so don't convert it to an array ref.

            let s = try!(input.skip_and_get_input(SCALAR_LEN));
            let s = s.as_slice_less_safe();
            let s = slice_as_array_ref!(s, SCALAR_LEN).unwrap();

            Ok((r, s))
        }));

        // Ensure `s` is not too large.
        if (signature_s[SCALAR_LEN - 1] & 0b11100000) != 0 {
            return Err(error::Unspecified);
        }

        let mut a = ExtPoint::new_at_infinity();
        try!(bssl::map_result(unsafe {
            GFp_x25519_ge_frombytes_vartime(&mut a, public_key)
        }));
        a.invert_vartime();

        let h_digest =
            eddsa_digest(signature_r, public_key, msg.as_slice_less_safe());
        let h = digest_scalar(h_digest);

        let mut r = Point::new_at_infinity();
        unsafe {
            GFp_ge_double_scalarmult_vartime(&mut r, &h, &a, &signature_s)
        };
        let mut r_check = [0u8; ELEM_LEN];
        unsafe { GFp_x25519_ge_tobytes(&mut r_check, &r) };
        if signature_r != r_check {
            return Err(error::Unspecified);
        }
        Ok(())
    }
}

impl private::Private for EdDSAParameters {}

fn eddsa_digest(signature_r: &[u8], public_key: &[u8], msg: &[u8])
                -> digest::Digest {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(signature_r);
    ctx.update(public_key);
    ctx.update(msg);
    ctx.finish()
}

fn digest_scalar(digest: digest::Digest) -> Scalar {
    let mut unreduced = [0u8; digest::SHA512_OUTPUT_LEN];
    unreduced.copy_from_slice(digest.as_ref());
    unsafe { GFp_x25519_sc_reduce(&mut unreduced) };
    let mut scalar = [0u8; SCALAR_LEN];
    scalar.copy_from_slice(&unreduced[..SCALAR_LEN]);
    scalar
}

extern  {
    fn GFp_ed25519_scalar_mask(a: &mut Scalar);
    fn GFp_ge_double_scalarmult_vartime(r: &mut Point, a_coeff: &Scalar,
                                        a: &ExtPoint, b_coeff: &Scalar);
    fn GFp_ge_p3_tobytes(s: &mut [u8; ELEM_LEN], h: &ExtPoint);
    fn GFp_x25519_ge_frombytes_vartime(h: &mut ExtPoint, s: &Scalar) -> c::int;
    fn GFp_x25519_ge_scalarmult_base(h: &mut ExtPoint, a: &Seed);
    fn GFp_x25519_ge_tobytes(s: &mut Scalar, h: &Point);
    fn GFp_x25519_sc_muladd(s: &mut Scalar, a: &Scalar, b: &Scalar, c: &Scalar);
    fn GFp_x25519_sc_reduce(s: &mut UnreducedScalar);
}

// Keep this in sync with `ge_p3` in curve25519/internal.h.
#[repr(C)]
struct ExtPoint {
    x: Elem,
    y: Elem,
    z: Elem,
    t: Elem,
}

impl ExtPoint {
    fn new_at_infinity() -> Self {
        ExtPoint {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
            t: [0; ELEM_LIMBS],
        }
    }

    fn invert_vartime(&mut self) {
        for i in 0..ELEM_LIMBS {
            self.x[i] = -self.x[i];
            self.t[i] = -self.t[i];
        }
    }
}

// Keep this in sync with `ge_p2` in curve25519/internal.h.
#[repr(C)]
struct Point {
    x: Elem,
    y: Elem,
    z: Elem,
}

impl Point {
    fn new_at_infinity() -> Self {
        Point {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
        }
    }
}

// Keep this in sync with `fe` in curve25519/internal.h.
type Elem = [i32; ELEM_LIMBS];
const ELEM_LIMBS: usize = 10;
const ELEM_LEN: usize = 32;

type PublicKey = [u8; PUBLIC_KEY_LEN];
const PUBLIC_KEY_LEN: usize = ELEM_LEN;

type Prefix = [u8; PREFIX_LEN];
const PREFIX_LEN: usize = digest::SHA512_OUTPUT_LEN - SCALAR_LEN;

const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;

type Scalar = [u8; SCALAR_LEN];
const SCALAR_LEN: usize = 32;

type UnreducedScalar = [u8; UNREDUCED_SCALAR_LEN];
const UNREDUCED_SCALAR_LEN: usize = SCALAR_LEN * 2;

type Seed = [u8; SEED_LEN];
const SEED_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use {test, rand, signature};
    use super::Ed25519KeyPair;
    use untrusted;

    /// Test vectors from BoringSSL.
    #[test]
    fn test_signature_ed25519() {
        test::from_file("src/ec/ed25519_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let private_key = test_case.consume_bytes("PRIV");
            assert_eq!(64, private_key.len());
            let public_key = test_case.consume_bytes("PUB");
            assert_eq!(32, public_key.len());
            let msg = test_case.consume_bytes("MESSAGE");
            let expected_sig = test_case.consume_bytes("SIG");

            let key_pair = Ed25519KeyPair::from_bytes(&private_key[..32],
                                                      &public_key).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_slice());

            let public_key = untrusted::Input::from(&public_key);
            let msg = untrusted::Input::from(&msg);
            let expected_sig = untrusted::Input::from(&expected_sig);

            assert!(signature::verify(&signature::ED25519, public_key,
                                      msg, expected_sig).is_ok());

            Ok(())
        });
    }

    #[test]
    fn test_ed25519_from_bytes_misuse() {
        let rng = rand::SystemRandom::new();
        let (_, bytes) = Ed25519KeyPair::generate_serializable(&rng).unwrap();

        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key,
                                           &bytes.public_key).is_ok());

        // Truncated private key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key[..31],
                                           &bytes.public_key).is_err());

        // Truncated public key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.private_key,
                                           &bytes.public_key[..31]).is_err());

        // Swapped public and private key.
        assert!(Ed25519KeyPair::from_bytes(&bytes.public_key,
                                           &bytes.private_key).is_err());
    }
}
