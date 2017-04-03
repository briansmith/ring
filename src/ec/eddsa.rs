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
    private_public: [u8; KEY_PAIR_LEN],
}

/// The raw bytes of the Ed25519 key pair, for serialization.
pub struct Ed25519KeyPairBytes {
    /// Private key bytes.
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
        let mut bytes = Ed25519KeyPairBytes {
            private_key: [0; SEED_LEN],
            public_key: [0; PUBLIC_KEY_LEN],
        };
        try!(rng.fill(&mut bytes.private_key));
        public_from_private(&bytes.private_key, &mut bytes.public_key);
        let key_pair =
            try!(Ed25519KeyPair::from_bytes_unchecked(&bytes.private_key,
                                                      &bytes.public_key));
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
    pub fn from_bytes(private_key: &[u8], public_key: &[u8])
                      -> Result<Ed25519KeyPair, error::Unspecified> {
        let pair = try!(Ed25519KeyPair::from_bytes_unchecked(private_key,
                                                             public_key));
        { // borrow pair;
            let (private_key, public_key) =
                pair.private_public.split_at(SEED_LEN);
            let private_key =
                slice_as_array_ref!(private_key, SEED_LEN).unwrap();
            let mut public_key_check = [0; PUBLIC_KEY_LEN];
            public_from_private(private_key, &mut public_key_check);
            if public_key != public_key_check {
                return Err(error::Unspecified);
            }
        }
        Ok(pair)
    }

    fn from_bytes_unchecked(private_key: &[u8], public_key: &[u8])
                            -> Result<Ed25519KeyPair, error::Unspecified> {
        if private_key.len() != SEED_LEN {
            return Err(error::Unspecified);
        }
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(error::Unspecified);
        }
        let mut pair = Ed25519KeyPair { private_public: [0; KEY_PAIR_LEN] };
        {
            let (pair_private_key, pair_public_key) =
                pair.private_public.split_at_mut(SEED_LEN);
            pair_private_key.copy_from_slice(private_key);
            pair_public_key.copy_from_slice(public_key);
        }
        Ok(pair)
    }

    // Returns a reference to the little-endian-encoded private key bytes.
    fn private_key_bytes(&'a self) -> &'a [u8] {
        &self.private_public[..SEED_LEN]
    }

    /// Returns a reference to the little-endian-encoded public key bytes.
    pub fn public_key_bytes(&'a self) -> &'a [u8] {
        &self.private_public[SEED_LEN..]
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        let mut signature_bytes = [0u8; SIGNATURE_LEN];
        { // borrow signature_bytes;
            let (signature_r, signature_s) =
                signature_bytes.split_at_mut(ELEM_LEN);
            let signature_r =
                slice_as_array_ref_mut!(signature_r, ELEM_LEN).unwrap();
            let signature_s =
                slice_as_array_ref_mut!(signature_s, SCALAR_LEN).unwrap();

            let az = digest::digest(&digest::SHA512, self.private_key_bytes());
            let (a_encoded, z_encoded) = az.as_ref().split_at(SCALAR_LEN);

            let mut a = [0; SCALAR_LEN];
            a.copy_from_slice(a_encoded);
            unsafe { GFp_ed25519_scalar_mask(&mut a) };

            let nonce = {
                let mut ctx = digest::Context::new(&digest::SHA512);
                ctx.update(z_encoded);
                ctx.update(msg);
                ctx.finish()
            };
            let nonce = digest_scalar(nonce);

            let mut r = ExtPoint::new_at_infinity();
            unsafe {
                GFp_x25519_ge_scalarmult_base(&mut r, &nonce);
                GFp_ge_p3_tobytes(signature_r, &r);
            }

            let hram_digest =
                eddsa_digest(signature_r, self.public_key_bytes(), msg);
            let hram = digest_scalar(hram_digest);
            unsafe {
                GFp_x25519_sc_muladd(signature_s, &hram, &a, &nonce);
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

fn public_from_private(seed: &Seed, out: &mut PublicKey) {
    let seed_sha512 = digest::digest(&digest::SHA512, seed);
    let a_bytes =
        slice_as_array_ref!(&seed_sha512.as_ref()[..SCALAR_LEN], SCALAR_LEN)
            .unwrap();
    let mut a_bytes = *a_bytes;
    unsafe {
        GFp_ed25519_scalar_mask(&mut a_bytes);
    }
    let mut a = ExtPoint::new_at_infinity();
    unsafe {
        GFp_x25519_ge_scalarmult_base(&mut a, &a_bytes);
        GFp_ge_p3_tobytes(out, &a);
    }
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

const KEY_PAIR_LEN: usize = SEED_LEN + PUBLIC_KEY_LEN;
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
