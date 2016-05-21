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

//! ECDH Key agreement.

#![allow(unsafe_code)]

use {c, ec, init};

use bssl;
use input::Input;

/// A key agreement algorithm.
pub struct Algorithm {
    ec_group_fn: unsafe extern fn () -> *const ec::EC_GROUP,

    encoded_public_key_len: usize,

    nid: c::int,

    generate_key_pair: fn(alg: &'static Algorithm) -> Result<KeyPairImpl, ()>,

    fill_with_public_key: fn(algorithm: &Algorithm, key_pair_impl: &KeyPairImpl,
                             out: &mut [u8]) -> Result<(), ()>,

    agree: fn(key_pair: &KeyPairImpl, peer_public_key_pair_alg: &Algorithm,
              peer_public_key: &[u8], shared_key: &mut [u8])
              -> Result<usize, ()>,

    drop_key_pair: fn(key_pair_impl: &mut KeyPairImpl),
}

/// An ephemeral key pair for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `EphemeralKeyPair` can be
/// used for at most one key agreement.
// XXX: The implementation is weird because the crypto/ec API is completely
// different from the crypto/curve25519 API. We want to keep link-time dead
// code elimination to work, but we need to use an enum type `KeyPairImpl` to
// join the implementations that use the two APIs, but we don't want to expose
// the enum in the API. In the future, the internal APIs for the NIST-based and
// Curve25519-based curves will converge so that such ugliness is not necessary.
pub struct EphemeralKeyPair {
    key_pair_impl: KeyPairImpl,
    algorithm: &'static Algorithm,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral key pair for the given algorithm.
    ///
    /// C analog: `EC_KEY_new_by_curve_name` + `EC_KEY_generate_key`.
    pub fn generate(algorithm: &'static Algorithm)
                    -> Result<EphemeralKeyPair, ()> {
        init::init_once();

        let key_pair_impl = try!((algorithm.generate_key_pair)(algorithm));
        Ok(EphemeralKeyPair {
            key_pair_impl: key_pair_impl,
            algorithm: algorithm,
        })
    }

    /// The size in bytes of the encoded public key.
    #[inline(always)]
    pub fn public_key_len(&self) -> usize {
        self.algorithm.encoded_public_key_len
    }

    /// Fills `out` with the public point encoded in the standard form for the
    /// algorithm.
    ///
    /// `out.len()` must be equal to the value returned by `public_key_len`.
    pub fn fill_with_encoded_public_key(&self, out: &mut [u8])
                                        -> Result<(), ()> {
        (self.algorithm.fill_with_public_key)(self.algorithm,
                                              &self.key_pair_impl, out)
    }
}

impl Drop for EphemeralKeyPair {
    fn drop(&mut self) {
        (self.algorithm.drop_key_pair)(&mut self.key_pair_impl)
    }
}

enum KeyPairImpl {
    NIST {
        key: *mut EC_KEY,
    },
}

/// Performs a key agreement with an ephemeral key pair's private key and the
/// given public key.
///
/// `my_key_pair` is the ephemeral key pair to use. Since `my_key_pair` is
/// moved, it will not be usable after calling `agree_ephemeral`, thus
/// guaranteeing that the key is used for only one key agreement.
///
/// `peer_public_key_alg` is the algorithm/curve for the peer's public key
/// point; `agree_ephemeral` will return `Err(())` if it does not match
/// `my_key_pair's` algorithm/curve. `peer_pubic_key` is the peer's public key.
/// `agree_ephemeral` verifies that it is encoded in the standard form for the
/// algorithm and that the key is *valid*; see the algorithm's documentation
/// for details on how keys are to be encoded and what constitutes a valid key
/// for that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agrement operation and then returns what `kdf`
/// returns.
///
/// C analogs: `ECDH_compute_key_ex` (*ring* only), `EC_POINT_oct2point` +
/// `ECDH_compute_key`, `X25519`.
pub fn agree_ephemeral<F, R, E>(my_key_pair: EphemeralKeyPair,
                                peer_public_key_alg: &Algorithm,
                                peer_public_key: Input,
                                error_value: E, kdf: F) -> Result<R, E>
                                where F: FnOnce(&[u8]) -> Result<R, E> {
    let mut shared_key = [0u8; MAX_COORDINATE_LEN];
    let peer_public_key = peer_public_key.as_slice_less_safe();
    let shared_key_len =
        try!((my_key_pair.algorithm.agree)(&my_key_pair.key_pair_impl,
                                           peer_public_key_alg, peer_public_key,
                                           &mut shared_key)
                .map_err(|_| error_value));
    kdf(&shared_key[..shared_key_len])
}


// XXX: This should be computed from ecc_build.rs.
const MAX_COORDINATE_LEN: usize = (384 + 7) / 8;


macro_rules! nist_ecdh {
    ( $NAME:ident, $bits:expr, $name_str:expr, $ec_group_fn:expr, $nid:expr ) => {
        #[doc="ECDH using the NIST"]
        #[doc=$name_str]
        #[doc="curve."]
        ///
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in [SEC 1: Elliptic
        /// Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
        /// Public keys are validated during key agreement according as
        /// described in [NIST Special Publication 800-56A, revision
        /// 2](http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-56Arev1_3-8-07.pdf)
        /// Section 5.6.2.5 and the [Suite B Implementer's Guide to NIST SP
        /// 800-56A](https://www.nsa.gov/ia/_files/suiteb_implementer_g-113808.pdf)
        /// Appendix B.3. Note that, as explained in the NSA guide, "partial"
        /// validation is equivalent to "full" validation for prime-order
        /// curves like this one.
        ///
        /// TODO: Each of the encoded coordinates are verified to be the
        /// correct length, but values of the allowed length that haven't been
        /// reduced modulo *q* are currently reduced mod *q* during
        /// verification. Soon, coordinates larger than *q* - 1 will be
        /// rejected.
        ///
        /// Not available in `no_heap` mode.
        pub static $NAME: Algorithm = Algorithm {
            ec_group_fn: $ec_group_fn,
            encoded_public_key_len: 1 + (2 * (($bits + 7) / 8)),
            generate_key_pair: nist_ecdh_generate_key_pair,
            agree: nist_ecdh_agree,
            fill_with_public_key: nist_ecdh_fill_with_public_key,
            drop_key_pair: nist_ecdh_drop_key_pair,
            nid: $nid,
        };
    }
}

nist_ecdh!(ECDH_P256, 256, "P-256 (secp256r1)", ec::EC_GROUP_P256,
           415 /*NID_X9_62_prime256v1*/);
nist_ecdh!(ECDH_P384, 384, "P-384 (secp256r1)", ec::EC_GROUP_P384,
           715 /*NID_secp384r1*/);

fn nist_ecdh_generate_key_pair(algorithm: &Algorithm) -> Result<KeyPairImpl, ()> {
    let key = try!(bssl::map_ptr_result(unsafe {
        EC_KEY_generate_key_ex((algorithm.ec_group_fn)())
    }));
    Ok(KeyPairImpl::NIST { key: key })
}

fn nist_ecdh_fill_with_public_key(algorithm: &Algorithm,
                                  key_pair_impl: &KeyPairImpl, out: &mut [u8])
                                  -> Result<(), ()> {
    match key_pair_impl {
        &KeyPairImpl::NIST { key } => {
            match unsafe {
                EC_KEY_public_key_to_oct(key, out.as_mut_ptr(), out.len())
            } {
                n if n == algorithm.encoded_public_key_len => Ok(()),
                _ => Err(())
            }
        },
    }
}

fn nist_ecdh_agree(key_pair_impl: &KeyPairImpl, peer_public_key_alg: &Algorithm,
                   peer_public_key: &[u8], shared_key: &mut [u8])
                   -> Result<usize, ()> {
    match key_pair_impl {
        &KeyPairImpl::NIST { key } => {
            let mut shared_key_len = 0;
            bssl::map_result(unsafe {
                ECDH_compute_key_ex(shared_key.as_mut_ptr(),
                                    &mut shared_key_len, shared_key.len(),
                                    key, peer_public_key_alg.nid,
                                    peer_public_key.as_ptr(),
                                    peer_public_key.len())
            }).map(|_| shared_key_len)
        },
    }
}

fn nist_ecdh_drop_key_pair(key_pair_impl: &mut KeyPairImpl) {
    match key_pair_impl {
        &mut KeyPairImpl::NIST { key } => {
            unsafe {
                EC_KEY_free(key);
             }
        },
    }
}

#[allow(non_camel_case_types)]
enum EC_KEY { }

extern {
    fn EC_KEY_generate_key_ex(group: *const ec::EC_GROUP) -> *mut EC_KEY;

    fn EC_KEY_public_key_to_oct(key: *const EC_KEY, out: *mut u8,
                                out_len: c::size_t) -> c::size_t;

    fn EC_KEY_free(key: *mut EC_KEY);

    fn ECDH_compute_key_ex(out: *mut u8, out_len: *mut c::size_t,
                           max_out_len: c::size_t, my_key_pair: *const EC_KEY,
                           peer_curve_nid: c::int,
                           peer_pub_point_bytes: *const u8,
                           peer_pub_point_bytes_len: c::size_t) -> c::int;
}
