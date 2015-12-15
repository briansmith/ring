// Copyright 2015 Brian Smith.
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

//! Key agreement: ECDH.

use super::{c, digest, ecc, ffi};
use super::input::Input;
use std;

/// A key agreement algorithm.
pub struct Algorithm {
    ec_group_fn: unsafe extern fn () -> *const ecc::EC_GROUP,
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
//
// As noted above, `agree_ephemeral` validates that key points are valid.
// However, if the key is ephemeral and authenticated then, depending on other
// details of the protocol and the specific algorithm, it may not be necessary
// to validate that a peer's public point is on the curve. A malicious
// authenticated peer could just as easily give us a bad public point that is
// on the curve. Also, given that our key pair is ephemeral, we're not risking
// the leakage of a long-term key via invalid point attacks. Note that DJB's
// Curve25519 documentation has a FAQ that includes ["Q: How do I validate
// Curve25519 public keys? A: Don't. [...]"](http://cr.yp.to/ecdh.html#validate).
//
// On the other hand, some users may feel that it is worthwhile to do point
// validity check even if it seems to be not strictly necessary. And, it is
// often not obvious that it is necessary. For example, point validation is
// sometimes even in the case of authenticated key exchange to prevent key
// dictation attacks, e.g. for TLS because of Triple Handshake; see
// [Why not validate Curve25519 public keys could be
// harmful](https://vnhacker.blogspot.com/2015/09/why-not-validating-curve25519-public.html)
// by Thai Duong. Point validation is fast relative to other public key
// operations, and it seems like point validation is never *bad* to do.
//
// So, it might be worthwhile to add another interface that is like
// `agree_ephemeral` but which doesn't do the public key point validation, but
// there are some doubts that its utility would justify the complexity and the
// risks of its misuse.
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
    kdf(&shared_key[0..shared_key_len])
}


// XXX: This should be computed from ecc_build.rs.
const MAX_COORDINATE_LEN: usize = (521 + 7) / 8;

// TODO: After ecdsa_test.cc is removed, this function should be removed and
// the caller should be changed to call `SHA512_5` directly. Also, the
// alternative implementation of this in crypto/test should be removed at
// that time.
#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub extern fn BN_generate_dsa_nonce_digest(
        out: *mut u8, out_len: c::size_t,
        part1: *const u8, part1_len: c::size_t,
        part2: *const u8, part2_len: c::size_t,
        part3: *const u8, part3_len: c::size_t,
        part4: *const u8, part4_len: c::size_t,
        part5: *const u8, part5_len: c::size_t)
        -> c::int {
    SHA512_5(out, out_len, part1, part1_len, part2, part2_len, part3,
             part3_len, part4, part4_len, part5, part5_len);
    1
}

/// SHA512_5 calculates the SHA-512 digest of the concatenation of |part1|
/// through |part5|. Any part<N> may be null if and only if the corresponding
/// part<N>_len is zero. This ugliness exists in order to allow some of the
/// C ECC code to calculate SHA-512 digests.
#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub extern fn SHA512_5(out: *mut u8, out_len: c::size_t,
                       part1: *const u8, part1_len: c::size_t,
                       part2: *const u8, part2_len: c::size_t,
                       part3: *const u8, part3_len: c::size_t,
                       part4: *const u8, part4_len: c::size_t,
                       part5: *const u8, part5_len: c::size_t) {
    fn maybe_update(ctx: &mut digest::Context, part: *const u8,
                    part_len: c::size_t) {
        if part_len != 0 {
            assert!(!part.is_null());
            ctx.update(unsafe { std::slice::from_raw_parts(part, part_len) });
        }
    }

    let mut ctx = digest::Context::new(&digest::SHA512);
    maybe_update(&mut ctx, part1, part1_len);
    maybe_update(&mut ctx, part2, part2_len);
    maybe_update(&mut ctx, part3, part3_len);
    maybe_update(&mut ctx, part4, part4_len);
    maybe_update(&mut ctx, part5, part5_len);
    let digest = ctx.finish();
    let digest = digest.as_ref();
    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    assert_eq!(out.len(), digest.len());
    for i in 0..digest.len() {
        out[i] = digest[i];
    }
}


macro_rules! nist_ecdh {
    ( $NAME:ident, $bits:expr, $name_str:expr, $ec_group_fn:expr, $nid:expr ) => {
        #[doc="ECDH using the NIST"]
        #[doc=$name_str]
        #[doc="curve."]
        ///
        /// Public keys are encoding in uncompressed form using the
        /// Octet-String-to-Elliptic-Curve-Point algorithm in [SEC 1: Elliptic
        /// Curve Cryptography, Version 2.0](http://www.secg.org/sec1-v2.pdf).
        /// A valid public key is a point that is on the curve and not at
        /// infinity. TODO: Each of the encoded coordinates are verified to be
        /// the correct length, but values of the allowed length that haven't
        /// been reduced modulo *q* are currently reduced mod *q* during
        /// verification; soon, coordinates larger than *q* - 1 will be
        /// rejected.
        ///
        /// See NISTS's [SP 800-56Ar2: Recommendation for Pair-Wise Key
        /// Establishment Schemes Using Discrete Logarithm
        /// Cryptography](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf),
        /// and the NSA's [Suite B Implementerâ€™s Guide to NIST SP
        /// 800-56A](https://www.nsa.gov/ia/_files/suiteb_implementer_g-113808.pdf)
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

nist_ecdh!(ECDH_P256, 256, "P-256 (secp256r1)", ecc::EC_GROUP_P256,
           415 /*NID_X9_62_prime256v1*/);
nist_ecdh!(ECDH_P384, 384, "P-384 (secp256r1)", ecc::EC_GROUP_P384,
           715 /*NID_secp384r1*/);
nist_ecdh!(ECDH_P521, 521, "P-521 (secp256r1)", ecc::EC_GROUP_P521,
           716 /*NID_secp521r1*/);

fn nist_ecdh_generate_key_pair(algorithm: &Algorithm) -> Result<KeyPairImpl, ()> {
    let key = try!(ffi::map_bssl_ptr_result(unsafe {
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
            ffi::map_bssl_result(unsafe {
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
    fn EC_KEY_generate_key_ex(group: *const ecc::EC_GROUP) -> *mut EC_KEY;
    fn EC_KEY_public_key_to_oct(key: *const EC_KEY, out: *mut u8,
                                out_len: c::size_t) -> c::size_t;
    fn EC_KEY_free(key: *mut EC_KEY);

    fn ECDH_compute_key_ex(out: *mut u8, out_len: *mut c::size_t,
                           max_out_len: c::size_t, my_key_pair: *const EC_KEY,
                           peer_curve_nid: c::int,
                           peer_pub_point_bytes: *const u8,
                           peer_pub_point_bytes_len: c::size_t) -> c::int;
}
