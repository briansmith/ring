// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// RSA PKCS#1 1.5 signatures.

use {bits, der, digest, error, pkcs8};
use rand;
use std;
use super::{blinding, bigint, bigint::Prime, N};
use arithmetic::montgomery::{R, RR, RRR};
use untrusted;

/// An RSA key pair, used for signing. Feature: `rsa_signing`.
///
/// After constructing an `RSAKeyPair`, construct one or more
/// `RSASigningState`s that reference the `RSAKeyPair` and use
/// `RSASigningState::sign()` to generate signatures. See `ring::signature`'s
/// module-level documentation for an example.
#[derive(Clone)]
pub struct RSAKeyPair {
    n: bigint::Modulus<N>,
    e: bigint::PublicExponent,
    p: PrivatePrime<P>,
    q: PrivatePrime<Q>,
    qInv: bigint::Elem<P, R>,
    oneRR_mod_n: bigint::One<N, RR>,
    qq: bigint::Modulus<QQ>,
    q_mod_n: bigint::Elem<N, R>,
    n_bits: bits::BitLength,
}

impl RSAKeyPair {
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
    ///        -pkeyopt rsa_keygen_bits:2048 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform der > rsa-2048-private-key.pk8
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
    ///   check between these values and the private key's value of n isn't done.
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
    ///
    pub fn from_pkcs8(input: untrusted::Input)
                      -> Result<RSAKeyPair, error::Unspecified> {
        const RSA_ENCRYPTION: &'static [u8] =
            include_bytes!("../data/alg-rsa-encryption.der");
        let (der, _) = pkcs8::unwrap_key_(&RSA_ENCRYPTION,
                                          pkcs8::Version::V1Only, input)?;
        Self::from_der(der)
    }

    /// Parses an RSA private key that is not inside a PKCS#8 wrapper.
    ///
    /// The private key must be encoded as a binary DER-encoded ASN.1
    /// `RSAPrivateKey` as described in [RFC 3447 Appendix A.1.2]). In all other
    /// respects, this is just like `RSAKeyPair::from_pkcs8()`. See the
    /// documentation for `from_pkcs8()` for more details.
    ///
    /// It is recommended to use `RSAKeyPair::from_pkcs8()` (with a
    /// PKCS#8-encoded key) instead.
    ///
    /// [RFC 3447 Appendix A.1.2]:
    ///     https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    ///
    /// [NIST SP-800-56B rev. 1]:
    ///     http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf
    pub fn from_der(input: untrusted::Input)
                    -> Result<RSAKeyPair, error::Unspecified> {
        input.read_all(error::Unspecified, |input| {
            der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
                let version = der::small_nonnegative_integer(input)?;
                if version != 0 {
                    return Err(error::Unspecified);
                }
                let n = der::positive_integer(input)?;
                let e = der::positive_integer(input)?;
                let d = der::positive_integer(input)?;
                let p = der::positive_integer(input)?;
                let q = der::positive_integer(input)?;
                let dP = der::positive_integer(input)?;
                let dQ = der::positive_integer(input)?;
                let qInv = der::positive_integer(input)?;

                let (p, p_bits) =
                    bigint::Nonnegative::from_be_bytes_with_bit_length(p)?;
                let (q, q_bits) =
                    bigint::Nonnegative::from_be_bytes_with_bit_length(q)?;

                // Our implementation of CRT-based modular exponentiation used
                // requires that `p > q` so swap them if `p < q`. If swapped,
                // `qInv` is recalculated below. `p != q` is verified
                // implicitly below, e.g. when `q_mod_p` is constructed.
                let ((p, p_bits, dP), (q, q_bits, dQ, qInv)) =
                    match q.verify_less_than(&p) {
                    Ok(_)  => ((p, p_bits, dP), (q, q_bits, dQ, Some(qInv))),
                    Err(_) => {
                        // TODO: verify `q` and `qInv` are inverses (mod p).
                        ((q, q_bits, dQ), (p, p_bits, dP, None))
                    },
                };

                // XXX: Some steps are done out of order, but the NIST steps
                // are worded in such a way that it is clear that NIST intends
                // for them to be done in order. TODO: Does this matter at all?

                // 6.4.1.4.3/6.4.1.2.1 - Step 1.

                // Step 1.a is omitted, as explained above.

                // Step 1.b is omitted per above. Instead, we check that the
                // public modulus is 2048 to
                // `PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS` bits. XXX: The maximum
                // limit of 4096 bits is primarily due to lack of testing of
                // larger key sizes; see, in particular,
                // https://www.mail-archive.com/openssl-dev@openssl.org/msg44586.html
                // and
                // https://www.mail-archive.com/openssl-dev@openssl.org/msg44759.html.
                // Also, this limit might help with memory management decisions
                // later.

                // Step 1.c. We validate e >= 65537.
                let (n, n_bits, e) = super::check_public_modulus_and_exponent(
                    n, e, bits::BitLength::from_usize_bits(2048),
                    super::PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS, 65537)?;

                // 6.4.1.4.3 says to skip 6.4.1.2.1 Step 2.

                // 6.4.1.4.3 Step 3.

                // Step 3.a is done below, out of order.
                // Step 3.b is unneeded since `n_bits` is derived here from `n`.

                // 6.4.1.4.3 says to skip 6.4.1.2.1 Step 4. (We don't need to
                // recover the prime factors since they are already given.)

                // 6.4.1.4.3 - Step 5.

                // Steps 5.a and 5.b are omitted, as explained above.

                // Step 5.c.
                //
                // TODO: First, stop if `p < (√2) * 2**((nBits/2) - 1)`.
                //
                // Second, stop if `p > 2**(nBits/2) - 1`.
                let half_n_bits = n_bits.half_rounded_up();
                if p_bits != half_n_bits {
                    return Err(error::Unspecified);
                }

                // TODO: Step 5.d: Verify GCD(p - 1, e) == 1.

                // Steps 5.e and 5.f are omitted as explained above.

                // Step 5.g.
                //
                // TODO: First, stop if `q < (√2) * 2**((nBits/2) - 1)`.
                //
                // Second, stop if `q > 2**(nBits/2) - 1`.
                if p_bits != q_bits {
                    return Err(error::Unspecified);
                }

                // TODO: Step 5.h: Verify GCD(p - 1, e) == 1.

                let oneRR_mod_n = bigint::One::newRR(&n);
                let q_mod_n_decoded = q.to_elem(&n)?;

                // TODO: Step 5.i
                //
                // 3.b is unneeded since `n_bits` is derived here from `n`.

                // 6.4.1.4.3 - Step 3.a (out of order).
                //
                // Verify that p * q == n. We restrict ourselves to modular
                // multiplication. We rely on the fact that we've verified
                // 0 < q < p < n. We check that q and p are close to sqrt(n)
                // and then assume that these preconditions are enough to
                // let us assume that checking p * q == 0 (mod n) is equivalent
                // to checking p * q == n.
                let q_mod_n = bigint::elem_mul(oneRR_mod_n.as_ref(),
                                               q_mod_n_decoded.clone(), &n);
                let p_mod_n = p.to_elem(&n)?;
                let pq_mod_n = bigint::elem_mul(&q_mod_n, p_mod_n, &n);
                if !pq_mod_n.is_zero() {
                    return Err(error::Unspecified);
                }

                // 6.4.1.4.3/6.4.1.2.1 - Step 6.

                // Step 6.a, partial.
                //
                // First, validate `2**half_n_bits < d`. Since 2**half_n_bits
                // has a bit length of half_n_bits + 1, this check gives us
                // 2**half_n_bits <= d, and knowing d is odd makes the
                // inequality strict.
                let (d, d_bits) =
                    bigint::Nonnegative::from_be_bytes_with_bit_length(d)?;
                if !(half_n_bits < d_bits) {
                    return Err(error::Unspecified);
                }
                // XXX: This check should be `d < LCM(p - 1, q - 1)`, but we
                // don't have a good way of calculating LCM, so it is omitted,
                // as explained above.
                d.verify_less_than_modulus(&n)?;
                if !d.is_odd() {
                    return Err(error::Unspecified);
                }

                // Step 6.b is omitted as explained above.

                // 6.4.1.4.3 - Step 7.

                // Step 7.a.
                let p = PrivatePrime::new(p, dP)?;

                // Step 7.b.
                let q = PrivatePrime::new(q, dQ)?;

                let q_mod_p = q.modulus.to_elem(&p.modulus);

                // Step 7.c.
                let qInv = if let Some(qInv) = qInv {
                    bigint::Elem::from_be_bytes_padded(qInv, &p.modulus)?
                } else {
                    // We swapped `p` and `q` above, so we need to calculate
                    // `qInv`.  Step 7.f below will verify `qInv` is correct.
                    let q_mod_p = bigint::elem_mul(p.oneRR.as_ref(),
                                                   q_mod_p.clone(),
                                                   &p.modulus);
                    bigint::elem_inverse_consttime(q_mod_p, &p.modulus, &p.oneR)?
                };

                // Steps 7.d and 7.e are omitted per the documentation above,
                // and because we don't (in the long term) have a good way to
                // do modulo with an even modulus.

                // Step 7.f.
                let qInv =
                    bigint::elem_mul(p.oneRR.as_ref(), qInv, &p.modulus);
                bigint::verify_inverses_consttime(&qInv, q_mod_p, &p.modulus)?;

                let qq = bigint::elem_mul(&q_mod_n, q_mod_n_decoded, &n)
                    .into_modulus::<QQ>()?;

                Ok(RSAKeyPair {
                    n,
                    e,
                    p,
                    q,
                    qInv,
                    oneRR_mod_n,
                    q_mod_n,
                    qq,
                    n_bits
                })
            })
        })
    }

    /// Returns the length in bytes of the key pair's public modulus.
    ///
    /// A signature has the same length as the public modulus.
    pub fn public_modulus_len(&self) -> usize {
        self.n_bits.as_usize_bytes_rounded_up()
    }
}

#[derive(Clone)]
struct PrivatePrime<M: Prime> {
    modulus: bigint::Modulus<M>,
    exponent: bigint::PrivateExponent<M>,
    oneR: bigint::One<M, R>,
    oneRR: bigint::One<M, RR>,
    oneRRR: bigint::One<M, RRR>,
}

impl<M: Prime + Clone> PrivatePrime<M> {
    /// Constructs a `PrivatePrime` from the private prime `p` and `dP` where
    /// dP == d % (p - 1).
    fn new(p: bigint::Nonnegative, dP: untrusted::Input)
           -> Result<Self, error::Unspecified> {
        let p = bigint::Modulus::from(p)?;

        // [NIST SP-800-56B rev. 1] 6.4.1.4.3 - Steps 7.a & 7.b.
        let dP = bigint::PrivateExponent::from_be_bytes_padded(dP, &p)?;

        // XXX: Steps 7.d and 7.e are omitted. We don't check that
        // `dP == d % (p - 1)` because we don't (in the long term) have a good
        // way to do modulo with an even modulus. Instead we just check that
        // `1 <= dP < p - 1`. We'll check it, to some unknown extent, when we
        // do the private key operation, since we verify that the result of the
        // private key operation using the CRT parameters is consistent with `n`
        // and `e`. TODO: Either prove that what we do is sufficient, or make
        // it so.

        let oneRR = bigint::One::newRR(&p);
        let oneR = bigint::One::newR(&oneRR, &p);
        let oneRRR = bigint::One::newRRR(oneRR.clone(), &p);

        Ok(PrivatePrime {
            modulus: p,
            exponent: dP,
            oneR: oneR,
            oneRR: oneRR,
            oneRRR: oneRRR,
        })
    }
}

fn elem_exp_consttime<M, MM>(c: &bigint::Elem<MM>, p: &PrivatePrime<M>)
                             -> Result<bigint::Elem<M>, error::Unspecified>
                             where M: bigint::NotMuchSmallerModulus<MM>,
                                   M: Prime {
    let c_mod_m = bigint::elem_reduced(c, &p.modulus)?;
    let c_mod_m = bigint::elem_mul(p.oneRRR.as_ref(), c_mod_m, &p.modulus);
    bigint::elem_exp_consttime(c_mod_m, &p.exponent, &p.oneR, &p.modulus)
}


// Type-level representations of the different moduli used in RSA signing, in
// addition to `super::N`. See `super::bigint`'s modulue-level documentation.

#[derive(Copy, Clone)]
enum P {}
unsafe impl Prime for P {}
unsafe impl bigint::SmallerModulus<N> for P {}
unsafe impl bigint::NotMuchSmallerModulus<N> for P {}

#[derive(Copy, Clone)]
enum QQ {}
unsafe impl bigint::SmallerModulus<N> for QQ {}
unsafe impl bigint::NotMuchSmallerModulus<N> for QQ {}

// `q < p < 2*q` since `q` is slightly smaller than `p` (see below). Thus:
//
//                         q <  p  < 2*q
//                       q*q < p*q < 2*q*q.
//                      q**2 <  n  < 2*(q**2).
unsafe impl bigint::SlightlySmallerModulus<N> for QQ {}

#[derive(Copy, Clone)]
enum Q {}
unsafe impl Prime for Q {}
unsafe impl bigint::SmallerModulus<N> for Q {}
unsafe impl bigint::SmallerModulus<P> for Q {}

// q < p && `p.bit_length() == q.bit_length()` implies `q < p < 2*q`.
unsafe impl bigint::SlightlySmallerModulus<P> for Q {}

unsafe impl bigint::SmallerModulus<QQ> for Q {}
unsafe impl bigint::NotMuchSmallerModulus<QQ> for Q {}


/// State used for RSA Signing. Feature: `rsa_signing`.
///
/// # Performance Considerations
///
/// Every time `sign` is called, some internal state is updated. Usually the
/// state update is relatively cheap, but the first time, and periodically, a
/// relatively expensive computation (computing the modular inverse of a random
/// number modulo the public key modulus, for blinding the RSA exponentiation)
/// will be done. Reusing the same `RSASigningState` when generating multiple
/// signatures improves the computational efficiency of signing by minimizing
/// the frequency of the expensive computations.
///
/// `RSASigningState` is not `Sync`; i.e. concurrent use of an `sign()` on the
/// same `RSASigningState` from multiple threads is not allowed. An
/// `RSASigningState` can be wrapped in a `Mutex` to be shared between threads;
/// this would maximize the computational efficiency (as explained above) and
/// minimizes memory usage, but it also minimizes concurrency because all the
/// calls to `sign()` would be serialized. To increases concurrency one could
/// create multiple `RSASigningState`s that share the same `RSAKeyPair`; the
/// number of `RSASigningState` in use at once determines the concurrency
/// factor. This increases memory usage, but only by a small amount, as each
/// `RSASigningState` is much smaller than the `RSAKeyPair` that they would
/// share. Using multiple `RSASigningState` per `RSAKeyPair` may also decrease
/// computational efficiency by increasing the frequency of the expensive
/// modular inversions; managing a pool of `RSASigningState`s in a
/// most-recently-used fashion would improve the computational efficiency.
pub struct RSASigningState {
    key_pair: std::sync::Arc<RSAKeyPair>,
    blinding: blinding::Blinding,
}

impl RSASigningState {
    /// Construct an `RSASigningState` for the given `RSAKeyPair`.
    pub fn new(key_pair: std::sync::Arc<RSAKeyPair>)
               -> Result<Self, error::Unspecified> {
        Ok(RSASigningState {
            key_pair: key_pair,
            blinding: blinding::Blinding::new(),
        })
    }

    /// The `RSAKeyPair`. This can be used, for example, to access the key
    /// pair's public key through the `RSASigningState`.
    pub fn key_pair(&self) -> &RSAKeyPair { self.key_pair.as_ref() }

    /// Sign `msg`. `msg` is digested using the digest algorithm from
    /// `padding_alg` and the digest is then padded using the padding algorithm
    /// from `padding_alg`. The signature it written into `signature`;
    /// `signature`'s length must be exactly the length returned by
    /// `public_modulus_len()`. `rng` is used for blinding the message during
    /// signing, to mitigate some side-channel (e.g. timing) attacks.
    ///
    /// Many other crypto libraries have signing functions that takes a
    /// precomputed digest as input, instead of the message to digest. This
    /// function does *not* take a precomputed digest; instead, `sign`
    /// calculates the digest itself.
    ///
    /// Lots of effort has been made to make the signing operations close to
    /// constant time to protect the private key from side channel attacks. On
    /// x86-64, this is done pretty well, but not perfectly. On other
    /// platforms, it is done less perfectly. To help mitigate the current
    /// imperfections, and for defense-in-depth, base blinding is always done.
    /// Exponent blinding is not done, but it may be done in the future.
    #[allow(non_shorthand_field_patterns)] // Work around compiler bug.
    pub fn sign(&mut self, padding_alg: &'static ::signature::RSAEncoding,
                rng: &rand::SecureRandom, msg: &[u8], signature: &mut [u8])
                -> Result<(), error::Unspecified> {
        let mod_bits = self.key_pair.n_bits;
        if signature.len() != mod_bits.as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        let RSASigningState { key_pair: key, blinding } = self;

        let m_hash = digest::digest(padding_alg.digest_alg(), msg);
        padding_alg.encode(&m_hash, signature, mod_bits, rng)?;

        // RFC 8017 Section 5.1.2: RSADP, using the Chinese Remainder Theorem
        // with Garner's algorithm.

        // Step 1. The value zero is also rejected.
        let base = bigint::Elem::from_be_bytes_padded(
            untrusted::Input::from(signature), &key.n)?;

        // Step 2.
        let result = blinding.blind(base, key.e, &key.oneRR_mod_n, &key.n, rng,
                                    |c| {
            // Step 2.b.i.
            let m_1 = elem_exp_consttime(&c, &key.p)?;
            let c_mod_qq = bigint::elem_reduced_once(&c, &key.qq);
            let m_2 = elem_exp_consttime(&c_mod_qq, &key.q)?;

            // Step 2.b.ii isn't needed since there are only two primes.

            // Step 2.b.iii.
            let p = &key.p.modulus;
            let m_2 = bigint::elem_widen(m_2, &p);
            let m_1_minus_m_2 = bigint::elem_sub(m_1, &m_2, p);
            let h = bigint::elem_mul(&key.qInv, m_1_minus_m_2, p);

            // Step 2.b.iv. The reduction in the modular multiplication isn't
            // necessary because `h < p` and `p * q == n` implies `h * q < n`.
            // Modular arithmetic is used simply to avoid implementing
            // non-modular arithmetic.
            let h = bigint::elem_widen(h, &key.n);
            let q_times_h = bigint::elem_mul(&key.q_mod_n, h, &key.n);
            let m_2 = bigint::elem_widen(m_2, &key.n);
            let m = bigint::elem_add(m_2, q_times_h, &key.n);

            // Step 2.b.v isn't needed since there are only two primes.

            // Verify the result to protect against fault attacks as described
            // in "On the Importance of Checking Cryptographic Protocols for
            // Faults" by Dan Boneh, Richard A. DeMillo, and Richard J. Lipton.
            // This check is cheap assuming `e` is small, which is ensured
            // during `RSAKeyPair` construction. Note that this is the only
            // validation of `e` that is done other than basic checks on its
            // size, oddness, and minimum value, since the relationship of `e`
            // to `d`, `p`, and `q` is not verified during `RSAKeyPair`
            // construction.
            let computed =
                bigint::elem_mul(&key.oneRR_mod_n.as_ref(), m.clone(), &key.n);
            let verify = bigint::elem_exp_vartime(computed, key.e, &key.n);
            let verify = verify.into_unencoded(&key.n);
            bigint::elem_verify_equal_consttime(&verify, &c)?;

            // Step 3.
            Ok(m)
        })?;

        result.fill_be_bytes(signature);

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    // We intentionally avoid `use super::*` so that we are sure to use only
    // the public API; this ensures that enough of the API is public.
    use core;
    use {rand, signature, test};
    use std;
    use super::super::blinding;
    use untrusted;

    // `RSAKeyPair::sign` requires that the output buffer is the same length as
    // the public key modulus. Test what happens when it isn't the same length.
    #[test]
    fn test_signature_rsa_pkcs1_sign_output_buffer_len() {
        // Sign the message "hello, world", using PKCS#1 v1.5 padding and the
        // SHA256 digest algorithm.
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        // The output buffer is one byte too short.
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len() - 1];

        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());

        // The output buffer is the right length.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_ok());


        // The output buffer is one byte too long.
        signature.push(0);
        assert!(signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng, MESSAGE,
                                   &mut signature).is_err());
    }

    // Once the `Blinding` in an `RSAKeyPair` has been used
    // `blinding::REMAINING_MAX` times, a new blinding should be created. we
    // don't check that a new blinding was created; we just make sure to
    // exercise the code path, so this is basically a coverage test.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_reuse() {
        const MESSAGE: &'static [u8] = b"hello, world";
        let rng = rand::SystemRandom::new();

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();
        let key_pair = std::sync::Arc::new(key_pair);
        let mut signature = vec![0; key_pair.public_modulus_len()];

        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();

        for _ in 0..(blinding::REMAINING_MAX + 1) {
            let prev_remaining = signing_state.blinding.remaining();
            let _ = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                       MESSAGE, &mut signature);
            let remaining = signing_state.blinding.remaining();
            assert_eq!((remaining + 1) % blinding::REMAINING_MAX,
            prev_remaining);
        }
    }

    // When we fail to randomly generate an invertible blinding factor too many
    // times in a loop, we fail. This checks that we fail in a reasonable way
    // when that happens.
    #[test]
    fn test_signature_rsa_pkcs1_sign_blinding_creation_failure() {
        const MESSAGE: &'static [u8] = b"hello, world";

        const PRIVATE_KEY_DER: &'static [u8] =
            include_bytes!("signature_rsa_example_private_key.der");
        let key_bytes_der = untrusted::Input::from(PRIVATE_KEY_DER);
        let key_pair = signature::RSAKeyPair::from_der(key_bytes_der).unwrap();

        // The inversion itself is blinded. This blinding factor must be
        // non-zero.
        let mut inverse_blinding_factor =
            vec![0u8; key_pair.public_modulus_len()];
        inverse_blinding_factor[0] = 1;

        let zero = vec![0u8; key_pair.public_modulus_len()];

        let mut bytes = std::vec::Vec::new();
        bytes.push(&inverse_blinding_factor[..]);
        for _ in 0..100 {
            bytes.push(&zero[..]);
        }

        let rng = test::rand::FixedSliceSequenceRandom {
            bytes: &bytes[..],
            current: core::cell::UnsafeCell::new(0),
        };

        let key_pair = std::sync::Arc::new(key_pair);
        let mut signing_state =
            signature::RSASigningState::new(key_pair).unwrap();
        let mut signature =
            vec![0; signing_state.key_pair().public_modulus_len()];
        let result = signing_state.sign(&signature::RSA_PKCS1_SHA256, &rng,
                                        MESSAGE, &mut signature);

        assert!(result.is_err());
    }
}
