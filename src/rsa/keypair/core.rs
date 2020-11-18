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

//! RSA key pairs.

use super::{
    super::{public, N},
    Components,
};
use crate::{
    arithmetic::{
        bigint::{self, Prime},
        montgomery::R,
    },
    bits,
    error::{self, KeyRejected},
};
use core::convert::TryFrom;

// Keep in sync with the documentation comment for `KeyPair`.
const PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS: bits::BitLength = bits::BitLength::from_usize_bits(4096);

/// An RSA key pair.
pub struct RsaKeyPair {
    p: PrivatePrime<P>,
    q: PrivatePrime<Q>,
    qInv: bigint::Elem<P, R>,
    qq: bigint::Modulus<QQ>,
    q_mod_n: bigint::Elem<N, R>,
    public: public::Key,
}

derive_debug_via_field!(RsaKeyPair, stringify!(RsaKeyPair), public);

impl RsaKeyPair {
    fn try_from_(
        &Components {
            public_key,
            d,
            p,
            q,
            dP,
            dQ,
            qInv,
        }: &Components<&[u8]>,
    ) -> Result<Self, KeyRejected> {
        let d = untrusted::Input::from(d);
        let p = untrusted::Input::from(p);
        let q = untrusted::Input::from(q);
        let dP = untrusted::Input::from(dP);
        let dQ = untrusted::Input::from(dQ);
        let qInv = untrusted::Input::from(qInv);

        let (p, p_bits) = bigint::Nonnegative::from_be_bytes_with_bit_length(p)
            .map_err(|error::Unspecified| KeyRejected::invalid_encoding())?;
        let (q, q_bits) = bigint::Nonnegative::from_be_bytes_with_bit_length(q)
            .map_err(|error::Unspecified| KeyRejected::invalid_encoding())?;

        // Our implementation of CRT-based modular exponentiation used requires
        // that `p > q` so swap them if `p < q`. If swapped, `qInv` is
        // recalculated below. `p != q` is verified implicitly below, e.g. when
        // `q_mod_p` is constructed.
        let ((p, p_bits, dP), (q, q_bits, dQ, qInv)) = match q.verify_less_than(&p) {
            Ok(_) => ((p, p_bits, dP), (q, q_bits, dQ, Some(qInv))),
            Err(error::Unspecified) => {
                // TODO: verify `q` and `qInv` are inverses (mod p).
                ((q, q_bits, dQ), (p, p_bits, dP, None))
            }
        };

        // XXX: Some steps are done out of order, but the NIST steps are worded
        // in such a way that it is clear that NIST intends for them to be done
        // in order. TODO: Does this matter at all?

        // 6.4.1.4.3/6.4.1.2.1 - Step 1.

        // Step 1.a is omitted, as explained above.

        // Step 1.b is omitted per above. Instead, we check that the public
        // modulus is 2048 to `PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS` bits.
        // XXX: The maximum limit of 4096 bits is primarily due to lack of
        // testing of larger key sizes; see, in particular,
        // https://www.mail-archive.com/openssl-dev@openssl.org/msg44586.html
        // and
        // https://www.mail-archive.com/openssl-dev@openssl.org/msg44759.html.
        // Also, this limit might help with memory management decisions later.

        // Step 1.c. We validate e >= 65537.
        let public_key =
            public::Key::from_modulus_and_exponent(public_key.n, public_key.e, &KeyPairBounds)?;

        // 6.4.1.4.3 says to skip 6.4.1.2.1 Step 2.

        // 6.4.1.4.3 Step 3.

        // Step 3.a is done below, out of order.
        // Step 3.b is unneeded since `n_bits` is derived here from `n`.

        // 6.4.1.4.3 says to skip 6.4.1.2.1 Step 4. (We don't need to recover
        // the prime factors since they are already given.)

        // 6.4.1.4.3 - Step 5.

        // Steps 5.a and 5.b are omitted, as explained above.

        // Step 5.c.
        //
        // TODO: First, stop if `p < (√2) * 2**((nBits/2) - 1)`.
        //
        // Second, stop if `p > 2**(nBits/2) - 1`.
        let half_n_bits = public_key.n().len_bits().half_rounded_up();
        if p_bits != half_n_bits {
            return Err(KeyRejected::inconsistent_components());
        }

        // TODO: Step 5.d: Verify GCD(p - 1, e) == 1.

        // Steps 5.e and 5.f are omitted as explained above.

        // Step 5.g.
        //
        // TODO: First, stop if `q < (√2) * 2**((nBits/2) - 1)`.
        //
        // Second, stop if `q > 2**(nBits/2) - 1`.
        if p_bits != q_bits {
            return Err(KeyRejected::inconsistent_components());
        }

        // TODO: Step 5.h: Verify GCD(p - 1, e) == 1.

        let n = &public_key.n().value;

        let q_mod_n_decoded = q
            .to_elem(n)
            .map_err(|error::Unspecified| KeyRejected::inconsistent_components())?;

        // TODO: Step 5.i
        //
        // 3.b is unneeded since `n_bits` is derived here from `n`.

        // 6.4.1.4.3 - Step 3.a (out of order).
        //
        // Verify that p * q == n. We restrict ourselves to modular
        // multiplication. We rely on the fact that we've verified
        // 0 < q < p < n. We check that q and p are close to sqrt(n) and then
        // assume that these preconditions are enough to let us assume that
        // checking p * q == 0 (mod n) is equivalent to checking p * q == n.
        let q_mod_n = bigint::elem_mul(n.oneRR().as_ref(), q_mod_n_decoded.clone(), n);
        let p_mod_n = p
            .to_elem(n)
            .map_err(|error::Unspecified| KeyRejected::inconsistent_components())?;
        let pq_mod_n = bigint::elem_mul(&q_mod_n, p_mod_n, n);
        if !pq_mod_n.is_zero() {
            return Err(KeyRejected::inconsistent_components());
        }

        // 6.4.1.4.3/6.4.1.2.1 - Step 6.

        // Step 6.a, partial.
        //
        // First, validate `2**half_n_bits < d`. Since 2**half_n_bits has a bit
        // length of half_n_bits + 1, this check gives us 2**half_n_bits <= d,
        // and knowing d is odd makes the inequality strict.
        let (d, d_bits) = bigint::Nonnegative::from_be_bytes_with_bit_length(d)
            .map_err(|_| error::KeyRejected::invalid_encoding())?;
        if !(half_n_bits < d_bits) {
            return Err(KeyRejected::inconsistent_components());
        }
        // XXX: This check should be `d < LCM(p - 1, q - 1)`, but we don't have
        // a good way of calculating LCM, so it is omitted, as explained above.
        d.verify_less_than_modulus(n)
            .map_err(|error::Unspecified| KeyRejected::inconsistent_components())?;
        if !d.is_odd() {
            return Err(KeyRejected::invalid_component());
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
            bigint::Elem::from_be_bytes_padded(qInv, &p.modulus)
                .map_err(|error::Unspecified| KeyRejected::invalid_component())?
        } else {
            // We swapped `p` and `q` above, so we need to calculate `qInv`.
            // Step 7.f below will verify `qInv` is correct.
            let q_mod_p = bigint::elem_mul(p.modulus.oneRR().as_ref(), q_mod_p.clone(), &p.modulus);
            bigint::elem_inverse_consttime(q_mod_p, &p.modulus)
                .map_err(|error::Unspecified| KeyRejected::unexpected_error())?
        };

        // Steps 7.d and 7.e are omitted per the documentation above, and
        // because we don't (in the long term) have a good way to do modulo
        // with an even modulus.

        // Step 7.f.
        let qInv = bigint::elem_mul(p.modulus.oneRR().as_ref(), qInv, &p.modulus);
        bigint::verify_inverses_consttime(&qInv, q_mod_p, &p.modulus)
            .map_err(|error::Unspecified| KeyRejected::inconsistent_components())?;

        let qq = bigint::elem_mul(&q_mod_n, q_mod_n_decoded, n).into_modulus::<QQ>()?;

        Ok(Self {
            p,
            q,
            qInv,
            q_mod_n,
            qq,
            public: public_key,
        })
    }

    /// Returns a reference to the public key.
    pub fn public(&self) -> &public::Key {
        &self.public
    }
}

// TODO:
struct KeyPairBounds;

impl crate::sealed::Sealed for KeyPairBounds {}

impl super::super::Bounds for KeyPairBounds {
    fn n_min_bits(&self) -> bits::BitLength {
        bits::BitLength::from_usize_bits(2048)
    }

    fn n_max_bits(&self) -> bits::BitLength {
        PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS
    }

    fn e_min_value(&self) -> u64 {
        65537
    }
}

impl<Public, Private> TryFrom<&Components<Public, Private>> for RsaKeyPair
where
    Public: AsRef<[u8]> + core::fmt::Debug,
    Private: AsRef<[u8]>,
{
    type Error = KeyRejected;

    fn try_from(
        Components {
            public_key,
            d,
            p,
            q,
            dP,
            dQ,
            qInv,
        }: &Components<Public, Private>,
    ) -> Result<Self, Self::Error> {
        let components = Components {
            public_key: public::Components {
                n: public_key.n.as_ref(),
                e: public_key.e.as_ref(),
            },
            d: d.as_ref(),
            p: p.as_ref(),
            q: q.as_ref(),
            dP: dP.as_ref(),
            dQ: dQ.as_ref(),
            qInv: qInv.as_ref(),
        };
        Self::try_from_(&components)
    }
}

struct PrivatePrime<M: Prime> {
    modulus: bigint::Modulus<M>,
    exponent: bigint::PrivateExponent<M>,
}

impl<M: Prime + Clone> PrivatePrime<M> {
    /// Constructs a `PrivatePrime` from the private prime `p` and `dP` where
    /// dP == d % (p - 1).
    fn new(p: bigint::Nonnegative, dP: untrusted::Input) -> Result<Self, KeyRejected> {
        let (p, p_bits) = bigint::Modulus::from_nonnegative_with_bit_length(p)?;
        if p_bits.as_usize_bits() % 512 != 0 {
            return Err(error::KeyRejected::private_modulus_len_not_multiple_of_512_bits());
        }

        // [NIST SP-800-56B rev. 1] 6.4.1.4.3 - Steps 7.a & 7.b.
        let dP = bigint::PrivateExponent::from_be_bytes_padded(dP, &p)
            .map_err(|error::Unspecified| KeyRejected::inconsistent_components())?;

        // XXX: Steps 7.d and 7.e are omitted. We don't check that
        // `dP == d % (p - 1)` because we don't (in the long term) have a good
        // way to do modulo with an even modulus. Instead we just check that
        // `1 <= dP < p - 1`. We'll check it, to some unknown extent, when we
        // do the private key operation, since we verify that the result of the
        // private key operation using the CRT parameters is consistent with `n`
        // and `e`. TODO: Either prove that what we do is sufficient, or make
        // it so.

        Ok(PrivatePrime {
            modulus: p,
            exponent: dP,
        })
    }
}

fn elem_exp_consttime<M, MM>(
    c: &bigint::Elem<MM>,
    p: &PrivatePrime<M>,
) -> Result<bigint::Elem<M>, error::Unspecified>
where
    M: bigint::NotMuchSmallerModulus<MM>,
    M: Prime,
{
    let c_mod_m = bigint::elem_reduced(c, &p.modulus);
    // We could precompute `oneRRR = elem_squared(&p.oneRR`) as mentioned
    // in the Smooth CRT-RSA paper.
    let c_mod_m = bigint::elem_mul(p.modulus.oneRR().as_ref(), c_mod_m, &p.modulus);
    let c_mod_m = bigint::elem_mul(p.modulus.oneRR().as_ref(), c_mod_m, &p.modulus);
    bigint::elem_exp_consttime(c_mod_m, &p.exponent, &p.modulus)
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

impl RsaKeyPair {
    pub(super) fn rsa_private_in_place(&self, in_out: &mut [u8]) -> Result<(), error::Unspecified> {
        if in_out.len() != self.public.n().len_bits().as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        // RFC 8017 Section 5.1.2: RSADP, using the Chinese Remainder Theorem
        // with Garner's algorithm.

        let n = &self.public.n().value;

        // Step 1. The value zero is also rejected.
        let base = bigint::Elem::from_be_bytes_padded(untrusted::Input::from(in_out), n)?;

        // Step 2
        let c = base;

        // Step 2.b.i.
        let m_1 = elem_exp_consttime(&c, &self.p)?;
        let c_mod_qq = bigint::elem_reduced_once(&c, &self.qq);
        let m_2 = elem_exp_consttime(&c_mod_qq, &self.q)?;

        // Step 2.b.ii isn't needed since there are only two primes.

        // Step 2.b.iii.
        let p = &self.p.modulus;
        let m_2 = bigint::elem_widen(m_2, p);
        let m_1_minus_m_2 = bigint::elem_sub(m_1, &m_2, p);
        let h = bigint::elem_mul(&self.qInv, m_1_minus_m_2, p);

        // Step 2.b.iv. The reduction in the modular multiplication isn't
        // necessary because `h < p` and `p * q == n` implies `h * q < n`.
        // Modular arithmetic is used simply to avoid implementing
        // non-modular arithmetic.
        let h = bigint::elem_widen(h, n);
        let q_times_h = bigint::elem_mul(&self.q_mod_n, h, n);
        let m_2 = bigint::elem_widen(m_2, n);
        let m = bigint::elem_add(m_2, q_times_h, n);

        // Step 2.b.v isn't needed since there are only two primes.

        // Verify the result to protect against fault attacks as described
        // in "On the Importance of Checking Cryptographic Protocols for
        // Faults" by Dan Boneh, Richard A. DeMillo, and Richard J. Lipton.
        // This check is cheap assuming `e` is small, which is ensured during
        // `KeyPair` construction. Note that this is the only validation of `e`
        // that is done other than basic checks on its size, oddness, and
        // minimum value, since the relationship of `e` to `d`, `p`, and `q` is
        // not verified during `KeyPair` construction.
        {
            let verify = bigint::elem_exp_vartime(m.clone(), self.public.e().0, n);
            let verify = verify.into_unencoded(n);
            bigint::elem_verify_equal_consttime(&verify, &c)?;
        }

        // Step 3.
        //
        // See Falko Strenzke, "Manger's Attack revisited", ICICS 2010.
        m.fill_be_bytes(in_out);

        Ok(())
    }

    pub(super) fn rsa_private<R>(
        &self,
        input: &[u8],
        f: impl FnOnce(&mut [u8]) -> Result<R, error::Unspecified>,
    ) -> Result<R, error::Unspecified> {
        let mut buffer = [0u8; PRIVATE_KEY_PUBLIC_MODULUS_MAX_BITS.as_usize_bytes_rounded_up()];
        let buffer = buffer.get_mut(..input.len()).ok_or(error::Unspecified)?;
        buffer.copy_from_slice(input);
        self.rsa_private_in_place(buffer)?;
        f(buffer)
    }
}
