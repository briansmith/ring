// Copyright 2015-2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    super::{N, PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN, PublicKeyComponents},
    PublicExponent, PublicModulus, public_modulus,
};
use crate::{
    arithmetic::{bigint, montgomery::RR},
    bits, cpu, error,
    limb::LIMB_BYTES,
};
use core::num::NonZero;

/// An RSA Public Key.
#[derive(Clone)]
pub(crate) struct PublicKey<S> {
    n: PublicModulus<S>,
    e: PublicExponent,
}

pub struct ValidatedInput<'a> {
    n: public_modulus::ValidatedInput<'a>,
    e: PublicExponent,
    e_input: untrusted::Input<'a>,
}

impl<'a> ValidatedInput<'a> {
    pub(in super::super) fn try_from_be_bytes(
        components: PublicKeyComponents<&'a [u8]>,
        n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength,
        e_min_value: PublicExponent,
    ) -> Result<Self, error::KeyRejected> {
        // This is an incomplete implementation of NIST SP800-56Br1 Section
        // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers
        // to NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key
        // Validation for RSA," "with the caveat that the length of the modulus
        // shall be a length that is specified in this Recommendation." In
        // SP800-89, two different sets of steps are given, one set numbered,
        // and one set lettered. TODO: Document this in the end-user
        // documentation for RSA keys.

        // If `n` is less than `e` then somebody has probably accidentally swapped
        // them. The largest acceptable `e` is smaller than the smallest acceptable
        // `n`, so no additional checks need to be done.

        // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
        // case in most other commonly-used crypto libraries.

        let n =
            public_modulus::ValidatedInput::from_be_bytes(components.n, n_min_bits..=n_max_bits)?;
        let e_input = components.e.into();
        let e = PublicExponent::from_be_bytes(e_input, e_min_value)?;
        Ok(Self { n, e, e_input })
    }

    pub fn n(&self) -> &public_modulus::ValidatedInput<'_> {
        &self.n
    }

    pub(in super::super) fn e_input(&self) -> untrusted::Input<'_> {
        self.e_input
    }

    pub(in super::super) fn build_boxed(
        &self,
        cpu: cpu::Features,
    ) -> PublicKey<bigint::BoxedIntoMont<N, RR>> {
        PublicKey {
            n: self.n.build_boxed_into_mont(cpu),
            e: self.e,
        }
    }

    pub(in super::super) fn build<'o>(
        &self,
        out: &'o mut bigint::OversizedUninit<2>,
        cpu: cpu::Features,
    ) -> PublicKey<bigint::IntoMont<'o, N, RR>> {
        PublicKey {
            n: self.n.build(out, cpu),
            e: self.e,
        }
    }
}

impl PublicKey<bigint::BoxedIntoMont<N, RR>> {
    pub fn reborrow(&self) -> PublicKey<bigint::IntoMont<'_, N, RR>> {
        PublicKey {
            n: self.n.reborrow(),
            e: self.e,
        }
    }
}

impl PublicKey<bigint::IntoMont<'_, N, RR>> {
    /// The public modulus.
    #[inline]
    pub(in super::super) fn n(&self) -> &PublicModulus<bigint::IntoMont<'_, N, RR>> {
        &self.n
    }

    /// The public exponent.
    #[inline]
    pub(in super::super) fn e(&self) -> PublicExponent {
        self.e
    }

    /// Calculates base**e (mod n), filling the first part of `out_buffer` with
    /// the result.
    ///
    /// This is constant-time with respect to the value in `base` (only).
    ///
    /// The result will be a slice of the encoded bytes of the result within
    /// `out_buffer`, if successful.
    pub(in super::super) fn exponentiate<'out>(
        &self,
        base: untrusted::Input,
        out_buffer: &'out mut [u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN],
        cpu_features: cpu::Features,
    ) -> Result<&'out [u8], error::Unspecified> {
        let n = &self.n.value();
        let n = &n.modulus(cpu_features);

        // The encoded value of the base must be the same length as the modulus,
        // in bytes.
        if base.len() != self.n.len_bits().as_usize_bytes_rounded_up() {
            return Err(error::Unspecified);
        }

        // RFC 8017 Section 5.2.2: RSAVP1.

        // Step 1.
        let s = n.alloc_uninit().into_elem_from_be_bytes_padded(base, n)?;
        if s.is_zero() {
            return Err(error::Unspecified);
        }

        // Step 2.
        let m = n.alloc_uninit();
        let m = self.exponentiate_elem(m, &s, cpu_features);

        // Step 3.
        Ok(fill_be_bytes_n(m, self.n.len_bits(), out_buffer))
    }

    /// Calculates base**e (mod n).
    ///
    /// This is constant-time with respect to `base` only.
    pub(in super::super) fn exponentiate_elem(
        &self,
        out: bigint::Uninit<N>,
        base: &bigint::Elem<N>,
        cpu_features: cpu::Features,
    ) -> bigint::Elem<N> {
        // The exponent was already checked to be at least 3.
        let exponent_without_low_bit = NonZero::<u64>::try_from(self.e.value().get() & !1).unwrap();
        // The exponent was already checked to be odd.
        debug_assert_ne!(exponent_without_low_bit, self.e.value());

        let n = &self.n.value();
        let nm = &n.modulus(cpu_features);

        let tmp = nm.alloc_uninit();
        let base_r = base.clone_into(tmp).encode_mont(n, cpu_features);

        // During RSA public key operations the exponent is almost always either
        // 65537 (0b10000000000000001) or 3 (0b11), both of which have a Hamming
        // weight of 2. The maximum bit length and maximum Hamming weight of the
        // exponent is bounded by the value of `PublicExponent::MAX`.
        let acc = bigint::elem_exp_vartime(out, base_r, exponent_without_low_bit, nm);

        // Now do the multiplication for the low bit and convert out of the Montgomery domain.
        acc.mul(base, nm)
    }
}

/// Returns the big-endian representation of `elem` that is
/// the same length as the minimal-length big-endian representation of
/// the modulus `n`.
///
/// `n_bits` must be the bit length of the public modulus `n`.
fn fill_be_bytes_n(
    elem: bigint::Elem<N>,
    n_bits: bits::BitLength,
    out: &mut [u8; PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN],
) -> &[u8] {
    let n_bytes = n_bits.as_usize_bytes_rounded_up();
    let n_bytes_padded = n_bytes.next_multiple_of(LIMB_BYTES);
    let out = &mut out[..n_bytes_padded];
    elem.fill_be_bytes(out);
    let (padding, out) = out.split_at(n_bytes_padded - n_bytes);
    assert!(padding.iter().all(|&b| b == 0));
    out
}
