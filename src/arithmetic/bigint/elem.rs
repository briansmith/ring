// Copyright 2015-2012 Brian Smith.
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

use super::{
    super::montgomery::{ReductionEncoding, R},
    limbs_mont_mul, BoxedLimbs, Limb, LimbMask, Modulus, Unencoded, Width, MODULUS_MAX_LIMBS,
};
use crate::{error, limb};
use core::marker::PhantomData;

/// Elements of ℤ/mℤ for some modulus *m*.
//
// Defaulting `E` to `Unencoded` is a convenience for callers from outside this
// submodule. However, for maximum clarity, we always explicitly use
// `Unencoded` within the `bigint` submodule.
pub(crate) struct Elem<M, E = Unencoded> {
    limbs: BoxedLimbs<M>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    encoding: PhantomData<E>,
}

// TODO: `derive(Clone)` after https://github.com/rust-lang/rust/issues/26925
// is resolved or restrict `M: Clone` and `E: Clone`.
impl<M, E> Clone for Elem<M, E> {
    fn clone(&self) -> Self {
        Self {
            limbs: self.limbs.clone(),
            encoding: self.encoding,
        }
    }
}

impl<M, E> Elem<M, E> {
    pub(super) fn new_unchecked(limbs: BoxedLimbs<M>) -> Self {
        Self {
            limbs,
            encoding: PhantomData,
        }
    }

    pub(super) fn zero(width: Width<M>) -> Self {
        Self {
            limbs: BoxedLimbs::zero(width),
            encoding: PhantomData,
        }
    }

    #[inline(always)]
    pub(super) fn limbs(&self) -> &BoxedLimbs<M> {
        &self.limbs
    }

    #[inline(always)]
    pub(super) fn limbs_mut(&mut self) -> &mut [Limb] {
        &mut self.limbs
    }

    #[inline(always)]
    pub(super) fn into_limbs(self) -> BoxedLimbs<M> {
        self.limbs
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs().is_zero()
    }
}

impl<M, E: ReductionEncoding> Elem<M, E> {
    fn decode_once(self, m: &Modulus<M>) -> Elem<M, <E as ReductionEncoding>::Output> {
        // A multiplication isn't required since we're multiplying by the
        // unencoded value one (1); only a Montgomery reduction is needed.
        // However the only non-multiplication Montgomery reduction function we
        // have requires the input to be large, so we avoid using it here.
        let mut limbs = self.into_limbs();
        let num_limbs = m.width().num_limbs;
        let mut one = [0; MODULUS_MAX_LIMBS];
        one[0] = 1;
        let one = &one[..num_limbs]; // assert!(num_limbs <= MODULUS_MAX_LIMBS);
        limbs_mont_mul(&mut limbs, one, m.limbs(), m.n0(), m.cpu_features());
        Elem::new_unchecked(limbs)
    }
}

impl<M> Elem<M, R> {
    #[inline]
    pub fn into_unencoded(self, m: &Modulus<M>) -> Elem<M, Unencoded> {
        self.decode_once(m)
    }
}

impl<M> Elem<M, Unencoded> {
    pub(crate) fn from_be_bytes_padded(
        input: untrusted::Input,
        m: &Modulus<M>,
    ) -> Result<Self, error::Unspecified> {
        Ok(Self {
            limbs: BoxedLimbs::from_be_bytes_padded_less_than(input, m)?,
            encoding: PhantomData,
        })
    }

    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        // See Falko Strenzke, "Manger's Attack revisited", ICICS 2010.
        limb::big_endian_from_limbs(self.limbs(), out)
    }

    pub(super) fn is_one(&self) -> bool {
        limb::limbs_equal_limb_constant_time(self.limbs(), 1) == LimbMask::True
    }
}
