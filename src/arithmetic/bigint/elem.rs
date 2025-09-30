// Copyright 2015-2023 Brian Smith.
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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    super::{montgomery::*, MAX_LIMBS},
    boxed_limbs::BoxedLimbs,
    unwrap_impossible_len_mismatch_error, unwrap_impossible_limb_slice_error, IntoMont, Mont,
    Uninit,
};
use crate::{
    bits::BitLength,
    c, cpu,
    error::{self, LenMismatchError},
    limb::{self, Limb},
    polyfill::{
        slice::{AliasingSlices, InOut},
        StartMutPtr,
    },
};
use core::{marker::PhantomData, num::NonZeroUsize};

/// Elements of ℤ/mℤ for some modulus *m*.
//
// Defaulting `E` to `Unencoded` is a convenience for callers from outside this
// submodule. However, for maximum clarity, we always explicitly use
// `Unencoded` within the `bigint` submodule.
pub struct Elem<M, E = Unencoded> {
    limbs: BoxedLimbs<M>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    encoding: PhantomData<E>,
}

impl<M, E> Elem<M, E> {
    #[inline]
    pub(super) fn assume_in_range_and_encoded_less_safe(limbs: BoxedLimbs<M>) -> Self {
        Self {
            limbs,
            encoding: PhantomData,
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    pub(super) fn transmute_encoding_less_safe<RE>(self) -> Elem<M, RE> {
        Elem {
            limbs: self.limbs,
            encoding: PhantomData,
        }
    }

    #[allow(dead_code)]
    pub(super) fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    pub(super) fn leak_limbs_less_safe(&self) -> &[Limb] {
        self.limbs.as_ref()
    }

    #[allow(dead_code)]
    pub(super) fn leak_limbs_mut_less_safe(&mut self) -> &mut [Limb] {
        self.limbs.as_mut()
    }

    pub(super) fn leak_limbs_into_box_less_safe(self) -> BoxedLimbs<M> {
        self.limbs
    }

    pub fn clone_into(&self, out: Uninit<M>) -> Self {
        let limbs = out
            .write_copy_of_slice_checked(self.limbs.as_ref())
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        Self::assume_in_range_and_encoded_less_safe(limbs)
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        limb::limbs_are_zero(self.limbs.as_ref()).leak()
    }
}

/// Does a Montgomery reduction on `limbs` assuming they are Montgomery-encoded ('R') and assuming
/// they are the same size as `m`, but perhaps not reduced mod `m`. The result will be
/// fully reduced mod `m`.
///
/// WARNING: Takes a `Storage` as an in/out value.
pub(super) fn from_montgomery_amm<M>(mut in_out: BoxedLimbs<M>, m: &Mont<M>) -> Elem<M, Unencoded> {
    let mut one = [0; MAX_LIMBS];
    one[0] = 1;
    let one = &one[..m.limbs().len()];
    let _: &[Limb] = limbs_mul_mont(
        (InOut(in_out.as_mut()), one),
        m.limbs(),
        m.n0(),
        m.cpu_features(),
    )
    .unwrap_or_else(unwrap_impossible_limb_slice_error);
    Elem::assume_in_range_and_encoded_less_safe(in_out)
}

#[cfg(any(test, not(target_arch = "x86_64")))]
impl<M> Elem<M, R> {
    #[inline]
    pub fn into_unencoded(self, m: &Mont<M>) -> Elem<M, Unencoded> {
        from_montgomery_amm(self.limbs, m)
    }
}

impl<M> Elem<M, Unencoded> {
    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        // See Falko Strenzke, "Manger's Attack revisited", ICICS 2010.
        limb::big_endian_from_limbs(self.limbs.as_ref(), out)
    }
}

impl<M, E> Elem<M, E> {
    pub(crate) fn encode_mont<OE>(
        self,
        im: &IntoMont<M, OE>,
        cpu: cpu::Features,
    ) -> Elem<M, <(E, OE) as ProductEncoding>::Output>
    where
        (E, OE): ProductEncoding,
    {
        let oneRR = im.one();
        let m = im.modulus(cpu);

        let mut in_out = self.limbs;
        let _: &[Limb] = limbs_mul_mont(
            (InOut(in_out.as_mut()), oneRR.leak_limbs_less_safe()),
            m.limbs(),
            m.n0(),
            m.cpu_features(),
        )
        .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Elem::assume_in_range_and_encoded_less_safe(in_out)
    }
}

impl<M, E> Elem<M, E> {
    pub fn mul<BE>(
        self,
        b: &Elem<M, BE>,
        m: &Mont<M>,
    ) -> Elem<M, <(E, BE) as ProductEncoding>::Output>
    where
        (E, BE): ProductEncoding,
    {
        let mut in_out = self.limbs;
        let _: &[Limb] = limbs_mul_mont(
            (InOut(in_out.as_mut()), b.limbs.as_ref()),
            m.limbs(),
            m.n0(),
            m.cpu_features(),
        )
        .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Elem::assume_in_range_and_encoded_less_safe(in_out)
    }

    #[inline]
    pub fn square(self, m: &Mont<M>) -> Elem<M, <(E, E) as ProductEncoding>::Output>
    where
        (E, E): ProductEncoding,
    {
        let mut in_out = self.limbs;
        let _: &[Limb] = limbs_square_mont(in_out.as_mut(), m.limbs(), m.n0(), m.cpu_features())
            .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Elem::assume_in_range_and_encoded_less_safe(in_out)
    }
}

impl<M> Uninit<M> {
    pub fn elem_reduced_once<Larger>(
        self,
        a: &Elem<Larger>,
        m: &Mont<M>,
        other_modulus_len_bits: BitLength,
    ) -> Elem<M, Unencoded> {
        assert_eq!(m.len_bits(), other_modulus_len_bits);
        // TODO: We should add a variant of `limbs_reduced_once` that does the
        // reduction out-of-place, to eliminate this copy.
        let mut r = self
            .write_copy_of_slice_checked(a.limbs.as_ref())
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        limb::limbs_reduce_once(r.as_mut(), m.limbs())
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        Elem::<M, Unencoded>::assume_in_range_and_encoded_less_safe(r)
    }

    #[inline]
    pub fn elem_reduce_mont<Larger>(
        self,
        a: &Elem<Larger, Unencoded>,
        m: &Mont<M>,
        other_prime_len_bits: BitLength,
    ) -> Elem<M, RInverse> {
        // This is stricter than required mathematically but this is what we
        // guarantee and this is easier to check. The real requirement is that
        // that `a < m*R` where `R` is the Montgomery `R` for `m`.
        assert_eq!(other_prime_len_bits, m.len_bits());

        // `limbs_from_mont_in_place` requires this.
        assert_eq!(a.limbs.len(), m.limbs().len() * 2);

        let mut tmp = [0; MAX_LIMBS];
        let tmp = &mut tmp[..a.limbs.len()];
        tmp.copy_from_slice(a.limbs.as_ref());

        self.write_fully_with(|out| limbs_from_mont_in_place(out, tmp, m.limbs(), m.n0()))
            .map(Elem::<M, RInverse>::assume_in_range_and_encoded_less_safe)
            .unwrap_or_else(unwrap_impossible_len_mismatch_error)
    }
}

pub fn elem_widen<Larger, Smaller>(
    r: Uninit<Larger>,
    a: Elem<Smaller, Unencoded>,
    m: &Mont<Larger>,
    smaller_modulus_bits: BitLength,
) -> Result<Elem<Larger, Unencoded>, error::Unspecified> {
    if smaller_modulus_bits >= m.len_bits() {
        return Err(error::Unspecified);
    }
    let r = r
        .write_copy_of_slice_padded(a.limbs.as_ref())
        .map_err(error::erase::<LenMismatchError>)?;
    Ok(Elem::assume_in_range_and_encoded_less_safe(r))
}

// TODO: Document why this works for all Montgomery factors.
pub fn elem_add<M, E>(mut a: Elem<M, E>, b: Elem<M, E>, m: &Mont<M>) -> Elem<M, E> {
    limb::limbs_add_assign_mod(a.limbs.as_mut(), b.limbs.as_ref(), m.limbs())
        .unwrap_or_else(unwrap_impossible_len_mismatch_error);
    a
}

// TODO: Document why this works for all Montgomery factors.
pub fn elem_sub<M, E>(mut a: Elem<M, E>, b: &Elem<M, E>, m: &Mont<M>) -> Elem<M, E> {
    prefixed_extern! {
        // `r` and `a` may alias.
        fn LIMBS_sub_mod(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            m: *const Limb,
            num_limbs: c::NonZero_size_t,
        );
    }
    let num_limbs = NonZeroUsize::new(m.limbs().len()).unwrap();
    let _: &[Limb] = (InOut(a.limbs.as_mut()), b.limbs.as_ref())
        .with_non_dangling_non_null_pointers(num_limbs, |mut r, [a, b]| {
            let m = m.limbs().as_ptr(); // Also non-dangling because num_limbs is non-zero.
            unsafe {
                LIMBS_sub_mod(r.start_mut_ptr(), a, b, m, num_limbs);
                r.deref_unchecked().assume_init()
            }
        })
        .unwrap_or_else(unwrap_impossible_len_mismatch_error);
    a
}

/// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
pub fn verify_inverses_consttime<M>(
    a: &Elem<M, R>,
    b: Elem<M, Unencoded>,
    m: &Mont<M>,
) -> Result<(), error::Unspecified> {
    let r = b.mul(a, m);
    limb::verify_limbs_equal_1_leak_bit(r.limbs.as_ref())
}

#[inline]
pub fn elem_verify_equal_consttime<M, E>(
    a: &Elem<M, E>,
    b: &Elem<M, E>,
) -> Result<(), error::Unspecified> {
    let equal = limb::limbs_equal_limbs_consttime(a.limbs.as_ref(), b.limbs.as_ref())
        .unwrap_or_else(unwrap_impossible_len_mismatch_error);
    if !equal.leak() {
        return Err(error::Unspecified);
    }
    Ok(())
}

#[cfg(test)]
pub mod testutil {
    use super::*;

    pub fn consume_elem<M>(
        test_case: &mut crate::testutil::TestCase,
        name: &str,
        m: &Mont<M>,
    ) -> Elem<M, Unencoded> {
        let value = test_case.consume_bytes(name);
        m.alloc_uninit()
            .into_elem_from_be_bytes_padded(untrusted::Input::from(&value), m)
            .unwrap()
    }

    pub fn consume_elem_unchecked<M>(
        test_case: &mut crate::testutil::TestCase,
        name: &str,
        num_limbs: usize,
    ) -> Elem<M, Unencoded> {
        let bytes = test_case.consume_bytes(name);
        let limbs = Uninit::new_less_safe(num_limbs)
            .write_from_be_bytes_padded(untrusted::Input::from(&bytes))
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        Elem::assume_in_range_and_encoded_less_safe(limbs)
    }

    pub fn assert_elem_eq<M, E>(a: &Elem<M, E>, b: &Elem<M, E>) {
        if elem_verify_equal_consttime(a, b).is_err() {
            panic!("{:x?} != {:x?}", a.limbs.as_ref(), b.limbs.as_ref());
        }
    }
}
