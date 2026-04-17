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
    super::{MAX_LIMBS, montgomery::*},
    BoxedLimbs, IntoMont, Mont, OversizedUninit, Uninit, unwrap_impossible_len_mismatch_error,
    unwrap_impossible_limb_slice_error,
};
use crate::{
    bits::BitLength,
    c, cpu,
    error::{self, LenMismatchError},
    limb::{self, Limb},
    polyfill,
    polyfill::{
        StartMutPtr,
        slice::{AliasingSlices, InOut},
    },
};
use core::{iter, marker::PhantomData, num::NonZero};

/// A boxed `Mut`.
pub struct Elem<M, E = Unencoded> {
    limbs: BoxedLimbs<M>,
    encoding: PhantomData<E>,
}

/// Elements of ℤ/mℤ for some modulus *m*.
//
// Defaulting `E` to `Unencoded` is a convenience for callers from outside this
// submodule. However, for maximum clarity, we always explicitly use
// `Unencoded` within the `bigint` submodule.
pub struct Mut<'l, M, E = Unencoded> {
    limbs: &'l mut [Limb],

    m: PhantomData<Mont<'l, M>>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    encoding: PhantomData<E>,
}

/// An immutable reference to a `Mut`.
pub struct Ref<'l, M, E = Unencoded> {
    limbs: &'l [Limb],
    m: PhantomData<Mont<'l, M>>,
    encoding: PhantomData<E>,
}

impl<'l, M, E> Clone for Ref<'l, M, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, E> Copy for Ref<'_, M, E> {}

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

    // This is only exposed internally because we don't want external callers
    // to borrow an `Elem<M, A>` into a `Mut<M, A>` and then compute a
    // `Mut<M, B>` from it, as that would write a `B`-encoded element into the
    // original `Elem`.
    pub(super) fn as_mut_internal(&mut self) -> Mut<'_, M, E> {
        Mut {
            limbs: self.limbs.as_mut(),
            m: PhantomData,
            encoding: self.encoding,
        }
    }

    pub fn as_ref(&self) -> Ref<'_, M, E> {
        Ref {
            limbs: self.limbs.as_ref(),
            m: PhantomData,
            encoding: self.encoding,
        }
    }

    pub(super) fn leak_limbs_less_safe(&self) -> &[Limb] {
        self.limbs.as_ref()
    }

    pub(super) fn leak_limbs_into_box_less_safe(self) -> BoxedLimbs<M> {
        self.limbs
    }
}

impl<'l, M, E> Mut<'l, M, E> {
    #[inline]
    pub(super) fn assume_in_range_and_encoded_less_safe(limbs: &'l mut [Limb]) -> Self {
        Self {
            limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn as_ref(&self) -> Ref<'_, M, E> {
        Ref::assume_in_range_and_encoded_less_safe(self.limbs)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub(super) fn leak_limbs_mut_less_safe(&mut self) -> &mut [Limb] {
        self.limbs
    }

    pub(super) fn leak_limbs_into_mut_less_safe(self) -> &'l mut [Limb] {
        self.limbs
    }
}

impl<'l, M> Mut<'l, M, Unencoded> {
    pub(super) fn from_limbs(
        out: &'l mut [Limb],
        m: &Mont<M>,
    ) -> Result<Mut<'l, M, Unencoded>, error::Unspecified> {
        limb::verify_limbs_less_than_limbs_leak_bit(out, m.limbs())?;
        Ok(Mut::assume_in_range_and_encoded_less_safe(out))
    }

    pub fn from_be_bytes_padded<'out>(
        input: untrusted::Input<'_>,
        out: &'out mut OversizedUninit<1>,
        m: &Mont<M>,
    ) -> Result<Mut<'out, M>, error::Unspecified> {
        let out = out
            .as_uninit(..m.num_limbs().get())
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!()); // because it's oversized.
        Self::from_be_bytes_padded_(out, input, m)
    }

    pub(super) fn from_be_bytes_padded_<'out>(
        out: polyfill::slice::Uninit<'out, Limb>,
        input: untrusted::Input<'_>,
        m: &Mont<M>,
    ) -> Result<Mut<'out, M>, error::Unspecified> {
        let num_limbs = m.num_limbs().get();
        if out.len() != num_limbs {
            return Err(error::Unspecified);
        }
        let input = limb::limbs_from_big_endian(input, 1..=num_limbs)
            .map_err(error::erase::<LenMismatchError>)?;
        let out = out
            .write_iter(
                input
                    .chain(iter::repeat(Limb::from(limb::ZERO)))
                    .take(num_limbs),
            )
            .src_empty()
            .map_err(error::erase::<LenMismatchError>)?
            .uninit_empty()
            .map_err(error::erase::<LenMismatchError>)?
            .into_written();
        Mut::from_limbs(out, m)
    }
}

impl<'l, M, E> Ref<'l, M, E> {
    #[inline]
    pub(super) fn assume_in_range_and_encoded_less_safe(limbs: &'l [Limb]) -> Self {
        Self {
            limbs,
            m: PhantomData,
            encoding: PhantomData,
        }
    }

    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }
}

impl<'l, M, E> Ref<'l, M, E> {
    pub fn clone_into<'out>(&self, out: &'out mut OversizedUninit<1>) -> Mut<'out, M, E> {
        let limbs = out
            .write_copy_of_slice(self.limbs, self.limbs.len())
            .unwrap_or_else(|LenMismatchError { .. }| unreachable!()); // Because it's oversized.
        Mut::assume_in_range_and_encoded_less_safe(limbs)
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        limb::limbs_are_zero(self.limbs).leak()
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

impl<M> Ref<'_, M, Unencoded> {
    #[inline]
    pub fn fill_be_bytes(&self, out: &mut [u8]) {
        // See Falko Strenzke, "Manger's Attack revisited", ICICS 2010.
        limb::big_endian_from_limbs(self.limbs, out)
    }
}

impl<M, E> Elem<M, E> {
    pub(crate) fn encode_mont<OE>(
        mut self,
        im: &IntoMont<M, OE>,
        cpu: cpu::Features,
    ) -> Elem<M, <(E, OE) as ProductEncoding>::Output>
    where
        (E, OE): ProductEncoding,
    {
        let _: Mut<'_, M, <(E, OE) as ProductEncoding>::Output> =
            self.as_mut_internal().encode_mont(im, cpu);
        Elem {
            limbs: self.limbs,
            encoding: PhantomData,
        }
    }
}

impl<'l, M, E> Mut<'l, M, E> {
    pub(crate) fn encode_mont<OE>(
        self,
        im: &IntoMont<M, OE>,
        cpu: cpu::Features,
    ) -> Mut<'l, M, <(E, OE) as ProductEncoding>::Output>
    where
        (E, OE): ProductEncoding,
    {
        let oneRR = im.one();
        let m = im.modulus(cpu);

        let in_out = self.limbs;
        let _: &[Limb] = limbs_mul_mont(
            (InOut(&mut *in_out), oneRR.leak_limbs_less_safe()),
            m.limbs(),
            m.n0(),
            m.cpu_features(),
        )
        .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Mut::assume_in_range_and_encoded_less_safe(in_out)
    }
}

impl<M, E> Elem<M, E> {
    pub fn mul<BE>(
        mut self,
        b: Ref<'_, M, BE>,
        m: &Mont<M>,
    ) -> Elem<M, <(E, BE) as ProductEncoding>::Output>
    where
        (E, BE): ProductEncoding,
    {
        let _: Mut<'_, M, <(E, BE) as ProductEncoding>::Output> = self.as_mut_internal().mul(b, m);
        Elem {
            limbs: self.limbs,
            encoding: PhantomData,
        }
    }

    #[cfg(any(test, not(target_arch = "x86_64")))]
    #[inline]
    pub fn square(mut self, m: &Mont<M>) -> Elem<M, <(E, E) as ProductEncoding>::Output>
    where
        (E, E): ProductEncoding,
    {
        let _: Mut<'_, M, <(E, E) as ProductEncoding>::Output> = self.as_mut_internal().square(m);
        Elem {
            limbs: self.limbs,
            encoding: PhantomData,
        }
    }
}

impl<'l, M, E> Mut<'l, M, E> {
    pub fn mul<BE>(
        self,
        b: Ref<M, BE>,
        m: &Mont<M>,
    ) -> Mut<'l, M, <(E, BE) as ProductEncoding>::Output>
    where
        (E, BE): ProductEncoding,
    {
        let in_out = self.limbs;
        let _: &[Limb] = limbs_mul_mont(
            (InOut(&mut *in_out), b.limbs),
            m.limbs(),
            m.n0(),
            m.cpu_features(),
        )
        .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Mut::assume_in_range_and_encoded_less_safe(in_out)
    }

    #[inline]
    pub fn square(self, m: &Mont<M>) -> Mut<'l, M, <(E, E) as ProductEncoding>::Output>
    where
        (E, E): ProductEncoding,
    {
        let in_out = self.limbs;
        let _: &[Limb] = limbs_square_mont(&mut *in_out, m.limbs(), m.n0(), m.cpu_features())
            .unwrap_or_else(unwrap_impossible_limb_slice_error);
        Mut::assume_in_range_and_encoded_less_safe(in_out)
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

        self.write_fully_with(|out| {
            limbs_from_mont_in_place(out, tmp, m.limbs(), m.n0())
                .map_err(error::erase::<LenMismatchError>)
        })
        .map(Elem::<M, RInverse>::assume_in_range_and_encoded_less_safe)
        .unwrap_or_else(|_: error::Unspecified| unreachable!())
    }

    pub fn elem_widen<Smaller>(
        self,
        a: &Elem<Smaller, Unencoded>,
        m: &Mont<M>,
        smaller_modulus_bits: BitLength,
    ) -> Result<Elem<M, Unencoded>, error::Unspecified> {
        if smaller_modulus_bits >= m.len_bits() {
            return Err(error::Unspecified);
        }
        let r = self
            .write_copy_of_slice_padded(a.limbs.as_ref())
            .map_err(error::erase::<LenMismatchError>)?;
        Ok(Elem::assume_in_range_and_encoded_less_safe(r))
    }
}

impl<M, E> Elem<M, E> {
    pub fn add(mut self, b: &Elem<M, E>, m: &Mont<M>) -> Elem<M, E> {
        limb::limbs_add_assign_mod(self.limbs.as_mut(), b.limbs.as_ref(), m.limbs())
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        self
    }

    pub fn sub(mut self, b: &Elem<M, E>, m: &Mont<M>) -> Elem<M, E> {
        prefixed_extern! {
            // `r` and `a` may alias.
            unsafe fn LIMBS_sub_mod(
                r: *mut Limb,
                a: *const Limb,
                b: *const Limb,
                m: *const Limb,
                num_limbs: NonZero<c::size_t>,
            );
        }
        let num_limbs = NonZero::new(m.limbs().len()).unwrap();
        let _: &[Limb] = (InOut(self.limbs.as_mut()), b.limbs.as_ref())
            .with_non_dangling_non_null_pointers(num_limbs, |mut r, [a, b]| {
                let m = m.limbs().as_ptr(); // Also non-dangling because num_limbs is non-zero.
                unsafe {
                    LIMBS_sub_mod(r.start_mut_ptr(), a, b, m, num_limbs);
                    r.deref_unchecked().assume_init()
                }
            })
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        self
    }
}

impl<M> Elem<M, Unencoded> {
    /// Verified a == b**-1 (mod m), i.e. a**-1 == b (mod m).
    pub fn verify_inverse_consttime(
        self,
        b: &Elem<M, R>,
        m: &Mont<M>,
    ) -> Result<(), error::Unspecified> {
        let r = self.mul(b.as_ref(), m);
        limb::verify_limbs_equal_1_leak_bit(r.limbs.as_ref())
    }
}

impl<M, E> Ref<'_, M, E> {
    #[inline]
    pub fn verify_equals_consttime(&self, b: Ref<'_, M, E>) -> Result<(), error::Unspecified> {
        let equal = limb::limbs_equal_limbs_consttime(self.limbs, b.limbs)
            .unwrap_or_else(unwrap_impossible_len_mismatch_error);
        if !equal.leak() {
            return Err(error::Unspecified);
        }
        Ok(())
    }
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
        if a.as_ref().verify_equals_consttime(b.as_ref()).is_err() {
            panic!("{:x?} != {:x?}", a.limbs.as_ref(), b.limbs.as_ref());
        }
    }
}
