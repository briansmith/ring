// Copyright 2015-2022 Brian Smith.
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
    elem_add, elem_sub, limb, BoxedLimbs, Elem, Limb, LimbMask, Modulus, Prime, Unencoded, R,
};

use crate::{bssl, c, error};
use alloc::vec;
use core::marker::PhantomData;

// `M` represents the prime modulus for which the exponent is in the interval
// [1, `m` - 1).
pub struct PrivateExponent<M> {
    limbs: BoxedLimbs<M>,
}

impl<M> PrivateExponent<M> {
    pub fn from_be_bytes_padded(
        input: untrusted::Input,
        p: &Modulus<M>,
    ) -> Result<Self, error::Unspecified> {
        let dP = BoxedLimbs::from_be_bytes_padded_less_than(input, p)?;

        // Proof that `dP < p - 1`:
        //
        // If `dP < p` then either `dP == p - 1` or `dP < p - 1`. Since `p` is
        // odd, `p - 1` is even. `d` is odd, and an odd number modulo an even
        // number is odd. Therefore `dP` must be odd. But then it cannot be
        // `p - 1` and so we know `dP < p - 1`.
        //
        // Further we know `dP != 0` because `dP` is not even.
        if limb::limbs_are_even_constant_time(&dP) != LimbMask::False {
            return Err(error::Unspecified);
        }

        Ok(Self { limbs: dP })
    }
}

impl<M: Prime> PrivateExponent<M> {
    // Returns `p - 2`.
    pub(super) fn for_flt(p: &Modulus<M>) -> Self {
        let two = elem_add(p.one(), p.one(), p);
        let p_minus_2 = elem_sub(p.zero(), &two, p);
        Self {
            limbs: p_minus_2.limbs,
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn elem_exp_consttime<M>(
    base: Elem<M, R>,
    exponent: &PrivateExponent<M>,
    m: &Modulus<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    use super::{elem_mul, elem_squared, limbs_mont_product};
    use crate::limb::Window;

    const WINDOW_BITS: usize = 5;
    const TABLE_ENTRIES: usize = 1 << WINDOW_BITS;

    let num_limbs = m.limbs().len();

    let mut table = vec![0; TABLE_ENTRIES * num_limbs];

    fn gather<M>(table: &[Limb], i: Window, r: &mut Elem<M, R>) {
        prefixed_extern! {
            fn LIMBS_select_512_32(
                r: *mut Limb,
                table: *const Limb,
                num_limbs: c::size_t,
                i: Window,
            ) -> bssl::Result;
        }
        Result::from(unsafe {
            LIMBS_select_512_32(r.limbs.as_mut_ptr(), table.as_ptr(), r.limbs.len(), i)
        })
        .unwrap();
    }

    fn power<M>(
        table: &[Limb],
        i: Window,
        mut acc: Elem<M, R>,
        mut tmp: Elem<M, R>,
        m: &Modulus<M>,
    ) -> (Elem<M, R>, Elem<M, R>) {
        for _ in 0..WINDOW_BITS {
            acc = elem_squared(acc, &m.as_partial());
        }
        gather(table, i, &mut tmp);
        let acc = elem_mul(&tmp, acc, m);
        (acc, tmp)
    }

    let tmp = m.one();
    let tmp = elem_mul(m.oneRR().as_ref(), tmp, m);

    fn entry(table: &[Limb], i: usize, num_limbs: usize) -> &[Limb] {
        &table[(i * num_limbs)..][..num_limbs]
    }
    fn entry_mut(table: &mut [Limb], i: usize, num_limbs: usize) -> &mut [Limb] {
        &mut table[(i * num_limbs)..][..num_limbs]
    }
    entry_mut(&mut table, 0, num_limbs).copy_from_slice(&tmp.limbs);
    entry_mut(&mut table, 1, num_limbs).copy_from_slice(&base.limbs);
    for i in 2..TABLE_ENTRIES {
        let (src1, src2) = if i % 2 == 0 {
            (i / 2, i / 2)
        } else {
            (i - 1, 1)
        };
        let (previous, rest) = table.split_at_mut(num_limbs * i);
        let src1 = entry(previous, src1, num_limbs);
        let src2 = entry(previous, src2, num_limbs);
        let dst = entry_mut(rest, 0, num_limbs);
        limbs_mont_product(dst, src1, src2, m.limbs(), m.n0(), m.cpu_features());
    }

    let (r, _) = limb::fold_5_bit_windows(
        &exponent.limbs,
        |initial_window| {
            let mut r = Elem {
                limbs: base.limbs,
                encoding: PhantomData,
            };
            gather(&table, initial_window, &mut r);
            (r, tmp)
        },
        |(acc, tmp), window| power(&table, window, acc, tmp, m),
    );

    let r = r.into_unencoded(m);

    Ok(r)
}

#[cfg(target_arch = "x86_64")]
pub fn elem_exp_consttime<M>(
    base: Elem<M, R>,
    exponent: &PrivateExponent<M>,
    m: &Modulus<M>,
) -> Result<Elem<M, Unencoded>, error::Unspecified> {
    use super::{limbs_mont_mul, limbs_mont_square, n0::N0};
    use crate::{cpu, limb::LIMB_BYTES};

    // Pretty much all the math here requires CPU feature detection to have
    // been done. `cpu_features` isn't threaded through all the internal
    // functions, so just make it clear that it has been done at this point.
    let _ = m.cpu_features();

    // The x86_64 assembly was written under the assumption that the input data
    // is aligned to `MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH` bytes, which was/is
    // 64 in OpenSSL. Similarly, OpenSSL uses the x86_64 assembly functions by
    // giving it only inputs `tmp`, `am`, and `np` that immediately follow the
    // table. The code seems to "work" even when the inputs aren't exactly
    // like that but the side channel defenses might not be as effective. All
    // the awkwardness here stems from trying to use the assembly code like
    // OpenSSL does.

    use crate::limb::Window;

    const WINDOW_BITS: usize = 5;
    const TABLE_ENTRIES: usize = 1 << WINDOW_BITS;

    let num_limbs = m.limbs().len();

    const ALIGNMENT: usize = 64;
    assert_eq!(ALIGNMENT % LIMB_BYTES, 0);
    let mut table = vec![0; ((TABLE_ENTRIES + 3) * num_limbs) + ALIGNMENT];
    let (table, state) = {
        let misalignment = (table.as_ptr() as usize) % ALIGNMENT;
        let table = &mut table[((ALIGNMENT - misalignment) / LIMB_BYTES)..];
        assert_eq!((table.as_ptr() as usize) % ALIGNMENT, 0);
        table.split_at_mut(TABLE_ENTRIES * num_limbs)
    };

    fn entry(table: &[Limb], i: usize, num_limbs: usize) -> &[Limb] {
        &table[(i * num_limbs)..][..num_limbs]
    }
    fn entry_mut(table: &mut [Limb], i: usize, num_limbs: usize) -> &mut [Limb] {
        &mut table[(i * num_limbs)..][..num_limbs]
    }

    const ACC: usize = 0; // `tmp` in OpenSSL
    const BASE: usize = ACC + 1; // `am` in OpenSSL
    const M: usize = BASE + 1; // `np` in OpenSSL

    entry_mut(state, BASE, num_limbs).copy_from_slice(&base.limbs);
    entry_mut(state, M, num_limbs).copy_from_slice(m.limbs());

    fn scatter(table: &mut [Limb], state: &[Limb], i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_scatter5(a: *const Limb, a_len: c::size_t, table: *mut Limb, i: Window);
        }
        unsafe {
            bn_scatter5(
                entry(state, ACC, num_limbs).as_ptr(),
                num_limbs,
                table.as_mut_ptr(),
                i,
            )
        }
    }

    fn gather(table: &[Limb], state: &mut [Limb], i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_gather5(r: *mut Limb, a_len: c::size_t, table: *const Limb, i: Window);
        }
        unsafe {
            bn_gather5(
                entry_mut(state, ACC, num_limbs).as_mut_ptr(),
                num_limbs,
                table.as_ptr(),
                i,
            )
        }
    }

    fn gather_square(
        table: &[Limb],
        state: &mut [Limb],
        n0: &N0,
        i: Window,
        num_limbs: usize,
        cpu_features: cpu::Features,
    ) {
        gather(table, state, i, num_limbs);
        assert_eq!(ACC, 0);
        let (acc, rest) = state.split_at_mut(num_limbs);
        let m = entry(rest, M - 1, num_limbs);
        limbs_mont_square(acc, m, n0, cpu_features);
    }

    fn gather_mul_base(table: &[Limb], state: &mut [Limb], n0: &N0, i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_mul_mont_gather5(
                rp: *mut Limb,
                ap: *const Limb,
                table: *const Limb,
                np: *const Limb,
                n0: &N0,
                num: c::size_t,
                power: Window,
            );
        }
        unsafe {
            bn_mul_mont_gather5(
                entry_mut(state, ACC, num_limbs).as_mut_ptr(),
                entry(state, BASE, num_limbs).as_ptr(),
                table.as_ptr(),
                entry(state, M, num_limbs).as_ptr(),
                n0,
                num_limbs,
                i,
            );
        }
    }

    fn power(table: &[Limb], state: &mut [Limb], n0: &N0, i: Window, num_limbs: usize) {
        prefixed_extern! {
            fn bn_power5(
                r: *mut Limb,
                a: *const Limb,
                table: *const Limb,
                n: *const Limb,
                n0: &N0,
                num: c::size_t,
                i: Window,
            );
        }
        unsafe {
            bn_power5(
                entry_mut(state, ACC, num_limbs).as_mut_ptr(),
                entry_mut(state, ACC, num_limbs).as_mut_ptr(),
                table.as_ptr(),
                entry(state, M, num_limbs).as_ptr(),
                n0,
                num_limbs,
                i,
            );
        }
    }

    // table[0] = base**0.
    {
        let acc = entry_mut(state, ACC, num_limbs);
        acc[0] = 1;
        limbs_mont_mul(acc, &m.oneRR().0.limbs, m.limbs(), m.n0(), m.cpu_features());
    }
    scatter(table, state, 0, num_limbs);

    // table[1] = base**1.
    entry_mut(state, ACC, num_limbs).copy_from_slice(&base.limbs);
    scatter(table, state, 1, num_limbs);

    for i in 2..(TABLE_ENTRIES as Window) {
        if i % 2 == 0 {
            // TODO: Optimize this to avoid gathering
            gather_square(table, state, m.n0(), i / 2, num_limbs, m.cpu_features());
        } else {
            gather_mul_base(table, state, m.n0(), i - 1, num_limbs)
        };
        scatter(table, state, i, num_limbs);
    }

    let state = limb::fold_5_bit_windows(
        &exponent.limbs,
        |initial_window| {
            gather(table, state, initial_window, num_limbs);
            state
        },
        |state, window| {
            power(table, state, m.n0(), window, num_limbs);
            state
        },
    );

    prefixed_extern! {
        fn bn_from_montgomery(
            r: *mut Limb,
            a: *const Limb,
            not_used: *const Limb,
            n: *const Limb,
            n0: &N0,
            num: c::size_t,
        ) -> bssl::Result;
    }
    Result::from(unsafe {
        bn_from_montgomery(
            entry_mut(state, ACC, num_limbs).as_mut_ptr(),
            entry(state, ACC, num_limbs).as_ptr(),
            core::ptr::null(),
            entry(state, M, num_limbs).as_ptr(),
            m.n0(),
            num_limbs,
        )
    })?;
    let mut r = Elem {
        limbs: base.limbs,
        encoding: PhantomData,
    };
    r.limbs.copy_from_slice(entry(state, ACC, num_limbs));
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::{super::tests::*, *};
    use crate::{cpu, test};

    // Type-level representation of an arbitrary modulus.
    struct M {}

    #[test]
    fn test_elem_exp_consttime() {
        let cpu_features = cpu::features();
        test::run(
            test_file!("bigint_elem_exp_consttime_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let m = consume_modulus::<M>(test_case, "M", cpu_features);
                let expected_result = consume_elem(test_case, "ModExp", &m);
                let base = consume_elem(test_case, "A", &m);
                let e = {
                    let bytes = test_case.consume_bytes("E");
                    PrivateExponent::from_be_bytes_padded(untrusted::Input::from(&bytes), &m)
                        .expect("valid exponent")
                };
                let base = into_encoded(base, &m);
                let actual_result = elem_exp_consttime(base, &e, &m).unwrap();
                assert_elem_eq(&actual_result, &expected_result);

                Ok(())
            },
        )
    }
}
