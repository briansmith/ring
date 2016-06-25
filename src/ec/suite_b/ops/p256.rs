// Copyright 2016 Brian Smith.
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

use super::{CommonOps, EC_GROUP, Elem, ElemDecoded, Limb, LIMB_BITS, Mont,
            PublicKeyOps, PublicScalarOps};


macro_rules! p256_limbs {
    [$limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
     $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr] => {
        limbs![0, 0, 0, 0,
               $limb_7, $limb_6, $limb_5, $limb_4,
               $limb_3, $limb_2, $limb_1, $limb_0]
    };
}


static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 256 / LIMB_BITS,

    q: Mont {
        p: p256_limbs![0xffffffff, 0x00000001, 0x00000000, 0x00000000,
                       0x00000000, 0xffffffff, 0xffffffff, 0xffffffff],
        rr: p256_limbs![0x00000004, 0xfffffffd, 0xffffffff, 0xfffffffe,
                        0xfffffffb, 0xffffffff, 0x00000000, 0x00000003],
    },

    elem_mul_mont: ecp_nistz256_mul_mont,
    elem_sqr_mont: ecp_nistz256_sqr_mont,

    ec_group: &EC_GROUP_P256,
};


pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,

    a: Elem {
        limbs: p256_limbs![0xfffffffc, 0x00000004, 0x00000000, 0x00000000,
                           0x00000003, 0xffffffff, 0xffffffff, 0xfffffffc],
    },
    b: Elem {
        limbs: p256_limbs![0xdc30061d, 0x04874834, 0xe5a220ab, 0xf7212ed6,
                           0xacf005cd, 0x78843090, 0xd89cdf62, 0x29c4bddf],
    },

    elem_add_impl: ecp_nistz256_add,
};


pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    public_key_ops: &PUBLIC_KEY_OPS,

    n: ElemDecoded {
        limbs: p256_limbs![0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
                           0xbce6faad, 0xa7179e84, 0xf3b9cac2, 0xfc632551],
    },

    q_minus_n: ElemDecoded {
        limbs: p256_limbs![0, 0, 0, 0,
                           0x43190553, 0x58e8617b, 0x0c46353d, 0x039cdaae],
    },

    scalar_inv_to_mont_impl: GFp_p256_scalar_inv_to_mont,
    scalar_mul_mont: GFp_p256_scalar_mul_mont,
};


extern {
    fn ecp_nistz256_add(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                        a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                        b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn ecp_nistz256_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                             a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                             b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn ecp_nistz256_sqr_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                             a: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn GFp_p256_scalar_inv_to_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                   a: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_p256_scalar_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                b: *const Limb/*[COMMON_OPS.num_limbs]*/);

    static EC_GROUP_P256: EC_GROUP;
}


#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::*;
    use super::super::internal_benches::*;

    bench_curve!(&[
        Scalar { limbs: LIMBS_1 },
        Scalar { limbs: LIMBS_ALTERNATING_10, },
        Scalar { // n - 1
            limbs: p256_limbs![0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
                               0xbce6faad, 0xa7179e84, 0xf3b9cac2,
                               0xfc632551 - 1],
        },
    ]);
}
