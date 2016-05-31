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

//! Common functionality on public keys for NIST curves.

pub mod ecdsa;
pub mod ecdh;

use core;
use {ec, input};
use input::Input;


// Field elements. Field elements are always Montgomery-encoded and always
// fully reduced mod q; i.e. their range is [0, q).
struct Elem {
    limbs: [Limb; MAX_LIMBS],
}

/// Parses a public key encoded in uncompressed form. The key's coordinates are
/// verified to be valid field elements and the point is verified to be on the
/// curve. (The point cannot be at infinity because it is given in affine
/// coordinates.)
fn parse_uncompressed_point<'a>(input: Input<'a>, curve: &Curve)
                                -> Result<(Elem, Elem), ()> {
    let (x, y) = try!(input::read_all(input, (), |input| {
        // The serialized bytes are in big-endian order, zero-padded. The limbs
        // of `Elem` are in the native endianness, least significant limb to
        // most significant limb.
        fn parse_elem(input: &mut input::Reader, curve: &Curve)
                      -> Result<Elem, ()> {
            let mut elem = Elem { limbs: [0; MAX_LIMBS] };
            for i in 0..curve.num_limbs {
                let mut limb: Limb = 0;
                for _ in 0..LIMB_BYTES {
                    limb = (limb << 8) | (try!(input.read_byte()) as Limb);
                }
                elem.limbs[curve.num_limbs - 1 - i] = limb;
            }

            // Verify that the value is in the range [0, q).
            for i in 0..curve.num_limbs {
                match elem.limbs[curve.num_limbs - 1 - i].cmp(
                        &curve.q.p[curve.num_limbs - 1 - i]) {
                    core::cmp::Ordering::Less => {
                        // Montgomery encode (elem_to_mont).
                        unsafe {
                            (curve.elem_mul_mont)(elem.limbs.as_mut_ptr(),
                                                  elem.limbs.as_ptr(),
                                                  curve.q.rr.as_ptr())
                        }
                        return Ok(elem);
                    },
                    core::cmp::Ordering::Equal => { }, // keep going
                    core::cmp::Ordering::Greater => { break; }
                }
            }
            return Err(());
        }
        // The encoding must be 4, which is the encoding for "uncompressed".
        let encoding = try!(input.read_byte());
        if encoding != 4 {
            return Err(());
        }
        let x = try!(parse_elem(input, curve));
        let y = try!(parse_elem(input, curve));
        Ok((x, y))
    }));

    // Verify that (x, y) is on the curve, which is true iif:
    //
    //     y**2 == x**3 + a*x + b
    //
    // Or, equivalently, but more efficiently:
    //
    //     y**2 == (x**2 + a)*x + b
    //
    let mut lhs = Elem { limbs: [0; MAX_LIMBS] };
    unsafe {
        (curve.elem_sqr_mont)(lhs.limbs.as_mut_ptr(), y.limbs.as_ptr());
    }
    let mut rhs = Elem { limbs: [0; MAX_LIMBS] };
    unsafe {
        (curve.elem_sqr_mont)(rhs.limbs.as_mut_ptr(), x.limbs.as_ptr());
        (curve.elem_add)(rhs.limbs.as_mut_ptr(), rhs.limbs.as_ptr(),
                            curve.a.limbs.as_ptr());
        (curve.elem_mul_mont)(rhs.limbs.as_mut_ptr(), rhs.limbs.as_ptr(),
                              x.limbs.as_ptr());
        (curve.elem_add)(rhs.limbs.as_mut_ptr(), rhs.limbs.as_ptr(),
                            curve.b.limbs.as_ptr());
    }
    if lhs.limbs[..curve.num_limbs] != rhs.limbs[..curve.num_limbs] {
        return Err(());
    }
    Ok((x, y))
}

struct Mont {
    p: [Limb; MAX_LIMBS],
    rr: [Limb; MAX_LIMBS],
}

struct Curve {
    num_limbs: usize,

    q: Mont,

    a: Elem, // Must be -3 mod q
    b: Elem,

    // In all cases, `r`, `a`, and `b` may all alias each other.
    elem_add: unsafe extern fn(r: *mut Limb, a: *const Limb, b: *const Limb),
    elem_mul_mont: unsafe extern fn(r: *mut Limb, a: *const Limb,
                                    b: *const Limb),
    elem_sqr_mont: unsafe extern fn(r: *mut Limb, a: *const Limb),

    ec_group_fn: unsafe extern fn() -> *const EC_GROUP,
}

#[allow(non_camel_case_types)]
enum EC_GROUP { }


// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")] type Limb = u64;
#[cfg(target_pointer_width = "32")] type Limb = u32;
#[cfg(target_pointer_width = "64")] const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")] const LIMB_BITS: usize = 32;

macro_rules! limbs {
    [ $limb0_hi:expr, $limb0_lo:expr,
      $limb1_hi:expr, $limb1_lo:expr,
      $limb2_hi:expr, $limb2_lo:expr,
      $limb3_hi:expr, $limb3_lo:expr ] => {
        limbs![$limb0_hi, $limb0_lo,
               $limb1_hi, $limb1_lo,
               $limb2_hi, $limb2_lo,
               $limb3_hi, $limb3_lo,
               0,         0,
               0,         0]
    };

    [ $limb0_hi:expr, $limb0_lo:expr,
      $limb1_hi:expr, $limb1_lo:expr,
      $limb2_hi:expr, $limb2_lo:expr,
      $limb3_hi:expr, $limb3_lo:expr,
      $limb4_hi:expr, $limb4_lo:expr,
      $limb5_hi:expr, $limb5_lo:expr ] => {
        limbs_inner![
            $limb0_hi, $limb0_lo,
            $limb1_hi, $limb1_lo,
            $limb2_hi, $limb2_lo,
            $limb3_hi, $limb3_lo,
            $limb4_hi, $limb4_lo,
            $limb5_hi, $limb5_lo]
    }
}

#[cfg(target_pointer_width = "64")]
macro_rules! limbs_inner {
    ( $limb0_hi:expr, $limb0_lo:expr,
      $limb1_hi:expr, $limb1_lo:expr,
      $limb2_hi:expr, $limb2_lo:expr,
      $limb3_hi:expr, $limb3_lo:expr,
      $limb4_hi:expr, $limb4_lo:expr,
      $limb5_hi:expr, $limb5_lo:expr ) => {
        [ (($limb0_hi | 0u64) << 32) | $limb0_lo,
          (($limb1_hi | 0u64) << 32) | $limb1_lo,
          (($limb2_hi | 0u64) << 32) | $limb2_lo,
          (($limb3_hi | 0u64) << 32) | $limb3_lo,
          (($limb4_hi | 0u64) << 32) | $limb4_lo,
          (($limb5_hi | 0u64) << 32) | $limb5_lo,
        ]
    }
}

#[cfg(all(target_pointer_width = "32", target_endian = "little"))]
macro_rules! limbs_inner {
    ( $limb0_hi:expr, $limb0_lo:expr,
      $limb1_hi:expr, $limb1_lo:expr,
      $limb2_hi:expr, $limb2_lo:expr,
      $limb3_hi:expr, $limb3_lo:expr,
      $limb4_hi:expr, $limb4_lo:expr,
      $limb5_hi:expr, $limb5_lo:expr ) => {
        [ $limb0_lo, $limb0_hi,
          $limb1_lo, $limb1_hi,
          $limb2_lo, $limb2_hi,
          $limb3_lo, $limb3_hi,
          $limb4_lo, $limb4_hi,
          $limb5_lo, $limb5_hi,
        ]
    }
}

const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;
const MAX_LIMBS: usize = (ec::ELEM_MAX_BYTES + (LIMB_BYTES - 1)) / LIMB_BYTES;


static P256: Curve = Curve {
    num_limbs: 256 / LIMB_BITS,

    q: Mont {
        p: limbs![
            0xffffffff, 0xffffffff,
            0x00000000, 0xffffffff,
            0x00000000, 0x00000000,
            0xffffffff, 0x00000001
        ],
        rr: limbs![
            0x00000000, 0x00000003,
            0xfffffffb, 0xffffffff,
            0xffffffff, 0xfffffffe,
            0x00000004, 0xfffffffd
        ],
    },

    a: Elem {
        limbs: limbs![
            0xffffffff, 0xfffffffc,
            0x00000003, 0xffffffff,
            0x00000000, 0x00000000,
            0xfffffffc, 0x00000004
        ],
    },
    b: Elem {
        limbs: limbs![
            0xd89cdf62, 0x29c4bddf,
            0xacf005cd, 0x78843090,
            0xe5a220ab, 0xf7212ed6,
            0xdc30061d, 0x04874834
        ],
    },

    // In all cases, `result`, `a`, and `b` may all alias each other.
    elem_add: ecp_nistz256_add,
    elem_mul_mont: ecp_nistz256_mul_mont,
    elem_sqr_mont: ecp_nistz256_sqr_mont,

    ec_group_fn: EC_GROUP_P256,
};

// XXX: Inefficient. TODO: Implement a dedicated squaring routine.
#[cfg(any(target_arch = "arm", target_arch = "x86"))]
unsafe extern fn ecp_nistz256_sqr_mont(r: *mut Limb/*[P256.num_limbs]*/,
                                       a: *const Limb/*[P256.num_limbs]*/) {
    ecp_nistz256_mul_mont(r, a, a);
}

extern {
    fn ecp_nistz256_add(r: *mut Limb/*[P256.num_limbs]*/,
                        a: *const Limb/*[P256.num_limbs]*/,
                        b: *const Limb/*[P256.num_limbs]*/);
    fn ecp_nistz256_mul_mont(r: *mut Limb/*[P256.num_limbs]*/,
                             a: *const Limb/*[P256.num_limbs]*/,
                             b: *const Limb/*[P256.num_limbs]*/);
    #[cfg(not(any(target_arch = "arm", target_arch = "x86")))]
    fn ecp_nistz256_sqr_mont(r: *mut Limb/*[P256.num_limbs]*/,
                             a: *const Limb/*[P256.num_limbs]*/);

    fn EC_GROUP_P256() -> *const EC_GROUP;
}


static P384: Curve = Curve {
    num_limbs: 384 / LIMB_BITS,

    q: Mont {
        p: limbs![
            0x00000000, 0xffffffff,
            0xffffffff, 0x00000000,
            0xffffffff, 0xfffffffe,
            0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff
        ],
        rr: limbs![
            0xfffffffe, 0x00000001,
            0x00000002, 0x00000000,
            0xfffffffe, 0x00000000,
            0x00000002, 0x00000000,
            0x00000000, 0x00000001,
            0x00000000, 0x00000000
        ],
    },


    a: Elem {
        limbs: limbs![
            0x00000003, 0xfffffffc,
            0xfffffffc, 0x00000000,
            0xffffffff, 0xfffffffb,
            0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff,
            0xffffffff, 0xffffffff
        ],
    },
    b: Elem {
        limbs: limbs![
            0x08118871, 0x9d412dcc,
            0xf729add8, 0x7a4c32ec,
            0x77f2209b, 0x1920022e,
            0xe3374bee, 0x94938ae2,
            0xb62b21f4, 0x1f022094,
            0xcd08114b, 0x604fbff9
        ],
    },

    elem_add: GFp_p384_elem_add,
    elem_mul_mont: GFp_p384_elem_mul_mont,
    elem_sqr_mont: GFp_p384_elem_sqr_mont,

    ec_group_fn: EC_GROUP_P384,
};

#[allow(non_snake_case)]
unsafe extern fn GFp_p384_elem_sqr_mont(r: *mut Limb/*[P384.num_limbs]*/,
                                        a: *const Limb/*[P384.num_limbs]*/) {
  /* XXX: Inefficient. TODO: Make a dedicated squaring routine. */
  GFp_p384_elem_mul_mont(r, a, a);
}

extern {
    /* XXX: Depends on crypto/bn. TODO: Make a dedicated implementation. */
    fn GFp_p384_elem_add(r: *mut Limb/*[P384.num_limbs]*/,
                         a: *const Limb/*[P384.num_limbs]*/,
                         b: *const Limb/*[P384.num_limbs]*/);

    /* XXX: Inefficient, depends on crypto/bn. TODO: Make a dedicated
     * implementation. */
    fn GFp_p384_elem_mul_mont(r: *mut Limb/*[P384.num_limbs]*/,
                              a: *const Limb/*[P384.num_limbs]*/,
                              b: *const Limb/*[P384.num_limbs]*/);

    fn EC_GROUP_P384() -> *const EC_GROUP;
}
