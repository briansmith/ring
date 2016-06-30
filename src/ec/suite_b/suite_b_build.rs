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

use num;
use num::integer::Integer as Integral;
use num::traits::{FromPrimitive, Num, One, Signed, ToPrimitive, Zero};
use std;

pub fn generate_code(out_dir: &str) -> std::io::Result<()> {
    generate_ec_groups(out_dir)
}

// The math

type Integer = num::bigint::BigInt;

fn mod_inv(a: &Integer, m: &Integer)
           -> Result<Integer, ()> {
    fn extended_gcd(aa: &Integer, bb: &Integer) -> (Integer, Integer, Integer) {
        let mut last_rem = aa.abs();
        let mut rem = bb.abs();
        let mut x = Integer::zero();
        let mut last_x = Integer::one();
        let mut y = Integer::one();
        let mut last_y = Integer::zero();
        while !rem.is_zero() {
            let (quotient, new_rem) = last_rem.div_rem(&rem);
            last_rem = rem;
            rem = new_rem;

            let new_x = last_x - &quotient * &x;
            last_x = x;
            x = new_x;

            let new_y = last_y - &quotient * &y;
            last_y = y;
            y = new_y;
        }
        (last_rem,
         if aa.is_negative() { -last_x } else { last_x },
         if bb.is_negative() { -last_y } else { last_y })
    }

    let (g, x, _) = extended_gcd(a, m);
    if g != Integer::one() {
        return Err(());
    }
    Ok(x % m)
}

struct ModP {
    rr: Integer,
    r: Integer,
    p: Integer,
    k: u64,
}


impl ModP {
    fn new(p_hex_str: &str) -> Result<ModP, ()> {
        // XXX: This works for 32-bit and 64-bit targets for P-256 and P-384
        // only. It might work for more curves, but it hasn't been tested for
        // them. It definitely does not work for P-224, probably because 224 is
        // not a multiple of 64, but maybe for other reasons.
        const LIMB_BITS: usize = 64;

        let p = integer_from_hex_str(p_hex_str);
        let p_bits = (p.to_biguint().unwrap().bits() + LIMB_BITS - 1) /
                     LIMB_BITS * LIMB_BITS;
        let neg_p = -&p;

        let r = (Integer::one() << p_bits) % &p;
        let rr = (&r * &r) % &p;
        let tmod = Integer::one() << 64;
        let k = try!(mod_inv(&neg_p, &tmod));
        let mut k = k % (Integer::one() << 64);
        if k.is_negative() {
            k = &k + (Integer::one() << 64);
        }
        let k = k.to_u64().unwrap();
        Ok(ModP {
            p: p.clone(),
            r: r.clone(),
            rr: rr.clone(),
            k: k.clone(),
        })
    }

    fn encode(&self, n: &Integer) -> Integer {
        (n * &self.r) % &self.p
    }
}

fn integer_from_hex_str(hex_str: &str) -> Integer {
    Integer::from_str_radix(hex_str, 16).unwrap()
}

// Generation of the C code for |EC_GROUP|
pub fn generate_ec_groups(out_dir: &str) -> std::io::Result<()> {
    use std::io::Write;

    let mut fragments = SUPPORTED_CURVES.into_iter()
                                        .map(|x| ec_group(x))
                                        .collect::<Vec<_>>();
    fragments.insert(0, String::from(EC_GROUPS_BOILERPLATE));

    // Ensure file ends with newline to avoid undefined behavior
    let code = fragments.join("\n") + "\n";

    let dest_path = std::path::Path::new(&out_dir).join("ec_curve_data.inl");
    let mut f = try!(std::fs::File::create(&dest_path));
    try!(f.write_all(code.as_bytes()));
    Ok(())
}

fn ec_group(curve: &NISTCurve) -> String {
    assert_eq!(curve.cofactor, 1);

    let q = ModP::new(&curve.q).unwrap();

    let n = ModP::new(&curve.n).unwrap();

    let one = Integer::one();
    assert_eq!(curve.a, -3);
    let a = &q.p + Integer::from_i8(curve.a).unwrap();
    let b = integer_from_hex_str(&curve.b);

    let (generator_x, generator_y) =
        (integer_from_hex_str(&curve.generator.0),
         integer_from_hex_str(&curve.generator.1));

    let one_mont = q.encode(&one);
    let a_mont = q.encode(&a);
    let b_mont = q.encode(&b);
    let generator_x_mont = q.encode(&generator_x);
    let generator_y_mont = q.encode(&generator_y);

    format!("
        static const BN_ULONG p{bits}_field_limbs[] = {q};
        static const BN_ULONG p{bits}_field_rr_limbs[] = {q_rr};
        static const BN_ULONG p{bits}_order_limbs[] = {n};
        static const BN_ULONG p{bits}_order_rr_limbs[] = {n_rr};
        static const BN_ULONG p{bits}_generator_x_limbs[] = {x_mont};
        static const BN_ULONG p{bits}_generator_y_limbs[] = {y_mont};
        static const BN_ULONG p{bits}_a_limbs[] = {a_mont};
        static const BN_ULONG p{bits}_b_limbs[] = {b_mont};
        static const BN_ULONG p{bits}_one_limbs[] = {one_mont};

        STATIC_BIGNUM_DIAGNOSTIC_PUSH

        const EC_GROUP EC_GROUP_P{bits} = {{
          FIELD(.meth =) &{name}_EC_METHOD,
          FIELD(.generator =) {{
            FIELD(.meth =) &{name}_EC_METHOD,
            FIELD(.X =) STATIC_BIGNUM(p{bits}_generator_x_limbs),
            FIELD(.Y =) STATIC_BIGNUM(p{bits}_generator_y_limbs),
            FIELD(.Z =) STATIC_BIGNUM(p{bits}_one_limbs),
          }},
          FIELD(.order =) STATIC_BIGNUM(p{bits}_order_limbs),
          FIELD(.order_mont =) {{
            FIELD(.RR =) STATIC_BIGNUM(p{bits}_order_rr_limbs),
            FIELD(.N =) STATIC_BIGNUM(p{bits}_order_limbs),
            FIELD(.n0 =) {{ BN_MONT_CTX_N0(0x{n_n1:x}, 0x{n_n0:x}) }},
          }},
          FIELD(.curve_name =) {nid},
          FIELD(.field =) STATIC_BIGNUM(p{bits}_field_limbs),
          FIELD(.a =) STATIC_BIGNUM(p{bits}_a_limbs),
          FIELD(.b =) STATIC_BIGNUM(p{bits}_b_limbs),
          FIELD(.mont =) {{
            FIELD(.RR =) STATIC_BIGNUM(p{bits}_field_rr_limbs),
            FIELD(.N =) STATIC_BIGNUM(p{bits}_field_limbs),
            FIELD(.n0 =) {{ BN_MONT_CTX_N0(0x{q_n1:x}, 0x{q_n0:x}) }},
          }},
          FIELD(.one =) STATIC_BIGNUM(p{bits}_one_limbs),
        }};

        STATIC_BIGNUM_DIAGNOSTIC_POP
        ",
        bits = curve.bits,
        name = curve.name,
        nid = curve.nid,

        q = bn_limbs(&q.p),
        q_rr = bn_limbs(&q.rr),
        q_n0 = (q.k % (1u64 << 32)) as usize,
        q_n1 = (q.k / (1u64 << 32)) as usize,

        n = bn_limbs(&n.p),
        n_rr = bn_limbs(&n.rr),
        n_n0 = (n.k % (1u64 << 32)) as usize,
        n_n1 = (n.k / (1u64 << 32)) as usize,

        one_mont = bn_limbs(&one_mont),
        x_mont = bn_limbs(&generator_x_mont),
        y_mont = bn_limbs(&generator_y_mont),
        a_mont = bn_limbs(&a_mont),
        b_mont = bn_limbs(&b_mont))
        .replace("\n        ", "\n")
}

fn bn_limbs(value: &Integer) -> String {
    const INDENT: &'static str = "            ";

    let limbs =
        value
        .to_bytes_le()
        .1
        .chunks(4)
        .map(|bytes| {
            let mut place = 0;
            let mut value = 0;
            for b in bytes {
                value |= (*b as u32) << place;
                place += 8;
            }
            value
        })
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|limbs_32x2| {
            match limbs_32x2.len() {
                2 => format!("{}TOBN(0x{:08x}, 0x{:08x}),\n", INDENT,
                             limbs_32x2[1], limbs_32x2[0]),
                1 => format!("{}0x{:08x},\n", INDENT,
                             limbs_32x2[0]),
                _ => unreachable!()
            }
        })
        .collect::<String>();

    format!("{{\n{}          }}", limbs)
}


struct NISTCurve {
    pub name: &'static str,
    pub bits: usize,
    pub nid: &'static str,
    pub q: &'static str,
    pub n: &'static str,
    pub generator: (&'static str, &'static str),
    pub a: i8, // Must always be -3.
    pub b: &'static str,
    pub cofactor: i8, // Must always be 1.
}

// The curve parameters are from
// http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf.

static SUPPORTED_CURVES: [NISTCurve; 2] = [
    // The math in ecc_build.rs has only been checked to work for P-256 and
    // P-384. In particular, it is known to NOT work for P-224 and it has NOT
    // been tested for other curves.

    NISTCurve {
        name: "CURVE_P256",
        bits: 256,
        nid: "NID_X9_62_prime256v1",

        // 2**256 - 2**224 + 2**192 + 2**96 - 1
        q: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",

        // 2**256 - 2**224 + 2**192 - 2**128 +
        // 0xbce6faada7179e84f3b9cac2fc632551
        n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",

        generator:
          ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
           "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),

        a: -3,
        b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        cofactor: 1,
    },
    NISTCurve {
        name: "CURVE_P384",
        bits: 384,
        nid: "NID_secp384r1",

        // 2^384 − 2^128 − 2^96 + 2^32 − 1
        q: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
            ffffffff0000000000000000ffffffff",

        // 2^384 - 2^192 + 0xc7634d81f4372ddf581a0db248b0a77aecec196accc52973
        n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",

        generator:
          ("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
            5502f25dbf55296c3a545e3872760ab7",
           "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
            0a60b1ce1d7e819d7a431d7c90ea0e5f"),

        a: -3,
        b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
            c656398d8a2ed19d2a85c8edd3ec2aef",
        cofactor: 1,
    },
];


const EC_GROUPS_BOILERPLATE: &'static str = r##"/* Copyright 2015 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* This entire file was generated by ecc_build.rs from
 * https://github.com/briansmith/ring. */
"##;
