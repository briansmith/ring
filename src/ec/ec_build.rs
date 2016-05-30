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
use super::curves::*;

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
    let n_minus_2 = &n.p - Integer::from_i8(2).unwrap();

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
        const EC_GROUP *{ec_group_fn_name}(void) {{
          static const BN_ULONG field_limbs[] = {q};
          static const BN_ULONG field_rr_limbs[] = {q_rr};
          static const BN_ULONG order_limbs[] = {n};
          static const BN_ULONG order_rr_limbs[] = {n_rr};
          static const BN_ULONG order_minus_2_limbs[] = {n_minus_2};
        #if defined({name}_NO_MONT)
          static const BN_ULONG generator_x_limbs[] = {x};
          static const BN_ULONG generator_y_limbs[] = {y};
          static const BN_ULONG a_limbs[] = {a};
          static const BN_ULONG b_limbs[] = {b};
          static const BN_ULONG one_limbs[] = {one};
        #else
          static const BN_ULONG generator_x_limbs[] = {x_mont};
          static const BN_ULONG generator_y_limbs[] = {y_mont};
          static const BN_ULONG a_limbs[] = {a_mont};
          static const BN_ULONG b_limbs[] = {b_mont};
          static const BN_ULONG one_limbs[] = {one_mont};
        #endif
          STATIC_BIGNUM_DIAGNOSTIC_PUSH

          static const EC_GROUP group = {{
            FIELD(.meth =) &{name}_EC_METHOD,
            FIELD(.generator =) {{
              FIELD(.meth =) &{name}_EC_METHOD,
              FIELD(.X =) STATIC_BIGNUM(generator_x_limbs),
              FIELD(.Y =) STATIC_BIGNUM(generator_y_limbs),
              FIELD(.Z =) STATIC_BIGNUM(one_limbs),
            }},
            FIELD(.order =) STATIC_BIGNUM(order_limbs),
            FIELD(.order_mont =) {{
              FIELD(.RR =) STATIC_BIGNUM(order_rr_limbs),
              FIELD(.N =) STATIC_BIGNUM(order_limbs),
              FIELD(.n0 =) {{ BN_MONT_CTX_N0(0x{n_n1:x}, 0x{n_n0:x}) }},
            }},
            FIELD(.order_minus_2 =) STATIC_BIGNUM(order_minus_2_limbs),
            FIELD(.curve_name =) {nid},
            FIELD(.field =) STATIC_BIGNUM(field_limbs),
            FIELD(.a =) STATIC_BIGNUM(a_limbs),
            FIELD(.b =) STATIC_BIGNUM(b_limbs),
            FIELD(.mont =) {{
              FIELD(.RR =) STATIC_BIGNUM(field_rr_limbs),
              FIELD(.N =) STATIC_BIGNUM(field_limbs),
              FIELD(.n0 =) {{ BN_MONT_CTX_N0(0x{q_n1:x}, 0x{q_n0:x}) }},
            }},
            FIELD(.one =) STATIC_BIGNUM(one_limbs),
          }};

          STATIC_BIGNUM_DIAGNOSTIC_POP

          return &group;
        }}

        /* Prototypes to avoid -Wmissing-prototypes warnings. */
        int GFp_p{bits}_generate_private_key(
                uint8_t out[{elem_and_scalar_len}], RAND *rng);
        int GFp_p{bits}_public_from_private(
                uint8_t public_key_out[{public_key_len}],
                const uint8_t private_key[{elem_and_scalar_len}]);


        int GFp_p{bits}_generate_private_key(
                uint8_t out[{elem_and_scalar_len}], RAND *rng) {{
            return GFp_suite_b_generate_private_key({ec_group_fn_name}(), out,
                                                    {elem_and_scalar_len}, rng);
        }}

        int GFp_p{bits}_public_from_private(
                uint8_t public_key_out[{public_key_len}],
                const uint8_t private_key[{elem_and_scalar_len}]) {{
            return GFp_suite_b_public_from_private(
                    {ec_group_fn_name}(), public_key_out, {public_key_len},
                    private_key, {elem_and_scalar_len});
        }}",
        ec_group_fn_name = curve.name.replace("CURVE", "EC_GROUP"),
        bits = curve.bits,
        elem_and_scalar_len = (curve.bits + 7) / 8,
        public_key_len = 1 + (2 * ((curve.bits + 7) / 8)),
        name = curve.name,
        nid = curve.nid,

        q = bn_limbs(&q.p),
        q_rr = bn_limbs(&q.rr),
        q_n0 = (q.k % (1u64 << 32)) as usize,
        q_n1 = (q.k / (1u64 << 32)) as usize,

        n = bn_limbs(&n.p),
        n_minus_2 = bn_limbs(&n_minus_2),
        n_rr = bn_limbs(&n.rr),
        n_n0 = (n.k % (1u64 << 32)) as usize,
        n_n1 = (n.k / (1u64 << 32)) as usize,

        one = bn_limbs(&one),
        x = bn_limbs(&generator_x),
        y = bn_limbs(&generator_y),
        a = bn_limbs(&a),
        b = bn_limbs(&b),

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
