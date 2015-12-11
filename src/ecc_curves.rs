// Copyright 2015 Brian Smith.
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

//! Data defining the supported elliptic curves.

pub struct NISTCurve {
    pub name: &'static str,
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

pub static SUPPORTED_CURVES: [NISTCurve; 4] = [
    NISTCurve {
        name: "CURVE_P224",

        // 2^224 − 2^96 + 1
        q: "ffffffffffffffffffffffffffffffff000000000000000000000001",

        n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",

        generator:
          ("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
           "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),

        a: -3,
        b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        cofactor: 1,

        nid: "NID_secp224r1",
    },
    NISTCurve {
        name: "CURVE_P256",

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

        nid: "NID_X9_62_prime256v1",
    },
    NISTCurve {
        name: "CURVE_P384",

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

        nid: "NID_secp384r1",
    },
    NISTCurve {
        name: "CURVE_P521",

        // 2^521 − 1
        q: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",

        n: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",

        generator:
          ("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d\
            baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
           "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e66\
            2c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),

        a: -3,
        b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109\
            e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        cofactor: 1,

        nid: "NID_secp521r1",
    },
];
