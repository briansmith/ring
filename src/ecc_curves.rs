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

pub static SUPPORTED_CURVES: [NISTCurve; 2] = [
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
