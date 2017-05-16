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

//! X25519 Key agreement.

use {agreement, constant_time, ec, error, rand};
use super::ops;
use untrusted;


static CURVE25519: ec::Curve = ec::Curve {
    public_key_len: PUBLIC_KEY_LEN,
    elem_and_scalar_len: ELEM_AND_SCALAR_LEN,
    id: ec::CurveID::Curve25519,
    check_private_key_bytes: x25519_check_private_key_bytes,
    generate_private_key: x25519_generate_private_key,
    public_from_private: x25519_public_from_private,
};

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub static X25519: agreement::Algorithm = agreement::Algorithm {
    i: ec::AgreementAlgorithmImpl {
        curve: &CURVE25519,
        ecdh: x25519_ecdh,
    },
};

fn x25519_check_private_key_bytes(bytes: &[u8])
                                  -> Result<(), error::Unspecified> {
    debug_assert_eq!(bytes.len(), PRIVATE_KEY_LEN);
    Ok(())
}

fn x25519_generate_private_key(rng: &rand::SecureRandom)
                               -> Result<ec::PrivateKey, error::Unspecified> {
    let mut result = ec::PrivateKey { bytes: [0; ec::SCALAR_MAX_BYTES] };
    try!(rng.fill(&mut result.bytes[..PRIVATE_KEY_LEN]));
    Ok(result)
}

fn x25519_public_from_private(public_out: &mut [u8],
                              private_key: &ec::PrivateKey)
                              -> Result<(), error::Unspecified> {
    let public_out = try!(slice_as_array_ref_mut!(public_out, PUBLIC_KEY_LEN));

    let mut scalar = [0u8; ops::SCALAR_LEN];
    scalar.copy_from_slice(&private_key.bytes[..PRIVATE_KEY_LEN]);
    unsafe { GFp_curve25519_scalar_mask(&mut scalar); }

    *public_out = ops::scalar_mult_with_base_point(&scalar);

    Ok(())
}

fn x25519_ecdh(out: &mut [u8], my_private_key: &ec::PrivateKey,
               peer_public_key: untrusted::Input)
               -> Result<(), error::Unspecified> {
    let out = try!(slice_as_array_ref_mut!(out, SHARED_SECRET_LEN));

    // XXX: This shouldn't require dynamic checks, but rustc can't slice an
    // array reference to a shorter array reference. TODO(perf): Fix this.
    let my_private_key =
        try!(slice_as_array_ref!(&my_private_key.bytes[..PRIVATE_KEY_LEN],
                                 PRIVATE_KEY_LEN));
    let peer_public_key =
        try!(slice_as_array_ref!(peer_public_key.as_slice_less_safe(),
                                 PUBLIC_KEY_LEN));

    unsafe {
        GFp_x25519_scalar_mult(out, my_private_key, peer_public_key);
    }

    let zeros: SharedSecret = [0; SHARED_SECRET_LEN];
    if constant_time::verify_slices_are_equal(out, &zeros).is_ok() {
        // All-zero output results when the input is a point of small order.
        return Err(error::Unspecified);
    }

    Ok(())
}

const ELEM_AND_SCALAR_LEN: usize = ops::ELEM_LEN;
const PRIVATE_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;
const PUBLIC_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;

// An X25519 shared secret as an encoded Curve25519 point.
type SharedSecret = [u8; SHARED_SECRET_LEN];
const SHARED_SECRET_LEN: usize = ELEM_AND_SCALAR_LEN;


extern {
    fn GFp_curve25519_scalar_mask(a: &mut ops::Scalar);
    fn GFp_x25519_scalar_mult(out: &mut ops::EncodedPoint, scalar: &ops::Scalar,
                              point: &ops::EncodedPoint);
}

#[cfg(test)]
mod tests {
    use {agreement, error, test};
    use std;
    use untrusted;

    #[test]
    fn test_agreement_ecdh_x25519_rfc_iterated() {
        let mut k =
            h("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k.clone();

        fn expect_iterated_x25519(expected_result: &str,
                                  range: std::ops::Range<usize>,
                                  k: &mut std::vec::Vec<u8>,
                                  u: &mut std::vec::Vec<u8>) {
            for _ in range {
                let new_k = x25519(k, u);
                *u = k.clone();
                *k = new_k;
            }
            assert_eq!(&h(expected_result), k);
        }

        expect_iterated_x25519(
            "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            0..1, &mut k, &mut u);
        expect_iterated_x25519(
            "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            1..1_000, &mut k, &mut u);

        // The spec gives a test vector for 1,000,000 iterations but it takes
        // too long to do 1,000,000 iterations by default right now. This
        // 10,000 iteration vector is self-computed.
        expect_iterated_x25519(
            "2c125a20f639d504a7703d2e223c79a79de48c4ee8c23379aa19a62ecd211815",
            1_000..10_000, &mut k, &mut u);

        if cfg!(feature = "slow_tests") {
          expect_iterated_x25519(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            10_000..1_000_000, &mut k, &mut u);
        }
    }

    fn x25519(private_key: &[u8], public_key: &[u8]) -> std::vec::Vec<u8> {
        x25519_(private_key, public_key).unwrap()
    }

    fn x25519_(private_key: &[u8], public_key: &[u8])
               -> Result<std::vec::Vec<u8>, error::Unspecified> {
        let private_key =
            agreement::EphemeralPrivateKey::from_test_vector(
                &agreement::X25519, untrusted::Input::from(private_key));
        let public_key = untrusted::Input::from(public_key);
        agreement::agree_ephemeral(private_key, &agreement::X25519, public_key,
                                   error::Unspecified, |agreed_value| {
            Ok(std::vec::Vec::from(agreed_value))
        })
    }

    fn h(s: &str) -> std::vec::Vec<u8> {
        match test::from_hex(s) {
            Ok(v) => v,
            Err(msg) => {
                panic!("{} in {}", msg, s);
            },
        }
    }
}
