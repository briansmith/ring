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

#![allow(unsafe_code)]

use {agreement, c, ec, rand};

use bssl;
use input::Input;


/// X25519 (ECDH using Curve25519).
///
/// Public keys are encoding as described in
/// [RFC rfc7748](https://tools.ietf.org/html/rfc7748). All computations and
/// checks are done as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in
/// [RFC 7748 section 6.1](https://tools.ietf.org/html/rfc7748#section-6.1).
pub static X25519: agreement::Algorithm = agreement::Algorithm {
    i: ec::AgreementAlgorithmImpl {
        public_key_len: X25519_ELEM_SCALAR_PUBLIC_KEY_LEN,
        elem_and_scalar_len: X25519_ELEM_SCALAR_PUBLIC_KEY_LEN,
        nid: 948 /* NID_X25519 */,
        generate_private_key: GFp_x25519_generate_private_key,
        public_from_private: GFp_x25519_public_from_private,
        ecdh: x25519_ecdh,
    },
};

fn x25519_ecdh(out: &mut [u8], my_private_key: &ec::PrivateKey,
               peer_public_key: Input) -> Result<(), ()> {
    debug_assert_eq!(out.len(), X25519_ELEM_SCALAR_PUBLIC_KEY_LEN);
    debug_assert_eq!(peer_public_key.len(), X25519_ELEM_SCALAR_PUBLIC_KEY_LEN);
    bssl::map_result(unsafe {
        GFp_x25519_ecdh(out.as_mut_ptr(), my_private_key.bytes.as_ptr(),
                        peer_public_key.as_slice_less_safe().as_ptr())
    })
}

agreement_externs!(GFp_x25519_generate_private_key,
                   GFp_x25519_public_from_private);

const X25519_ELEM_SCALAR_PUBLIC_KEY_LEN: usize = 32;

extern {
    fn GFp_x25519_ecdh(out_shared_key: *mut u8/*[32]*/,
                       private_key: *const u8/*[u32]*/,
                       peer_public_value: *const u8/*[32]*/) -> c::int;
}

#[cfg(test)]
mod tests {
    use {agreement, file_test};
    use input::Input;
    use std;

    #[test]
    fn test_agreement_ecdh_x25519_rfc_iterated() {
        let mut k =
            h("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k.clone();

        fn expect_iterated_x25519(expected_result: &str,
                                  range: std::ops::Range<usize>,
                                  k: &mut std::vec::Vec<u8>, u:
                                  &mut std::vec::Vec<u8>) {
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
               -> Result<std::vec::Vec<u8>, ()> {
        let private_key =
            agreement::EphemeralPrivateKey::from_test_vector(
                &agreement::X25519, private_key);
        let public_key = try!(Input::new(public_key));
        agreement::agree_ephemeral(private_key, &agreement::X25519, public_key,
                                   (), |agreed_value| {
            Ok(std::vec::Vec::from(agreed_value))
        })
    }

    fn h(s: &str) -> std::vec::Vec<u8> {
        match file_test::from_hex(s) {
            Ok(v) => v,
            Err(msg) => {
                panic!("{} in {}", msg, s);
            }
        }
    }
}
