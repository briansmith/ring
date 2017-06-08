// Copyright 2015-2017 Brian Smith.
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

extern crate ring;
extern crate untrusted;

use ring::{agreement, rand, test};

#[test]
fn agreement_agree_ephemeral() {
    let rng = rand::SystemRandom::new();

    test::from_file("tests/agreement_tests.txt", |section, test_case| {
        assert_eq!(section, "");

        let curve_name = test_case.consume_string("Curve");
        let alg = alg_from_curve_name(&curve_name);
        let peer_public = test_case.consume_bytes("PeerQ");
        let peer_public = untrusted::Input::from(&peer_public);

        match test_case.consume_optional_string("Error") {
            None => {
                let my_private = test_case.consume_bytes("D");
                let rng = test::rand::FixedSliceRandom { bytes: &my_private };
                let my_private =
                    agreement::EphemeralPrivateKey::generate(alg, &rng)?;

                let my_public = test_case.consume_bytes("MyQ");
                let output = test_case.consume_bytes("Output");

                let mut computed_public = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
                let computed_public =
                    &mut computed_public[..my_private.public_key_len()];
                assert!(my_private.compute_public_key(computed_public).is_ok());
                assert_eq!(computed_public, &my_public[..]);

                assert!(agreement::agree_ephemeral(my_private, alg, peer_public,
                                                   (), |key_material| {
                    assert_eq!(key_material, &output[..]);
                    Ok(())
                }).is_ok());
            },

            Some(_) => {
                // In the no-heap mode, some algorithms aren't supported so
                // we have to skip those algorithms' test cases.
                let dummy_private_key =
                    agreement::EphemeralPrivateKey::generate(alg, &rng)?;
                fn kdf_not_called(_: &[u8]) -> Result<(), ()> {
                    panic!("The KDF was called during ECDH when the peer's \
                            public key is invalid.");
                }
                assert!(agreement::agree_ephemeral(dummy_private_key, alg,
                                                   peer_public, (),
                                                   kdf_not_called).is_err());
            }
        }

        return Ok(());
    });
}

fn alg_from_curve_name(curve_name: &str) -> &'static agreement::Algorithm {
    if curve_name == "P-256" {
        &agreement::ECDH_P256
    } else if curve_name == "P-384" {
        &agreement::ECDH_P384
    } else if curve_name == "X25519" {
        &agreement::X25519
    } else {
        panic!("Unsupported curve: {}", curve_name);
    }
}
