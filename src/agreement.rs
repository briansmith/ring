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

//! Key Agreement: ECDH, including X25519.
//!
//! # Examples
//!
//! ## X25519 (Curve25519) key agreement
//!
//! ```
//! fn x25519_agreement_example() -> Result<(), ()> {
//!
//!     use ring::{agreement, rand};
//!     use ring::input::Input;
//!
//!     let rng = rand::SystemRandom::new();
//!
//!     let my_private_key =
//!         try!(agreement::EphemeralPrivateKey::generate(&agreement::X25519,
//!                                                       &rng));
//!
//!     // Make `my_public_key` a byte slice containing my public key. In a
//!     // real application, this would be sent to the peer in an encoded
//!     // protocol message.
//!     let mut my_public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//!     let my_public_key =
//!         &mut my_public_key[..my_private_key.public_key_len()];
//!     try!(my_private_key.compute_public_key(my_public_key));
//!
//!     // In a real application, the peer public key would be parsed out of a
//!     // protocol message. Here we just generate one.
//!     let mut peer_public_key_buf = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
//!     let peer_public_key;
//!     {
//!         let peer_private_key =
//!            try!(agreement::EphemeralPrivateKey::generate(&agreement::X25519,
//!                                                          &rng));
//!         peer_public_key =
//!             &mut peer_public_key_buf[..peer_private_key.public_key_len()];
//!         try!(peer_private_key.compute_public_key(peer_public_key));
//!     }
//!     let peer_public_key = try!(Input::new(peer_public_key));
//!
//!     // In a real application, the protocol specifies how to determine what
//!     // algorithm was used to generate the peer's private key. Here, we know
//!     // it is X25519 since we just generated it.
//!     let peer_public_key_alg = &agreement::X25519;
//!
//!     let error_value = ();
//!
//!     agreement::agree_ephemeral(my_private_key, peer_public_key_alg,
//!                                peer_public_key, error_value,
//!                                |_key_material| {
//!         // In a real application, we'd apply a KDF to the key material and
//!         // the public keys, as recommended in RFC 7748.
//!         Ok(())
//!     })
//! }
//! ```

pub use ec::PUBLIC_KEY_MAX_LEN;

pub use ec::ecdh::{
    Algorithm,
    EphemeralPrivateKey,

    X25519,

    agree_ephemeral,
};

#[cfg(not(feature = "no_heap"))]
pub use ec::ecdh::{
    ECDH_P256,
    ECDH_P384,
};
