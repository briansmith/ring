// Copyright 2015-2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{N, base};
use crate::{
    arithmetic::{bigint, montgomery::RR},
    cpu, error,
    io::{self, der, der_writer},
};
use alloc::boxed::Box;

pub(super) use base::public_key::ValidatedInput;

/// An RSA Public Key.
#[derive(Clone)]
pub struct PublicKey {
    inner: base::public_key::PublicKey<bigint::BoxedIntoMont<N, RR>>,
    serialized: Box<[u8]>,
}

derive_debug_self_as_ref_hex_bytes!(PublicKey);

impl PublicKey {
    pub(super) fn new(
        input: ValidatedInput<'_>,
        cpu_features: cpu::Features,
    ) -> Result<Self, error::KeyRejected> {
        let inner = input.build_boxed(cpu_features);

        let n_bytes = input.n().input();
        let e_bytes = input.e_input();

        // TODO: Remove this re-parsing, and stop allocating this here.
        // Instead we should serialize on demand without allocation, from
        // `Modulus::be_bytes()` and `Exponent::be_bytes()`. Once this is
        // fixed, merge `Inner` back into `PublicKey`.
        let n_bytes = io::Positive::from_be_bytes(n_bytes)
            .map_err(|_: error::Unspecified| error::KeyRejected::unexpected_error())?;
        let e_bytes = io::Positive::from_be_bytes(e_bytes)
            .map_err(|_: error::Unspecified| error::KeyRejected::unexpected_error())?;
        let serialized = der_writer::write_all(der::Tag::Sequence, &|output| {
            der_writer::write_positive_integer(output, &n_bytes)?;
            der_writer::write_positive_integer(output, &e_bytes)
        })
        .map_err(|_: io::TooLongError| error::KeyRejected::unexpected_error())?;

        Ok(Self { inner, serialized })
    }

    /// The length, in bytes, of the public modulus.
    ///
    /// The modulus length is rounded up to a whole number of bytes if its
    /// bit length isn't a multiple of 8.
    pub fn modulus_len(&self) -> usize {
        self.inner
            .reborrow()
            .n()
            .len_bits()
            .as_usize_bytes_rounded_up()
    }

    pub(super) fn inner(&self) -> base::public_key::PublicKey<bigint::IntoMont<'_, N, RR>> {
        self.inner.reborrow()
    }
}

// XXX: Refactor `signature::KeyPair` to get rid of this.
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}
