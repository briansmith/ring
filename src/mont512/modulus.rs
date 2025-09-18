// Copyright 2015-2016 Brian Smith.
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

use crate::{
    arithmetic::{
        bigint::modulus,
        montgomery::{RR, RRR},
    },
    cpu,
    error::KeyRejected,
};

pub struct ValidatedInput<'a> {
    value: modulus::ValidatedInput<'a>,
}

pub struct Modulus<M, E> {
    value: modulus::IntoMont<M, E>,
}

impl<'a> modulus::ValidatedInput<'a> {
    pub fn try_into_mont512(self) -> Result<ValidatedInput<'a>, KeyRejected> {
        if self.len_bits().as_bits() % 512 != 0 {
            return Err(KeyRejected::private_modulus_len_not_multiple_of_512_bits());
        }

        Ok(ValidatedInput { value: self })
    }
}

impl ValidatedInput<'_> {
    pub(crate) fn build<M>(self, cpu: cpu::Features) -> Modulus<M, RR> {
        // TODO: Step 5.d: Verify GCD(p - 1, e) == 1.
        // TODO: Step 5.h: Verify GCD(q - 1, e) == 1.

        // Steps 5.e and 5.f are omitted as explained above.
        let value = self.value.build_value().into_modulus(cpu);

        Modulus { value }
    }
}

impl<M, E> Modulus<M, E> {
    pub(crate) fn value(&self) -> &modulus::IntoMont<M, E> {
        &self.value
    }
}

impl<M> Modulus<M, RR> {
    pub(crate) fn for_exponentiation(self, cpu: cpu::Features) -> Modulus<M, RRR> {
        Modulus {
            value: self.value.into_rrr(cpu),
        }
    }
}
