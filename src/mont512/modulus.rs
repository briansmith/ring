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

use crate::error::LenMismatchError;
use crate::{
    arithmetic::{
        bigint::{modulus, One},
        montgomery::{RR, RRR},
    },
    cpu,
    error::KeyRejected,
};

pub struct ValidatedInput<'a> {
    value: modulus::ValidatedInput<'a>,
}

pub struct Modulus<M, E> {
    value: modulus::OwnedModulus<M>,
    one: One<M, E>,
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
    pub fn build<M>(self, cpu_features: cpu::Features) -> Modulus<M, RR> {
        // TODO: Step 5.d: Verify GCD(p - 1, e) == 1.
        // TODO: Step 5.h: Verify GCD(q - 1, e) == 1.

        // Steps 5.e and 5.f are omitted as explained above.
        let p = self.value.build_value().into_modulus();
        let pm = p.modulus(cpu_features);
        let one = pm.alloc_uninit();
        let one = One::newRR(one, &pm).unwrap_or_else(|LenMismatchError { .. }| unreachable!());

        Modulus { value: p, one }
    }
}

impl<M, E> Modulus<M, E> {
    pub(crate) fn value(&self) -> &modulus::OwnedModulus<M> {
        &self.value
    }

    pub(crate) fn one(&self) -> &One<M, E> {
        &self.one
    }
}

impl<M> Modulus<M, RR> {
    pub(crate) fn for_exponentiation(self, cpu: cpu::Features) -> Modulus<M, RRR> {
        let Self { value, one } = self;
        let m = &value.modulus(cpu);
        let one = One::newRRR(one, m);
        Modulus { value, one }
    }
}
