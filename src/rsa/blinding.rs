// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use {error, rand};
use core;
use super::{bigint, N};
use arithmetic::montgomery::{R, RR};

pub struct Blinding(Option<Contents>);

struct Contents {
    blinding_factor: bigint::Elem<N, R>,
    blinding_factor_inv: bigint::Elem<N, R>,
    remaining: usize,
}

impl Blinding {
    pub fn new() -> Self { Blinding(None) }

    pub fn blind<F>(&mut self, x: bigint::Elem<N>,
                    e: bigint::PublicExponent, oneRR: &bigint::One<N, RR>,
                    n: &bigint::Modulus<N>, rng: &rand::SecureRandom, f: F)
                    -> Result<bigint::Elem<N>, error::Unspecified>
                    where F: FnOnce(bigint::Elem<N>)
                                    -> Result<bigint::Elem<N>,
                                              error::Unspecified> {
        let old_contents = core::mem::replace(&mut self.0, None);

        let new_contents = match old_contents {
            Some(Contents {
                blinding_factor,
                blinding_factor_inv,
                remaining,
            }) => {
                if remaining > 0 {
                    let blinding_factor =
                        bigint::elem_squared(blinding_factor, n);
                    let blinding_factor_inv =
                        bigint::elem_squared(blinding_factor_inv, n);
                    Ok(Contents {
                        blinding_factor: blinding_factor,
                        blinding_factor_inv: blinding_factor_inv,
                        remaining: remaining - 1,
                    })
                } else {
                    reset(blinding_factor, blinding_factor_inv, e, oneRR, n, rng)
                }
            },

            None => {
                let elem1 = n.zero();
                let elem2 = n.zero();
                reset(elem1, elem2, e, oneRR, n, rng)
            },
        }?;

        let blinded_input =
            bigint::elem_mul(&new_contents.blinding_factor, x, n);
        let blinded_result = f(blinded_input)?;
        let result = bigint::elem_mul(&new_contents.blinding_factor_inv,
                                      blinded_result, n);

        let _ = core::mem::replace(&mut self.0, Some(new_contents));

        Ok(result)
    }

    #[cfg(test)]
    pub fn remaining(&self) -> usize {
        match self.0 {
            Some(Contents { remaining, .. }) => remaining,
            None => { 0 },
        }
    }
}

fn reset(elem1: bigint::Elem<N, R>, elem2: bigint::Elem<N, R>,
         e: bigint::PublicExponent, oneRR: &bigint::One<N, RR>,
         n: &bigint::Modulus<N>, rng: &rand::SecureRandom)
         -> Result<Contents, error::Unspecified> {
    let mut random = bigint::Elem::take_storage(elem1);
    let mut random_inv = bigint::Elem::take_storage(elem2);

    for _ in 0..32 {
        bigint::elem_randomize(&mut random, n, rng)?;
        match bigint::elem_set_to_inverse_blinded(&mut random_inv, &random, n,
                                                  rng) {
            Ok(()) => {
                let random = bigint::elem_mul(oneRR.as_ref(), random, n);
                let random = bigint::elem_exp_vartime(random, e, n);
                return Ok(Contents {
                    blinding_factor: random,
                    blinding_factor_inv: random_inv,
                    remaining: REMAINING_MAX - 1,
                });
            },
            Err(bigint::InversionError::NoInverse) => {}, // continue
            Err(_) => { return Err(error::Unspecified); }
        }
    }

    Err(error::Unspecified)
}


// The paper suggests reusing blinding factors 32 times. Note that this must
// never be zero.
// TODO: citation. TODO: Skepticism.
pub const REMAINING_MAX: usize = 32;

#[cfg(test)]
mod tests {
    // Testing for this module is done as part of the ring::rsa::signing tests.
}
