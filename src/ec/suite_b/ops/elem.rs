// Copyright 2017 Brian Smith.
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

use arithmetic::montgomery::ReductionEncoding;
use core::marker::PhantomData;
use limb::*;

/// Elements of ℤ/mℤ for some modulus *m*. Elements are always fully reduced
/// with respect to *m*; i.e. the 0 <= x < m for every value x.
#[derive(Clone)]
pub struct Elem<M, E: ReductionEncoding> {
    // XXX: pub
    pub limbs: [Limb; MAX_LIMBS],

    /// The modulus *m* for the ring ℤ/mℤ for which this element is a value.
    pub m: PhantomData<M>,

    /// The number of Montgomery factors that need to be canceled out from
    /// `value` to get the actual value.
    pub encoding: PhantomData<E>,
}

impl<M, E: ReductionEncoding> Elem<M, E> {
    // There's no need to convert `value` to the Montgomery domain since
    // 0 * R**2 (mod m) == 0, so neither the modulus nor the encoding are needed
    // as inputs for constructing a zero-valued element.
    pub fn zero() -> Elem<M, E> {
        Elem {
            limbs: [0; MAX_LIMBS],
            m: PhantomData,
            encoding: PhantomData,
        }
    }
}

pub const MAX_LIMBS: usize = (384 + (LIMB_BITS - 1)) / LIMB_BITS;
