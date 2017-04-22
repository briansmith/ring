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

//! Elliptic curve operations on Curve25519.


// Keep this in sync with `fe` in curve25519/internal.h.
pub type Elem = [i32; ELEM_LIMBS];
const ELEM_LIMBS: usize = 10;
pub const ELEM_LEN: usize = 32;

// Keep this in sync with `ge_p3` in curve25519/internal.h.
#[repr(C)]
pub struct ExtPoint {
    x: Elem,
    y: Elem,
    z: Elem,
    t: Elem,
}

impl ExtPoint {
    pub fn new_at_infinity() -> Self {
        ExtPoint {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
            t: [0; ELEM_LIMBS],
        }
    }

    pub fn invert_vartime(&mut self) {
        for i in 0..ELEM_LIMBS {
            self.x[i] = -self.x[i];
            self.t[i] = -self.t[i];
        }
    }
}

// Keep this in sync with `ge_p2` in curve25519/internal.h.
#[repr(C)]
pub struct Point {
    x: Elem,
    y: Elem,
    z: Elem,
}

impl Point {
    pub fn new_at_infinity() -> Self {
        Point {
            x: [0; ELEM_LIMBS],
            y: [0; ELEM_LIMBS],
            z: [0; ELEM_LIMBS],
        }
    }
}
