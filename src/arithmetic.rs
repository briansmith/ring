// Copyright 2017-2023 Brian Smith.
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

#[macro_use]
mod ffi;

mod constant;

#[cfg(feature = "alloc")]
pub mod bigint;

mod inout;
pub mod montgomery;

mod n0;

pub(crate) use self::ffi::BIGINT_MODULUS_MIN_LIMBS;

#[allow(dead_code)]
const BIGINT_MODULUS_MAX_LIMBS: usize = 8192 / crate::limb::LIMB_BITS;

pub use self::{constant::limbs_from_hex, inout::InOut};
