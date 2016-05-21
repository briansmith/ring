// Copyright 2015 Brian Smith.
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


struct PrivateKey {
    bytes: [u8; SCALAR_MAX_BYTES],
}

const INVALID_ZERO_PRIVATE_KEY_BYTES: [u8; SCALAR_MAX_BYTES] =
    [0u8; SCALAR_MAX_BYTES];

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")] type Limb = u64;
#[cfg(target_pointer_width = "32")] type Limb = u32;

const ELEM_MAX_BITS: usize = 384;
const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;

const SCALAR_MAX_BYTES: usize = ELEM_MAX_BYTES;


#[allow(non_camel_case_types)]
#[cfg(not(feature = "no_heap"))]
enum EC_GROUP { }

#[cfg(not(feature = "no_heap"))]
extern {
    fn EC_GROUP_P256() -> *const EC_GROUP;
    fn EC_GROUP_P384() -> *const EC_GROUP;
}

#[cfg(not(feature = "no_heap"))]
pub mod ecdh;

#[cfg(not(feature = "no_heap"))]
pub mod ecdsa;

pub mod eddsa;
