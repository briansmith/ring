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

use error;
use super::bigint;

pub struct Blinding(*mut BN_BLINDING);

impl Drop for Blinding {
    fn drop(&mut self) { unsafe { GFp_BN_BLINDING_free(self.as_mut_ref()) } }
}

// `Blinding` uniquely owns and references its contents.
unsafe impl Send for Blinding {}

impl Blinding {
    pub fn new() -> Result<Blinding, error::Unspecified> {
        let r = unsafe { GFp_BN_BLINDING_new() };
        if r.is_null() {
            return Err(error::Unspecified);
        }
        Ok(Blinding(r))
    }

    #[cfg(test)]
    pub fn counter(&self) -> u32 { unsafe { (*self.0).counter } }

    pub fn as_mut_ref(&mut self) -> &mut BN_BLINDING { unsafe { &mut *self.0 } }
}

/// Needs to be kept in sync with `bn_blinding_st` in `crypto/rsa/blinding.c`.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct BN_BLINDING {
    a: *mut bigint::BIGNUM,
    ai: *mut bigint::BIGNUM,
    counter: u32,
}

extern {
    fn GFp_BN_BLINDING_new() -> *mut BN_BLINDING;
    fn GFp_BN_BLINDING_free(b: &mut BN_BLINDING);
}

#[cfg(test)]
extern {
    pub static GFp_BN_BLINDING_COUNTER: u32;
}

#[cfg(test)]
mod tests {
    // Testing for this module is done as part of the ring::rsa::signing tests.
}
