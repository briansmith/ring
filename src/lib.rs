// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

extern crate libc;

#[cfg(test)]
extern crate rustc_serialize;

// All code belongs in submodules, not in lib.rs. The public interface of all
// submodules is re-exported from this one, and users are expected to use this
// module instead of the submodules.

mod digest;
pub use digest::{
    Digest, digest,
    MD5, MD5_DIGEST_LEN,
    SHA1, SHA1_DIGEST_LEN,
    SHA256, SHA256_DIGEST_LEN,
    SHA384, SHA384_DIGEST_LEN,
    SHA512, SHA512_DIGEST_LEN,
};

mod ffi;
pub mod ecc;
pub mod rand;
mod rsa;
