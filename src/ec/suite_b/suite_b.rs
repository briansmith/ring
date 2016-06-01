// Copyright 2016 Brian Smith.
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

//! Common functionality on public keys for NIST curves.

use input;
use input::Input;


pub mod ecdsa;
pub mod ecdh;


/// Parses a public key encoded in uncompressed form.
///
/// XXX: The coordinates are *not* validated to be proper field elements; the
/// caller is responsible for doing that check (this check is done in the C
/// code).
pub fn parse_uncompressed_point<'a>(input: Input<'a>,
                                    elem_and_scalar_len: usize)
                                    -> Result<(&'a [u8], &'a [u8]), ()> {
    input::read_all(input, (), |input| {
        // The encoding must be 4, which is the encoding for
        // "uncompressed".
        let encoding = try!(input.read_byte());
        if encoding != 4 {
            return Err(());
        }
        let x = try!(input.skip_and_get_input(elem_and_scalar_len));
        let y = try!(input.skip_and_get_input(elem_and_scalar_len));
        Ok((x.as_slice_less_safe(), y.as_slice_less_safe()))
    })
}


#[allow(non_camel_case_types)]
enum EC_GROUP { }

extern {
    static EC_GROUP_P256: EC_GROUP;
    static EC_GROUP_P384: EC_GROUP;
}
