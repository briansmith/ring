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

use libc;

/// Appends `num_bytes` of cryptographically-secure random bytes to `out`.
pub fn append_secure_random(out: &mut Vec<u8>, num_bytes: usize)
                            -> Result<(), ()> {
    // XXX: Why isn't usize the same as libc::size_t?

    let old_len = out.len();
    out.reserve(num_bytes);
    unsafe {
        out.set_len(old_len + num_bytes);
        if RAND_bytes(out.get_unchecked_mut(old_len),
                      num_bytes as libc::size_t) != 1 {
            out.set_len(old_len);
            return Err(());
        }
    }
    return Ok(())
}

extern {

fn RAND_bytes(buf: *mut libc::uint8_t, len: libc::size_t) -> libc::c_int;

}
