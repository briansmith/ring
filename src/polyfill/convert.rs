// Copyright 2018 Brian Smith.
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

/// An approximation of `core::convert::From` that lets us define our own
/// conversions between types defined outside this crate.
///
/// Do not use this this in situations where `From` could be used.
pub trait From_<F>: Sized {
    fn from_(value: F) -> Self;
}

pub trait Into_<T>
where
    T: Sized,
{
    fn into_(self) -> T;
}

impl<T, F> Into_<T> for F
where
    T: From_<F>,
{
    #[inline]
    fn into_(self) -> T {
        T::from_(self)
    }
}
