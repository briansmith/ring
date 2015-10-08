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

//! Building blocks for building safe parsers.
//!
//! TODO: More documentation, especially design documentation.

/// Calls `read` with the given input as a `Reader`, ensuring that `read`
/// consumed the entire input. If `read` does not consume the entire input,
/// `incomplete_read` is returned.
pub fn read_all<'a, F, R, E>(input: Input<'a>, incomplete_read: E, read: F)
                             -> Result<R, E>
                             where F: FnOnce(&mut Reader<'a>) -> Result<R, E> {
    let mut input = Reader::new(input);
    let result = try!(read(&mut input));
    if input.at_end() {
        Ok(result)
    } else {
        Err(incomplete_read)
    }
}

/// Like `read_all`, except taking an `FnMut`.
pub fn read_all_mut<'a, F, R, E>(input: Input<'a>, incomplete_read: E, mut read: F)
                                 -> Result<R, E>
                                 where F: FnMut(&mut Reader<'a>)
                                                -> Result<R, E> {
    let mut input = Reader::new(input);
    let result = try!(read(&mut input));
    if input.at_end() {
        Ok(result)
    } else {
        Err(incomplete_read)
    }
}

/// Calls `read` with the given input as a `Reader`, ensuring that `read`
/// consumed the entire input. When `input` is `None`, `read` will be called
/// with `None`.
pub fn read_all_optional<'a, F, R, E>(input: Option<Input<'a>>,
                                      incomplete_read: E, read: F)
                                      -> Result<R, E>
                                      where F: FnOnce(Option<&mut Reader>)
                                                      -> Result<R, E> {
    match input {
        Some(input) => {
            let mut input = Reader::new(input);
            let result = try!(read(Option::Some(&mut input)));
            if input.at_end() {
                Ok(result)
            } else {
                Err(incomplete_read)
            }
        },
        None => read(Option::None)
    }
}

/// A wrapper around `&'a [u8]` that helps in writing panic-free code.
///
/// No methods of `Input` will ever panic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Input<'a> {
    value: no_panic::NoPanicSlice<'a>
}

impl<'a> Input<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Input<'a>> {
        // This limit is important for avoiding integer overflow. In particular,
        // `Reader` assumes that an `i + 1 > i` if `input.value.get(i)` does
        // not return `None`.
        if bytes.len() > 0xFFFF {
            return None
        }
        Some(Input { value: no_panic::NoPanicSlice::new(bytes) })
    }

    #[inline]
    pub fn is_empty(&self) -> bool { self.value.len() == 0 }

    #[inline]
    pub fn len(&self) -> usize { self.value.len() }

    #[inline]
    pub fn as_slice_less_safe(&self) -> &'a [u8] {
        self.value.as_slice_less_safe()
    }
}

#[inline]
pub fn input_equals(a: Input, b: &[u8]) -> bool {
    a.value.as_slice_less_safe() == b
}

#[derive(Debug)]
pub struct Reader<'a> {
    input: no_panic::NoPanicSlice<'a>,
    i: usize
}

/// An index into the already-parsed input of a `Reader`.
pub struct Mark {
    i: usize
}

/// A read-only, forward-only* cursor into the data in an `Input`.
///
/// Using `Reader` to parse input helps to ensure that no byte of the input
/// will be accidentally processed more than once. Using `Reader` in
/// conjunction with `read_all`, `read_all_mut`, and `read_all_optional`
/// helps ensure that no byte of the input is accidentally left unprocessed.
/// The methods of `Reader` never panic, so `Reader` also assists the writing
/// of panic-free code.
///
/// * `Reader` is not strictly forward-only because of the method
/// `get_input_between_marks`, which is provided mainly to support calculating
/// digests over parsed data.
impl<'a> Reader<'a> {
    /// Construct a new Reader for the given input. Use `read_all`,
    /// `read_all_mut`, or `read_all_optional` instead of `Reader::new`
    /// whenever possible.
    #[inline]
    pub fn new(input: Input<'a>) -> Reader<'a> {
        Reader { input: input.value, i: 0 }
    }

    #[inline]
    pub fn at_end(&self) -> bool { self.i == self.input.len() }

    #[inline]
    pub fn get_input_between_marks(&self, mark1: Mark, mark2: Mark)
                                   -> Result<Input<'a>, ()> {
        self.input.subslice(mark1.i, mark2.i)
                  .map(|subslice| Input { value: subslice })
                  .ok_or(())
    }

    #[inline]
    pub fn mark(&self) -> Mark { Mark { i: self.i } }

    pub fn peek(&self, b: u8) -> bool {
        match self.input.get(self.i) {
            Some(actual_b) => return b == *actual_b,
            None => false
        }
    }

    pub fn read_byte(&mut self) -> Result<u8, ()> {
        match self.input.get(self.i) {
            Some(b) => {
                self.i += 1; // safe from overflow; see Input::new.
                Ok(*b)
            }
            None => Err(())
        }
    }

    pub fn skip(&mut self, num_bytes: usize) -> Result<(), ()> {
        self.skip_and_get_input(num_bytes).map(|_| ())
    }

    pub fn skip_and_get_input(&mut self, num_bytes: usize)
                              -> Result<Input<'a>, ()> {
        match self.i.checked_add(num_bytes) {
            Some(new_i) => {
                let ret = self.input.subslice(self.i, new_i)
                                    .map(|subslice| Input { value: subslice })
                                    .ok_or(());
                self.i = new_i;
                ret
            },
            _ => Err(())
        }
    }

    pub fn skip_to_end(&mut self) -> Input<'a> {
        let to_skip = self.input.len() - self.i;
        self.skip_and_get_input(to_skip).unwrap()
    }
}

mod no_panic {

/// A wrapper around a slice that exposes no functions that can panic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NoPanicSlice<'a> {
    bytes: &'a [u8]
}

impl<'a> NoPanicSlice<'a> {
    #[inline]
    pub fn new(bytes: &'a [u8]) -> NoPanicSlice<'a> {
        NoPanicSlice { bytes: bytes }
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&u8> { self.bytes.get(i) }

    #[inline]
    pub fn len(&self) -> usize { self.bytes.len() }

    #[inline]
    pub fn subslice(&self, start: usize, end: usize) -> Option<NoPanicSlice<'a>> {
        if start <= end && end <= self.bytes.len() {
            Some(NoPanicSlice::new(&self.bytes[start..end]))
        } else {
            None
        }
    }

    #[inline]
    pub fn as_slice_less_safe(&self) -> &'a [u8] { self.bytes }
}

} // mod no_panic
