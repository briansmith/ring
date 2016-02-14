// Copyright 2015-2016 Brian Smith.
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

//! The Input/Reader framework for safe, fast, zero-heap-usage protocol parsing.
//!
//! The Input/Reader framework goes beyond Rust's normal safety guarantees by
//! also guaranteeing that parsing will be panic-free, as long as
//! `Input::as_slice_less_safe` is not used. It avoids copying data and heap
//! allocation and strives to prevent common pitfalls such as accidentally
//! parsing input bytes multiple times. In order to meet these goals, the
//! Input/Reader framework is limited in functionality such that it works best
//! for input languages with a small fixed amount of lookahead such as ASN.1,
//! TLS, TCP/IP, and many other networking, IPC, and related protocols.
//! Input languages that require more lookahead and/or backtracking require
//! some significant contortions to parse using this framework. It would not be
//! realistic to use it for parsing programming language code or natural
//! language text, for example.
//!
//! The overall pattern for using the Input/Reader framework is:
//!
//! 1. Write a recursive-descent-style parser for the input language, where the
//!    input data is given as a `&mut Reader` parameter to each function. Each
//!    function should have a return type of `Result<V, E>` for some value type
//!    `V` and some error type `E`, either or both of which may be `()`.
//!    Functions for parsing the lowest-level language constructs should be
//!    defined. Those lowest-level functions will parse their inputs using
//!    `Reader::read_byte`, `Reader::peek`, and similar functions. Higher-level
//!    language constructs are then parsed by calling the lower-level functions
//!    in sequence.
//!
//! 2. Wrap the top-most functions of your recursive-descent parser in
//!    functions that take their input data as an `Input`. The wrapper
//!    functions should pass the `Input` to `read_all` or one of the variants.
//!    The wrapper functions are the only ones that should be exposed outside
//!    the parser's module.
//!
//! 3. After receiving the input data to parse, wrap it in an `Input` using
//!    `Input::new` as early as possible. Pass the `Input` to the wrapper
//!    functions when they need to be parsed.
//!
//! In general parsers built using `Reader` do not need to explicitly check
//! for end-of-input unless they are parsing optional constructs, because
//! `Reader::read_byte()` will return `Err(())` on end-of-input. Similarly,
//! parsers using `Reader` generally don't need to check for extra junk at the
//! end of the input as long as the parser's API uses the pattern described
//! above, as `read_all` and its variants automatically check for trailing
//! junk. `Reader::skip_to_end` should be used when the end of the input should
//! be ignored without triggering an error.
//!
//! The Input/Reader framework works best when all processing of the input data
//! is done through the `Input` and `Reader` types. In particular, avoid trying
//! to parse input data using functions that take slices. However, when you
//! need to access a part of the input data as a slice,
//! `Input::as_slice_less_safe` can be used. *ring* is in the process of
//! migrating fully to using `Input` for all inputs to the crypto functions,
//! which means that `Input::as_slice_less_safe` currently needs to be used
//! frequently to use *ring*'s crypto functionality. This will change soon.
//!
//! [libwebpki](https://github.com/briansmith/webpki)'s X.509 certificate
//! parser is a good example of a real-world use of the Input/Reader framework
//! to parse complex data.

use core;

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
            let result = try!(read(Some(&mut input)));
            if input.at_end() {
                Ok(result)
            } else {
                Err(incomplete_read)
            }
        },
        None => read(None)
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
    /// Construct a new `Input` for the given input `bytes`.
    pub fn new(bytes: &'a [u8]) -> Result<Input<'a>, ()> {
        // This limit is important for avoiding integer overflow. In particular,
        // `Reader` assumes that an `i + 1 > i` if `input.value.get(i)` does
        // not return `None`.
        if bytes.len() > core::usize::MAX - 1 {
            return Err(())
        }
        Ok(Input { value: no_panic::NoPanicSlice::new(bytes) })
    }

    /// Returns `true` if the input is empty and false otherwise.
    #[inline]
    pub fn is_empty(&self) -> bool { self.value.len() == 0 }

    /// Returns the length of the `Input`.
    #[inline]
    pub fn len(&self) -> usize { self.value.len() }

    /// Access the input as a slice so it can be processed by functions that
    /// are not written using the Input/Reader framework.
    #[inline]
    pub fn as_slice_less_safe(&self) -> &'a [u8] {
        self.value.as_slice_less_safe()
    }
}

/// Returns `true` if the contents of `Input` `a` are equal to the contents of
/// slice `b`, and `false` otherwise.
#[inline]
pub fn input_equals(a: Input, b: &[u8]) -> bool {
    a.value.as_slice_less_safe() == b
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
/// \* `Reader` is not strictly forward-only because of the method
/// `get_input_between_marks`, which is provided mainly to support calculating
/// digests over parsed data.
#[derive(Debug)]
pub struct Reader<'a> {
    input: no_panic::NoPanicSlice<'a>,
    i: usize
}

/// An index into the already-parsed input of a `Reader`.
pub struct Mark {
    i: usize
}

impl<'a> Reader<'a> {
    /// Construct a new Reader for the given input. Use `read_all`,
    /// `read_all_mut`, or `read_all_optional` instead of `Reader::new`
    /// whenever possible.
    #[inline]
    pub fn new(input: Input<'a>) -> Reader<'a> {
        Reader { input: input.value, i: 0 }
    }

    /// Returns `true` if the reader is at the end of the input, and `false`
    /// otherwise.
    #[inline]
    pub fn at_end(&self) -> bool { self.i == self.input.len() }

    /// Returns an `Input` for already-parsed input that has had its boundaries
    /// marked using `mark`.
    #[inline]
    pub fn get_input_between_marks(&self, mark1: Mark, mark2: Mark)
                                   -> Result<Input<'a>, ()> {
        self.input.subslice(mark1.i, mark2.i)
                  .map(|subslice| Input { value: subslice })
                  .ok_or(())
    }

    /// Return the current position of the `Reader` for future use in a call
    /// to `get_input_between_marks`.
    #[inline]
    pub fn mark(&self) -> Mark { Mark { i: self.i } }

    /// Returns `true` if there is at least one more byte in the input and that
    /// byte is equal to `b`, and false otherwise.
    pub fn peek(&self, b: u8) -> bool {
        match self.input.get(self.i) {
            Some(actual_b) => return b == *actual_b,
            None => false
        }
    }

    /// Reads the next input byte.
    ///
    /// Returns `Ok(b)` where `b` is the next input byte, or `Err(())` if the
    /// `Reader` is at the end of the input.
    pub fn read_byte(&mut self) -> Result<u8, ()> {
        match self.input.get(self.i) {
            Some(b) => {
                self.i += 1; // safe from overflow; see Input::new.
                Ok(*b)
            }
            None => Err(())
        }
    }

    /// Skips `num_bytes` of the input.
    ///
    /// Returns `Ok(())` if there are at least `num_bytes` of input remaining,
    /// and `Err(())` otherwise.
    pub fn skip(&mut self, num_bytes: usize) -> Result<(), ()> {
        self.skip_and_get_input(num_bytes).map(|_| ())
    }

    /// Skips `num_bytes` of the input, returning the skipped input as an `Input`.
    ///
    /// Returns `Ok(i)` where `i` is an `Input` if there are at least
    /// `num_bytes` of input remaining, and `Err(())` otherwise.
    pub fn skip_and_get_input(&mut self, num_bytes: usize)
                              -> Result<Input<'a>, ()> {
        let new_i = try!(self.i.checked_add(num_bytes).ok_or(()));
        let ret = self.input.subslice(self.i, new_i)
                            .map(|subslice| Input { value: subslice })
                            .ok_or(());
        self.i = new_i;
        ret
    }

    /// Skips the reader to the end of the input, returning the skipped input
    /// as an `Input`.
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
