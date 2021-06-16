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

//! Building blocks for parsing DER-encoded ASN.1 structures.
//!
//! This module contains the foundational parts of an ASN.1 DER parser.

use super::Positive;
use crate::error;

pub const CONSTRUCTED: u8 = 1 << 5;
pub const CONTEXT_SPECIFIC: u8 = 2 << 6;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    OID = 0x06,
    Sequence = CONSTRUCTED | 0x10, // 0x30
    UTCTime = 0x17,
    GeneralizedTime = 0x18,

    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

impl From<Tag> for usize {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as Self
    } // XXX: narrowing conversion.
}

pub fn expect_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
) -> Result<untrusted::Input<'a>, error::Unspecified> {
    let (actual_tag, inner) = read_tag_and_get_value(input)?;
    if usize::from(tag) != usize::from(actual_tag) {
        return Err(error::Unspecified);
    }
    Ok(inner)
}

pub fn read_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<(u8, untrusted::Input<'a>), error::Unspecified> {
    let tag = input.read_byte()?;
    if (tag & 0x1F) == 0x1F {
        return Err(error::Unspecified); // High tag number form is not allowed.
    }

    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length.
    let length = match input.read_byte()? {
        n if (n & 0x80) == 0 => usize::from(n),
        0x81 => {
            let second_byte = input.read_byte()?;
            if second_byte < 128 {
                return Err(error::Unspecified); // Not the canonical encoding.
            }
            usize::from(second_byte)
        }
        0x82 => {
            let second_byte = usize::from(input.read_byte()?);
            let third_byte = usize::from(input.read_byte()?);
            let combined = (second_byte << 8) | third_byte;
            if combined < 256 {
                return Err(error::Unspecified); // Not the canonical encoding.
            }
            combined
        }
        _ => {
            return Err(error::Unspecified); // We don't support longer lengths.
        }
    };

    let inner = input.read_bytes(length)?;
    Ok((tag, inner))
}

pub fn bit_string_with_no_unused_bits<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, error::Unspecified> {
    nested(input, Tag::BitString, error::Unspecified, |value| {
        let unused_bits_at_end = value.read_byte().map_err(|_| error::Unspecified)?;
        if unused_bits_at_end != 0 {
            return Err(error::Unspecified);
        }
        Ok(value.read_bytes_to_end())
    })
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested<'a, F, R, E: Copy>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
    error: E,
    decoder: F,
) -> Result<R, E>
where
    F: FnOnce(&mut untrusted::Reader<'a>) -> Result<R, E>,
{
    let inner = expect_tag_and_get_value(input, tag).map_err(|_| error)?;
    inner.read_all(error, decoder)
}

fn nonnegative_integer<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>, error::Unspecified> {
    let value = expect_tag_and_get_value(input, Tag::Integer)?;
    match value
        .as_slice_less_safe()
        .split_first()
        .ok_or(error::Unspecified)?
    {
        // Zero or leading zero.
        (0, rest) => {
            match rest.first() {
                // Zero.
                None => Ok(value),
                // Necessary leading zero.
                Some(&second) if second & 0x80 == 0x80 => Ok(untrusted::Input::from(rest)),
                // Unnecessary leading zero.
                _ => Err(error::Unspecified),
            }
        }
        // Positive value with no leading zero.
        (first, _) if first & 0x80 == 0 => Ok(value),
        // Negative value.
        (_, _) => Err(error::Unspecified),
    }
}

/// Parse as integer with a value in the in the range [0, 255], returning its
/// numeric value. This is typically used for parsing version numbers.
#[inline]
pub fn small_nonnegative_integer(input: &mut untrusted::Reader) -> Result<u8, error::Unspecified> {
    let value = nonnegative_integer(input)?;
    match *value.as_slice_less_safe() {
        [b] => Ok(b),
        _ => Err(error::Unspecified),
    }
}

/// Parses a positive DER integer, returning the big-endian-encoded value,
/// sans any leading zero byte.
pub fn positive_integer<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<Positive<'a>, error::Unspecified> {
    let value = nonnegative_integer(input)?;
    Positive::from_be_bytes(value)
}
