// Copyright 2015-2021 Brian Smith.
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

use ring::{
    error,
    io::der::{positive_integer, small_nonnegative_integer},
};

#[test]
fn test_small_nonnegative_integer() {
    with_good_i(ZERO_INTEGER, |input| {
        assert_eq!(small_nonnegative_integer(input)?, 0x00);
        Ok(())
    });
    for &(test_in, test_out) in GOOD_POSITIVE_INTEGERS.iter() {
        with_good_i(test_in, |input| {
            assert_eq!(small_nonnegative_integer(input)?, test_out);
            Ok(())
        });
    }
    for &test_in in BAD_NONNEGATIVE_INTEGERS.iter() {
        with_bad_i(test_in, |input| {
            let _ = small_nonnegative_integer(input)?;
            Ok(())
        });
    }
}

#[test]
fn test_positive_integer() {
    with_bad_i(ZERO_INTEGER, |input| {
        let _ = positive_integer(input)?;
        Ok(())
    });
    for &(test_in, test_out) in GOOD_POSITIVE_INTEGERS.iter() {
        with_good_i(test_in, |input| {
            let test_out = [test_out];
            assert_eq!(
                positive_integer(input)?.big_endian_without_leading_zero(),
                &test_out[..]
            );
            Ok(())
        });
    }
    for &test_in in BAD_NONNEGATIVE_INTEGERS.iter() {
        with_bad_i(test_in, |input| {
            let _ = positive_integer(input)?;
            Ok(())
        });
    }
}

fn with_good_i<F, R>(value: &[u8], f: F)
where
    F: FnOnce(&mut untrusted::Reader) -> Result<R, error::Unspecified>,
{
    let r = untrusted::Input::from(value).read_all(error::Unspecified, f);
    assert!(r.is_ok());
}

fn with_bad_i<F, R>(value: &[u8], f: F)
where
    F: FnOnce(&mut untrusted::Reader) -> Result<R, error::Unspecified>,
{
    let r = untrusted::Input::from(value).read_all(error::Unspecified, f);
    assert!(r.is_err());
}

static ZERO_INTEGER: &[u8] = &[0x02, 0x01, 0x00];

static GOOD_POSITIVE_INTEGERS: &[(&[u8], u8)] = &[
    (&[0x02, 0x01, 0x01], 0x01),
    (&[0x02, 0x01, 0x02], 0x02),
    (&[0x02, 0x01, 0x7e], 0x7e),
    (&[0x02, 0x01, 0x7f], 0x7f),
    // Values that need to have an 0x00 prefix to disambiguate them from
    // them from negative values.
    (&[0x02, 0x02, 0x00, 0x80], 0x80),
    (&[0x02, 0x02, 0x00, 0x81], 0x81),
    (&[0x02, 0x02, 0x00, 0xfe], 0xfe),
    (&[0x02, 0x02, 0x00, 0xff], 0xff),
];

static BAD_NONNEGATIVE_INTEGERS: &[&[u8]] = &[
    &[],           // At end of input
    &[0x02],       // Tag only
    &[0x02, 0x00], // Empty value
    // Length mismatch
    &[0x02, 0x00, 0x01],
    &[0x02, 0x01],
    &[0x02, 0x01, 0x00, 0x01],
    &[0x02, 0x01, 0x01, 0x00], // Would be valid if last byte is ignored.
    &[0x02, 0x02, 0x01],
    // Negative values
    &[0x02, 0x01, 0x80],
    &[0x02, 0x01, 0xfe],
    &[0x02, 0x01, 0xff],
    // Values that have an unnecessary leading 0x00
    &[0x02, 0x02, 0x00, 0x00],
    &[0x02, 0x02, 0x00, 0x01],
    &[0x02, 0x02, 0x00, 0x02],
    &[0x02, 0x02, 0x00, 0x7e],
    &[0x02, 0x02, 0x00, 0x7f],
];
