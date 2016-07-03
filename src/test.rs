// Copyright 2015-2016 Brian Smith.
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

//! Testing framework.
//!
//! Unlike the rest of *ring*, this testing framework uses panics pretty
//! liberally. It was originally designed for internal use--it drives most of
//! *ring*'s internal tests, and so it is optimized for getting *ring*'s tests
//! written quickly at the expense of some usability. The documentation is
//! lacking. The best way to learn it is to look at some examples. The digest
//! tests are the most complicated because they use named sections. Other tests
//! avoid named sections and so are easier to understand.
//!
//! # Example
//!
//! Input files look like this:
//!
//! ```text
//! # This is a comment.
//!
//! HMAC = SHA1
//! Input = "My test data"
//! Key = ""
//! Output = 61afdecb95429ef494d61fdee15990cabf0826fc
//!
//! HMAC = SHA256
//! Input = "Sample message for keylen<blocklen"
//! Key = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
//! Output = A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790
//! ```
//!
//! Test cases are separated with blank lines. Note how the bytes of the `Key`
//! attribute are specified as a quoted string in the first test case and as
//! hex in the second test case; you can use whichever form is more convenient
//! and you can mix and match within the same file. The empty sequence of bytes
//! can only be represented with the quoted string form (`""`).
//!
//! Here's how you would consume the test data:
//!
//! ```ignore
//! use ring::test;
//!
//! test::from_file("src/hmac_tests.txt", |section, test_case| {
//!     assert_eq!(section, ""); // This test doesn't use named sections.
//!
//!     let digest_alg = test_case.consume_digest_alg("HMAC");
//!     let input = test_case.consume_bytes("Input");
//!     let key = test_case.consume_bytes("Key");
//!     let output = test_case.consume_bytes("Output");
//!
//!     // Do the actual testing here
//! });
//! ```
//!
//! Note that `consume_digest_alg` automatically maps the string "SHA1" to a
//! reference to `digest::SHA1`, "SHA256" to `digest::SHA256`, etc.

use digest;
use std;
use std::string::String;
use std::vec::Vec;
use std::io::BufRead;

/// A test case. A test case consists of a set of named attributes. Every
/// attribute in the test case must be consumed exactly once; this helps catch
/// typos and omissions.
pub struct TestCase {
    attributes: std::collections::HashMap<String, String>,
}

impl TestCase {
    /// Maps the strings "SHA1", "SHA256", "SHA384", and "SHA512" to digest
    /// algorithms, maps "SHA224" to `None`, and panics on other (erroneous)
    /// inputs. "SHA224" is mapped to None because *ring* intentionally does
    /// not support SHA224, but we need to consume test vectors from NIST that
    /// have SHA224 vectors in them.
    pub fn consume_digest_alg(&mut self, key: &str)
                              -> Option<&'static digest::Algorithm> {
        let name = self.consume_string(key);
        match name.as_ref() {
            "SHA1" => Some(&digest::SHA1),
            "SHA224" => None, // We actively skip SHA-224 support.
            "SHA256" => Some(&digest::SHA256),
            "SHA384" => Some(&digest::SHA384),
            "SHA512" => Some(&digest::SHA512),
            _ => panic!("Unsupported digest algorithm: {}", name)
        }
    }

    /// Returns the value of an attribute that is encoded as a sequence of an
    /// even number of hex digits, or as a double-quoted UTF-8 string. The
    /// empty (zero-length) value is represented as "".
    pub fn consume_bytes(&mut self, key: &str) -> Vec<u8> {
        let mut s = self.consume_string(key);
        if s.starts_with("\"") {
            // The value is a quoted strong.
            // XXX: We don't deal with any inner quotes.
            if !s.ends_with("\"") {
                panic!("expected quoted string, found {}", s);
            }
            let _ = s.pop();
            let _ = s.remove(0);
            Vec::from(s.as_bytes())
        } else {
            // The value is hex encoded.
            match from_hex(&s) {
                Ok(s) => s,
                Err(ref err_str) => {
                    panic!("{} in {}", err_str, s);
                }
            }
        }
    }

    /// Returns the value of an attribute that is an integer, in decimal
    /// notation.
    pub fn consume_usize(&mut self, key: &str) -> usize {
        let s = self.consume_string(key);
        s.parse::<usize>().unwrap()
    }

    /// Returns the raw value of an attribute, without any unquoting or
    /// other interpretation.
    pub fn consume_string(&mut self, key: &str) -> String {
        self.consume_optional_string(key)
            .unwrap_or_else(|| panic!("No attribute named \"{}\"", key))
    }

    /// Like `consume_string()` except it returns `None` if the test case
    /// doesn't have the attribute.
    pub fn consume_optional_string(&mut self, key: &str) -> Option<String> {
        self.attributes.remove(key)
    }
}


/// Reads test cases out of the file with the path given by
/// `test_data_relative_file_path`, calling `f` on each vector until `f` fails
/// or until all the test vectors have been read. `f` can indicate failure
/// either by returning `Err()` or by panicking.
pub fn from_file<F>(test_data_relative_file_path: &str, mut f: F)
                    where F: FnMut(&str, &mut TestCase) -> Result<(), ()> {
    let path = std::path::PathBuf::from(test_data_relative_file_path);
    let file = std::fs::File::open(path).unwrap();
    let mut lines = std::io::BufReader::new(&file).lines();

    let mut current_section = String::from("");

    loop {
        match parse_test_case(&mut current_section, &mut lines) {
            Some(ref mut test_case) => {
                f(&current_section, test_case).unwrap();

                // Make sure all the attributes in the test case were consumed.
                assert!(test_case.attributes.is_empty());
            },

            None => {
                break;
            }
        }
    }
}

/// Decode an string of hex digits into a sequence of bytes. The input must
/// have an even number of digits.
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err(
            String::from("Hex string does not have an even number of digits"));
    }

    fn from_hex_digit(d: u8) -> Result<u8, String> {
        if d >= b'0' && d <= b'9' {
            Ok(d - b'0')
        } else if d >= b'a' && d <= b'f' {
            Ok(d - b'a' + 10u8)
        } else if d >= b'A' && d <= b'F' {
            Ok(d - b'A' + 10u8)
        } else {
            Err(format!("Invalid hex digit '{}'", d as char))
        }
    }

    let mut result = Vec::with_capacity(hex_str.len() / 2);
    for digits in hex_str.as_bytes().chunks(2) {
        let hi = try!(from_hex_digit(digits[0]));
        let lo = try!(from_hex_digit(digits[1]));
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

fn parse_test_case(current_section: &mut String,
                   lines: &mut FileLines) -> Option<TestCase> {
    let mut attributes = std::collections::HashMap::new();

    let mut is_first_line = true;
    loop {
        let line = match lines.next() {
            None => None,
            Some(result) => Some(result.unwrap()),
        };

        if cfg!(feature = "test_logging") {
            if let Some(ref text) = line {
                println!("Line: {}", text);
            }
        }

        match line {
            // If we get to EOF when we're not in the middle of a test case,
            // then we're done.
            None if is_first_line => {
                return None;
            },

            // End of the file on a non-empty test cases ends the test case.
            None => {
                return Some(TestCase { attributes: attributes });
            },

            // A blank line ends a test case if the test case isn't empty.
            Some(ref line) if line.len() == 0 => {
                if !is_first_line {
                    return Some(TestCase { attributes: attributes });
                }
                // Ignore leading blank lines.
            },

            // Comments start with '#'; ignore them.
            Some(ref line) if line.starts_with("#") => { },

            Some(ref line) if line.starts_with("[") => {
                assert!(is_first_line);
                assert!(line.ends_with("]"));
                current_section.truncate(0);
                current_section.push_str(line);
                let _ = current_section.pop();
                let _ = current_section.remove(0);
            },

            Some(ref line) => {
                is_first_line = false;

                let parts: Vec<&str> = line.splitn(2, " = ").collect();
                let key = parts[0].trim();
                let value = parts[1].trim();

                // Don't allow the value to be ommitted. An empty value can be
                // represented as an empty quoted string.
                assert!(value.len() != 0);

                // Checking is_none() ensures we don't accept duplicate keys.
                assert!(attributes.insert(String::from(key),
                                          String::from(value)).is_none());
            }
        }
    }
}
