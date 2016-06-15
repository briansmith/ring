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

use std;
use std::string::String;
use std::vec::Vec;
use std::io::BufRead;
use super::digest;

pub struct TestCase {
    attributes: std::collections::HashMap<String, String>,
}

impl TestCase {
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

    pub fn consume_usize(&mut self, key: &str) -> usize {
        let s = self.consume_string(key);
        s.parse::<usize>().unwrap()
    }

    pub fn consume_string(&mut self, key: &str) -> String {
        self.consume_optional_string(key)
            .unwrap_or_else(|| panic!("No attribute named \"{}\"", key))
    }

    pub fn consume_optional_string(&mut self, key: &str) -> Option<String> {
        self.attributes.remove(key)
    }
}

pub fn run<F>(test_data_relative_file_path: &str, f: F)
              where F: Fn(&str, &mut TestCase) -> Result<(), ()> {
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

pub fn run_mut<F>(test_data_relative_file_path: &str, f: &mut F)
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
