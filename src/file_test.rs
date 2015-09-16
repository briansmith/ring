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

use rustc_serialize::hex::FromHex;
use super::*;
use std;
use std::io::BufRead;

pub struct TestCase {
    attributes: std::collections::HashMap<String, String>,
}

impl TestCase {
    pub fn consume_digest_alg(&mut self, key: &str)
                              -> Option<&'static digest::Algorithm> {
        let name = self.consume_string(key);
        match name.as_ref() {
            "MD5" => Some(&digest::MD5),
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
            s.pop();
            s.remove(0);
            Vec::from(s.as_bytes())
        } else {
            // The value is hex encoded.
            match s.from_hex() {
                Ok(value) => value,
                Err(..) => panic!("Invalid hex encoding of attribute: {}", s)
            }
        }
    }

    pub fn consume_usize(&mut self, key: &str) -> usize {
        let s = self.consume_string(key);
        s.parse::<usize>().unwrap()
    }

    pub fn consume_string(&mut self, key: &str) -> String {
        self.attributes.remove(key)
                       .unwrap_or_else(
                            || panic!("No attribute named \"{}\"", key))
    }
}

pub fn run(test_data_relative_file_path: &str, test: fn(&mut TestCase)) {
    let path = std::path::PathBuf::from(test_data_relative_file_path);
    let file = std::fs::File::open(path).unwrap();
    let mut lines = std::io::BufReader::new(&file).lines();

    loop {
        match parse_test_case(&mut lines) {
            Some(ref mut test_case) => {
                test(test_case);

                // Make sure all the attributes in the test case were consumed.
                assert!(test_case.attributes.is_empty());
            },

            None => {
                break;
            }
        }
    }
}

type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

fn parse_test_case(lines: &mut FileLines) -> Option<TestCase> {
    let mut attributes = std::collections::HashMap::new();

    let mut is_first_line = true;
    loop {
        let line = match lines.next() {
            None => None,
            Some(result) => Some(result.unwrap()),
        };

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

            Some(line) => {
                is_first_line = false;

                println!("Line: {}", line);

                let parts: Vec<&str> = line.splitn(2, '=').collect();
                let key = parts[0].trim();
                let value = parts[1].trim();

                // Checking is_none() ensures we don't accept duplicate keys.
                assert!(attributes.insert(String::from(key),
                                          String::from(value)).is_none());
            }
        }
    }
}
