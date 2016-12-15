extern crate base64;

use std;

// We want to use pem files in tests in src/ and also tests/ without exposing
// pem in the public API. This file can be used with `include!` in src/
// and used as a typical module in integration tests.

type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

pub fn read_pem_section(lines: & mut FileLines, section_name: &str)
                    -> std::vec::Vec<u8> {
    // Skip comments and header
    let begin_section = format!("-----BEGIN {}-----", section_name);
    loop {
        let line = lines.next().unwrap().unwrap();
        if line == begin_section {
            break;
        }
    }

    let mut b64_str = std::string::String::new();

    let end_section = format!("-----END {}-----", section_name);
    loop {
        let line = lines.next().unwrap().unwrap();
        if line == end_section {
            break;
        }
        b64_str.push_str(&line);
    }

    base64::decode(&b64_str).unwrap()
}
