// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

extern crate ring;

use ring::*;
use std::error::Error;
use std::io::{Read, Write};


fn print_usage(program_name: &str) {
    let program_file_name = std::path::Path::new(program_name)
                                .file_name().unwrap().to_str().unwrap();

    println!(
        "Usage: {} sha256|sha384|sha512 <digest value in hex> <filename>\n\
         \n\
         On success nothing is output, and 0 is returned.\n\
         On failure, an error message is printed, and a non-zero value is returned\n\
         \n\
         Example:\n\
         {} sha256 \
           def7352915ac84bea5e2ed16f6fff712d35de519799777bf927e2a567ab53b7e \
           LICENSE",
         program_file_name, program_file_name);
}

fn run(digest_name: &str, expected_digest_hex: &str,
       file_path: &std::path::Path) -> Result<(), &'static str> {
    let digest_alg = match digest_name {
        "sha256" => &digest::SHA256,
        "sha384" => &digest::SHA384,
        "sha512" => &digest::SHA512,
        _ => { return Err("unsupported digest algorithm"); }
    };

    let mut ctx = digest::Context::new(digest_alg);

    {
        let mut file = match std::fs::File::open(file_path) {
            Ok(file) => file,
            // TODO: don't use panic here.
            Err(why) => panic!("couldn't open {}: {}", file_path.display(),
                               why.description())
        };

        let mut chunk = vec![0u8; 128 * 1024];
        loop {
            match file.read(&mut chunk[..]) {
                Ok(0) => break,
                Ok(bytes_read) => ctx.update(&chunk[0..bytes_read]),
                // TODO: don't use panic here
                Err(why) => panic!("couldn't open {}: {}", file_path.display(),
                               why.description())
            }
        }
    }

    let actual_digest = ctx.finish();

    let matched = match from_hex(&expected_digest_hex) {
        Ok(expected) => actual_digest.as_ref() == &expected[..],
        Err(msg) => panic!("syntactically invalid digest: {} in {}", msg,
                           &expected_digest_hex),
    };

    match matched {
        true => Ok(()),
        false => Err("digest mismatch") // TODO: calculated digest.
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
        let hi = from_hex_digit(digits[0])?;
        let lo = from_hex_digit(digits[1])?;
        result.push((hi * 0x10) | lo);
    }
    Ok(result)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "-h") {
        print_usage(&args[0]);
        return
    } else if args.len() < 4 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    match run(&args[1], &args[2], std::path::Path::new(&args[3])) {
        Ok(x) => x,
        Err(s) => {
            let _ = writeln!(&mut std::io::stderr(), "{}", s);
            std::process::exit(1)
        }
    }
}
