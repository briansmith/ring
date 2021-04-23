#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = untrusted::Reader::new(untrusted::Input::from(data));
    let _ = ring::io::der::bit_string_with_no_unused_bits(&mut reader);
});
