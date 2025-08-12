#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = untrusted::Reader::new(untrusted::Input::from(data));
    let _ = ring::io::der::read_tag_and_get_value(&mut reader);
});
