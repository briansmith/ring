// Copyright 2017 Peter Reid
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

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod intel {
extern "C" {
    fn GFp_cpuid(result: *mut u32, leaf: u32);
    fn GFp_xcr0_low() -> u32;
    static mut GFp_ia32cap_P: [u32; 4];
}

/// Returns (eax, ebx, ecx, edx) for a cpuid leaf specified in EAX. ECX is 0.
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut result = [0u32; 4];
    unsafe {
        GFp_cpuid(result.as_mut_ptr(), leaf);
    }
    (result[0], result[1], result[2], result[3])
}

fn xcr0_lo() -> u32 {
    unsafe { GFp_xcr0_low() }
}

fn u32_le(chars: &[u8; 4]) -> u32 {
    (chars[0] as u32)
        | ((chars[1] as u32) << 8)
        | ((chars[2] as u32) << 16)
        | ((chars[3] as u32) << 24)
}

fn vendor_id(start: &[u8; 4], middle: &[u8; 4], end: &[u8; 4]) -> (u32, u32, u32) {
    (u32_le(start), u32_le(middle), u32_le(end))
}

fn bit_on(word: u32, bit: u8) -> bool {
    (word & (1<<bit)) != 0
}

fn set_bit(dest: &mut u32, bit_index: u8, bit_value: bool) {
    if bit_value {
        *dest = *dest | (1 << bit_index);
    } else {
        *dest = *dest & !(1 << bit_index);
    }
}

fn and_bit_with(dest: &mut u32, bit_index: u8, bit_mask: bool) {
    if !bit_mask {
        *dest = *dest & !(1 << bit_index);
    }
}

pub fn cpuid_setup() {
    let (leaf_max, vendor_start, vendor_end, vendor_middle) = cpuid(0);
    let vendor = (vendor_start, vendor_middle, vendor_end);
    let (_, _, mut feature_ecx, mut feature_edx) = cpuid(1);
    let intel = vendor == vendor_id(b"Genu", b"ineI", b"ntel");
    let amd = vendor == vendor_id(b"Auth", b"enti", b"cAMD");
    let ymm = bit_on(feature_ecx, 27) && (xcr0_lo()&0b110)==0b110;
    let xop = amd
        && cpuid(0x80000000).0 >= 0x80000001
        && bit_on(cpuid(0x80000001).2, 11);
    let mut extended_features = if leaf_max >= 7 { cpuid(7).1 } else { 0 };
    set_bit(&mut feature_edx, 20, false); // used by OpenSSL, but not ring
    set_bit(&mut feature_edx, 28, false); // used by OpenSSL, but not ring
    set_bit(&mut feature_edx, 30, intel);

    set_bit(&mut feature_ecx, 11, amd && xop && ymm);
    and_bit_with(&mut feature_ecx, 12, ymm);
    and_bit_with(&mut feature_ecx, 28, ymm);

    and_bit_with(&mut extended_features, 5, ymm);

    unsafe {
        GFp_ia32cap_P[0] = feature_edx;
        GFp_ia32cap_P[1] = feature_ecx;
        GFp_ia32cap_P[2] = extended_features;
        GFp_ia32cap_P[3] = 0;
    }
}

#[test]
fn cpuid_vendor_id() {
    fn is_in_printable_range(x: u32) {
        assert!(x >= 0x20 && x <= 0x7E);
    }

    let vendor_id = cpuid(0);
    for word in [vendor_id.1, vendor_id.2, vendor_id.3].iter() {
        is_in_printable_range((*word >> 0) & 0xff);
        is_in_printable_range((*word >> 8) & 0xff);
        is_in_printable_range((*word >> 16) & 0xff);
        is_in_printable_range((*word >> 24) & 0xff);
    }
}
}


#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use self::intel::cpuid_setup;
