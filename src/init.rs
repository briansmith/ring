// Copyright 2016 Brian Smith.
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

#[allow(unsafe_code)]
#[inline(always)]
#[cfg(not(all(target_arch = "aarch64", target_os = "ios")))]
pub fn init_once() {
    extern crate std;
    static INIT: std::sync::Once = std::sync::ONCE_INIT;
    INIT.call_once(|| unsafe { OPENSSL_cpuid_setup() });
}

#[cfg(not(all(target_arch = "aarch64", target_os = "ios")))]
extern {
    fn OPENSSL_cpuid_setup();
}

#[cfg(all(target_arch = "aarch64", target_os = "ios"))]
pub fn init_once() {
}
