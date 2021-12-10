// Copyright 2016-2021 Brian Smith.
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

#![cfg_attr(
    not(any(target_arch = "x86", target_arch = "x86_64")),
    allow(dead_code)
)]

use crate::c;

pub(crate) struct Feature {
    word: usize,
    mask: u32,
}

impl Feature {
    #[allow(clippy::needless_return)]
    #[inline(always)]
    pub fn available(&self, _: super::Features) -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            return self.mask == self.mask & unsafe { OPENSSL_ia32cap_P[self.word] };
        }

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            return false;
        }
    }
}

pub(crate) const FXSR: Feature = Feature {
    word: 0,
    mask: 1 << 24,
};

pub(crate) const PCLMULQDQ: Feature = Feature {
    word: 1,
    mask: 1 << 1,
};

pub(crate) const SSSE3: Feature = Feature {
    word: 1,
    mask: 1 << 9,
};

#[cfg(target_arch = "x86_64")]
pub(crate) const SSE41: Feature = Feature {
    word: 1,
    mask: 1 << 19,
};

#[cfg(target_arch = "x86_64")]
pub(crate) const MOVBE: Feature = Feature {
    word: 1,
    mask: 1 << 22,
};

pub(crate) const AES: Feature = Feature {
    word: 1,
    mask: 1 << 25,
};

#[cfg(target_arch = "x86_64")]
pub(crate) const AVX: Feature = Feature {
    word: 1,
    mask: 1 << 28,
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) fn setup() {
    prefixed_extern! {
        fn OPENSSL_ia32cap_init(is_intel: c::int, extended_features_in: &[u32; 2],
                                eax: u32, ebx: u32, ecx: u32, edx: u32, xcr0: u64,
                                output: *mut [u32; 4]);
    }

    // See
    // https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf.
    // Chapter 3 "Instruction Set Reference," Section "CPUID—CPU Identification".

    #[cfg(target_arch = "x86")]
    use core::arch::x86 as arch;

    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64 as arch;

    let (max_leaf, is_intel) = {
        const GENU: u32 = u32::from_le_bytes([b'G', b'e', b'n', b'u']);
        const INEI: u32 = u32::from_le_bytes([b'i', b'n', b'e', b'I']);
        const NTEL: u32 = u32::from_le_bytes([b'n', b't', b'e', b'l']);

        // Safety: This has undefined behavior on a CPU that doesn't support
        // CPUID, but all the CPUs we support (32-bit i686 or later, and all
        // non-SGX x86-64 targets) do support CPUID. All CPUs that support
        // CPUID support leaf 0.
        let result = unsafe { arch::__cpuid(0) };
        let max_leaf = result.eax;
        let is_intel = if result.ebx == GENU && result.edx == INEI && result.ecx == NTEL {
            1
        } else {
            0
        };
        (max_leaf, is_intel)
    };

    let extended_features = if max_leaf >= 7 {
        // Safety: We just verified that leaf 7 is supported.
        let result = unsafe { arch::__cpuid(7) };
        [result.ebx, result.ecx]
    } else {
        [0, 0]
    };

    // Safety: All CPUs that we support (see above) do support leaf 1.
    let arch::CpuidResult { eax, ebx, ecx, edx } = unsafe { arch::__cpuid(1) };

    // Safety: `_xgetbv` is supported if `OSXSAVE` (bit 27) is set.
    let xcr0 = if (ecx & (1 << 27)) != 0 {
        unsafe { arch::_xgetbv(0) }
    } else {
        0
    };

    unsafe {
        OPENSSL_ia32cap_init(
            is_intel,
            &extended_features,
            eax,
            ebx,
            ecx,
            edx,
            xcr0,
            core::ptr::addr_of_mut!(OPENSSL_ia32cap_P),
        );
    }
}

prefixed_extern! {
    static mut OPENSSL_ia32cap_P: [u32; 4];
}

#[cfg(all(target_arch = "x86_64", test))]
mod x86_64_tests {
    use super::*;

    #[test]
    fn test_avx_movbe_mask() {
        // This is the OpenSSL style of testing these bits.
        assert_eq!((AVX.mask | MOVBE.mask) >> 22, 0x41);
    }
}
