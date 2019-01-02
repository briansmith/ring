/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <GFp/cpu.h>

#if defined(OPENSSL_ARM) && !defined(OPENSSL_STATIC_ARMCAP)

#include <sys/auxv.h>
#include <GFp/arm_arch.h>

#include "internal.h"


#define AT_HWCAP 16
#define AT_HWCAP2 26

#define HWCAP_NEON (1 << 12)

// See /usr/include/asm/hwcap.h on an ARM installation for the source of
// these values.
#define HWCAP2_AES (1 << 0)
#define HWCAP2_PMULL (1 << 1)
#define HWCAP2_SHA1 (1 << 2)
#define HWCAP2_SHA2 (1 << 3)

extern uint32_t GFp_armcap_P;

void GFp_cpuid_setup(void) {
  // |getauxval| is not available on Android until API level 20. Unlike
  // BoringSSL, require API level 20.
  unsigned long hwcap = getauxval(AT_HWCAP);

  // Matching OpenSSL, only report other features if NEON is present.
  if (hwcap & HWCAP_NEON) {
    GFp_armcap_P |= ARMV7_NEON;

    // Note that some (old?) ARMv8 Android devices don't support |AT_HWCAP2|
    // even when the instructions are available.
    unsigned long hwcap2 = getauxval(AT_HWCAP2);

    if (hwcap2 & HWCAP2_AES) {
      GFp_armcap_P |= ARMV8_AES;
    }
    if (hwcap2 & HWCAP2_PMULL) {
      GFp_armcap_P |= ARMV8_PMULL;
    }
    if (hwcap2 & HWCAP2_SHA1) {
      GFp_armcap_P |= ARMV8_SHA1;
    }
    if (hwcap2 & HWCAP2_SHA2) {
      GFp_armcap_P |= ARMV8_SHA256;
    }
  }
}

#endif  // OPENSSL_ARM && !OPENSSL_STATIC_ARMCAP
