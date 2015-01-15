/* Copyright (c) 2014, Google Inc.
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

#include <openssl/cpu.h>

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#include <inttypes.h>
#include <stdio.h>

#include "arm_arch.h"


/* We can't include <sys/auxv.h> because the Android SDK version against which
 * Chromium builds is too old to have it. Instead we define all the constants
 * that we need and have a weak pointer to getauxval. */

unsigned long getauxval(unsigned long type) __attribute__((weak));

static const unsigned long AT_HWCAP = 16;
static const unsigned long AT_HWCAP2 = 26;

char CRYPTO_is_NEON_capable(void) {
  return (OPENSSL_armcap_P & ARMV7_NEON) != 0;
}

void CRYPTO_set_NEON_capable(char neon_capable) {
  if (neon_capable) {
    OPENSSL_armcap_P |= ARMV7_NEON;
  } else {
    OPENSSL_armcap_P &= ~ARMV7_NEON;
  }
}

char CRYPTO_is_NEON_functional(void) {
  static const uint32_t kWantFlags = ARMV7_NEON | ARMV7_NEON_FUNCTIONAL;
  return (OPENSSL_armcap_P & kWantFlags) == kWantFlags;
}

void CRYPTO_set_NEON_functional(char neon_functional) {
  if (neon_functional) {
    OPENSSL_armcap_P |= ARMV7_NEON_FUNCTIONAL;
  } else {
    OPENSSL_armcap_P &= ~ARMV7_NEON_FUNCTIONAL;
  }
}

void OPENSSL_cpuid_setup(void) {
  if (getauxval == NULL) {
    return;
  }

  unsigned long hwcap = getauxval(AT_HWCAP);

#if defined(OPENSSL_ARM)
  static const unsigned long kNEON = 1 << 12;
  if ((hwcap & kNEON) == 0) {
    return;
  }

  /* In 32-bit mode, the ARMv8 feature bits are in a different aux vector
   * value. */
  hwcap = getauxval(AT_HWCAP2);

  /* See /usr/include/asm/hwcap.h on an ARM installation for the source of
   * these values. */
  static const unsigned long kAES = 1 << 0;
  static const unsigned long kPMULL = 1 << 1;
  static const unsigned long kSHA1 = 1 << 2;
  static const unsigned long kSHA256 = 1 << 3;
#elif defined(OPENSSL_AARCH64)
  /* See /usr/include/asm/hwcap.h on an aarch64 installation for the source of
   * these values. */
  static const unsigned long kNEON = 1 << 1;
  static const unsigned long kAES = 1 << 3;
  static const unsigned long kPMULL = 1 << 4;
  static const unsigned long kSHA1 = 1 << 5;
  static const unsigned long kSHA256 = 1 << 6;

  if ((hwcap & kNEON) == 0) {
    return;
  }
#endif

  OPENSSL_armcap_P |= ARMV7_NEON | ARMV7_NEON_FUNCTIONAL;

  if (hwcap & kAES) {
    OPENSSL_armcap_P |= ARMV8_AES;
  }
  if (hwcap & kPMULL) {
    OPENSSL_armcap_P |= ARMV8_PMULL;
  }
  if (hwcap & kSHA1) {
    OPENSSL_armcap_P |= ARMV8_SHA1;
  }
  if (hwcap & kSHA256) {
    OPENSSL_armcap_P |= ARMV8_SHA256;
  }
}

#endif  /* defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64) */
