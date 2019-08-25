// Copyright 2019 Greg V
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


// Run-time feature detection for aarch64 on any OS that emulates the mrs instruction.
//
// On FreeBSD >= 12.0, Linux >= 4.11 and other operating systems, it is possible to use
// privileged system registers from userspace to check CPU feature support.
//
// For proper support of SoCs where different cores have different capabilities
// the OS has to always report only the features supported by all cores, like FreeBSD does.
//
// Only FreeBSD uses this right now.

#include <stdint.h>

uint64_t GFp_aarch64_read_isar0(void) {
  uint64_t val;
  __asm __volatile("mrs %0, ID_AA64ISAR0_EL1" : "=&r" (val));
  return val;
}
