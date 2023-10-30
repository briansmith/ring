// Copyright 2016-2023 Brian Smith.
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

// Polyfills for <string.h>.

#ifndef RING_HEADER_RING_CORE_STRING_POLYFILL_H
#define RING_HEADER_RING_CORE_STRING_POLYFILL_H

#if !defined(RING_CORE_NOSTDLIBINC)
#include <string.h>
#endif

// `uint8_t` isn't guaranteed to be 'unsigned char' and only 'char' and
// 'unsigned char' are allowed to alias according to ISO C.
typedef unsigned char aliasing_uint8_t;

static inline void *RING_memcpy(void *dst, const void *src, size_t n) {
#if !defined(RING_CORE_NOSTDLIBINC)
  return memcpy(dst, src, n);
#else
  aliasing_uint8_t *d = dst;
  const aliasing_uint8_t *s = src;
  for (size_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
#endif
}

static inline void *RING_memset(void *dst, int c, size_t n) {
#if !defined(RING_CORE_NOSTDLIBINC)
  return memset(dst, c, n);
#else
  aliasing_uint8_t *d = dst;
  for (size_t i = 0; i < n; ++i) {
    d[i] = (aliasing_uint8_t)c;
  }
  return dst;
#endif
}

#endif // RING_HEADER_RING_CORE_STRING_POLYFILL_H
