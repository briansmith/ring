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

#include <openssl/buf.h>
#include <openssl/mem.h>
#include <openssl/bytestring.h>

#include <assert.h>
#include <string.h>


void CBS_init(CBS *cbs, const uint8_t *data, size_t len) {
  cbs->data = data;
  cbs->len = len;
}

static int cbs_get(CBS *cbs, const uint8_t **p, size_t n) {
  if (cbs->len < n) {
    return 0;
  }

  *p = cbs->data;
  cbs->data += n;
  cbs->len -= n;
  return 1;
}

int CBS_skip(CBS *cbs, size_t len) {
  const uint8_t *dummy;
  return cbs_get(cbs, &dummy, len);
}

const uint8_t *CBS_data(const CBS *cbs) {
  return cbs->data;
}

size_t CBS_len(const CBS *cbs) {
  return cbs->len;
}

int CBS_stow(const CBS *cbs, uint8_t **out_ptr, size_t *out_len) {
  if (*out_ptr != NULL) {
    OPENSSL_free(*out_ptr);
    *out_ptr = NULL;
  }
  *out_len = 0;

  if (cbs->len == 0) {
    return 1;
  }
  *out_ptr = BUF_memdup(cbs->data, cbs->len);
  if (*out_ptr == NULL) {
    return 0;
  }
  *out_len = cbs->len;
  return 1;
}

int CBS_strdup(const CBS *cbs, char **out_ptr) {
  if (*out_ptr != NULL) {
    OPENSSL_free(*out_ptr);
  }
  *out_ptr = BUF_strndup((const char*)cbs->data, cbs->len);
  return (*out_ptr != NULL);
}

int CBS_contains_zero_byte(const CBS *cbs) {
  return memchr(cbs->data, 0, cbs->len) != NULL;
}

int CBS_mem_equal(const CBS *cbs, const uint8_t *data, size_t len) {
  if (len != cbs->len)
    return 0;
  return CRYPTO_memcmp(cbs->data, data, len) == 0;
}

static int cbs_get_u(CBS *cbs, uint32_t *out, size_t len) {
  uint32_t result = 0;
  size_t i;
  const uint8_t *data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}

int CBS_get_u8(CBS *cbs, uint8_t *out) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

int CBS_get_u16(CBS *cbs, uint16_t *out) {
  uint32_t v;
  if (!cbs_get_u(cbs, &v, 2)) {
    return 0;
  }
  *out = v;
  return 1;
}

int CBS_get_u24(CBS *cbs, uint32_t *out) {
  return cbs_get_u(cbs, out, 3);
}

int CBS_get_u32(CBS *cbs, uint32_t *out) {
  return cbs_get_u(cbs, out, 4);
}

int CBS_get_bytes(CBS *cbs, CBS *out, size_t len) {
  const uint8_t *v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  CBS_init(out, v, len);
  return 1;
}

static int cbs_get_length_prefixed(CBS *cbs, CBS *out, size_t len_len) {
  uint32_t len;
  if (!cbs_get_u(cbs, &len, len_len)) {
    return 0;
  }
  return CBS_get_bytes(cbs, out, len);
}

int CBS_get_u8_length_prefixed(CBS *cbs, CBS *out) {
  return cbs_get_length_prefixed(cbs, out, 1);
}

int CBS_get_u16_length_prefixed(CBS *cbs, CBS *out) {
  return cbs_get_length_prefixed(cbs, out, 2);
}

int CBS_get_u24_length_prefixed(CBS *cbs, CBS *out) {
  return cbs_get_length_prefixed(cbs, out, 3);
}

static int cbs_get_asn1_element(CBS *cbs, CBS *out, unsigned *out_tag,
                                size_t *out_header_len, unsigned depth,
                                int *was_indefinite_len);

/* cbs_get_asn1_indefinite_len sets |*out| to be a CBS that covers an
 * indefinite length element in |cbs| and advances |*in|. On entry, |cbs| will
 * not have had the tag and length byte removed. On exit, |*out| does not cover
 * the EOC element, but |*in| is skipped over it.
 *
 * The |depth| argument counts the number of times the code has recursed trying
 * to find an indefinite length. */
static int cbs_get_asn1_indefinite_len(CBS *in, CBS *out, unsigned depth) {
  static const size_t kEOCLength = 2;
  size_t header_len;
  unsigned tag;
  int was_indefinite_len;
  CBS orig = *in, child;

  if (!CBS_skip(in, 2 /* tag plus 0x80 byte for indefinite len */)) {
    return 0;
  }

  for (;;) {
    if (!cbs_get_asn1_element(in, &child, &tag, &header_len, depth + 1,
                              &was_indefinite_len)) {
      return 0;
    }

    if (!was_indefinite_len && CBS_len(&child) == kEOCLength &&
        header_len == kEOCLength && tag == 0) {
      break;
    }
  }

  return CBS_get_bytes(&orig, out, CBS_len(&orig) - CBS_len(in) - kEOCLength);
}

/* MAX_DEPTH the maximum number of levels of indefinite lengths that we'll
 * support. */
#define MAX_DEPTH 64

static int cbs_get_asn1_element(CBS *cbs, CBS *out, unsigned *out_tag,
                                size_t *out_header_len, unsigned depth,
                                int *was_indefinite_len) {
  uint8_t tag, length_byte;
  CBS header = *cbs;
  if (!CBS_get_u8(&header, &tag) ||
      !CBS_get_u8(&header, &length_byte)) {
    return 0;
  }

  if ((tag & 0x1f) == 0x1f) {
    /* Long form tags are not supported. */
    return 0;
  }

  *out_tag = tag;
  if (was_indefinite_len) {
    *was_indefinite_len = 0;
  }

  size_t len;
  if ((length_byte & 0x80) == 0) {
    /* Short form length. */
    len = ((size_t) length_byte) + 2;
    *out_header_len = 2;
  } else {
    /* Long form length. */
    const size_t num_bytes = length_byte & 0x7f;
    uint32_t len32;

    if (depth < MAX_DEPTH && num_bytes == 0) {
      /* indefinite length */
      *out_header_len = 2;
      if (was_indefinite_len) {
        *was_indefinite_len = 1;
      }
      return cbs_get_asn1_indefinite_len(cbs, out, depth);
    }

    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!cbs_get_u(&header, &len32, num_bytes)) {
      return 0;
    }
    if (len32 < 128) {
      /* Length should have used short-form encoding. */
      return 0;
    }
    if ((len32 >> ((num_bytes-1)*8)) == 0) {
      /* Length should have been at least one byte shorter. */
      return 0;
    }
    len = len32;
    if (len + 2 + num_bytes < len) {
      /* Overflow. */
      return 0;
    }
    len += 2 + num_bytes;
    *out_header_len = 2 + num_bytes;
  }

  return CBS_get_bytes(cbs, out, len);
}

static int cbs_get_asn1(CBS *cbs, CBS *out, unsigned tag_value, int ber,
                        int skip_header) {
  size_t header_len;
  unsigned tag;
  CBS throwaway;

  if (out == NULL) {
    out = &throwaway;
  }

  if (!cbs_get_asn1_element(cbs, out, &tag, &header_len, ber ? 0 : MAX_DEPTH,
                            NULL) ||
      tag != tag_value) {
    return 0;
  }

  if (skip_header && !CBS_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int CBS_get_asn1(CBS *cbs, CBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 0 /* DER */,
                      1 /* skip header */);
}

int CBS_get_asn1_ber(CBS *cbs, CBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 1 /* BER */,
                      1 /* skip header */);
}

int CBS_get_asn1_element(CBS *cbs, CBS *out, unsigned tag_value) {
  return cbs_get_asn1(cbs, out, tag_value, 0 /* DER */,
                      0 /* include header */);
}
