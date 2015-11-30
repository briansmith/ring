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

#if !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#include <openssl/crypto.h>
#include <openssl/bytestring.h>

#include "internal.h"
#include "../test/scoped_types.h"


static bool TestGetASN1() {
  static const uint8_t kData1[] = {0x30, 2, 1, 2};
  static const uint8_t kData2[] = {0x30, 3, 1, 2};
  static const uint8_t kData3[] = {0x30, 0x80};
  static const uint8_t kData4[] = {0x30, 0x81, 1, 1};
  static const uint8_t kData5[4 + 0x80] = {0x30, 0x82, 0, 0x80};

  CBS data, contents;

  CBS_init(&data, kData1, sizeof(kData1));
  if (CBS_peek_asn1_tag(&data, 0x1) ||
      !CBS_peek_asn1_tag(&data, 0x30)) {
    return false;
  }
  if (!CBS_get_asn1(&data, &contents, 0x30) ||
      CBS_len(&contents) != 2 ||
      memcmp(CBS_data(&contents), "\x01\x02", 2) != 0) {
    return false;
  }

  CBS_init(&data, kData2, sizeof(kData2));
  // data is truncated
  if (CBS_get_asn1(&data, &contents, 0x30)) {
    return false;
  }

  CBS_init(&data, kData3, sizeof(kData3));
  // zero byte length of length
  if (CBS_get_asn1(&data, &contents, 0x30)) {
    return false;
  }

  CBS_init(&data, kData4, sizeof(kData4));
  // long form mistakenly used.
  if (CBS_get_asn1(&data, &contents, 0x30)) {
    return false;
  }

  CBS_init(&data, kData5, sizeof(kData5));
  // length takes too many bytes.
  if (CBS_get_asn1(&data, &contents, 0x30)) {
    return false;
  }

  CBS_init(&data, kData1, sizeof(kData1));
  // wrong tag.
  if (CBS_get_asn1(&data, &contents, 0x31)) {
    return false;
  }

  CBS_init(&data, NULL, 0);
  // peek at empty data.
  if (CBS_peek_asn1_tag(&data, 0x30)) {
    return false;
  }

  return true;
}

static bool TestCBBBasic() {
  static const uint8_t kExpected[] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint8_t *buf;
  size_t buf_len;
  CBB cbb;

  if (!CBB_init(&cbb, 100)) {
    return false;
  }
  CBB_cleanup(&cbb);

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_u8(&cbb, 1) ||
      !CBB_add_u16(&cbb, 0x203) ||
      !CBB_add_u24(&cbb, 0x40506) ||
      !CBB_add_bytes(&cbb, (const uint8_t*) "\x07\x08", 2) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }

  ScopedOpenSSLBytes scoper(buf);
  return buf_len == sizeof(kExpected) && memcmp(buf, kExpected, buf_len) == 0;
}

static bool TestCBBFixed() {
  CBB cbb;
  uint8_t buf[1];
  uint8_t *out_buf;
  size_t out_size;

  if (!CBB_init_fixed(&cbb, NULL, 0) ||
      CBB_add_u8(&cbb, 1) ||
      !CBB_finish(&cbb, &out_buf, &out_size) ||
      out_buf != NULL ||
      out_size != 0) {
    return false;
  }

  if (!CBB_init_fixed(&cbb, buf, 1) ||
      !CBB_add_u8(&cbb, 1) ||
      CBB_add_u8(&cbb, 2) ||
      !CBB_finish(&cbb, &out_buf, &out_size) ||
      out_buf != buf ||
      out_size != 1 ||
      buf[0] != 1) {
    return false;
  }

  return true;
}

static bool TestCBBFinishChild() {
  CBB cbb, child;
  uint8_t *out_buf;
  size_t out_size;

  if (!CBB_init(&cbb, 16)) {
    return false;
  }
  if (!CBB_add_u8_length_prefixed(&cbb, &child) ||
      CBB_finish(&child, &out_buf, &out_size) ||
      !CBB_finish(&cbb, &out_buf, &out_size)) {
    CBB_cleanup(&cbb);
    return false;
  }
  ScopedOpenSSLBytes scoper(out_buf);
  return out_size == 1 && out_buf[0] == 0;
}

static bool TestCBBPrefixed() {
  static const uint8_t kExpected[] = {0, 1, 1, 0, 2, 2, 3, 0, 0, 3,
                                      4, 5, 6, 5, 4, 1, 0, 1, 2};
  uint8_t *buf;
  size_t buf_len;
  CBB cbb, contents, inner_contents, inner_inner_contents;

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_u8_length_prefixed(&cbb, &contents) ||
      !CBB_add_u8_length_prefixed(&cbb, &contents) ||
      !CBB_add_u8(&contents, 1) ||
      !CBB_add_u16_length_prefixed(&cbb, &contents) ||
      !CBB_add_u16(&contents, 0x203) ||
      !CBB_add_u24_length_prefixed(&cbb, &contents) ||
      !CBB_add_u24(&contents, 0x40506) ||
      !CBB_add_u8_length_prefixed(&cbb, &contents) ||
      !CBB_add_u8_length_prefixed(&contents, &inner_contents) ||
      !CBB_add_u8(&inner_contents, 1) ||
      !CBB_add_u16_length_prefixed(&inner_contents, &inner_inner_contents) ||
      !CBB_add_u8(&inner_inner_contents, 2) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }

  ScopedOpenSSLBytes scoper(buf);
  return buf_len == sizeof(kExpected) && memcmp(buf, kExpected, buf_len) == 0;
}

static bool TestCBBMisuse() {
  CBB cbb, child, contents;
  uint8_t *buf;
  size_t buf_len;

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_u8_length_prefixed(&cbb, &child) ||
      !CBB_add_u8(&child, 1) ||
      !CBB_add_u8(&cbb, 2)) {
    CBB_cleanup(&cbb);
    return false;
  }

  // Since we wrote to |cbb|, |child| is now invalid and attempts to write to
  // it should fail.
  if (CBB_add_u8(&child, 1) ||
      CBB_add_u16(&child, 1) ||
      CBB_add_u24(&child, 1) ||
      CBB_add_u8_length_prefixed(&child, &contents) ||
      CBB_add_u16_length_prefixed(&child, &contents) ||
      CBB_add_asn1(&child, &contents, 1) ||
      CBB_add_bytes(&child, (const uint8_t*) "a", 1)) {
    fprintf(stderr, "CBB operation on invalid CBB did not fail.\n");
    CBB_cleanup(&cbb);
    return false;
  }

  if (!CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }
  ScopedOpenSSLBytes scoper(buf);

  if (buf_len != 3 ||
      memcmp(buf, "\x01\x01\x02", 3) != 0) {
    return false;
  }
  return true;
}

static bool TestCBBASN1() {
  static const uint8_t kExpected[] = {0x30, 3, 1, 2, 3};
  uint8_t *buf;
  size_t buf_len;
  CBB cbb, contents, inner_contents;

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_asn1(&cbb, &contents, 0x30) ||
      !CBB_add_bytes(&contents, (const uint8_t*) "\x01\x02\x03", 3) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }
  ScopedOpenSSLBytes scoper(buf);

  if (buf_len != sizeof(kExpected) || memcmp(buf, kExpected, buf_len) != 0) {
    return false;
  }

  std::vector<uint8_t> test_data(100000, 0x42);

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_asn1(&cbb, &contents, 0x30) ||
      !CBB_add_bytes(&contents, test_data.data(), 130) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }
  scoper.reset(buf);

  if (buf_len != 3 + 130 ||
      memcmp(buf, "\x30\x81\x82", 3) != 0 ||
      memcmp(buf + 3, test_data.data(), 130) != 0) {
    return false;
  }

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_asn1(&cbb, &contents, 0x30) ||
      !CBB_add_bytes(&contents, test_data.data(), 1000) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }
  scoper.reset(buf);

  if (buf_len != 4 + 1000 ||
      memcmp(buf, "\x30\x82\x03\xe8", 4) != 0 ||
      memcmp(buf + 4, test_data.data(), 1000)) {
    return false;
  }

  if (!CBB_init(&cbb, 0)) {
    return false;
  }
  if (!CBB_add_asn1(&cbb, &contents, 0x30) ||
      !CBB_add_asn1(&contents, &inner_contents, 0x30) ||
      !CBB_add_bytes(&inner_contents, test_data.data(), 100000) ||
      !CBB_finish(&cbb, &buf, &buf_len)) {
    CBB_cleanup(&cbb);
    return false;
  }
  scoper.reset(buf);

  if (buf_len != 5 + 5 + 100000 ||
      memcmp(buf, "\x30\x83\x01\x86\xa5\x30\x83\x01\x86\xa0", 10) != 0 ||
      memcmp(buf + 10, test_data.data(), 100000)) {
    return false;
  }

  return true;
}

struct ASN1Uint64Test {
  uint64_t value;
  const char *encoding;
  size_t encoding_len;
};

static const ASN1Uint64Test kASN1Uint64Tests[] = {
    {0, "\x02\x01\x00", 3},
    {1, "\x02\x01\x01", 3},
    {127, "\x02\x01\x7f", 3},
    {128, "\x02\x02\x00\x80", 4},
    {0xdeadbeef, "\x02\x05\x00\xde\xad\xbe\xef", 7},
    {UINT64_C(0x0102030405060708),
     "\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08", 10},
    {UINT64_C(0xffffffffffffffff),
      "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", 11},
};

struct ASN1InvalidUint64Test {
  const char *encoding;
  size_t encoding_len;
};

static const ASN1InvalidUint64Test kASN1InvalidUint64Tests[] = {
    // Bad tag.
    {"\x03\x01\x00", 3},
    // Empty contents.
    {"\x02\x00", 2},
    // Negative number.
    {"\x02\x01\x80", 3},
    // Overflow.
    {"\x02\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
    // Leading zeros.
    {"\x02\x02\x00\x01", 4},
};

static bool TestASN1Uint64() {
  for (size_t i = 0; i < sizeof(kASN1Uint64Tests) / sizeof(kASN1Uint64Tests[0]);
       i++) {
    const ASN1Uint64Test *test = &kASN1Uint64Tests[i];
    CBS cbs;
    uint64_t value;
    CBB cbb;
    uint8_t *out;
    size_t len;

    CBS_init(&cbs, (const uint8_t *)test->encoding, test->encoding_len);
    if (!CBS_get_asn1_uint64(&cbs, &value) ||
        CBS_len(&cbs) != 0 ||
        value != test->value) {
      return false;
    }

    if (!CBB_init(&cbb, 0)) {
      return false;
    }
    if (!CBB_add_asn1_uint64(&cbb, test->value) ||
        !CBB_finish(&cbb, &out, &len)) {
      CBB_cleanup(&cbb);
      return false;
    }
    ScopedOpenSSLBytes scoper(out);
    if (len != test->encoding_len || memcmp(out, test->encoding, len) != 0) {
      return false;
    }
  }

  for (size_t i = 0;
       i < sizeof(kASN1InvalidUint64Tests) / sizeof(kASN1InvalidUint64Tests[0]);
       i++) {
    const ASN1InvalidUint64Test *test = &kASN1InvalidUint64Tests[i];
    CBS cbs;
    uint64_t value;

    CBS_init(&cbs, (const uint8_t *)test->encoding, test->encoding_len);
    if (CBS_get_asn1_uint64(&cbs, &value)) {
      return false;
    }
  }

  return true;
}

static int TestZero() {
  CBB cbb;
  CBB_zero(&cbb);
  // Calling |CBB_cleanup| on a zero-state |CBB| must not crash.
  CBB_cleanup(&cbb);
  return 1;
}

int main(void) {
  CRYPTO_library_init();

  if (!TestGetASN1() ||
      !TestCBBBasic() ||
      !TestCBBFixed() ||
      !TestCBBFinishChild() ||
      !TestCBBMisuse() ||
      !TestCBBPrefixed() ||
      !TestCBBASN1() ||
      !TestASN1Uint64() ||
      !TestZero()) {
    return 1;
  }

  return 0;
}
