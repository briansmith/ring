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

#include <stdio.h>

#include <gtest/gtest.h>

#include <openssl/asn1.h>
#include <openssl/err.h>

#include "../test/test_util.h"


// kTag128 is an ASN.1 structure with a universal tag with number 128.
static const uint8_t kTag128[] = {
    0x1f, 0x81, 0x00, 0x01, 0x00,
};

// kTag258 is an ASN.1 structure with a universal tag with number 258.
static const uint8_t kTag258[] = {
    0x1f, 0x82, 0x02, 0x01, 0x00,
};

static_assert(V_ASN1_NEG_INTEGER == 258,
              "V_ASN1_NEG_INTEGER changed. Update kTag258 to collide with it.");

// kTagOverflow is an ASN.1 structure with a universal tag with number 2^35-1,
// which will not fit in an int.
static const uint8_t kTagOverflow[] = {
    0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x01, 0x00,
};

TEST(ASN1Test, LargeTags) {
  const uint8_t *p = kTag258;
  bssl::UniquePtr<ASN1_TYPE> obj(d2i_ASN1_TYPE(NULL, &p, sizeof(kTag258)));
  EXPECT_FALSE(obj) << "Parsed value with illegal tag" << obj->type;
  ERR_clear_error();

  p = kTagOverflow;
  obj.reset(d2i_ASN1_TYPE(NULL, &p, sizeof(kTagOverflow)));
  EXPECT_FALSE(obj) << "Parsed value with tag overflow" << obj->type;
  ERR_clear_error();

  p = kTag128;
  obj.reset(d2i_ASN1_TYPE(NULL, &p, sizeof(kTag128)));
  ASSERT_TRUE(obj);
  EXPECT_EQ(128, obj->type);
  const uint8_t kZero = 0;
  EXPECT_EQ(Bytes(&kZero, 1), Bytes(obj->value.asn1_string->data,
                                    obj->value.asn1_string->length));
}

TEST(ASN1Test, IntegerSetting) {
  bssl::UniquePtr<ASN1_INTEGER> by_bn(M_ASN1_INTEGER_new());
  bssl::UniquePtr<ASN1_INTEGER> by_long(M_ASN1_INTEGER_new());
  bssl::UniquePtr<ASN1_INTEGER> by_uint64(M_ASN1_INTEGER_new());
  bssl::UniquePtr<BIGNUM> bn(BN_new());

  const std::vector<unsigned> kValues = {
      0, 1, 2, 0xff, 0x100, 0xffff, 0x10000,
  };
  for (const auto &i : kValues) {
    SCOPED_TRACE(i);

    ASSERT_EQ(1, ASN1_INTEGER_set(by_long.get(), i));
    ASSERT_EQ(1, ASN1_INTEGER_set_uint64(by_uint64.get(), i));
    ASSERT_TRUE(BN_set_word(bn.get(), i));
    ASSERT_TRUE(BN_to_ASN1_INTEGER(bn.get(), by_bn.get()));

    if (i != 0) {
      // |ASN1_INTEGER_set| and |BN_to_ASN1_INTEGER| disagree about how to
      // encode zero. The former leaves an empty value while the latter encodes
      // as a single zero byte.
      EXPECT_EQ(0, ASN1_INTEGER_cmp(by_bn.get(), by_long.get()));
    }
    EXPECT_EQ(0, ASN1_INTEGER_cmp(by_bn.get(), by_uint64.get()));
  }
}
