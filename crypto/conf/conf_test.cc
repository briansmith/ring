/* Copyright (c) 2021, Google Inc.
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

#include <openssl/bio.h>
#include <openssl/conf.h>

#include <gtest/gtest.h>


TEST(ConfTest, Parse) {
  // Check that basic parsing works. (We strongly recommend that people don't
  // use the [N]CONF functions.)

  static const char kConf[] = R"(
# Comment

key=value

[section_name]
key=value2
)";

  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kConf, sizeof(kConf) - 1));
  ASSERT_TRUE(bio);
  bssl::UniquePtr<CONF> conf(NCONF_new(nullptr));
  ASSERT_TRUE(conf);
  ASSERT_TRUE(NCONF_load_bio(conf.get(), bio.get(), nullptr));
  EXPECT_TRUE(NCONF_get_section(conf.get(), "section_name"));
  EXPECT_FALSE(NCONF_get_section(conf.get(), "other_section"));
  EXPECT_STREQ(NCONF_get_string(conf.get(), nullptr, "key"), "value");
  EXPECT_STREQ(NCONF_get_string(conf.get(), "section_name", "key"), "value2");
  EXPECT_STREQ(NCONF_get_string(conf.get(), "other_section", "key"), nullptr);
}
