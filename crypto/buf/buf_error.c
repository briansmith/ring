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

#include <openssl/err.h>

#include <openssl/buf.h>

const ERR_STRING_DATA BUF_error_string_data[] = {
  {ERR_PACK(ERR_LIB_BUF, BUF_F_BUF_MEM_new, 0), "BUF_MEM_new"},
  {ERR_PACK(ERR_LIB_BUF, BUF_F_BUF_memdup, 0), "BUF_memdup"},
  {ERR_PACK(ERR_LIB_BUF, BUF_F_BUF_strndup, 0), "BUF_strndup"},
  {ERR_PACK(ERR_LIB_BUF, BUF_F_buf_mem_grow, 0), "buf_mem_grow"},
  {0, NULL},
};
