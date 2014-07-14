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

#include <openssl/obj.h>

const ERR_STRING_DATA OBJ_error_string_data[] = {
  {ERR_PACK(ERR_LIB_OBJ, OBJ_F_OBJ_create, 0), "OBJ_create"},
  {ERR_PACK(ERR_LIB_OBJ, OBJ_F_OBJ_dup, 0), "OBJ_dup"},
  {ERR_PACK(ERR_LIB_OBJ, OBJ_F_OBJ_nid2obj, 0), "OBJ_nid2obj"},
  {ERR_PACK(ERR_LIB_OBJ, OBJ_F_OBJ_txt2obj, 0), "OBJ_txt2obj"},
  {ERR_PACK(ERR_LIB_OBJ, 0, OBJ_R_UNKNOWN_NID), "UNKNOWN_NID"},
  {0, NULL},
};
