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

#include <openssl/dh.h>

const ERR_STRING_DATA DH_error_string_data[] = {
  {ERR_PACK(ERR_LIB_DH, DH_F_DH_new_method, 0), "DH_new_method"},
  {ERR_PACK(ERR_LIB_DH, DH_F_compute_key, 0), "compute_key"},
  {ERR_PACK(ERR_LIB_DH, DH_F_generate_key, 0), "generate_key"},
  {ERR_PACK(ERR_LIB_DH, DH_F_generate_parameters, 0), "generate_parameters"},
  {ERR_PACK(ERR_LIB_DH, 0, DH_R_BAD_GENERATOR), "BAD_GENERATOR"},
  {ERR_PACK(ERR_LIB_DH, 0, DH_R_INVALID_PUBKEY), "INVALID_PUBKEY"},
  {ERR_PACK(ERR_LIB_DH, 0, DH_R_MODULUS_TOO_LARGE), "MODULUS_TOO_LARGE"},
  {ERR_PACK(ERR_LIB_DH, 0, DH_R_NO_PRIVATE_VALUE), "NO_PRIVATE_VALUE"},
  {0, NULL},
};
