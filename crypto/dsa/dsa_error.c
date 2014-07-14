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

#include <openssl/dsa.h>

const ERR_STRING_DATA DSA_error_string_data[] = {
  {ERR_PACK(ERR_LIB_DSA, DSA_F_DSA_new_method, 0), "DSA_new_method"},
  {ERR_PACK(ERR_LIB_DSA, DSA_F_dsa_sig_cb, 0), "dsa_sig_cb"},
  {ERR_PACK(ERR_LIB_DSA, DSA_F_sign, 0), "sign"},
  {ERR_PACK(ERR_LIB_DSA, DSA_F_sign_setup, 0), "sign_setup"},
  {ERR_PACK(ERR_LIB_DSA, DSA_F_verify, 0), "verify"},
  {ERR_PACK(ERR_LIB_DSA, 0, DSA_R_BAD_Q_VALUE), "BAD_Q_VALUE"},
  {ERR_PACK(ERR_LIB_DSA, 0, DSA_R_MISSING_PARAMETERS), "MISSING_PARAMETERS"},
  {ERR_PACK(ERR_LIB_DSA, 0, DSA_R_MODULUS_TOO_LARGE), "MODULUS_TOO_LARGE"},
  {ERR_PACK(ERR_LIB_DSA, 0, DSA_R_NEED_NEW_SETUP_VALUES), "NEED_NEW_SETUP_VALUES"},
  {0, NULL},
};
