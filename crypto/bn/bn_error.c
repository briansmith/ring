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

#include <openssl/bn.h>

const ERR_STRING_DATA BN_error_string_data[] = {
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_CTX_get, 0), "BN_CTX_get"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_CTX_new, 0), "BN_CTX_new"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_CTX_start, 0), "BN_CTX_start"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_bn2dec, 0), "BN_bn2dec"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_bn2hex, 0), "BN_bn2hex"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_div, 0), "BN_div"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_div_recp, 0), "BN_div_recp"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_exp, 0), "BN_exp"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_generate_dsa_nonce, 0), "BN_generate_dsa_nonce"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_generate_prime_ex, 0), "BN_generate_prime_ex"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_exp2_mont, 0), "BN_mod_exp2_mont"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_exp_mont, 0), "BN_mod_exp_mont"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_exp_mont_consttime, 0), "BN_mod_exp_mont_consttime"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_exp_mont_word, 0), "BN_mod_exp_mont_word"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_inverse, 0), "BN_mod_inverse"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_inverse_no_branch, 0), "BN_mod_inverse_no_branch"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_lshift_quick, 0), "BN_mod_lshift_quick"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_mod_sqrt, 0), "BN_mod_sqrt"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_new, 0), "BN_new"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_rand, 0), "BN_rand"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_rand_range, 0), "BN_rand_range"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_sqrt, 0), "BN_sqrt"},
  {ERR_PACK(ERR_LIB_BN, BN_F_BN_usub, 0), "BN_usub"},
  {ERR_PACK(ERR_LIB_BN, BN_F_bn_wexpand, 0), "bn_wexpand"},
  {ERR_PACK(ERR_LIB_BN, BN_F_mod_exp_recp, 0), "mod_exp_recp"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_ARG2_LT_ARG3), "ARG2_LT_ARG3"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_BAD_RECIPROCAL), "BAD_RECIPROCAL"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_BIGNUM_TOO_LONG), "BIGNUM_TOO_LONG"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_BITS_TOO_SMALL), "BITS_TOO_SMALL"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_CALLED_WITH_EVEN_MODULUS), "CALLED_WITH_EVEN_MODULUS"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_DIV_BY_ZERO), "DIV_BY_ZERO"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA), "EXPAND_ON_STATIC_BIGNUM_DATA"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_INPUT_NOT_REDUCED), "INPUT_NOT_REDUCED"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_INVALID_RANGE), "INVALID_RANGE"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_NEGATIVE_NUMBER), "NEGATIVE_NUMBER"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_A_SQUARE), "NOT_A_SQUARE"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_NOT_INITIALIZED), "NOT_INITIALIZED"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_NO_INVERSE), "NO_INVERSE"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_PRIVATE_KEY_TOO_LARGE), "PRIVATE_KEY_TOO_LARGE"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_P_IS_NOT_PRIME), "P_IS_NOT_PRIME"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_ITERATIONS), "TOO_MANY_ITERATIONS"},
  {ERR_PACK(ERR_LIB_BN, 0, BN_R_TOO_MANY_TEMPORARY_VARIABLES), "TOO_MANY_TEMPORARY_VARIABLES"},
  {0, NULL},
};
