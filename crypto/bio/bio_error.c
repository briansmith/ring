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

#include <openssl/bio.h>

const ERR_STRING_DATA BIO_error_string_data[] = {
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_callback_ctrl, 0), "BIO_callback_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_ctrl, 0), "BIO_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_new, 0), "BIO_new"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_new_file, 0), "BIO_new_file"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_new_mem_buf, 0), "BIO_new_mem_buf"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_zero_copy_get_read_buf, 0), "BIO_zero_copy_get_read_buf"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_zero_copy_get_read_buf_done, 0), "BIO_zero_copy_get_read_buf_done"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_zero_copy_get_write_buf, 0), "BIO_zero_copy_get_write_buf"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_BIO_zero_copy_get_write_buf_done, 0), "BIO_zero_copy_get_write_buf_done"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_bio_ctrl, 0), "bio_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_bio_io, 0), "bio_io"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_bio_ip_and_port_to_socket_and_addr, 0), "bio_ip_and_port_to_socket_and_addr"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_bio_make_pair, 0), "bio_make_pair"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_bio_write, 0), "bio_write"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_buffer_ctrl, 0), "buffer_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_conn_ctrl, 0), "conn_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_conn_state, 0), "conn_state"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_file_ctrl, 0), "file_ctrl"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_file_read, 0), "file_read"},
  {ERR_PACK(ERR_LIB_BIO, BIO_F_mem_write, 0), "mem_write"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_ASN1_OBJECT_TOO_LONG), "ASN1_OBJECT_TOO_LONG"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_BAD_FOPEN_MODE), "BAD_FOPEN_MODE"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_BROKEN_PIPE), "BROKEN_PIPE"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_CONNECT_ERROR), "CONNECT_ERROR"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_ERROR_SETTING_NBIO), "ERROR_SETTING_NBIO"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_INVALID_ARGUMENT), "INVALID_ARGUMENT"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_IN_USE), "IN_USE"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_KEEPALIVE), "KEEPALIVE"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NBIO_CONNECT_ERROR), "NBIO_CONNECT_ERROR"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_HOSTNAME_SPECIFIED), "NO_HOSTNAME_SPECIFIED"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_PORT_SPECIFIED), "NO_PORT_SPECIFIED"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NO_SUCH_FILE), "NO_SUCH_FILE"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_NULL_PARAMETER), "NULL_PARAMETER"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_SYS_LIB), "SYS_LIB"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNABLE_TO_CREATE_SOCKET), "UNABLE_TO_CREATE_SOCKET"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNINITIALIZED), "UNINITIALIZED"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_UNSUPPORTED_METHOD), "UNSUPPORTED_METHOD"},
  {ERR_PACK(ERR_LIB_BIO, 0, BIO_R_WRITE_TO_READ_ONLY_BIO), "WRITE_TO_READ_ONLY_BIO"},
  {0, NULL},
};
