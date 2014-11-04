#!/usr/bin/env bash

# Copyright (c) 2014, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

SRC=..
if [ "$#" -ge 1 ]; then
  SRC=$1
fi

TESTS="
./crypto/base64/base64_test
./crypto/bio/bio_test
./crypto/bn/bn_test
./crypto/bytestring/bytestring_test
./crypto/cipher/aead_test aes-128-gcm $SRC/crypto/cipher/aes_128_gcm_tests.txt
./crypto/cipher/aead_test aes-128-key-wrap $SRC/crypto/cipher/aes_128_key_wrap_tests.txt
./crypto/cipher/aead_test aes-256-gcm $SRC/crypto/cipher/aes_256_gcm_tests.txt
./crypto/cipher/aead_test aes-256-key-wrap $SRC/crypto/cipher/aes_256_key_wrap_tests.txt
./crypto/cipher/aead_test chacha20-poly1305 $SRC/crypto/cipher/chacha20_poly1305_tests.txt
./crypto/cipher/aead_test rc4-md5 $SRC/crypto/cipher/rc4_md5_tests.txt
./crypto/cipher/cipher_test $SRC/crypto/cipher/cipher_test.txt
./crypto/constant_time_test
./crypto/dh/dh_test
./crypto/digest/digest_test
./crypto/dsa/dsa_test
./crypto/ec/ec_test
./crypto/ec/example_mul
./crypto/ecdsa/ecdsa_test
./crypto/err/err_test
./crypto/evp/evp_test
./crypto/hmac/hmac_test
./crypto/lhash/lhash_test
./crypto/modes/gcm_test
./crypto/pkcs8/pkcs12_test
./crypto/rsa/rsa_test
./crypto/x509/pkcs7_test
./crypto/x509v3/tab_test
./crypto/x509v3/v3name_test
./ssl/pqueue/pqueue_test
./ssl/ssl_test
"

IFS=$'\n'
for bin in $TESTS; do
  echo $bin
  out=$(bash -c "$bin" | tail -n 1)
  if [ $? -ne 0 ]; then
    echo $bin failed to complete.
    exit 1
  fi

  if [ "x$out" != "xPASS" ]; then
    echo $bin failed to print PASS on the last line.
    exit 1
  fi
done
