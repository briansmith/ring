#!/bin/bash

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

TESTS="
./crypto/cipher/aead_test aes-128-gcm ../crypto/cipher/aes_128_gcm_tests.txt
./crypto/cipher/aead_test aes-256-gcm ../crypto/cipher/aes_256_gcm_tests.txt
./crypto/cipher/aead_test chacha20-poly1305 ../crypto/cipher/chacha20_poly1305_tests.txt
./crypto/bio/bio_test
./crypto/bn/bn_test
./crypto/cipher/cipher_test ../crypto/cipher/cipher_test.txt
./crypto/dh/dh_test
./crypto/dsa/dsa_test
./crypto/err/err_test
./crypto/ec/example_mul
./crypto/ecdsa/ecdsa_test
./crypto/evp/example_sign
./crypto/hmac/hmac_test
./crypto/lhash/lhash_test
./crypto/md5/md5_test
./crypto/modes/gcm_test
./crypto/rsa/rsa_test
./crypto/sha/sha1_test
./crypto/x509v3/tab_test
./crypto/x509v3/v3name_test
./crypto/bytestring/bytestring_test
./ssl/heartbeat_test
"

IFS=$'\n'
for bin in $TESTS; do
  echo $bin
  out=$(/bin/bash -c "$bin" | tail -n 1)
  if [ $? -ne 0 ]; then
    echo $bin failed to complete.
    exit 1
  fi

  if [ "x$out" != "xPASS" ]; then
    echo $bin failed to print PASS on the last line.
    exit 1
  fi
done
