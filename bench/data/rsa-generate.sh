#!/usr/bin/env bash
#
# Copyright 2023 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

truncate --size 0 empty_message

openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_keygen_pubexp:65537 | \
  openssl pkcs8 -topk8 -nocrypt -outform der > rsa-2048-65537.p8

openssl pkey -pubout -inform der -outform der \
    -in rsa-2048-65537.p8 | \
  openssl rsa -pubin -RSAPublicKey_out -inform DER -outform DER \
    -out rsa-2048-65537-public-key.der
openssl dgst -sha256 -sign rsa-2048-65537.p8 -out rsa-2048-65537-signature.bin empty_message
rm rsa-2048-65537.p8

m=(2048 3072 4096 8192)
for i in "${m[@]}"
do
    echo "$i"
    openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:2048 \
        -pkeyopt rsa_keygen_pubexp:3 | \
      openssl pkcs8 -topk8 -nocrypt -outform der > "rsa-$i-3.p8"

    openssl pkey -pubout -inform der -outform der \
        -in "rsa-$i-3.p8" | \
      openssl rsa -pubin -RSAPublicKey_out -inform DER -outform DER \
        -out "rsa-$i-3-public-key.der"

    openssl dgst -sha256 -sign "rsa-$i-3.p8" -out "rsa-$i-3-signature.bin" empty_message

    rm "rsa-$i-3.p8"
done

rm empty_message
