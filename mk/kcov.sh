#!/usr/bin/env bash
set -eux -o pipefail
IFS=$'\n\t'

output=target/kcov/unmerged/$(basename $1)
echo $output
kcov \
  --collect-only \
  --exclude-path=/usr/include \
  --include-pattern=ring/crypto,ring/src,ring/tests \
  --verify \
  $output \
  $1
