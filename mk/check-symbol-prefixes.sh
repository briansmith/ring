#!/usr/bin/env bash
#
# Copyright 2021 Brian Smith.
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

llvm_version=14

for arg in $*; do
  case $arg in
    --target=*)
      target=${arg#*=}
      ;;
    *)
      ;;
  esac
done

nm_exe=nm
case $target in
--target=aarch64-unknown-linux-gnu|*-musl*|wasm32-*)
  nm_exe=llvm-nm-$llvm_version
  ;;
--target=*-android*)
    ndk_version=25.1.8937393
    ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT:-${ANDROID_HOME}/ndk/$ndk_version}
    android_tools=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin
    nm_exe=$android_tools/llvm-nm
  ;;
esac


# TODO: This should only look in one target directory.
# TODO: This isn't as strict as it should be.
#
# This assumes that if the prefix starts with "ring_core_" then it is correct.
# It would be better to get the prefix exactly correct.
#
# This is very liberal in filtering out symbols that "look like"
# Rust-compiler-generated symbols.
find target/$target -type f -name libring-*.rlib | while read -r infile; do
  tmpfile=$infile-without-lib-rmeta
  cp "$infile" "$tmpfile"
  # `nm` doesn't understand `lib.rmeta`.
  ar d "$tmpfile" lib.rmeta
  bad=$($nm_exe --defined-only --extern-only --print-file-name "$tmpfile" \
    | ( grep -v -E " . _?(ring_core_|__rustc|_ZN|DW.ref.rust_eh_personality)" || [[ $? == 1 ]] ))
  rm "$tmpfile"
  if [ ! -z "${bad-}" ]; then
    echo "$bad"
    exit 1
  fi
done
