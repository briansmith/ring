#!/usr/bin/env bash
#
# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

if [[ -n ${TIDY-} ]]; then
  python util/tidy.py
  exit
fi

printenv

case $TARGET_X in
aarch64-unknown-linux-gnu)
  DL_TARGET=aarch64-linux-gnu
  DL_DIGEST=b9137008744d9009877f662dbac7481d673cdcb1798e727e325a37c98a0f63da
  ;;
arm-unknown-linux-gnueabi)
  DL_TARGET=arm-linux-gnueabi
  DL_DIGEST=1c11a944d3e515405e01effc129f3bbf24effb300effa10bf486c9119378ccd7
  ;;
*)
  ;;
esac

if [[ -n ${DL_TARGET-} ]]; then
  DL_ROOT=https://releases.linaro.org/components/toolchain/binaries/
  DL_RELEASE=5.1-2015.08
  DL_BASENAME=gcc-linaro-$DL_RELEASE-x86_64_$DL_TARGET
  wget $DL_ROOT/$DL_RELEASE/$DL_TARGET/$DL_BASENAME.tar.xz
  echo "$DL_DIGEST  $DL_BASENAME.tar.xz" | sha256sum -c
  tar xf $DL_BASENAME.tar.xz
  export PATH=$PWD/$DL_BASENAME/bin:$PATH
fi

if [[ ! "$TARGET_X" =~ "x86_64-" ]]; then
  ./mk/travis-install-rust-std.sh

  # By default cargo/rustc seems to use cc for linking, We installed the
  # multilib support that corresponds to $CC_X and $CXX_X but unless cc happens
  # to match #CC_X, that's not the right version. The symptom is a linker error
  # where it fails to find -lgcc_s.
  mkdir .cargo
  echo "[target.$TARGET_X]" > .cargo/config
  echo "linker= \"$CC_X\"" >> .cargo/config
  cat .cargo/config
fi

$CC_X --version
$CXX_X --version
make --version

cargo version
rustc --version

if [[ "$MODE_X" == "RELWITHDEBINFO" ]]; then mode=--release; fi

CC=$CC_X CXX=$CXX_X cargo build -j2 ${mode-} --verbose --target=$TARGET_X

case $TARGET_X in
arm-unknown-linux-gnueabi|aarch64-unknown-linux-gnu)
  ;;
*)
  CC=$CC_X CXX=$CXX_X cargo test -j2 ${mode-} --verbose --target=$TARGET_X
  CC=$CC_X CXX=$CXX_X cargo doc -j2 ${mode-} --verbose --target=$TARGET_X
  ;;
esac

CC=$CC_X CXX=$CXX_X cargo clean --verbose

echo end of mk/travis.sh
