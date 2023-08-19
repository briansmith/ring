#!/usr/bin/env bash
#
# Copyright 2020 Brian Smith.
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

target=$1
features=${2-}

function install_packages {
  sudo apt-get -yq --no-install-suggests --no-install-recommends install "$@"
}

use_clang=
case $target in
--target*android*)
  # https://blog.rust-lang.org/2023/01/09/android-ndk-update-r25.html says
  # "Going forward the Android platform will target the most recent LTS NDK,
  # allowing Rust developers to access platform features sooner. These updates
  # should occur yearly and will be announced in release notes." Assume that
  # means that we should always prefer to be using the latest 25.x.y version of
  # the NDK until the Rust project announces that we should use a higher major
  # version number.
  #
  # TODO: This should probably be implemented as a map of Rust toolchain version
  # to NDK version; e.g. our MSRV might (only) support an older NDK than the
  # latest stable Rust toolchain.
  #
  # Keep the following line in sync with the corresponding line in cargo.sh.
  ndk_version=25.2.9519653

  mkdir -p "${ANDROID_HOME}/licenses"
  android_license_file="${ANDROID_HOME}/licenses/android-sdk-license"
  accept_android_license=24333f8a63b6825ea9c5514f83c2829b004d1fee
  grep --quiet --no-messages "$accept_android_license" "$android_license_file" \
    || echo $accept_android_license  >> "$android_license_file"
  "${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager" "ndk;$ndk_version"

  # XXX: Older Rust toolchain versions link with `-lgcc` instead of `-lunwind`;
  # see https://github.com/rust-lang/rust/pull/85806.
  find -L ${ANDROID_NDK_ROOT:-${ANDROID_HOME}/ndk/$ndk_version} -name libunwind.a \
          -execdir sh -c 'echo "INPUT(-lunwind)" > libgcc.a' \;
  ;;
esac

case $target in
--target=aarch64-unknown-linux-gnu)
  # Clang is needed for code coverage.
  use_clang=1
  install_packages \
    qemu-user \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross
  ;;
--target=aarch64-unknown-linux-musl|--target=armv7-unknown-linux-musleabihf)
  use_clang=1
  install_packages \
    qemu-user
  ;;
--target=arm-unknown-linux-gnueabihf)
  install_packages \
    qemu-user \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross
  ;;
--target=i686-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-multilib \
    libc6-dev-i386
  ;;
--target=i686-unknown-linux-musl|--target=x86_64-unknown-linux-musl)
  use_clang=1
  ;;
--target=mipsel-unknown-linux-gnu)
  install_packages \
    gcc-mipsel-linux-gnu \
    libc6-dev-mipsel-cross \
    qemu-user
  ;;
--target=riscv64gc-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-riscv64-linux-gnu \
    libc6-dev-riscv64-cross \
    qemu-user
  ;;
--target=wasm32-unknown-unknown)
  cargo install wasm-bindgen-cli --bin wasm-bindgen-test-runner
  use_clang=1
  ;;
--target=*)
  ;;
esac

case "$OSTYPE" in
linux*)
  ubuntu_codename=$(lsb_release --codename --short)
  llvm_version=16
  sudo apt-key add mk/llvm-snapshot.gpg.key
  sudo add-apt-repository "deb http://apt.llvm.org/$ubuntu_codename/ llvm-toolchain-$ubuntu_codename-$llvm_version main"
  sudo apt-get update
  # We need to use `llvm-nm` in `mk/check-symbol-prefixes.sh`.
  install_packages llvm-$llvm_version
  if [ -n "$use_clang" ]; then
    install_packages clang-$llvm_version
  fi
  ;;
esac
