#!/usr/bin/env bash
#
# Copyright 2020 Brian Smith.
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
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

toolchain=stable
for arg in $*; do
  case $arg in
    --target=*)
      target=${arg#*=}
      ;;
    +*)
      toolchain=${arg#*+}
      ;;
    *)
      ;;
  esac
done

function install_packages {
    # Sometimes GitHub Actions requires this `update` for the `install` to
    # work; sometimes it is unnecessary but other times it is required.
    sudo apt-get update
    sudo apt-get -yq --no-install-suggests --no-install-recommends install "$@"
}

use_clang=
case ${target-} in
*android*)
  # https://blog.rust-lang.org/2023/01/09/android-ndk-update-r25.html says
  # "Going forward the Android platform will target the most recent LTS NDK,
  # allowing Rust developers to access platform features sooner. These updates
  # should occur yearly and will be announced in release notes."
  #
  # https://github.com/actions/runner-images/issues/10614 indicates that GitHub
  # actions doesn't intend to keep unsupported versions around, so in general
  # we'll end up only supporting the latest NDK even for MSRV builds.
  #
  # https://developer.android.com/ndk/guides/other_build_systems explains how
  # to set the API level.
  #
  # Keep the following line in sync with the corresponding line in cargo.sh.
  #
  ndk_version=27.1.12297006

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

case ${target-} in
*-tvos | *-tvos-sim | \
*-visionos | *-visionos-sim | \
*-watchos | *-watchos-sim \
)
  build_std=1
  ;;
aarch64-unknown-linux-gnu)
  # Clang is needed for code coverage.
  use_clang=1
  install_packages \
    qemu-user \
    gcc-aarch64-linux-gnu \
    libc6-dev-arm64-cross
  ;;
aarch64-unknown-linux-musl|armv7-unknown-linux-musleabihf)
  use_clang=1
  install_packages \
    qemu-user
  ;;
arm-unknown-linux-gnueabi)
  install_packages \
    qemu-user \
    gcc-arm-linux-gnueabi \
    libc6-dev-armel-cross
  ;;
arm-unknown-linux-gnueabihf|armv7-unknown-linux-gnueabihf)
  install_packages \
    qemu-user \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross
  ;;
i686-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-multilib \
    libc6-dev-i386
  if [ -n "${RING_CPU_MODEL-}" ]; then
    install_packages qemu-user
  fi
  ;;
i686-unknown-linux-musl|x86_64-unknown-linux-musl)
  use_clang=1
  ;;
loongarch64-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-14-loongarch64-linux-gnu \
    libc6-dev-loong64-cross \
    qemu-user
  ;;
loongarch64-unknown-linux-musl)
  use_clang=1
  install_packages \
    qemu-user
  ;;
mips-unknown-linux-gnu)
  install_packages \
    gcc-mips-linux-gnu \
    libc6-dev-mips-cross \
    qemu-user
  ;;
mips64-unknown-linux-gnuabi64)
  install_packages \
    gcc-mips64-linux-gnuabi64 \
    libc6-dev-mips64-cross \
    qemu-user
  ;;
mips64el-unknown-linux-gnuabi64)
  install_packages \
    gcc-mips64el-linux-gnuabi64 \
    libc6-dev-mips64el-cross \
    qemu-user
  ;;
mipsel-unknown-linux-gnu)
  install_packages \
    gcc-mipsel-linux-gnu \
    libc6-dev-mipsel-cross \
    qemu-user
  ;;
powerpc-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-powerpc-linux-gnu \
    libc6-dev-powerpc-cross \
    qemu-user
  ;;
powerpc64-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-powerpc64-linux-gnu \
    libc6-dev-ppc64-cross \
    qemu-user
  ;;
powerpc64le-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-powerpc64le-linux-gnu \
    libc6-dev-ppc64el-cross \
    qemu-user
  ;;
riscv64gc-unknown-linux-gnu)
  use_clang=1
  install_packages \
    gcc-riscv64-linux-gnu \
    libc6-dev-riscv64-cross \
    qemu-user
  ;;
s390x-unknown-linux-gnu)
  # Clang is needed for code coverage.
  use_clang=1
  install_packages \
    qemu-user \
    gcc-s390x-linux-gnu \
    libc6-dev-s390x-cross
  ;;
sparc64-unknown-linux-gnu)
  install_packages \
    qemu-user \
    gcc-sparc64-linux-gnu \
    libc6-dev-sparc64-cross
  ;;
wasm32-unknown-unknown)
  cargo install wasm-bindgen-cli --bin wasm-bindgen-test-runner
  use_clang=1
  ;;
wasm32-wasi|wasm32-wasip1|wasm32-wasip2)
  use_clang=1
  git clone \
      --branch linux-x86_64 \
      --depth 1 \
      https://github.com/briansmith/ring-toolchain \
      target/tools/linux-x86_64
  ;;
x86_64-unknown-linux-*)
  if [ -n "${RING_CPU_MODEL-}" ]; then
    install_packages qemu-user
  fi
  ;;
*)
  ;;
esac

if [ -n "${RING_COVERAGE-}" ]; then
  use_clang=1
fi

case "${OSTYPE-}" in
linux*)
  if [ -n "$use_clang" ]; then
    ubuntu_codename=$(lsb_release --codename --short)
    llvm_version=20
    sudo apt-key add mk/llvm-snapshot.gpg.key
    sudo add-apt-repository "deb http://apt.llvm.org/$ubuntu_codename/ llvm-toolchain-$ubuntu_codename-$llvm_version main"
    # `install_packages` does the `apt-get update`.
    install_packages clang-$llvm_version llvm-$llvm_version
  fi
  ;;
esac

rustup toolchain install --no-self-update --profile=minimal ${toolchain}
if [ -n "${target-}" ]; then
  if [ -n "${build_std-}" ]; then
    rustup +${toolchain} component add rust-src
  else
    rustup +${toolchain} target add ${target}
  fi
fi
if [ -n "${RING_COVERAGE-}" ]; then
  rustup +${toolchain} component add llvm-tools-preview
fi
