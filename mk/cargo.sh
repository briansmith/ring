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

if [ -n "${ANDROID_SDK_ROOT-}" ]; then
  export PATH=${ANDROID_SDK_ROOT}/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
fi

export CC_aarch64_linux_android=aarch64-linux-android21-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android21-clang
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu"
export CC_arm_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc

export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_RUNNER="qemu-arm -L /usr/arm-linux-gnueabihf"
export CC_armv7_linux_androideabi=armv7a-linux-androideabi18-clang

export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi18-clang
export CC_i686_unknown_linux_gnu=clang
export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=clang

export CC_i686_unknown_linux_musl=clang
export CARGO_TARGET_i686_UNKNOWN_LINUX_MUSL_LINKER=clang

export CC_x86_64_unknown_linux_musl=clang
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang

cargo "$@"
