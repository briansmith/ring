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

rustflags_self_contained="-Clink-self-contained=yes -Clinker=rust-lld"
qemu_aarch64="qemu-aarch64 -L /usr/aarch64-linux-gnu"
qemu_arm_gnueabi="qemu-arm -L /usr/arm-linux-gnueabi"
qemu_arm_gnueabihf="qemu-arm -L /usr/arm-linux-gnueabihf"
qemu_mips="qemu-mips -L /usr/mips-linux-gnu"
qemu_mips64="qemu-mips64 -L /usr/mips64-linux-gnuabi64"
qemu_mips64el="qemu-mips64el -L /usr/mips64el-linux-gnuabi64"
qemu_mipsel="qemu-mipsel -L /usr/mipsel-linux-gnu"
qemu_powerpc="qemu-ppc -L /usr/powerpc-linux-gnu"
qemu_powerpc64="qemu-ppc64 -L /usr/powerpc64-linux-gnu"
qemu_powerpc64le="qemu-ppc64le -L /usr/powerpc64le-linux-gnu"
qemu_riscv64="qemu-riscv64 -L /usr/riscv64-linux-gnu"
qemu_s390x="qemu-s390x -L /usr/s390x-linux-gnu"

# Avoid putting the Android tools in `$PATH` because there are tools in this
# directory like `clang` that would conflict with the same-named tools that may
# be needed to compile the build script, or to compile for other targets.
if [ -n "${ANDROID_HOME-}" ]; then
  # Keep the next line in sync with the corresponding line in install-build-tools.sh.
  ndk_version=25.2.9519653
  ANDROID_NDK_ROOT=${ANDROID_NDK_ROOT:-${ANDROID_HOME}/ndk/$ndk_version}
fi
if [ -n "${ANDROID_NDK_ROOT-}" ]; then
  android_tools=${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin
fi

for arg in $*; do
  case $arg in
    --target=*)
      target=${arg#*=}
      ;;
    *)
      ;;
  esac
done

# See comments in install-build-tools.sh.
llvm_version=18

case $target in
   aarch64-linux-android)
    export CC_aarch64_linux_android=$android_tools/aarch64-linux-android21-clang
    export AR_aarch64_linux_android=$android_tools/llvm-ar
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$android_tools/aarch64-linux-android21-clang
    ;;
  aarch64-unknown-linux-gnu)
    export CC_aarch64_unknown_linux_gnu=clang-$llvm_version
    export AR_aarch64_unknown_linux_gnu=llvm-ar-$llvm_version
    export CFLAGS_aarch64_unknown_linux_gnu="--sysroot=/usr/aarch64-linux-gnu"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_aarch64"
    ;;
  aarch64-unknown-linux-musl)
    export CC_aarch64_unknown_linux_musl=clang-$llvm_version
    export AR_aarch64_unknown_linux_musl=llvm-ar-$llvm_version
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$rustflags_self_contained"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$qemu_aarch64"
    ;;
  arm-unknown-linux-gnueabi)
    export CC_arm_unknown_linux_gnueabi=arm-linux-gnueabi-gcc
    export AR_arm_unknown_linux_gnueabi=arm-linux-gnueabi-gcc-ar
    export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABI_LINKER=arm-linux-gnueabi-gcc
    export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABI_RUNNER="$qemu_arm_gnueabi"
    ;;
  arm-unknown-linux-gnueabihf)
    # XXX: clang cannot build the sha256 and x25519 assembly.
    export CC_arm_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
    export AR_arm_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc-ar
    export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
    export CARGO_TARGET_ARM_UNKNOWN_LINUX_GNUEABIHF_RUNNER="$qemu_arm_gnueabihf"
    ;;
  armv7-linux-androideabi)
    export CC_armv7_linux_androideabi=$android_tools/armv7a-linux-androideabi19-clang
    export AR_armv7_linux_androideabi=$android_tools/llvm-ar
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$android_tools/armv7a-linux-androideabi19-clang
    ;;
  armv7-unknown-linux-gnueabihf)
    export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
    export AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc-ar
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUNNER="$qemu_arm_gnueabihf"
    ;;
  armv7-unknown-linux-musleabihf)
    export CC_armv7_unknown_linux_musleabihf=clang-$llvm_version
    export AR_armv7_unknown_linux_musleabihf=llvm-ar-$llvm_version
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="$rustflags_self_contained"
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUNNER="$qemu_arm_gnueabihf"
    ;;
  i686-unknown-linux-gnu)
    export CC_i686_unknown_linux_gnu=clang-$llvm_version
    export AR_i686_unknown_linux_gnu=llvm-ar-$llvm_version
    export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=clang-$llvm_version
    ;;
  i686-unknown-linux-musl)
    export CC_i686_unknown_linux_musl=clang-$llvm_version
    export AR_i686_unknown_linux_musl=llvm-ar-$llvm_version
    export CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$rustflags_self_contained"
    ;;
  mips-unknown-linux-gnu)
    export CC_mips_unknown_linux_gnu=mips-linux-gnu-gcc
    export AR_mips_unknown_linux_gnu=mips-linux-gnu-gcc-ar
    export CARGO_TARGET_MIPS_UNKNOWN_LINUX_GNU_LINKER=mips-linux-gnu-gcc
    export CARGO_TARGET_MIPS_UNKNOWN_LINUX_GNU_RUNNER="$qemu_mips"
    ;;
  mips64-unknown-linux-gnuabi64)
    export CC_mips64_unknown_linux_gnuabi64=mips64-linux-gnuabi64-gcc
    export AR_mips64_unknown_linux_gnuabi64=mips64-linux-gnuabi64-gcc-ar
    export CARGO_TARGET_MIPS64_UNKNOWN_LINUX_GNUABI64_LINKER=mips64-linux-gnuabi64-gcc
    export CARGO_TARGET_MIPS64_UNKNOWN_LINUX_GNUABI64_RUNNER="$qemu_mips64"
    ;;
  mips64el-unknown-linux-gnuabi64)
    export CC_mips64el_unknown_linux_gnuabi64=mips64el-linux-gnuabi64-gcc
    export AR_mips64el_unknown_linux_gnuabi64=mips64el-linux-gnuabi64-gcc-ar
    export CARGO_TARGET_MIPS64EL_UNKNOWN_LINUX_GNUABI64_LINKER=mips64el-linux-gnuabi64-gcc
    export CARGO_TARGET_MIPS64EL_UNKNOWN_LINUX_GNUABI64_RUNNER="$qemu_mips64el"
    ;;
  mipsel-unknown-linux-gnu)
    export CC_mipsel_unknown_linux_gnu=mipsel-linux-gnu-gcc
    export AR_mipsel_unknown_linux_gnu=mipsel-linux-gnu-gcc-ar
    export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_LINKER=mipsel-linux-gnu-gcc
    export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_GNU_RUNNER="$qemu_mipsel"
    ;;
  powerpc-unknown-linux-gnu)
    export CC_powerpc_unknown_linux_gnu=clang-$llvm_version
    export AR_powerpc_unknown_linux_gnu=llvm-ar-$llvm_version
    export CFLAGS_powerpc_unknown_linux_gnu="--sysroot=/usr/powerpc-linux-gnu"
    export CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_LINKER=powerpc-linux-gnu-gcc
    export CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc"
    ;;
  powerpc64-unknown-linux-gnu)
    export CC_powerpc64_unknown_linux_gnu=clang-$llvm_version
    export AR_powerpc64_unknown_linux_gnu=llvm-ar-$llvm_version
    export CFLAGS_powerpc64_unknown_linux_gnu="--sysroot=/usr/powerpc64-linux-gnu"
    export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_GNU_LINKER=powerpc64-linux-gnu-gcc
    export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc64"
    ;;
  powerpc64le-unknown-linux-gnu)
    export CC_powerpc64le_unknown_linux_gnu=clang-$llvm_version
    export AR_powerpc64le_unknown_linux_gnu=llvm-ar-$llvm_version
    export CFLAGS_powerpc64le_unknown_linux_gnu="--sysroot=/usr/powerpc64le-linux-gnu"
    export CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_LINKER=powerpc64le-linux-gnu-gcc
    export CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc64le"
    ;;
  riscv64gc-unknown-linux-gnu)
    export CC_riscv64gc_unknown_linux_gnu=clang-$llvm_version
    export AR_riscv64gc_unknown_linux_gnu=llvm-ar-$llvm_version
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="$qemu_riscv64"
    ;;
  s390x-unknown-linux-gnu)
    export CC_s390x_unknown_linux_gnu=clang-$llvm_version
    export AR_s390x_unknown_linux_gnu=llvm-ar-$llvm_version
    # XXX: Using -march=zEC12 to work around a z13 instruction bug in
    # QEMU 8.0.2 and earlier that causes `test_constant_time` to fail
    # (https://lists.gnu.org/archive/html/qemu-devel/2023-05/msg06965.html).
    export CFLAGS_s390x_unknown_linux_gnu="--sysroot=/usr/s390x-linux-gnu -march=zEC12"
    export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc
    export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER="$qemu_s390x"
    ;;
  x86_64-unknown-linux-musl)
    export CC_x86_64_unknown_linux_musl=clang-$llvm_version
    export AR_x86_64_unknown_linux_musl=llvm-ar-$llvm_version
    # XXX: Work around https://github.com/rust-lang/rust/issues/79555.
    if [ -n "${RING_COVERAGE-}" ]; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang-$llvm_version
    else
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$rustflags_self_contained"
    fi
    ;;
  loongarch64-unknown-linux-gnu)
    export CC_loongarch64_unknown_linux_gnu=clang-$llvm_version
    export AR_loongarch64_unknown_linux_gnu=llvm-ar-$llvm_version
    export CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_GNU_LINKER=clang-$llvm_version
    ;;
  wasm32-unknown-unknown)
    # The first two are only needed for when the "wasm_c" feature is enabled.
    export CC_wasm32_unknown_unknown=clang-$llvm_version
    export AR_wasm32_unknown_unknown=llvm-ar-$llvm_version
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export WASM_BINDGEN_TEST_TIMEOUT=60
    ;;
  wasm32-wasi)
    # The first two are only needed for when the "wasm_c" feature is enabled.
    export CC_wasm32_wasi=clang-$llvm_version
    export AR_wasm32_wasi=llvm-ar-$llvm_version
    export CARGO_TARGET_WASM32_WASI_RUNNER=target/tools/linux-x86_64/wasmtime/wasmtime
    ;;
  *)
    ;;
esac

if [ -n "${RING_COVERAGE-}" ]; then
  # XXX: Collides between release and debug.
  coverage_dir=$PWD/target/$target/debug/coverage
  mkdir -p "$coverage_dir"
  rm -f "$coverage_dir/*.profraw"

  export RING_BUILD_EXECUTABLE_LIST="$coverage_dir/executables"
  truncate --size=0 "$RING_BUILD_EXECUTABLE_LIST"

  # This doesn't work when profiling under QEMU. Instead mk/runner does
  # something similar but different.
  # export LLVM_PROFILE_FILE="$coverage_dir/%m.profraw"

  # ${target} with hyphens replaced by underscores, lowercase and uppercase.
  target_lower=${target//-/_}
  target_upper=${target_lower^^}

  cflags_var=CFLAGS_${target_lower}
  declare -x "${cflags_var}=-fprofile-instr-generate -fcoverage-mapping ${!cflags_var-}"

  runner_var=CARGO_TARGET_${target_upper}_RUNNER
  declare -x "${runner_var}=mk/runner ${!runner_var-}"

  rustflags_var=CARGO_TARGET_${target_upper}_RUSTFLAGS
  declare -x "${rustflags_var}=-Cinstrument-coverage ${!rustflags_var-}"
fi

cargo "$@"

if [ -n "${RING_COVERAGE-}" ]; then
  while read executable; do
    basename=$(basename "$executable")
    llvm-profdata-$llvm_version merge -sparse ""$coverage_dir"/$basename.profraw" -o "$coverage_dir"/$basename.profdata
    mkdir -p "$coverage_dir"/reports
    llvm-cov-$llvm_version export \
      --instr-profile "$coverage_dir"/$basename.profdata \
      --format lcov \
      "$executable" \
    > "$coverage_dir"/reports/coverage-$basename.txt
  done < "$RING_BUILD_EXECUTABLE_LIST"
fi
