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

rustflags_self_contained="-Clink-self-contained=yes -Clinker=rust-lld"
qemu_aarch64="qemu-aarch64 -L /usr/aarch64-linux-gnu"
qemu_arm_gnueabi="qemu-arm -L /usr/arm-linux-gnueabi"
qemu_arm_gnueabihf="qemu-arm -L /usr/arm-linux-gnueabihf"
qemu_loongarch64="qemu-loongarch64 -L /usr/loongarch64-linux-gnu"
qemu_mips="qemu-mips -L /usr/mips-linux-gnu"
qemu_mips64="qemu-mips64 -L /usr/mips64-linux-gnuabi64"
qemu_mips64el="qemu-mips64el -L /usr/mips64el-linux-gnuabi64"
qemu_mipsel="qemu-mipsel -L /usr/mipsel-linux-gnu"
qemu_powerpc="qemu-ppc -L /usr/powerpc-linux-gnu"
qemu_powerpc64="qemu-ppc64 -L /usr/powerpc64-linux-gnu"
qemu_powerpc64le="qemu-ppc64le -L /usr/powerpc64le-linux-gnu"
qemu_riscv64="qemu-riscv64 -L /usr/riscv64-linux-gnu"
qemu_s390x="qemu-s390x -L /usr/s390x-linux-gnu"
qemu_sparc64="qemu-sparc64 -L /usr/sparc64-linux-gnu"
qemu_x86="qemu-i386"
qemu_x86_64="qemu-x86_64"

# Avoid putting the Android tools in `$PATH` because there are tools in this
# directory like `clang` that would conflict with the same-named tools that may
# be needed to compile the build script, or to compile for other targets.
if [ -n "${ANDROID_HOME-}" ]; then
  # Keep the next line in sync with the corresponding line in install-build-tools.sh.
  ndk_version=27.1.12297006
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
    +*)
      toolchain=${arg#*+}
      ;;
    *)
      ;;
  esac
done

# See comments in install-build-tools.sh.
llvm_version=20

use_clang=
case $target in
   aarch64-linux-android)
    export CC_aarch64_linux_android=$android_tools/aarch64-linux-android21-clang
    export AR_aarch64_linux_android=$android_tools/llvm-ar
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CC_aarch64_linux_android
    ;;
  aarch64-unknown-linux-gnu)
    use_clang=1
    export CFLAGS_aarch64_unknown_linux_gnu="--sysroot=/usr/aarch64-linux-gnu"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_aarch64"
    ;;
  aarch64-unknown-linux-musl)
    use_clang=1
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
    # https://github.com/android/ndk/wiki/Changelog-r26#announcements says API
    # level 21 is the minimum supported as of NDK 26, even though we'd like to
    # support API level 19. Rust 1.82 is doing the same; see
    # https://github.com/rust-lang/rust/commit/6ef11b81c2c02c3c4b7556d1991a98572fe9af87.
    export CC_armv7_linux_androideabi=$android_tools/armv7a-linux-androideabi21-clang
    export AR_armv7_linux_androideabi=$android_tools/llvm-ar
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$CC_armv7_linux_androideabi
    ;;
  armv7-unknown-linux-gnueabihf)
    export CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc
    export AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc-ar
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUNNER="$qemu_arm_gnueabihf"
    ;;
  armv7-unknown-linux-musleabihf)
    use_clang=1
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="$rustflags_self_contained"
    export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUNNER="$qemu_arm_gnueabihf"
    ;;
  i686-unknown-linux-gnu)
    use_clang=1
    export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_LINKER=clang-$llvm_version
    if [ -n "${RING_CPU_MODEL-}" ]; then
      export CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_RUNNER="$qemu_x86 -cpu ${RING_CPU_MODEL}"
    fi
    ;;
  i686-unknown-linux-musl)
    use_clang=1
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
    use_clang=1
    export CFLAGS_powerpc_unknown_linux_gnu="--sysroot=/usr/powerpc-linux-gnu"
    export CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_LINKER=powerpc-linux-gnu-gcc
    export CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc"
    ;;
  powerpc64-unknown-linux-gnu)
    use_clang=1
    export CFLAGS_powerpc64_unknown_linux_gnu="--sysroot=/usr/powerpc64-linux-gnu"
    export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_GNU_LINKER=powerpc64-linux-gnu-gcc
    export CARGO_TARGET_POWERPC64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc64"
    ;;
  powerpc64le-unknown-linux-gnu)
    use_clang=1
    export CFLAGS_powerpc64le_unknown_linux_gnu="--sysroot=/usr/powerpc64le-linux-gnu"
    export CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_LINKER=powerpc64le-linux-gnu-gcc
    export CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_RUNNER="$qemu_powerpc64le"
    ;;
  riscv64gc-unknown-linux-gnu)
    use_clang=1
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER=riscv64-linux-gnu-gcc
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER="$qemu_riscv64"
    ;;
  s390x-unknown-linux-gnu)
    use_clang=1
    # XXX: Using -march=zEC12 to work around a z13 instruction bug in
    # QEMU 8.0.2 and earlier that causes `test_constant_time` to fail
    # (https://lists.gnu.org/archive/html/qemu-devel/2023-05/msg06965.html).
    export CFLAGS_s390x_unknown_linux_gnu="--sysroot=/usr/s390x-linux-gnu"
    export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_LINKER=s390x-linux-gnu-gcc
    export CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER="$qemu_s390x"
    ;;
  sparc64-unknown-linux-gnu)
    export CFLAGS_sparc64_unknown_linux_gnu="--sysroot=/usr/sparc64-linux-gnu"
    export CARGO_TARGET_SPARC64_UNKNOWN_LINUX_GNU_LINKER=sparc64-linux-gnu-gcc
    export CARGO_TARGET_SPARC64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_sparc64"
    ;;
  x86_64-unknown-linux-gnu)
    if [ -n "${RING_CPU_MODEL-}" ]; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_x86_64 -cpu ${RING_CPU_MODEL}"
    fi
    ;;
  x86_64-unknown-linux-musl)
    if [ -n "${RING_CPU_MODEL-}" ]; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_x86_64 -cpu ${RING_CPU_MODEL}"
    fi
    use_clang=1
    # XXX: Work around https://github.com/rust-lang/rust/issues/79555.
    if [ -n "${RING_COVERAGE-}" ]; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang-$llvm_version
    else
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$rustflags_self_contained"
    fi
    ;;
  loongarch64-unknown-linux-gnu)
    use_clang=1
    export CC_loongarch64_unknown_linux_gnu=loongarch64-linux-gnu-gcc-14
    export AR_loongarch64_unknown_linux_gnu=loongarch64-linux-gnu-gcc-ar
    export CFLAGS_loongarch64_unknown_linux_gnu="--sysroot=/usr/loongarch64-linux-gnu"
    export CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_GNU_LINKER=loongarch64-linux-gnu-gcc-14
    export CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_GNU_RUNNER="$qemu_loongarch64"
    ;;
  loongarch64-unknown-linux-musl)
    use_clang=1
    export CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Ctarget-feature=+crt-static $rustflags_self_contained"
    export CARGO_TARGET_LOONGARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$qemu_loongarch64"
    ;;
  wasm32-unknown-unknown)
    # The first two are only needed for when the "wasm_c" feature is enabled.
    use_clang=1
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    export WASM_BINDGEN_TEST_TIMEOUT=60
    ;;
  wasm32-wasi)
    use_clang=1
    export CARGO_TARGET_WASM32_WASI_RUNNER=target/tools/linux-x86_64/wasmtime/wasmtime
    ;;
  wasm32-wasip1)
    use_clang=1
    export CARGO_TARGET_WASM32_WASIP1_RUNNER=target/tools/linux-x86_64/wasmtime/wasmtime
    ;;
  wasm32-wasip2)
    use_clang=1
    export CARGO_TARGET_WASM32_WASIP2_RUNNER=target/tools/linux-x86_64/wasmtime/wasmtime
    ;;
  *)
    ;;
esac

# ${target} with hyphens replaced by underscores.
target_lower=${target//-/_}

if [ -n "${RING_COVERAGE-}" ]; then
  # XXX: Collides between release and debug.
  coverage_dir=$PWD/target/$target/debug/coverage
  mkdir -p "$coverage_dir"
  rm -f "$coverage_dir/*.profraw"

  export RING_BUILD_EXECUTABLE_LIST="$coverage_dir/executables"
  # Create/truncate the file.
  : > "$RING_BUILD_EXECUTABLE_LIST"

  # This doesn't work when profiling under QEMU. Instead mk/runner does
  # something similar but different.
  # export LLVM_PROFILE_FILE="$coverage_dir/%m.profraw"

  target_upper=$(echo ${target_lower} | tr '[:lower:]' '[:upper:]')

  case "$OSTYPE" in
    linux*)
      use_clang=1
      cflags_var=CFLAGS_${target_lower}
      declare -x "${cflags_var}=-fprofile-instr-generate -fcoverage-mapping ${!cflags_var-}"
      ;;
    darwin*)
      # XXX: Don't collect code coverage for C because the installed version of Apple Clang
      # doesn't necessarily have the same code coverage format as the Rust toolchain.
      # TODO: Support "use_clang=1" for Apple targets and enable C code coverage.
      # We don't have any Apple-specific C code, so this shouldn't matter much.
      ;;
  esac

  additional_rustflags=""
  case "$target" in
    powerpc-unknown-linux-gnu)
      additional_rustflags="-latomic"
    ;;
  esac

  runner_var=CARGO_TARGET_${target_upper}_RUNNER
  declare -x "${runner_var}=mk/runner ${!runner_var-}"

  rustflags_var=CARGO_TARGET_${target_upper}_RUSTFLAGS
  declare -x "${rustflags_var}=${additional_rustflags} -Cinstrument-coverage ${!rustflags_var-} -Z coverage-options=branch"
fi

if [ -n "${use_clang}" ]; then
  cc_var=CC_${target_lower}
  declare -x "${cc_var}=clang-${llvm_version}"

  ar_var=AR_${target_lower}
  declare -x "${ar_var}=llvm-ar-${llvm_version}"
fi

cargo "$@"

if [ -n "${RING_COVERAGE-}" ]; then
  # Keep in sync with check-symbol-prefixes.sh.
  # Use the host target-libdir, not the target target-libdir.
  llvm_root="$(rustc +${toolchain} --print target-libdir)/../bin"

  while read executable; do
    basename=$(basename "$executable")
    ${llvm_root}/llvm-profdata merge -sparse "$coverage_dir/$basename.profraw" -o "$coverage_dir/$basename.profdata"
    mkdir -p "$coverage_dir"/reports
    ${llvm_root}/llvm-cov export \
      --instr-profile "$coverage_dir"/$basename.profdata \
      --format lcov \
      "$executable" \
    > "$coverage_dir"/reports/coverage-$basename.txt
  done < "$RING_BUILD_EXECUTABLE_LIST"
fi
