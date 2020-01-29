#!/usr/bin/env bash
#
# Copyright 2015 Brian Smith.
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

printenv

case $TARGET_X in
aarch64-unknown-linux-gnu)
  export QEMU_LD_PREFIX=/usr/aarch64-linux-gnu
  ;;
arm-unknown-linux-gnueabihf)
  export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
  ;;
aarch64-linux-android)
  # XXX: Tests are built but not run because we couldn't get the emulator to work; see
  # https://github.com/briansmith/ring/issues/838
  export ANDROID_ABI=aarch64
  ;;
armv7-linux-androideabi)
  # XXX: Tests are built but not run because we couldn't get the emulator to work; see
  # https://github.com/briansmith/ring/issues/838
  # export ANDROID_SYSTEM_IMAGE="system-images;android-18;default;armeabi-v7a"
  export ANDROID_ABI=armeabi-v7a
  ;;
esac

if [[ ! -z "${ANDROID_ABI-}" ]]; then
  # install the android sdk/ndk
  mkdir "$ANDROID_HOME/licenses" || true
  echo "24333f8a63b6825ea9c5514f83c2829b004d1fee" > "$ANDROID_HOME/licenses/android-sdk-license"
  sdkmanager ndk-bundle
  curl -sSf https://build.travis-ci.org/files/rustup-init.sh | sh -s -- --default-toolchain=$RUST_X -y
  export PATH=$HOME/.cargo/bin:$ANDROID_HOME/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
  rustup default
fi

if [[ "$TARGET_X" =~ ^(arm|aarch64) && ! "$TARGET_X" =~ android ]]; then
  # We need a newer QEMU than Travis has.
  # sudo is needed until the PPA and its packages are whitelisted.
  # See https://github.com/travis-ci/apt-source-whitelist/issues/271
  sudo add-apt-repository ppa:pietro-monteiro/qemu-backport -y
  sudo apt-get update -qq
  sudo apt-get install --no-install-recommends binfmt-support qemu-user-binfmt -y
fi

if [[ ! "$TARGET_X" =~ "x86_64-" ]]; then
  rustup target add "$TARGET_X"

  # By default cargo/rustc seems to use cc for linking, We installed the
  # multilib support that corresponds to $CC_X but unless cc happens to match
  # $CC_X, that's not the right version. The symptom is a linker error
  # where it fails to find -lgcc_s.
  if [[ ! -z "${CC_X-}" ]]; then
    mkdir .cargo
    echo "[target.$TARGET_X]" > .cargo/config
    echo "linker= \"$CC_X\"" >> .cargo/config
    cat .cargo/config
  fi
fi

if [[ ! -z "${CC_X-}" ]]; then
  export CC=$CC_X
  $CC --version
else
  cc --version
fi

# KCOV needs a C++ compiler.
if [[ "$KCOV" == "1" ]]; then
  if [[ ! -z "${CC_X-}" ]]; then
    CXX="${CC_X/clang/clang++}"
    CXX="${CC_X/gcc/g++}"
    export CXX=$CXX
    $CXX --version
  else
    c++ --version
  fi
fi

cargo version
rustc --version

if [[ "$MODE_X" == "RELWITHDEBINFO" ]]; then
  mode=--release
  target_dir=target/$TARGET_X/release
else
  target_dir=target/$TARGET_X/debug
fi

if [[ -z "${ANDROID_ABI-}" ]]; then
  cargo test -vv -j2 ${mode-} ${FEATURES_X-} --target=$TARGET_X
else
  cargo test -vv -j2 --no-run ${mode-} ${FEATURES_X-} --target=$TARGET_X

  if [[ ! -z "${ANDROID_SYSTEM_IMAGE-}" ]]; then
    # Building the AVD is slow. Do it here, after we build the code so that any
    # build breakage is reported sooner, instead of being delayed by this.
    sdkmanager tools
    echo no | avdmanager create avd --force --name $ANDROID_ABI -k $ANDROID_SYSTEM_IMAGE --abi $ANDROID_ABI
    avdmanager list avd

    $ANDROID_HOME/emulator/emulator @$ANDROID_ABI -memory 2048 -no-skin -no-boot-anim -no-window &
    adb wait-for-device

    # Run the unit tests first. The file named ring-<something> in $target_dir is
    # the test executable.

    find $target_dir -maxdepth 1 -name ring-* ! -name "*.*" \
      -exec adb push {} /data/ring-test \;
    adb shell "cd /data && ./ring-test" 2>&1 | tee /tmp/ring-test-log
    grep "test result: ok" /tmp/ring-test-log

    for test_exe in `find $target_dir -maxdepth 1 -name "*test*" -type f ! -name "*.*" `; do
        adb push $test_exe /data/`basename $test_exe`
        adb shell "cd /data && ./`basename $test_exe`" 2>&1 | \
            tee /tmp/`basename $test_exe`-log
        grep "test result: ok" /tmp/`basename $test_exe`-log
    done

     adb emu kill
  fi
fi

if [[ "$KCOV" == "1" ]]; then
  # kcov reports coverage as a percentage of code *linked into the executable*
  # (more accurately, code that has debug info linked into the executable), not
  # as a percentage of source code. Thus, any code that gets discarded by the
  # linker due to lack of usage isn't counted at all. Thus, we have to re-link
  # with "-C link-dead-code" to get accurate code coverage reports.
  # Alternatively, we could link pass "-C link-dead-code" in the "cargo test"
  # step above, but then "cargo test" we wouldn't be testing the configuration
  # we expect people to use in production.
  cargo clean
  CARGO_INCREMENTAL=0 \
  RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Clink-dead-code -Coverflow-checks=on -Zno-landing-pads" \
    cargo test -vv --no-run -j2  ${mode-} ${FEATURES_X-} --target=$TARGET_X
  mk/travis-install-kcov.sh
  for test_exe in `find target/$TARGET_X/debug -maxdepth 1 -executable -type f`; do
    ${HOME}/kcov-${TARGET_X}/bin/kcov \
      --verify \
      --coveralls-id=$TRAVIS_JOB_ID \
      --exclude-path=/usr/include \
      --include-pattern="ring/crypto,ring/src,ring/tests" \
      target/kcov \
      $test_exe
  done
fi

echo end of mk/travis.sh
