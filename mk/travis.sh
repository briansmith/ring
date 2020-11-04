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

source $HOME/.cargo/env

run_tests_on_host=1

case $TARGET_X in
aarch64-apple-ios)
  run_tests_on_host=
  ;;
aarch64-unknown-linux-gnu)
  export QEMU_LD_PREFIX=/usr/aarch64-linux-gnu
  ;;
arm-unknown-linux-gnueabihf)
  export QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf
  ;;
aarch64-linux-android|armv7-linux-androideabi)
  run_tests_on_host=
  PATH=$HOME/.cargo/bin:$ANDROID_HOME/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
  ;;
wasm32-unknown-unknown)
  run_tests_on_host=
  ;;
esac

printenv

if [[ "$TARGET_X" =~ .*"-unknown-linux-musl" || ! "$TARGET_X" =~ "x86_64" ]]; then
  rustup target add "$TARGET_X"
fi

if [[ "$MODE_X" == "RELWITHDEBINFO" ]]; then
  mode=--release
  target_dir=target/$TARGET_X/release
else
  target_dir=target/$TARGET_X/debug
fi

no_run=
if [[ -z $run_tests_on_host ]]; then
  no_run=--no-run
fi

if [ -n "${KCOV-}" ]; then
  mkdir -p target/kcov/unmerged
fi

cargo test -vv -j2 ${mode-} ${no_run-} ${FEATURES_X-} --target=$TARGET_X

if [ -n "${KCOV-}" ]; then
  kcov --merge --coveralls-id=$TRAVIS_JOB_ID target/kcov/merged target/kcov/unmerged/*
fi

# Android tests in emulator
#
# XXX: Tests are built but not run because we couldn't get the emulator to work; see
# https://github.com/briansmith/ring/issues/838
if false; then
  $ANDROID_HOME/emulator/emulator @$TARGET_X -memory 2048 -no-skin -no-boot-anim -no-window &
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

echo end of mk/travis.sh
