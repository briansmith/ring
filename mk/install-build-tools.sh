case $TARGET_X in
aarch64-linux-android)
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

  if [[ ! -z "${ANDROID_SYSTEM_IMAGE-}" ]]; then
    sdkmanager tools
    echo no | avdmanager create avd --force --name $TARGET_X -k $ANDROID_SYSTEM_IMAGE --abi $ANDROID_ABI
    avdmanager list avd
  fi

  curl -sSf https://build.travis-ci.org/files/rustup-init.sh | sh -s -- --default-toolchain=$RUST_X -y
fi
