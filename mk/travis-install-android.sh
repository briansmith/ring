#!/usr/bin/env bash
#
# Copyright (c) 2016 Pietro Monteiro
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
set -ex

ARGS=$(getopt -o a:l:b:s:r: --long arch:,api-level:,abi-name:,sys-img-api-level:,rust-target: -n 'travis-install-android.sh' -- "$@" )
eval set -- "${ARGS}"

while true; do
  case $1 in
  -a|--arch)
    ARCH="${2}"
    shift 2
    ;;
  -l|--api-level)
    API="${2}"
    shift 2
    ;;
  -l|--abi-name)
    ABI="${2}"
    shift 2
    ;;
  -s|--sys-img-api-level)
    SYS_IMG_API="${2}"
    shift 2
    ;;
  -r|--rust-target)
    RUST_TARGET="${2}"
    shift 2
    ;;
  --)
    shift
    break
    ;;
  *)
    echo "Error!"
    exit 1
    ;;
  esac
done

ANDROID_SDK_VERSION=${ANDROID_SDK_VERSION:-24.4.1}
ANDROID_SDK_URL=https://dl.google.com/android/android-sdk_r${ANDROID_SDK_VERSION}-linux.tgz

ANDROID_NDK_VERSION=${ANDROID_NDK_VERSION:-14}
ANDROID_NDK_URL=https://dl.google.com/android/repository/android-ndk-r${ANDROID_NDK_VERSION}-linux-x86_64.zip

ANDROID_INSTALL_PREFIX="${HOME}/android"
ANDROID_SDK_INSTALL_DIR="${ANDROID_INSTALL_PREFIX}/android-sdk-linux"
ANDROID_NDK_INSTALL_DIR="${ANDROID_INSTALL_PREFIX}/android-ndk"

# We're using API 21 for AArch24 and 18 for everything else.
# Unfortunately the only available AArch64 images have API level 24.
# Install the extra API package and have a different option for the system image.
ANDROID_PKGS="android-${API},android-${SYS_IMG_API},sys-img-${ABI}-android-${SYS_IMG_API}"

mkdir -p "${ANDROID_INSTALL_PREFIX}"
pushd "${ANDROID_INSTALL_PREFIX}"

if [[ ! -f $ANDROID_SDK_INSTALL_DIR/tools/emulator ]];then
  curl ${ANDROID_SDK_URL} | tar -zxf -

  ANDROID_PKGS="tools,platform-tools,${ANDROID_PKGS}"
fi

echo y | ./android-sdk-linux/tools/android update sdk -a --no-ui --filter ${ANDROID_PKGS}

popd

# Test all these directories because of the mismatch between Android arch name and rustc targets.
if [[ ! ( -d $ANDROID_NDK_INSTALL_DIR/sysroot/usr/include/${ARCH}-linux-androideabi ||
          -d $ANDROID_NDK_INSTALL_DIR/sysroot/usr/include/${ARCH}-linux-android     ||
          -d $ANDROID_NDK_INSTALL_DIR/sysroot/usr/include/${RUST_TARGET} )]];then

  mkdir -p "${ANDROID_INSTALL_PREFIX}/downloads"
  pushd "${ANDROID_INSTALL_PREFIX}/downloads"

  curl -O ${ANDROID_NDK_URL}
  unzip -q android-ndk-r${ANDROID_NDK_VERSION}-linux-x86_64.zip

  ./android-ndk-r${ANDROID_NDK_VERSION}/build/tools/make_standalone_toolchain.py \
		 --force \
		 --arch ${ARCH} \
		 --api ${API} \
		 --unified-headers \
		 --install-dir ${ANDROID_NDK_INSTALL_DIR}

  popd
fi

echo end of mk/travis-install-android
