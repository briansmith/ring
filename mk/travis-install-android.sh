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

ANDROID_SDK_VERSION=${ANDROID_SDK_VERSION:-24.4.1}
ANDROID_SDK_URL=https://dl.google.com/android/android-sdk_r${ANDROID_SDK_VERSION}-linux.tgz

ANDROID_NDK_VERSION=${ANDROID_NDK_VERSION:-14}
ANDROID_NDK_URL=https://dl.google.com/android/repository/android-ndk-r${ANDROID_NDK_VERSION}-linux-x86_64.zip

ANDROID_INSTALL_PREFIX="${HOME}/android"
ANDROID_SDK_INSTALL_DIR="${ANDROID_INSTALL_PREFIX}/android-sdk-linux"
ANDROID_NDK_INSTALL_DIR="${ANDROID_INSTALL_PREFIX}/android-ndk"

ANDROID_PKGS="android-18,android-18,sys-img-armeabiv7a-android-18"

mkdir -p "${ANDROID_INSTALL_PREFIX}"
pushd "${ANDROID_INSTALL_PREFIX}"

if [[ ! -f $ANDROID_SDK_INSTALL_DIR/tools/emulator ]];then
  curl ${ANDROID_SDK_URL} | tar -zxf -

  ANDROID_PKGS="tools,platform-tools,${ANDROID_PKGS}"
fi

echo y | ./android-sdk-linux/tools/android update sdk -a --no-ui --filter ${ANDROID_PKGS}

popd

if [[ ! -d $ANDROID_NDK_INSTALL_DIR/sysroot/usr/include/arm-linux-androideabi ]];then
  mkdir -p "${ANDROID_INSTALL_PREFIX}/downloads"
  pushd "${ANDROID_INSTALL_PREFIX}/downloads"

  curl -O ${ANDROID_NDK_URL}
  unzip -q android-ndk-r${ANDROID_NDK_VERSION}-linux-x86_64.zip

  ./android-ndk-r${ANDROID_NDK_VERSION}/build/tools/make_standalone_toolchain.py \
		 --force \
		 --arch arm \
		 --api 18 \
		 --unified-headers \
		 --install-dir ${ANDROID_NDK_INSTALL_DIR}

  popd
fi

echo end of mk/travis-install-android
