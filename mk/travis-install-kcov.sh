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


# kcov 26 or newer is needed when getting coverage information for Rust.
# kcov 31 is needed so `kcov --version` doesn't exit with status 1.
KCOV_VERSION=${KCOV_VERSION:-36}

KCOV_INSTALL_PREFIX="${HOME}/kcov-${TARGET_X}"

# Check if kcov has been cached on travis.
if [[ -f "$KCOV_INSTALL_PREFIX/bin/kcov" ]]; then
  KCOV_INSTALLED_VERSION=`$KCOV_INSTALL_PREFIX/bin/kcov --version`
  # Exit if we don't need to upgrade kcov.
  if [[ "$KCOV_INSTALLED_VERSION" == "kcov $KCOV_VERSION" ]]; then
    echo "Using cached kcov version: ${KCOV_VERSION}"
    exit 0
  else
    rm -rf "$KCOV_INSTALL_PREFIX"
  fi
fi

curl -L https://github.com/SimonKagstrom/kcov/archive/v$KCOV_VERSION.tar.gz | tar -zxf -

pushd kcov-$KCOV_VERSION

mkdir build

pushd build

if [[  "$TARGET_X" == "i686-unknown-linux-gnu" ]]; then
  # set PKG_CONFIG_PATH so the kcov build system uses the 32 bit libraries we installed.
  # otherwise kcov will be linked with 64 bit libraries and won't work with 32 bit executables.
  PKG_CONFIG_PATH="/usr/lib/i386-linux-gnu/pkgconfig" CFLAGS="-m32" \
  CXXFLAGS="-m32" TARGET=$TARGET_X \
  cmake -DCMAKE_INSTALL_PREFIX:PATH="${KCOV_INSTALL_PREFIX}" ..
else
  TARGET=$TARGET_X cmake -DCMAKE_INSTALL_PREFIX:PATH="${KCOV_INSTALL_PREFIX}" ..
fi

make
make install

$KCOV_INSTALL_PREFIX/bin/kcov --version

popd
popd
