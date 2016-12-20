#!/usr/bin/env bash
#
# Copyright (c) 2016 Marshall Pierce
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

# different versions behave differently even with the same config
RUSTFMT_VERSION=${RUSTFMT_VERSION:-"0.6.3"}

RUSTFMT_INSTALL_PREFIX="${HOME}/rustfmt-${TARGET_X}"

# Check if rustfmt has been cached on travis.
if [[ -f "$RUSTFMT_INSTALL_PREFIX/bin/rustfmt" ]]; then
  RUSTFMT_INSTALLED_VERSION=`$RUSTFMT_INSTALL_PREFIX/bin/rustfmt --version | awk '{print $1}'`
  if [[ "$RUSTFMT_VERSION" = "$RUSTFMT_INSTALLED_VERSION" ]]; then
    echo "Using cached rustfmt version: ${RUSTFMT_INSTALLED_VERSION}"
    exit 0
  else
    rm -rf "$RUSTFMT_INSTALL_PREFIX"
  fi
fi

# cargo's version resolution is annoying; force exact version
cargo install --vers "=${RUSTFMT_VERSION}" --root "$RUSTFMT_INSTALL_PREFIX" rustfmt
