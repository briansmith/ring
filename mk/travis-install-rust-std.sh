#!/usr/bin/env bash
#
# Copyright (c) 2015 Carl Lerche
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

# Extract some info from rustc
rustc_info() {
  rustc -Vv | grep $1 | awk '{print $2}'
}

RELEASE=$(rustc_info "release")

if echo $RELEASE | grep -q beta; then
    VERSION="beta"
elif echo $RELEASE | grep -q nightly; then
    VERSION="nightly"
else
    VERSION=$RELEASE
fi

RUST_STD_BASENAME=rust-std-$VERSION-$TARGET_X
curl https://static.rust-lang.org/dist/$RUST_STD_BASENAME.tar.gz | tar -zxf -
pushd $RUST_STD_BASENAME
./install.sh --prefix=~/rust
popd
