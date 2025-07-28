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

# https://blog.rust-lang.org/2023/01/09/android-ndk-update-r25.html says
# "Going forward the Android platform will target the most recent LTS NDK,
# allowing Rust developers to access platform features sooner. These updates
# should occur yearly and will be announced in release notes."
#
# https://github.com/actions/runner-images/issues/10614 indicates that GitHub
# actions doesn't intend to keep unsupported versions around, so in general
# we'll end up only supporting the latest NDK even for MSRV builds.
#
# https://developer.android.com/ndk/guides/other_build_systems explains how
# to set the API level.
#
# Keep the following line in sync with the corresponding line in cargo.sh.
#
ndk_version=27.1.12297006

mkdir -p "${ANDROID_HOME}/licenses"
android_license_file="${ANDROID_HOME}/licenses/android-sdk-license"
accept_android_license=24333f8a63b6825ea9c5514f83c2829b004d1fee
grep --quiet --no-messages "$accept_android_license" "$android_license_file" \
  || echo $accept_android_license  >> "$android_license_file"
"${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager" "ndk;$ndk_version"

# XXX: Older Rust toolchain versions link with `-lgcc` instead of `-lunwind`;
# see https://github.com/rust-lang/rust/pull/85806.
find -L ${ANDROID_NDK_ROOT:-${ANDROID_HOME}/ndk/$ndk_version} -name libunwind.a \
        -execdir sh -c 'echo "INPUT(-lunwind)" > libgcc.a' \;
;;
