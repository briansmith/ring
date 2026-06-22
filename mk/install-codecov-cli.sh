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

codecovcli_version=11.2.8
host=$(uname -sm)
case "$host" in
  "Linux aarch64")
    codecovcli_suffix=linux_arm64
    codecovcli_sha256=0a973204b2654e973a45470364bf64abab671a471e49b68d511c7dd3305ae4fd
    tools_subdir=linux-x86_64
    ;;
  "Linux x86_64")
    codecovcli_suffix=linux
    codecovcli_sha256=8930c4bb30254a42f3d8c340706b1be340885e20c0df5160a24efa2e030e662b
    tools_subdir=linux-aarch64
    ;;
  "Darwin arm64")
    codecovcli_suffix=macos
    codecovcli_sha256=ff380d049c376134c35fecedc10d620e5c54f3f2ee8068e6dd994dc4784619df
    tools_subdir=darwin-aarch64
    sha256_check=
    ;;
  *)
    echo $host
    exit 1
    ;;
esac
tools="target/tools/${tools_subdir}"
downloads="${tools}/unverified-downloads"
mkdir -p "${downloads}"
codecovcli_url="https://github.com/codecov/codecov-cli/releases/download/v${codecovcli_version}/codecovcli_${codecovcli_suffix}"
curl --location --output-dir "${downloads}" -O "${codecovcli_url}"
repo_root=$PWD
echo "${codecovcli_sha256}  ${downloads}/codecovcli_${codecovcli_suffix}" | shasum --algorithm 256 --binary --check --strict
mv "${downloads}/codecovcli_${codecovcli_suffix}" "${tools}/codecovcli"
chmod +x "${tools}/codecovcli"
