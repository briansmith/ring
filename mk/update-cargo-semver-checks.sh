#!/usr/bin/env bash
#
# Updates the cargo-semver-checks GitHub Actions job to use the latest
# cargo-semver-checks. Run `mk/update-cargo-semver-checks.sh` when the job
# fails with "error: unsupported rustdoc format vNN".

set -eux -o pipefail
IFS=$'\n\t'

# Find the newest release of cargo-semver-checks, regardless of which Rust
# toolchain is installed locally. Run it outside this workspace so that our
# `rust-version` doesn't affect it.
tmp=$(mktemp -d)
version=$(cd "$tmp" && cargo info --quiet cargo-semver-checks |
  sed -nE 's/^version: ([^ ]+ \(latest )?([^ )]+)\)?$/\2/p')
rmdir "$tmp"

# `-i.bak` works with both GNU and BSD sed.
sed -E -i.bak \
  -e "s/(cargo-semver-checks-)[0-9.]+$/\\1$version/" \
  -e "s/(cargo install cargo-semver-checks --locked --vers )\"[^\"]*\"/\\1\"$version\"/" \
  .github/workflows/ci.yml
rm .github/workflows/ci.yml.bak
