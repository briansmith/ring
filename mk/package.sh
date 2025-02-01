# This only works on Windows, using MinGW.
set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty.
# https://stackoverflow.com/a/5737794
if [[ -n "$(git status --porcelain)" ]]; then
  echo Repository is dirty.
  exit 1
fi

msrv=1.63.0
cargo clean --target-dir=target/pregenerate_asm
RING_PREGENERATE_ASM=1 CC_AARCH64_PC_WINDOWS_MSVC=clang \
  cargo +${msrv} build -p ring --target-dir=target/pregenerate_asm
if [[ -n "$(git status --porcelain -- ':(exclude)pregenerated/')" ]]; then
  echo Repository is dirty.
  exit 1
fi
cargo +${msrv} package -p ring --allow-dirty
