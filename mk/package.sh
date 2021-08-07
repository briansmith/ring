# This only works on Windows, using MinGW.
set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty.
# https://stackoverflow.com/a/5737794
if [[ $(git status --porcelain | wc -c) -ne 0 ]]; then
  echo Repository is dirty.
  exit 1
fi

cargo clean --target-dir=target/pregenerate_asm
RING_PREGENERATE_ASM=1 CC_AARCH64_PC_WINDOWS_MSVC=clang \
  cargo build --target-dir=target/pregenerate_asm
cargo package --allow-dirty
