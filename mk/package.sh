# This only works on Windows, using MinGW.
set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty.
# https://stackoverflow.com/a/5737794
if [[ $(git status --porcelain | wc -c) -ne 0 ]]; then
  echo Repository is dirty.
  exit 1
fi

(cd pregenerate_asm && cargo clean && cargo build)
./pregenerate_asm/target/debug/pregenerate_asm
cargo package --allow-dirty
