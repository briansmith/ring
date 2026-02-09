set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty other than what's in pregenerated/.
if [[ -n "$(git status --porcelain -- ':(exclude)pregenerated/')" ]]; then
  echo Repository is dirty.
  exit 1
fi
# Using 1.81 or later will add `.cargo_vcs_info.json` to the crate.
msrv=1.85.0
cargo +${msrv} publish -p ring --allow-dirty
