set -eux -o pipefail
IFS=$'\n\t'

# Make sure the current tree isn't dirty other than what's in pregenerated/.
if [[ -n "$(git status --porcelain -- ':(exclude)pregenerated/')" ]]; then
  echo Repository is dirty.
  exit 1
fi
msrv=1.66.0
cargo +${msrv} publish -p ring --allow-dirty
