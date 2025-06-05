set -eux -o pipefail
IFS=$'\n\t'

msrv=1.66.0
cargo +${msrv} package -p ring
