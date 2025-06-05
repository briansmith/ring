set -eux -o pipefail
IFS=$'\n\t'

diff build_settings_packaged.rs build_settings.rs
msrv=1.66.0
cargo +${msrv} package -p ring
