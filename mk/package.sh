# This only works on Windows, using MinGW.
set -eux -o pipefail
IFS=$'\n\t'

cargo clean
rm -Rf pregenerated/msvc*.lib
RING_PREGENERATED=GENERATE cargo build --target=x86_64-pc-windows-msvc
RING_PREGENERATED=GENERATE cargo build --target=i686-pc-windows-msvc
cargo package --allow-dirty
