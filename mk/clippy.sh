#!/bin/sh

export NULL=""
cargo clippy \
  --target-dir=target/clippy \
  --all-features ---all-targets \
  -- \
  --deny warnings \
  --allow clippy::from_over_into \
  --allow clippy::ptr_arg \
  --allow clippy::redundant_slicing \
  --allow clippy::upper_case_acronyms \
  --allow clippy::vec_init_then_push \
  $NULL
