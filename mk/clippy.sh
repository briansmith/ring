#!/bin/sh

export NULL=""
cargo clippy \
  --target-dir=target/clippy \
  --all-features ---all-targets \
  -- \
  --deny warnings \
  --allow clippy::collapsible_if \
  --allow clippy::from_over_into \
  --allow clippy::identity_op \
  --allow clippy::len_without_is_empty \
  --allow clippy::len_zero \
  --allow clippy::ptr_arg \
  --allow clippy::let_unit_value \
  --allow clippy::many_single_char_names \
  --allow clippy::needless_range_loop \
  --allow clippy::new_without_default \
  --allow clippy::neg_cmp_op_on_partial_ord \
  --allow clippy::range_plus_one \
  --allow clippy::redundant_slicing \
  --allow clippy::too_many_arguments \
  --allow clippy::trivially_copy_pass_by_ref \
  --allow clippy::type_complexity \
  --allow clippy::unreadable_literal \
  --allow clippy::upper_case_acronyms \
  --allow clippy::vec_init_then_push \

  $NULL
