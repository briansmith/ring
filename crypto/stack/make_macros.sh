#!/bin/sh

cat > stack_macros.h << EOF
/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#if !defined(IN_STACK_H)
#error "Don't include this file directly. Include stack.h."
#endif

EOF

output_stack () {
  type=$1
  star=$2

  cat >> stack_macros.h << EOF
/* ${type} */
#define sk_${type}_new(comp)\\
  ((STACK_OF(${type})*) sk_new(CHECKED_CAST(stack_cmp_func, int (*) (const ${type} *${star}a, const ${type} *${star}b), comp)))

#define sk_${type}_new_null()\\
  ((STACK_OF(${type})*) sk_new_null())

#define sk_${type}_num(sk)\\
  sk_num(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk))

#define sk_${type}_zero(sk)\\
  sk_zero(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk));

#define sk_${type}_value(sk, i)\\
  ((${type}${star}) sk_value(CHECKED_CAST(_STACK*, const STACK_OF(${type})*, sk), (i)))

#define sk_${type}_set(sk, i, p)\\
  ((${type}${star}) sk_set(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), (i), CHECKED_CAST(void*, ${type}${star}, p)))

#define sk_${type}_free(sk)\\
  sk_free(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk))

#define sk_${type}_pop_free(sk, free_func)\\
  sk_pop_free(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_CAST(void (*) (void*), void (*) (${type}${star}), free_func))

#define sk_${type}_insert(sk, p, where)\\
  sk_insert(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_CAST(void*, ${type}${star}, p), (where))

#define sk_${type}_delete(sk, where)\\
  ((${type}${star}) sk_delete(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), (where)))

#define sk_${type}_delete_ptr(sk, p)\\
  ((${type}${star}) sk_delete_ptr(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_CAST(void*, ${type}${star}, p)))

#define sk_${type}_find(sk, out_index, p)\\
  sk_find(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), (out_index), CHECKED_CAST(void*, ${type}${star}, p))

#define sk_${type}_shift(sk)\\
  ((${type}${star}) sk_shift(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk)))

#define sk_${type}_push(sk, p)\\
  sk_push(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_CAST(void*, ${type}${star}, p))

#define sk_${type}_pop(sk)\\
  ((${type}${star}) sk_pop(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk)))

#define sk_${type}_dup(sk)\\
  ((STACK_OF(${type})*) sk_dup(CHECKED_CAST(_STACK*, const STACK_OF(${type})*, sk)))

#define sk_${type}_sort(sk)\\
  sk_sort(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk))

#define sk_${type}_is_sorted(sk)\\
  sk_is_sorted(CHECKED_CAST(_STACK*, const STACK_OF(${type})*, sk))

#define sk_${type}_set_cmp_func(sk, comp)\\
  ((int (*) (const ${type} **a, const ${type} **b)) sk_set_cmp_func(CHECKED_CAST(_STACK*, STACK_OF(${type})*, sk), CHECKED_CAST(stack_cmp_func, int (*) (const ${type} **a, const ${type} **b), comp)))


EOF
}

stack_types=$(cat stack.h | grep '^ \* STACK_OF:' | sed -e 's/.*STACK_OF://' -e 's/ .*//')
special_stack_types=$(cat stack.h | grep '^ \* SPECIAL_STACK_OF:' | sed -e 's/.*SPECIAL_STACK_OF://' -e 's/ .*//')

for type in $stack_types; do
  echo Stack of ${type}
  output_stack "${type}" "*"
done

for type in $special_stack_types; do
  echo Stack of ${type}
  output_stack "${type}" ""
done

clang-format -i stack_macros.h
