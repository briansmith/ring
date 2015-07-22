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


/* void */
#define sk_void_new(comp)                \
  ((STACK_OF(void)*)sk_new(CHECKED_CAST( \
      stack_cmp_func, int (*)(const void **a, const void **b), comp)))

#define sk_void_new_null() ((STACK_OF(void)*)sk_new_null())

#define sk_void_num(sk) sk_num(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk))

#define sk_void_zero(sk) sk_zero(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk));

#define sk_void_value(sk, i) \
  ((void *)sk_value(CHECKED_CAST(_STACK *, const STACK_OF(void)*, sk), (i)))

#define sk_void_set(sk, i, p)                                       \
  ((void *)sk_set(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), (i), \
                  CHECKED_CAST(void *, void *, p)))

#define sk_void_free(sk) sk_free(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk))

#define sk_void_pop_free(sk, free_func)                    \
  sk_pop_free(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), \
              CHECKED_CAST(void (*)(void *), void (*)(void *), free_func))

#define sk_void_insert(sk, p, where)                     \
  sk_insert(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), \
            CHECKED_CAST(void *, void *, p), (where))

#define sk_void_delete(sk, where) \
  ((void *)sk_delete(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), (where)))

#define sk_void_delete_ptr(sk, p)                                     \
  ((void *)sk_delete_ptr(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), \
                         CHECKED_CAST(void *, void *, p)))

#define sk_void_find(sk, out_index, p)                              \
  sk_find(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), (out_index), \
          CHECKED_CAST(void *, void *, p))

#define sk_void_shift(sk) \
  ((void *)sk_shift(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk)))

#define sk_void_push(sk, p)                            \
  sk_push(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk), \
          CHECKED_CAST(void *, void *, p))

#define sk_void_pop(sk) \
  ((void *)sk_pop(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk)))

#define sk_void_dup(sk) \
  ((STACK_OF(void)*)sk_dup(CHECKED_CAST(_STACK *, const STACK_OF(void)*, sk)))

#define sk_void_sort(sk) sk_sort(CHECKED_CAST(_STACK *, STACK_OF(void)*, sk))

#define sk_void_is_sorted(sk) \
  sk_is_sorted(CHECKED_CAST(_STACK *, const STACK_OF(void)*, sk))

#define sk_void_set_cmp_func(sk, comp)                                      \
  ((int (*)(const void **a, const void **b))sk_set_cmp_func(                \
      CHECKED_CAST(_STACK *, STACK_OF(void)*, sk),                          \
      CHECKED_CAST(stack_cmp_func, int (*)(const void **a, const void **b), \
                   comp)))

#define sk_void_deep_copy(sk, copy_func, free_func)                  \
  ((STACK_OF(void)*)sk_deep_copy(                                    \
      CHECKED_CAST(const _STACK *, const STACK_OF(void)*, sk),       \
      CHECKED_CAST(void *(*)(void *), void *(*)(void *), copy_func), \
      CHECKED_CAST(void (*)(void *), void (*)(void *), free_func)))
