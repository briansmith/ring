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

/* CONF_VALUE */
#define sk_CONF_VALUE_new(comp)                                            \
  ((STACK_OF(CONF_VALUE) *)sk_new(CHECKED_CAST(                            \
      stack_cmp_func, int (*)(const CONF_VALUE **a, const CONF_VALUE **b), \
      comp)))

#define sk_CONF_VALUE_new_null() ((STACK_OF(CONF_VALUE) *)sk_new_null())

#define sk_CONF_VALUE_num(sk) \
  sk_num(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_zero(sk) \
  sk_zero(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk));

#define sk_CONF_VALUE_value(sk, i) \
  ((CONF_VALUE *)sk_value(         \
      CHECKED_CAST(_STACK *, const STACK_OF(CONF_VALUE) *, sk), (i)))

#define sk_CONF_VALUE_set(sk, i, p)                                         \
  ((CONF_VALUE *)sk_set(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
                        (i), CHECKED_CAST(void *, CONF_VALUE *, p)))

#define sk_CONF_VALUE_free(sk) \
  sk_free(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_pop_free(sk, free_func)             \
  sk_pop_free(                                            \
      CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_CAST(void (*)(void *), void (*)(CONF_VALUE *), free_func))

#define sk_CONF_VALUE_insert(sk, p, where)                      \
  sk_insert(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
            CHECKED_CAST(void *, CONF_VALUE *, p), (where))

#define sk_CONF_VALUE_delete(sk, where)                                        \
  ((CONF_VALUE *)sk_delete(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
                           (where)))

#define sk_CONF_VALUE_delete_ptr(sk, p)                   \
  ((CONF_VALUE *)sk_delete_ptr(                           \
      CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_CAST(void *, CONF_VALUE *, p)))

#define sk_CONF_VALUE_find(sk, out_index, p)                               \
  sk_find(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), (out_index), \
          CHECKED_CAST(void *, CONF_VALUE *, p))

#define sk_CONF_VALUE_shift(sk) \
  ((CONF_VALUE *)sk_shift(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_push(sk, p)                             \
  sk_push(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk), \
          CHECKED_CAST(void *, CONF_VALUE *, p))

#define sk_CONF_VALUE_pop(sk) \
  ((CONF_VALUE *)sk_pop(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_dup(sk)      \
  ((STACK_OF(CONF_VALUE) *)sk_dup( \
      CHECKED_CAST(_STACK *, const STACK_OF(CONF_VALUE) *, sk)))

#define sk_CONF_VALUE_sort(sk) \
  sk_sort(CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_is_sorted(sk) \
  sk_is_sorted(CHECKED_CAST(_STACK *, const STACK_OF(CONF_VALUE) *, sk))

#define sk_CONF_VALUE_set_cmp_func(sk, comp)                             \
  ((int (*)(const CONF_VALUE **a, const CONF_VALUE **b))sk_set_cmp_func( \
      CHECKED_CAST(_STACK *, STACK_OF(CONF_VALUE) *, sk),                \
      CHECKED_CAST(stack_cmp_func,                                       \
                   int (*)(const CONF_VALUE **a, const CONF_VALUE **b),  \
                   comp)))

#define sk_CONF_VALUE_deep_copy(sk, copy_func, free_func)             \
  ((STACK_OF(CONF_VALUE) *)sk_deep_copy(                              \
      CHECKED_CAST(const _STACK *, const STACK_OF(CONF_VALUE) *, sk), \
      CHECKED_CAST(void *(*)(void *), CONF_VALUE *(*)(CONF_VALUE *),  \
                   copy_func),                                        \
      CHECKED_CAST(void (*)(void *), void (*)(CONF_VALUE *), free_func)))

/* CRYPTO_EX_DATA_FUNCS */
#define sk_CRYPTO_EX_DATA_FUNCS_new(comp)                                      \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_new(CHECKED_CAST(                      \
      stack_cmp_func,                                                          \
      int (*)(const CRYPTO_EX_DATA_FUNCS **a, const CRYPTO_EX_DATA_FUNCS **b), \
      comp)))

#define sk_CRYPTO_EX_DATA_FUNCS_new_null() \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_new_null())

#define sk_CRYPTO_EX_DATA_FUNCS_num(sk) \
  sk_num(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_zero(sk) \
  sk_zero(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk));

#define sk_CRYPTO_EX_DATA_FUNCS_value(sk, i)                              \
  ((CRYPTO_EX_DATA_FUNCS *)sk_value(                                      \
      CHECKED_CAST(_STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
      (i)))

#define sk_CRYPTO_EX_DATA_FUNCS_set(sk, i, p)                            \
  ((CRYPTO_EX_DATA_FUNCS *)sk_set(                                       \
      CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), (i), \
      CHECKED_CAST(void *, CRYPTO_EX_DATA_FUNCS *, p)))

#define sk_CRYPTO_EX_DATA_FUNCS_free(sk) \
  sk_free(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk),    \
              CHECKED_CAST(void (*)(void *), void (*)(CRYPTO_EX_DATA_FUNCS *), \
                           free_func))

#define sk_CRYPTO_EX_DATA_FUNCS_insert(sk, p, where)                      \
  sk_insert(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
            CHECKED_CAST(void *, CRYPTO_EX_DATA_FUNCS *, p), (where))

#define sk_CRYPTO_EX_DATA_FUNCS_delete(sk, where) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_delete(             \
      CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), (where)))

#define sk_CRYPTO_EX_DATA_FUNCS_delete_ptr(sk, p)                   \
  ((CRYPTO_EX_DATA_FUNCS *)sk_delete_ptr(                           \
      CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
      CHECKED_CAST(void *, CRYPTO_EX_DATA_FUNCS *, p)))

#define sk_CRYPTO_EX_DATA_FUNCS_find(sk, out_index, p)                  \
  sk_find(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
          (out_index), CHECKED_CAST(void *, CRYPTO_EX_DATA_FUNCS *, p))

#define sk_CRYPTO_EX_DATA_FUNCS_shift(sk) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_shift(      \
      CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_push(sk, p)                             \
  sk_push(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk), \
          CHECKED_CAST(void *, CRYPTO_EX_DATA_FUNCS *, p))

#define sk_CRYPTO_EX_DATA_FUNCS_pop(sk) \
  ((CRYPTO_EX_DATA_FUNCS *)sk_pop(      \
      CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_dup(sk)      \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_dup( \
      CHECKED_CAST(_STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk)))

#define sk_CRYPTO_EX_DATA_FUNCS_sort(sk) \
  sk_sort(CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_is_sorted(sk) \
  sk_is_sorted(                               \
      CHECKED_CAST(_STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk))

#define sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func(sk, comp)                       \
  ((int (*)(const CRYPTO_EX_DATA_FUNCS **a, const CRYPTO_EX_DATA_FUNCS **b)) \
       sk_set_cmp_func(                                                      \
           CHECKED_CAST(_STACK *, STACK_OF(CRYPTO_EX_DATA_FUNCS) *, sk),     \
           CHECKED_CAST(stack_cmp_func,                                      \
                        int (*)(const CRYPTO_EX_DATA_FUNCS **a,              \
                                const CRYPTO_EX_DATA_FUNCS **b),             \
                        comp)))

#define sk_CRYPTO_EX_DATA_FUNCS_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(CRYPTO_EX_DATA_FUNCS) *)sk_deep_copy(                         \
      CHECKED_CAST(const _STACK *, const STACK_OF(CRYPTO_EX_DATA_FUNCS) *, \
                   sk),                                                    \
      CHECKED_CAST(void *(*)(void *),                                      \
                   CRYPTO_EX_DATA_FUNCS *(*)(CRYPTO_EX_DATA_FUNCS *),      \
                   copy_func),                                             \
      CHECKED_CAST(void (*)(void *), void (*)(CRYPTO_EX_DATA_FUNCS *),     \
                   free_func)))

/* RSA_additional_prime */
#define sk_RSA_additional_prime_new(comp)                                      \
  ((STACK_OF(RSA_additional_prime) *)sk_new(CHECKED_CAST(                      \
      stack_cmp_func,                                                          \
      int (*)(const RSA_additional_prime **a, const RSA_additional_prime **b), \
      comp)))

#define sk_RSA_additional_prime_new_null() \
  ((STACK_OF(RSA_additional_prime) *)sk_new_null())

#define sk_RSA_additional_prime_num(sk) \
  sk_num(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk))

#define sk_RSA_additional_prime_zero(sk) \
  sk_zero(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk));

#define sk_RSA_additional_prime_value(sk, i)                              \
  ((RSA_additional_prime *)sk_value(                                      \
      CHECKED_CAST(_STACK *, const STACK_OF(RSA_additional_prime) *, sk), \
      (i)))

#define sk_RSA_additional_prime_set(sk, i, p)                            \
  ((RSA_additional_prime *)sk_set(                                       \
      CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), (i), \
      CHECKED_CAST(void *, RSA_additional_prime *, p)))

#define sk_RSA_additional_prime_free(sk) \
  sk_free(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk))

#define sk_RSA_additional_prime_pop_free(sk, free_func)                        \
  sk_pop_free(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk),    \
              CHECKED_CAST(void (*)(void *), void (*)(RSA_additional_prime *), \
                           free_func))

#define sk_RSA_additional_prime_insert(sk, p, where)                      \
  sk_insert(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), \
            CHECKED_CAST(void *, RSA_additional_prime *, p), (where))

#define sk_RSA_additional_prime_delete(sk, where) \
  ((RSA_additional_prime *)sk_delete(             \
      CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), (where)))

#define sk_RSA_additional_prime_delete_ptr(sk, p)                   \
  ((RSA_additional_prime *)sk_delete_ptr(                           \
      CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), \
      CHECKED_CAST(void *, RSA_additional_prime *, p)))

#define sk_RSA_additional_prime_find(sk, out_index, p)                  \
  sk_find(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), \
          (out_index), CHECKED_CAST(void *, RSA_additional_prime *, p))

#define sk_RSA_additional_prime_shift(sk) \
  ((RSA_additional_prime *)sk_shift(      \
      CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk)))

#define sk_RSA_additional_prime_push(sk, p)                             \
  sk_push(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk), \
          CHECKED_CAST(void *, RSA_additional_prime *, p))

#define sk_RSA_additional_prime_pop(sk) \
  ((RSA_additional_prime *)sk_pop(      \
      CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk)))

#define sk_RSA_additional_prime_dup(sk)      \
  ((STACK_OF(RSA_additional_prime) *)sk_dup( \
      CHECKED_CAST(_STACK *, const STACK_OF(RSA_additional_prime) *, sk)))

#define sk_RSA_additional_prime_sort(sk) \
  sk_sort(CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk))

#define sk_RSA_additional_prime_is_sorted(sk) \
  sk_is_sorted(                               \
      CHECKED_CAST(_STACK *, const STACK_OF(RSA_additional_prime) *, sk))

#define sk_RSA_additional_prime_set_cmp_func(sk, comp)                       \
  ((int (*)(const RSA_additional_prime **a, const RSA_additional_prime **b)) \
       sk_set_cmp_func(                                                      \
           CHECKED_CAST(_STACK *, STACK_OF(RSA_additional_prime) *, sk),     \
           CHECKED_CAST(stack_cmp_func,                                      \
                        int (*)(const RSA_additional_prime **a,              \
                                const RSA_additional_prime **b),             \
                        comp)))

#define sk_RSA_additional_prime_deep_copy(sk, copy_func, free_func)        \
  ((STACK_OF(RSA_additional_prime) *)sk_deep_copy(                         \
      CHECKED_CAST(const _STACK *, const STACK_OF(RSA_additional_prime) *, \
                   sk),                                                    \
      CHECKED_CAST(void *(*)(void *),                                      \
                   RSA_additional_prime *(*)(RSA_additional_prime *),      \
                   copy_func),                                             \
      CHECKED_CAST(void (*)(void *), void (*)(RSA_additional_prime *),     \
                   free_func)))

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
