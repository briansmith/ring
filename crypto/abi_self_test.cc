/* Copyright (c) 2018, Google Inc.
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

#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include <openssl/rand.h>

#include "test/abi_test.h"


static bool test_function_ok;
static int TestFunction(int a1, int a2, int a3, int a4, int a5, int a6, int a7,
                        int a8, int a9, int a10) {
  test_function_ok = a1 == 1 || a2 == 2 || a3 == 3 || a4 == 4 || a5 == 5 ||
                     a6 == 6 || a7 == 7 || a8 == 8 || a9 == 9 || a10 == 10;
  return 42;
}

TEST(ABITest, SanityCheck) {
  EXPECT_NE(0, CHECK_ABI_NO_UNWIND(strcmp, "hello", "world"));

  test_function_ok = false;
  EXPECT_EQ(42, CHECK_ABI_SEH(TestFunction, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
  EXPECT_TRUE(test_function_ok);

#if defined(SUPPORTS_ABI_TEST)
  abi_test::internal::CallerState state;
  RAND_bytes(reinterpret_cast<uint8_t *>(&state), sizeof(state));
  crypto_word_t argv[] = {
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
  };
  CHECK_ABI_SEH(abi_test_trampoline,
                reinterpret_cast<crypto_word_t>(TestFunction), &state, argv, 10,
                0 /* no breakpoint */);

#if defined(OPENSSL_X86_64)
  if (abi_test::UnwindTestsEnabled()) {
    EXPECT_NONFATAL_FAILURE(CHECK_ABI_SEH(abi_test_bad_unwind_wrong_register),
                            "was not recovered unwinding");
    EXPECT_NONFATAL_FAILURE(CHECK_ABI_SEH(abi_test_bad_unwind_temporary),
                            "was not recovered unwinding");

    CHECK_ABI_NO_UNWIND(abi_test_bad_unwind_wrong_register);
    CHECK_ABI_NO_UNWIND(abi_test_bad_unwind_temporary);

#if defined(OPENSSL_WINDOWS)
    // The invalid epilog makes Windows believe the epilog starts later than it
    // actually does. As a result, immediately after the popq, it does not
    // realize the stack has been unwound and repeats the work.
    EXPECT_NONFATAL_FAILURE(CHECK_ABI_SEH(abi_test_bad_unwind_epilog),
                            "unwound past starting frame");
    CHECK_ABI_NO_UNWIND(abi_test_bad_unwind_epilog);
#endif  // OPENSSL_WINDOWS
  }
#endif  // OPENSSL_X86_64
#endif  // SUPPORTS_ABI_TEST
}

#if defined(OPENSSL_X86_64) && defined(SUPPORTS_ABI_TEST)
extern "C" {
void abi_test_clobber_rax(void);
void abi_test_clobber_rbx(void);
void abi_test_clobber_rcx(void);
void abi_test_clobber_rdx(void);
void abi_test_clobber_rsi(void);
void abi_test_clobber_rdi(void);
void abi_test_clobber_rbp(void);
void abi_test_clobber_r8(void);
void abi_test_clobber_r9(void);
void abi_test_clobber_r10(void);
void abi_test_clobber_r11(void);
void abi_test_clobber_r12(void);
void abi_test_clobber_r13(void);
void abi_test_clobber_r14(void);
void abi_test_clobber_r15(void);
void abi_test_clobber_xmm0(void);
void abi_test_clobber_xmm1(void);
void abi_test_clobber_xmm2(void);
void abi_test_clobber_xmm3(void);
void abi_test_clobber_xmm4(void);
void abi_test_clobber_xmm5(void);
void abi_test_clobber_xmm6(void);
void abi_test_clobber_xmm7(void);
void abi_test_clobber_xmm8(void);
void abi_test_clobber_xmm9(void);
void abi_test_clobber_xmm10(void);
void abi_test_clobber_xmm11(void);
void abi_test_clobber_xmm12(void);
void abi_test_clobber_xmm13(void);
void abi_test_clobber_xmm14(void);
void abi_test_clobber_xmm15(void);
}  // extern "C"

TEST(ABITest, X86_64) {
  // abi_test_trampoline hides unsaved registers from the caller, so we can
  // safely call the abi_test_clobber_* functions below.
  abi_test::internal::CallerState state;
  RAND_bytes(reinterpret_cast<uint8_t *>(&state), sizeof(state));
  CHECK_ABI_NO_UNWIND(abi_test_trampoline,
                      reinterpret_cast<crypto_word_t>(abi_test_clobber_rbx),
                      &state, nullptr, 0, 0 /* no breakpoint */);

  CHECK_ABI_NO_UNWIND(abi_test_clobber_rax);
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_rbx),
                          "rbx was not restored after return");
  CHECK_ABI_NO_UNWIND(abi_test_clobber_rcx);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_rdx);
#if defined(OPENSSL_WINDOWS)
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_rdi),
                          "rdi was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_rsi),
                          "rsi was not restored after return");
#else
  CHECK_ABI_NO_UNWIND(abi_test_clobber_rdi);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_rsi);
#endif
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_rbp),
                          "rbp was not restored after return");
  CHECK_ABI_NO_UNWIND(abi_test_clobber_r8);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_r9);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_r10);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_r11);
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_r12),
                          "r12 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_r13),
                          "r13 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_r14),
                          "r14 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_r15),
                          "r15 was not restored after return");

  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm0);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm1);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm2);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm3);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm4);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm5);
#if defined(OPENSSL_WINDOWS)
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm6),
                          "xmm6 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm7),
                          "xmm7 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm8),
                          "xmm8 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm9),
                          "xmm9 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm10),
                          "xmm10 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm11),
                          "xmm11 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm12),
                          "xmm12 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm13),
                          "xmm13 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm14),
                          "xmm14 was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm15),
                          "xmm15 was not restored after return");
#else
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm6);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm7);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm8);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm9);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm10);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm11);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm12);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm13);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm14);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm15);
#endif

  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_set_direction_flag),
                          "Direction flag set after return");
  EXPECT_EQ(0, abi_test_get_and_clear_direction_flag())
      << "CHECK_ABI did not insulate the caller from direction flag errors";
}
#endif   // OPENSSL_X86_64 && SUPPORTS_ABI_TEST

#if defined(OPENSSL_X86) && defined(SUPPORTS_ABI_TEST)
extern "C" {
void abi_test_clobber_eax(void);
void abi_test_clobber_ebx(void);
void abi_test_clobber_ecx(void);
void abi_test_clobber_edx(void);
void abi_test_clobber_esi(void);
void abi_test_clobber_edi(void);
void abi_test_clobber_ebp(void);
void abi_test_clobber_xmm0(void);
void abi_test_clobber_xmm1(void);
void abi_test_clobber_xmm2(void);
void abi_test_clobber_xmm3(void);
void abi_test_clobber_xmm4(void);
void abi_test_clobber_xmm5(void);
void abi_test_clobber_xmm6(void);
void abi_test_clobber_xmm7(void);
}  // extern "C"

TEST(ABITest, X86) {
  // abi_test_trampoline hides unsaved registers from the caller, so we can
  // safely call the abi_test_clobber_* functions below.
  abi_test::internal::CallerState state;
  RAND_bytes(reinterpret_cast<uint8_t *>(&state), sizeof(state));
  CHECK_ABI_NO_UNWIND(abi_test_trampoline,
                      reinterpret_cast<crypto_word_t>(abi_test_clobber_ebx),
                      &state, nullptr, 0, 0 /* no breakpoint */);

  CHECK_ABI_NO_UNWIND(abi_test_clobber_eax);
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_ebx),
                          "ebx was not restored after return");
  CHECK_ABI_NO_UNWIND(abi_test_clobber_ecx);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_edx);
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_edi),
                          "edi was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_esi),
                          "esi was not restored after return");
  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_clobber_ebp),
                          "ebp was not restored after return");

  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm0);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm1);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm2);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm3);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm4);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm5);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm6);
  CHECK_ABI_NO_UNWIND(abi_test_clobber_xmm7);

  EXPECT_NONFATAL_FAILURE(CHECK_ABI_NO_UNWIND(abi_test_set_direction_flag),
                          "Direction flag set after return");
  EXPECT_EQ(0, abi_test_get_and_clear_direction_flag())
      << "CHECK_ABI did not insulate the caller from direction flag errors";
}
#endif   // OPENSSL_X86 && SUPPORTS_ABI_TEST
