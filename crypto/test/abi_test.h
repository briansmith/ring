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

#ifndef OPENSSL_HEADER_ABI_TEST_H
#define OPENSSL_HEADER_ABI_TEST_H

#include <gtest/gtest.h>

#include <string>
#include <type_traits>
#include <vector>

#include <openssl/base.h>

#include "../internal.h"


// abi_test provides routines for verifying that functions satisfy platform ABI
// requirements.
namespace abi_test {

// Result stores the result of an ABI test.
struct Result {
  bool ok() const { return errors.empty(); }

  std::vector<std::string> errors;
};

namespace internal {

// DeductionGuard wraps |T| in a template, so that template argument deduction
// does not apply to it. This may be used to force C++ to deduce template
// arguments from another parameter.
template <typename T>
struct DeductionGuard {
  using Type = T;
};

// Reg128 contains storage space for a 128-bit register.
struct alignas(16) Reg128 {
  bool operator==(const Reg128 &x) const { return x.lo == lo && x.hi == hi; }
  bool operator!=(const Reg128 &x) const { return !((*this) == x); }
  uint64_t lo, hi;
};

// LOOP_CALLER_STATE_REGISTERS is a macro that iterates over all registers the
// callee is expected to save for the caller.
//
// TODO(davidben): Add support for other architectures.
#if defined(OPENSSL_X86_64)
#if defined(OPENSSL_WINDOWS)
// See https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions?view=vs-2017#register-usage
#define LOOP_CALLER_STATE_REGISTERS()  \
  CALLER_STATE_REGISTER(uint64_t, rbx) \
  CALLER_STATE_REGISTER(uint64_t, rbp) \
  CALLER_STATE_REGISTER(uint64_t, rdi) \
  CALLER_STATE_REGISTER(uint64_t, rsi) \
  CALLER_STATE_REGISTER(uint64_t, r12) \
  CALLER_STATE_REGISTER(uint64_t, r13) \
  CALLER_STATE_REGISTER(uint64_t, r14) \
  CALLER_STATE_REGISTER(uint64_t, r15) \
  CALLER_STATE_REGISTER(Reg128, xmm6)  \
  CALLER_STATE_REGISTER(Reg128, xmm7)  \
  CALLER_STATE_REGISTER(Reg128, xmm8)  \
  CALLER_STATE_REGISTER(Reg128, xmm9)  \
  CALLER_STATE_REGISTER(Reg128, xmm10) \
  CALLER_STATE_REGISTER(Reg128, xmm11) \
  CALLER_STATE_REGISTER(Reg128, xmm12) \
  CALLER_STATE_REGISTER(Reg128, xmm13) \
  CALLER_STATE_REGISTER(Reg128, xmm14) \
  CALLER_STATE_REGISTER(Reg128, xmm15)
#else
// See https://github.com/hjl-tools/x86-psABI/wiki/x86-64-psABI-1.0.pdf
#define LOOP_CALLER_STATE_REGISTERS()  \
  CALLER_STATE_REGISTER(uint64_t, rbx) \
  CALLER_STATE_REGISTER(uint64_t, rbp) \
  CALLER_STATE_REGISTER(uint64_t, r12) \
  CALLER_STATE_REGISTER(uint64_t, r13) \
  CALLER_STATE_REGISTER(uint64_t, r14) \
  CALLER_STATE_REGISTER(uint64_t, r15)
#endif  // OPENSSL_WINDOWS
#elif defined(OPENSSL_X86)
// See https://uclibc.org/docs/psABI-i386.pdf and
// https://docs.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions?view=vs-2017
#define LOOP_CALLER_STATE_REGISTERS()  \
  CALLER_STATE_REGISTER(uint32_t, esi) \
  CALLER_STATE_REGISTER(uint32_t, edi) \
  CALLER_STATE_REGISTER(uint32_t, ebx) \
  CALLER_STATE_REGISTER(uint32_t, ebp)
#endif  // X86_64 || X86

// Enable ABI testing if all of the following are true.
//
// - We have CallerState and trampoline support for the architecture.
//
// - Assembly is enabled.
//
// - This is not a shared library build. Assembly functions are not reachable
//   from tests in shared library builds.
#if defined(LOOP_CALLER_STATE_REGISTERS) && !defined(OPENSSL_NO_ASM) && \
    !defined(BORINGSSL_SHARED_LIBRARY)
#define SUPPORTS_ABI_TEST

// CallerState contains all caller state that the callee is expected to
// preserve.
struct CallerState {
#define CALLER_STATE_REGISTER(type, name) type name;
  LOOP_CALLER_STATE_REGISTERS()
#undef CALLER_STATE_REGISTER
};

// RunTrampoline runs |func| on |argv|, recording ABI errors in |out|. It does
// not perform any type-checking. If |unwind| is true and unwind tests have been
// enabled, |func| is single-stepped under an unwind test.
crypto_word_t RunTrampoline(Result *out, crypto_word_t func,
                            const crypto_word_t *argv, size_t argc,
                            bool unwind);

// CheckImpl runs |func| on |args|, recording ABI errors in |out|. If |unwind|
// is true and unwind tests have been enabled, |func| is single-stepped under an
// unwind test.
//
// It returns the value as a |crypto_word_t| to work around problems when |R| is
// void. |args| is wrapped in a |DeductionGuard| so |func| determines the
// template arguments. Otherwise, |args| may deduce |Args| incorrectly. For
// instance, if |func| takes const int *, and the caller passes an int *, the
// compiler will complain the deduced types do not match.
template <typename R, typename... Args>
inline crypto_word_t CheckImpl(Result *out, bool unwind, R (*func)(Args...),
                               typename DeductionGuard<Args>::Type... args) {
  static_assert(sizeof...(args) <= 10,
                "too many arguments for abi_test_trampoline");

  // Allocate one extra entry so MSVC does not complain about zero-size arrays.
  crypto_word_t argv[sizeof...(args) + 1] = {
      (crypto_word_t)args...,
  };
  return RunTrampoline(out, reinterpret_cast<crypto_word_t>(func), argv,
                       sizeof...(args), unwind);
}
#else
// To simplify callers when ABI testing support is unavoidable, provide a backup
// CheckImpl implementation. It must be specialized for void returns because we
// call |func| directly.
template <typename R, typename... Args>
inline typename std::enable_if<!std::is_void<R>::value, crypto_word_t>::type
CheckImpl(Result *out, bool /* unwind */, R (*func)(Args...),
          typename DeductionGuard<Args>::Type... args) {
  *out = Result();
  return func(args...);
}

template <typename... Args>
inline crypto_word_t CheckImpl(Result *out, bool /* unwind */,
                               void (*func)(Args...),
                               typename DeductionGuard<Args>::Type... args) {
  *out = Result();
  func(args...);
  return 0;
}
#endif  // SUPPORTS_ABI_TEST

// FixVAArgsString takes a string like "f, 1, 2" and returns a string like
// "f(1, 2)".
//
// This is needed because the |CHECK_ABI| macro below cannot be defined as
// CHECK_ABI(func, ...). The C specification requires that variadic macros bind
// at least one variadic argument. Clang, GCC, and MSVC all ignore this, but
// there are issues with trailing commas and different behaviors across
// compilers.
std::string FixVAArgsString(const char *str);

// CheckGTest behaves like |CheckImpl|, but it returns the correct type and
// raises GTest assertions on failure. If |unwind| is true and unwind tests are
// enabled, |func| is single-stepped under an unwind test.
template <typename R, typename... Args>
inline R CheckGTest(const char *va_args_str, const char *file, int line,
                    bool unwind, R (*func)(Args...),
                    typename DeductionGuard<Args>::Type... args) {
  Result result;
  crypto_word_t ret = CheckImpl(&result, unwind, func, args...);
  if (!result.ok()) {
    testing::Message msg;
    msg << "ABI failures in " << FixVAArgsString(va_args_str) << ":\n";
    for (const auto &error : result.errors) {
      msg << "    " << error << "\n";
    }
    ADD_FAILURE_AT(file, line) << msg;
  }
  return (R)ret;
}

}  // namespace internal

// Check runs |func| on |args| and returns the result. If ABI-testing is
// supported in this build configuration, it writes any ABI failures to |out|.
// Otherwise, it runs the function transparently.
template <typename R, typename... Args>
inline R Check(Result *out, R (*func)(Args...),
               typename internal::DeductionGuard<Args>::Type... args) {
  return (R)internal::CheckImpl(out, false, func, args...);
}

// EnableUnwindTests enables unwind tests, if supported. If not supported, it
// does nothing.
void EnableUnwindTests();

// UnwindTestsEnabled returns true if unwind tests are enabled and false
// otherwise.
bool UnwindTestsEnabled();

}  // namespace abi_test

// CHECK_ABI calls the first argument on the remaining arguments and returns the
// result. If ABI-testing is supported in this build configuration, it adds a
// non-fatal GTest failure if the call did not satisfy ABI requirements.
//
// |CHECK_ABI| does return the value and thus may replace any function call,
// provided it takes only simple parameters. However, it is recommended to test
// ABI separately from functional tests of assembly. Fully instrumenting a
// function for ABI checking requires single-stepping the function, which is
// inefficient.
//
// Functional testing requires coverage of input values, while ABI testing only
// requires branch coverage. Most of our assembly is constant-time, so usually
// only a few instrumented calls are necessray.
#define CHECK_ABI(...)                                                   \
  abi_test::internal::CheckGTest(#__VA_ARGS__, __FILE__, __LINE__, true, \
                                 __VA_ARGS__)

// CHECK_ABI_NO_UNWIND behaves like |CHECK_ABI| but disables unwind testing.
#define CHECK_ABI_NO_UNWIND(...)                                          \
  abi_test::internal::CheckGTest(#__VA_ARGS__, __FILE__, __LINE__, false, \
                                 __VA_ARGS__)


// Internal functions.

#if defined(SUPPORTS_ABI_TEST)
struct Uncallable {
  Uncallable() = delete;
};

extern "C" {

// abi_test_trampoline loads callee-saved registers from |state|, calls |func|
// with |argv|, then saves the callee-saved registers into |state|. It returns
// the result of |func|. If |unwind| is non-zero, this function triggers unwind
// instrumentation.
//
// We give |func| type |crypto_word_t| to avoid tripping MSVC's warning 4191.
crypto_word_t abi_test_trampoline(crypto_word_t func,
                                  abi_test::internal::CallerState *state,
                                  const crypto_word_t *argv, size_t argc,
                                  crypto_word_t unwind);

#if defined(OPENSSL_X86_64)
// abi_test_unwind_start points at the instruction that starts unwind testing in
// |abi_test_trampoline|. This is the value of the instruction pointer at the
// first |SIGTRAP| during unwind testing.
//
// This symbol is not a function and should not be called.
void abi_test_unwind_start(Uncallable);

// abi_test_unwind_return points at the instruction immediately after the call in
// |abi_test_trampoline|. When unwinding the function under test, this is the
// expected address in the |abi_test_trampoline| frame. After this address, the
// unwind tester should ignore |SIGTRAP| until |abi_test_unwind_stop|.
//
// This symbol is not a function and should not be called.
void abi_test_unwind_return(Uncallable);

// abi_test_unwind_stop is the value of the instruction pointer at the final
// |SIGTRAP| during unwind testing.
//
// This symbol is not a function and should not be called.
void abi_test_unwind_stop(Uncallable);

// abi_test_bad_unwind_wrong_register preserves the ABI, but annotates the wrong
// register in CFI metadata.
void abi_test_bad_unwind_wrong_register(void);

// abi_test_bad_unwind_temporary preserves the ABI, but temporarily corrupts the
// storage space for a saved register, breaking unwind.
void abi_test_bad_unwind_temporary(void);
#endif  // OPENSSL_X86_64

#if defined(OPENSSL_X86_64) || defined(OPENSSL_X86)
// abi_test_get_and_clear_direction_flag clears the direction flag. If the flag
// was previously set, it returns one. Otherwise, it returns zero.
int abi_test_get_and_clear_direction_flag(void);

// abi_test_set_direction_flag sets the direction flag. This does not conform to
// ABI requirements and must only be called within a |CHECK_ABI| guard to avoid
// errors later in the program.
int abi_test_set_direction_flag(void);
#endif  // OPENSSL_X86_64 || OPENSSL_X86

}  // extern "C"
#endif  // SUPPORTS_ABI_TEST


#endif  // OPENSSL_HEADER_ABI_TEST_H
