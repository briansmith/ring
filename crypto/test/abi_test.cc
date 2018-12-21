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

#include "abi_test.h"

#include <stdarg.h>
#include <stdio.h>

#include <algorithm>
#include <array>

#include <openssl/buf.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/span.h>

#if defined(OPENSSL_LINUX) && defined(SUPPORTS_ABI_TEST) && \
    defined(BORINGSSL_HAVE_LIBUNWIND)
#define UNWIND_TEST_SIGTRAP

#define UNW_LOCAL_ONLY
#include <errno.h>
#include <fcntl.h>
#include <libunwind.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif  // LINUX && SUPPORTS_ABI_TEST && HAVE_LIBUNWIND


namespace abi_test {

namespace internal {

static bool g_unwind_tests_enabled = false;

std::string FixVAArgsString(const char *str) {
  std::string ret = str;
  size_t idx = ret.find(',');
  if (idx == std::string::npos) {
    return ret + "()";
  }
  size_t idx2 = idx + 1;
  while (idx2 < ret.size() && ret[idx2] == ' ') {
    idx2++;
  }
  while (idx > 0 && ret[idx - 1] == ' ') {
    idx--;
  }
  return ret.substr(0, idx) + "(" + ret.substr(idx2) + ")";
}

#if defined(SUPPORTS_ABI_TEST)
// ForEachMismatch calls |func| for each register where |a| and |b| differ.
template <typename Func>
static void ForEachMismatch(const CallerState &a, const CallerState &b,
                            const Func &func) {
#define CALLER_STATE_REGISTER(type, name) \
  if (a.name != b.name) {                 \
    func(#name);                          \
  }
  LOOP_CALLER_STATE_REGISTERS()
#undef CALLER_STATE_REGISTER
}

// ReadUnwindResult adds the results of the most recent unwind test to |out|.
static void ReadUnwindResult(Result *out);

crypto_word_t RunTrampoline(Result *out, crypto_word_t func,
                            const crypto_word_t *argv, size_t argc,
                            bool unwind) {
  CallerState state;
  RAND_bytes(reinterpret_cast<uint8_t *>(&state), sizeof(state));

  unwind &= g_unwind_tests_enabled;
  CallerState state2 = state;
  crypto_word_t ret = abi_test_trampoline(func, &state2, argv, argc, unwind);

  *out = Result();
  ForEachMismatch(state, state2, [&](const char *reg) {
    out->errors.push_back(std::string(reg) + " was not restored after return");
  });
  if (unwind) {
    ReadUnwindResult(out);
  }
  return ret;
}
#endif  // SUPPORTS_ABI_TEST

#if defined(UNWIND_TEST_SIGTRAP)
// On Linux, we test unwind metadata using libunwind and |SIGTRAP|. We run the
// function under test with the trap flag set. This results in |SIGTRAP|s on
// every instruction. We then handle these signals and verify with libunwind.

// HandleEINTR runs |func| and returns the result, retrying the operation on
// |EINTR|.
template <typename Func>
static auto HandleEINTR(const Func &func) -> decltype(func()) {
  decltype(func()) ret;
  do {
    ret = func();
  } while (ret < 0 && errno == EINTR);
  return ret;
}

static bool ReadFileToString(std::string *out, const char *path) {
  out->clear();

  int fd = HandleEINTR([&] { return open(path, O_RDONLY); });
  if (fd < 0) {
    return false;
  }

  for (;;) {
    char buf[1024];
    ssize_t ret = HandleEINTR([&] { return read(fd, buf, sizeof(buf)); });
    if (ret < 0) {
      close(fd);
      return false;
    }
    if (ret == 0) {
      close(fd);
      return true;
    }
    out->append(buf, static_cast<size_t>(ret));
  }
}

static bool IsBeingDebugged() {
  std::string status;
  if (!ReadFileToString(&status, "/proc/self/status")) {
    perror("error reading /proc/self/status");
    return false;
  }
  std::string key = "\nTracerPid:\t";
  size_t idx = status.find(key);
  if (idx == std::string::npos) {
    return false;
  }
  idx += key.size();
  return idx < status.size() && status[idx] != '0';
}

// IsAncestorStackFrame returns true if |a_sp| is an ancestor stack frame of
// |b_sp|.
static bool IsAncestorStackFrame(unw_word_t a_sp, unw_word_t b_sp) {
#if defined(OPENSSL_X86_64)
  // The stack grows down, so ancestor stack frames have higher addresses.
  return a_sp > b_sp;
#else
#error "unknown architecture"
#endif
}

static int CallerStateFromUNWCursor(CallerState *out, unw_cursor_t *cursor) {
  // |CallerState| uses |crypto_word_t|, while libunwind uses |unw_word_t|, but
  // both are defined as |uint*_t| from stdint.h, so we can assume the types
  // match.
#if defined(OPENSSL_X86_64)
  int ret = 0;
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_RBX, &out->rbx);
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_RBP, &out->rbp);
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_R12, &out->r12);
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_R13, &out->r13);
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_R14, &out->r14);
  ret = ret < 0 ? ret : unw_get_reg(cursor, UNW_X86_64_R15, &out->r15);
  return ret;
#else
#error "unknown architecture"
#endif
}

// Implement some string formatting utilties. Ideally we would use |snprintf|,
// but this is called in a signal handler and |snprintf| is not async-signal-
// safe.

static std::array<char, DECIMAL_SIZE(unw_word_t) + 1> WordToDecimal(
    unw_word_t v) {
  std::array<char, DECIMAL_SIZE(unw_word_t) + 1> ret;
  size_t len = 0;
  do {
    ret[len++] = '0' + v % 10;
    v /= 10;
  } while (v != 0);
  for (size_t i = 0; i < len / 2; i++) {
    std::swap(ret[i], ret[len - 1 - i]);
  }
  ret[len] = '\0';
  return ret;
}

static std::array<char, sizeof(unw_word_t) * 2 + 1> WordToHex(unw_word_t v) {
  static const char kHex[] = "0123456789abcdef";
  std::array<char, sizeof(unw_word_t) * 2 + 1> ret;
  for (size_t i = sizeof(unw_word_t) - 1; i < sizeof(unw_word_t); i--) {
    uint8_t b = v & 0xff;
    v >>= 8;
    ret[i * 2] = kHex[b >> 4];
    ret[i * 2 + 1] = kHex[b & 0xf];
  }
  ret[sizeof(unw_word_t) * 2] = '\0';
  return ret;
}

static void StrCatSignalSafeImpl(bssl::Span<char> out) {}

template <typename... Args>
static void StrCatSignalSafeImpl(bssl::Span<char> out, const char *str,
                                 Args... args) {
  BUF_strlcat(out.data(), str, out.size());
  StrCatSignalSafeImpl(out, args...);
}

template <typename... Args>
static void StrCatSignalSafe(bssl::Span<char> out, Args... args) {
  if (out.empty()) {
    return;
  }
  out[0] = '\0';
  StrCatSignalSafeImpl(out, args...);
}

static int UnwindToSignalFrame(unw_cursor_t *cursor) {
  for (;;) {
    int ret = unw_is_signal_frame(cursor);
    if (ret < 0) {
      return ret;
    }
    if (ret != 0) {
      return 0;  // Found the signal frame.
    }
    ret = unw_step(cursor);
    if (ret < 0) {
      return ret;
    }
  }
}

// IPToString returns a human-readable representation of |ip|, using debug
// information from |ctx| if available. |ip| must be the address of |ctx|'s
// signal frame. This function is async-signal-safe.
static std::array<char, 256> IPToString(unw_word_t ip, unw_context_t *ctx) {
  std::array<char, 256> ret;
  // Use a new cursor. The caller's cursor has already been unwound, but
  // |unw_get_proc_name| is slow so we do not wish to call it all the time.
  unw_cursor_t cursor;
  // Work around a bug in libunwind. See
  // https://git.savannah.gnu.org/gitweb/?p=libunwind.git;a=commit;h=819bf51bbd2da462c2ec3401e8ac9153b6e725e3
  OPENSSL_memset(&cursor, 0, sizeof(cursor));
  unw_word_t off;
  if (unw_init_local(&cursor, ctx) != 0 ||
      UnwindToSignalFrame(&cursor) != 0 ||
      unw_get_proc_name(&cursor, ret.data(), ret.size(), &off) != 0) {
    StrCatSignalSafe(bssl::MakeSpan(ret), "0x", WordToHex(ip).data());
    return ret;
  }
  size_t len = strlen(ret.data());
  // Print the offset in decimal, to match gdb's disassembly output and ease
  // debugging.
  StrCatSignalSafe(bssl::MakeSpan(ret).subspan(len), "+",
                   WordToDecimal(off).data(), " (0x", WordToHex(ip).data(),
                   ")");
  return ret;
}

static pthread_t g_main_thread;

// g_in_trampoline is true if we are in an instrumented |abi_test_trampoline|
// call, in the region that triggers |SIGTRAP|.
static bool g_in_trampoline = false;
// g_unwind_function_done, if |g_in_trampoline| is true, is whether the function
// under test has returned. It is undefined otherwise.
static bool g_unwind_function_done;
// g_trampoline_state, if |g_in_trampoline| is true, is the state the function
// under test must preserve. It is undefined otherwise.
static CallerState g_trampoline_state;
// g_trampoline_sp, if |g_in_trampoline| is true, is the stack pointer of the
// trampoline frame. It is undefined otherwise.
static unw_word_t g_trampoline_sp;

// kMaxUnwindErrors is the maximum number of unwind errors reported per
// function. If a function's unwind tables are wrong, we are otherwise likely to
// repeat the same error at multiple addresses.
static constexpr size_t kMaxUnwindErrors = 10;

// Errors are saved in a signal handler. We use a static buffer to avoid
// allocation.
static size_t num_unwind_errors = 0;
static char unwind_errors[kMaxUnwindErrors][512];

template <typename... Args>
static void AddUnwindError(Args... args) {
  if (num_unwind_errors >= kMaxUnwindErrors) {
    return;
  }
  StrCatSignalSafe(unwind_errors[num_unwind_errors], args...);
  num_unwind_errors++;
}

template <typename... Args>
[[noreturn]] static void FatalError(Args... args) {
  // We cannot use |snprintf| here because it is not async-signal-safe.
  char buf[512];
  StrCatSignalSafe(buf, args..., "\n");
  write(STDERR_FILENO, buf, strlen(buf));
  abort();
}

static void TrapHandler(int sig) {
  // Note this is a signal handler, so only async-signal-safe functions may be
  // used here. See signal-safety(7). libunwind promises local unwind is
  // async-signal-safe.

  // |pthread_equal| is not listed as async-signal-safe, but this is clearly an
  // oversight.
  if (!pthread_equal(g_main_thread, pthread_self())) {
    FatalError("SIGTRAP on background thread");
  }

  unw_context_t ctx;
  int ret = unw_getcontext(&ctx);
  unw_cursor_t cursor;
  // Work around a bug in libunwind which breaks rax and rdx recovery. This
  // breaks functions which temporarily use rax as the CFA register. See
  // https://git.savannah.gnu.org/gitweb/?p=libunwind.git;a=commit;h=819bf51bbd2da462c2ec3401e8ac9153b6e725e3
  OPENSSL_memset(&cursor, 0, sizeof(cursor));
  ret = ret < 0 ? ret : unw_init_local(&cursor, &ctx);
  ret = ret < 0 ? ret : UnwindToSignalFrame(&cursor);
  unw_word_t sp, ip;
  ret = ret < 0 ? ret : unw_get_reg(&cursor, UNW_REG_SP, &sp);
  ret = ret < 0 ? ret : unw_get_reg(&cursor, UNW_REG_IP, &ip);
  if (ret < 0) {
    FatalError("Error initializing unwind cursor: ", unw_strerror(ret));
  }

  const unw_word_t kStartAddress =
      reinterpret_cast<unw_word_t>(&abi_test_unwind_start);
  const unw_word_t kReturnAddress =
      reinterpret_cast<unw_word_t>(&abi_test_unwind_return);
  const unw_word_t kStopAddress =
      reinterpret_cast<unw_word_t>(&abi_test_unwind_stop);
  if (!g_in_trampoline) {
    if (ip != kStartAddress) {
      FatalError("Unexpected SIGTRAP at ", IPToString(ip, &ctx).data());
    }

    // Save the current state and begin.
    g_in_trampoline = true;
    g_unwind_function_done = false;
    g_trampoline_sp = sp;
    ret = CallerStateFromUNWCursor(&g_trampoline_state, &cursor);
    if (ret < 0) {
      FatalError("Error getting initial caller state: ", unw_strerror(ret));
    }
  } else {
    if (sp == g_trampoline_sp || g_unwind_function_done) {
      // |g_unwind_function_done| should imply |sp| is |g_trampoline_sp|, but
      // clearing the trap flag in x86 briefly displaces the stack pointer.
      //
      // Also note we check both |ip| and |sp| below, in case the function under
      // test is also |abi_test_trampoline|.
      if (ip == kReturnAddress && sp == g_trampoline_sp) {
        g_unwind_function_done = true;
      }
      if (ip == kStopAddress && sp == g_trampoline_sp) {
        // |SIGTRAP| is fatal again.
        g_in_trampoline = false;
      }
    } else if (IsAncestorStackFrame(sp, g_trampoline_sp)) {
      // This should never happen. We went past |g_trampoline_sp| without
      // stopping at |kStopAddress|.
      AddUnwindError("stack frame is before caller at ",
                     IPToString(ip, &ctx).data());
      g_in_trampoline = false;
    } else if (num_unwind_errors < kMaxUnwindErrors) {
      for (;;) {
        ret = unw_step(&cursor);
        if (ret < 0) {
          AddUnwindError("error unwinding from ", IPToString(ip, &ctx).data(),
                         ": ", unw_strerror(ret));
          break;
        }
        if (ret == 0) {
          AddUnwindError("could not unwind to starting frame from ",
                         IPToString(ip, &ctx).data());
          break;
        }

        unw_word_t cur_sp;
        ret = unw_get_reg(&cursor, UNW_REG_SP, &cur_sp);
        if (ret < 0) {
          AddUnwindError("error recovering stack pointer unwinding from ",
                         IPToString(ip, &ctx).data(), ": ", unw_strerror(ret));
          break;
        }
        if (IsAncestorStackFrame(cur_sp, g_trampoline_sp)) {
          AddUnwindError("unwound past starting frame from ",
                         IPToString(ip, &ctx).data());
          break;
        }
        if (cur_sp == g_trampoline_sp) {
          // We found the parent frame. Check the return address.
          unw_word_t cur_ip;
          ret = unw_get_reg(&cursor, UNW_REG_IP, &cur_ip);
          if (ret < 0) {
            AddUnwindError("error recovering return address unwinding from ",
                           IPToString(ip, &ctx).data(), ": ",
                           unw_strerror(ret));
          } else if (cur_ip != kReturnAddress) {
            AddUnwindError("wrong return address unwinding from ",
                           IPToString(ip, &ctx).data());
          }

          // Check the remaining registers.
          CallerState state;
          ret = CallerStateFromUNWCursor(&state, &cursor);
          if (ret < 0) {
            AddUnwindError("error recovering registers unwinding from ",
                           IPToString(ip, &ctx).data(), ": ",
                           unw_strerror(ret));
          } else {
            ForEachMismatch(state, g_trampoline_state, [&](const char *reg) {
              AddUnwindError(reg, " was not recovered unwinding from ",
                             IPToString(ip, &ctx).data());
            });
          }
          break;
        }
      }
    }
  }
}

static void ReadUnwindResult(Result *out) {
  for (size_t i = 0; i < num_unwind_errors; i++) {
    out->errors.emplace_back(unwind_errors[i]);
  }
  if (num_unwind_errors == kMaxUnwindErrors) {
    out->errors.emplace_back("(additional errors omitted)");
  }
  num_unwind_errors = 0;
}

static void EnableUnwindTestsImpl() {
  if (IsBeingDebugged()) {
    // Unwind tests drive logic via |SIGTRAP|, which conflicts with debuggers.
    fprintf(stderr, "Debugger detected. Disabling unwind tests.\n");
    return;
  }

  g_main_thread = pthread_self();

  struct sigaction trap_action;
  OPENSSL_memset(&trap_action, 0, sizeof(trap_action));
  sigemptyset(&trap_action.sa_mask);
  trap_action.sa_handler = TrapHandler;
  if (sigaction(SIGTRAP, &trap_action, NULL) != 0) {
    perror("sigaction");
    abort();
  }

  g_unwind_tests_enabled = true;
}

#else
// TODO(davidben): Implement an SEH-based unwind-tester.
#if defined(SUPPORTS_ABI_TEST)
static void ReadUnwindResult(Result *) {}
#endif
static void EnableUnwindTestsImpl() {}
#endif  // UNWIND_TEST_SIGTRAP

}  // namespace internal

void EnableUnwindTests() { internal::EnableUnwindTestsImpl(); }

bool UnwindTestsEnabled() { return internal::g_unwind_tests_enabled; }

}  // namespace abi_test
