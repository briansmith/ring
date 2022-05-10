/* Copyright (c) 2019, Google Inc.
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
#include <stdlib.h>

#include <openssl/ctrdrbg.h>
#include <openssl/rand.h>

#include "getrandom_fillin.h"
#include "internal.h"

#if (defined(OPENSSL_X86_64) || defined(OPENSSL_AARCH64)) && \
    !defined(BORINGSSL_SHARED_LIBRARY) &&                    \
    !defined(BORINGSSL_UNSAFE_DETERMINISTIC_MODE) && defined(USE_NR_getrandom)

#include <linux/random.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>

#include "fork_detect.h"

#if !defined(PTRACE_O_EXITKILL)
#define PTRACE_O_EXITKILL (1 << 20)
#endif

#if defined(BORINGSSL_FIPS)
static const bool kIsFIPS = true;
#if defined(OPENSSL_ANDROID)
static const bool kUsesDaemon = true;
#else
static const bool kUsesDaemon = false;
#endif
#else
static const bool kIsFIPS = false;
static const bool kUsesDaemon = false;
#endif

// kDaemonWriteLength is the number of bytes that the entropy daemon writes.
static const size_t kDaemonWriteLength = 496;

// This test can be run with $OPENSSL_ia32cap=~0x4000000000000000 in order to
// simulate the absence of RDRAND of machines that have it.

// Event represents a system call from urandom.c that is observed by the ptrace
// code in |GetTrace|.
struct Event {
  enum class Syscall {
    kGetRandom,
    kOpen,
    kUrandomRead,
    kUrandomIoctl,
    kSocket,
    kConnect,
    kSocketRead,
    kSocketClose,
    kAbort,
  };

  explicit Event(Syscall syscall) : type(syscall) {}

  bool operator==(const Event &other) const {
    return type == other.type && length == other.length &&
           flags == other.flags &&
           ((filename == nullptr && other.filename == nullptr) ||
            strcmp(filename, other.filename) == 0);
  }

  static Event GetRandom(size_t length, unsigned flags) {
    Event e(Syscall::kGetRandom);
    e.length = length;
    e.flags = flags;
    return e;
  }

  static Event Open(const char *filename) {
    Event e(Syscall::kOpen);
    e.filename = filename;
    return e;
  }

  static Event UrandomRead(size_t length) {
    Event e(Syscall::kUrandomRead);
    e.length = length;
    return e;
  }

  static Event UrandomIoctl() {
    Event e(Syscall::kUrandomIoctl);
    return e;
  }

  static Event Socket() {
    Event e(Syscall::kSocket);
    return e;
  }

  static Event Connect() {
    Event e(Syscall::kConnect);
    return e;
  }

  static Event SocketRead(size_t length) {
    Event e(Syscall::kSocketRead);
    e.length = length;
    return e;
  }

  static Event SocketClose() {
    Event e(Syscall::kSocketClose);
    return e;
  }

  static Event Abort() {
    Event e(Syscall::kAbort);
    return e;
  }

  std::string String() const {
    char buf[256];

    switch (type) {
      case Syscall::kGetRandom:
        snprintf(buf, sizeof(buf), "getrandom(_, %zu, %u)", length, flags);
        break;

      case Syscall::kOpen:
        snprintf(buf, sizeof(buf), "open(%s, _)", filename);
        break;

      case Syscall::kUrandomRead:
        snprintf(buf, sizeof(buf), "read(urandom_fd, _, %zu)", length);
        break;

      case Syscall::kUrandomIoctl:
        return "ioctl(urandom_fd, RNDGETENTCNT, _)";

      case Syscall::kSocket:
        return "socket(UNIX, STREAM, _)";

      case Syscall::kConnect:
        return "connect(sock, _, _)";

      case Syscall::kSocketRead:
        snprintf(buf, sizeof(buf), "read(sock_fd, _, %zu)", length);
        break;

      case Syscall::kSocketClose:
        return "close(sock)";

      case Syscall::kAbort:
        return "abort()";
    }

    return std::string(buf);
  }

  const Syscall type;
  size_t length = 0;
  unsigned flags = 0;
  const char *filename = nullptr;
};

static std::string ToString(const std::vector<Event> &trace) {
  std::string ret;
  for (const auto &event : trace) {
    if (!ret.empty()) {
      ret += ", ";
    }
    ret += event.String();
  }
  return ret;
}

// The following are flags to tell |GetTrace| to inject faults, using ptrace,
// into the entropy-related system calls.

// getrandom gives |ENOSYS|.
static const unsigned NO_GETRANDOM = 1;
// opening /dev/urandom fails.
static const unsigned NO_URANDOM = 2;
// getrandom always returns |EAGAIN| if given |GRNG_NONBLOCK|.
static const unsigned GETRANDOM_NOT_READY = 4;
// The ioctl on urandom returns only 255 bits of entropy the first time that
// it's called.
static const unsigned URANDOM_NOT_READY = 8;
// getrandom gives |EINVAL| unless |NO_GETRANDOM| is set.
static const unsigned GETRANDOM_ERROR = 16;
// Reading from /dev/urandom gives |EINVAL|.
static const unsigned URANDOM_ERROR = 32;
static const unsigned SOCKET_ERROR = 64;
static const unsigned CONNECT_ERROR = 128;
static const unsigned SOCKET_READ_ERROR = 256;
static const unsigned SOCKET_READ_SHORT = 512;
static const unsigned NEXT_FLAG = 1024;

// regs_read fetches the registers of |child_pid| and writes them to |out_regs|.
// That structure will contain at least the following members:
//   syscall: the syscall number, if registers were read just before entering
//       one.
//   args[0..2]: syscall arguments, if registers were read just before
//       entering one.
//   ret: the syscall return value, if registers were read just after finishing
//       one.
//
// This call returns true on success and false otherwise.
static bool regs_read(struct regs *out_regs, int child_pid);

// regs_set_ret sets the return value of the system call that |child_pid| has
// just finished, to |ret|. It returns true on success and false otherwise.
static bool regs_set_ret(int child_pid, int ret);

// regs_break_syscall causes the system call that |child_pid| is about to enter
// to fail to run.
static bool regs_break_syscall(int child_pid, const struct regs *orig_regs);

#if defined(OPENSSL_X86_64)

struct regs {
  uintptr_t syscall;
  uintptr_t args[3];
  uintptr_t ret;
  struct user_regs_struct regs;
};

static bool regs_read(struct regs *out_regs, int child_pid) {
  if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &out_regs->regs) != 0) {
    return false;
  }

  out_regs->syscall = out_regs->regs.orig_rax;
  out_regs->ret = out_regs->regs.rax;
  out_regs->args[0] = out_regs->regs.rdi;
  out_regs->args[1] = out_regs->regs.rsi;
  out_regs->args[2] = out_regs->regs.rdx;
  return true;
}

static bool regs_set_ret(int child_pid, int ret) {
  struct regs regs;
  if (!regs_read(&regs, child_pid)) {
    return false;
  }
  regs.regs.rax = ret;
  return ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs.regs) == 0;
}

static bool regs_break_syscall(int child_pid, const struct regs *orig_regs) {
  // Replacing the syscall number with -1 doesn't work on AArch64 thus we set
  // the first argument to -1, which suffices to break the syscalls that we care
  // about here.
  struct user_regs_struct regs;
  memcpy(&regs, &orig_regs->regs, sizeof(regs));
  regs.rdi = -1;
  return ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs) == 0;
}

#elif defined(OPENSSL_AARCH64)

struct regs {
  uintptr_t syscall;
  uintptr_t args[3];
  uintptr_t ret;
  uint64_t regs[9];
};

static bool regs_read(struct regs *out_regs, int child_pid) {
  struct iovec io;
  io.iov_base = out_regs->regs;
  io.iov_len = sizeof(out_regs->regs);
  if (ptrace(PTRACE_GETREGSET, child_pid, (void *)/*NT_PRSTATUS*/ 1, &io) !=
      0) {
    return false;
  }

  out_regs->syscall = out_regs->regs[8];
  out_regs->ret = out_regs->regs[0];
  out_regs->args[0] = out_regs->regs[0];
  out_regs->args[1] = out_regs->regs[1];
  out_regs->args[2] = out_regs->regs[2];

  return true;
}

static bool regs_set(int child_pid, const struct regs *orig_regs,
                     uint64_t x0_value) {
  uint64_t regs[OPENSSL_ARRAY_SIZE(orig_regs->regs)];
  memcpy(regs, orig_regs->regs, sizeof(regs));
  regs[0] = x0_value;

  struct iovec io;
  io.iov_base = regs;
  io.iov_len = sizeof(regs);
  return ptrace(PTRACE_SETREGSET, child_pid, (void *)/*NT_PRSTATUS*/ 1, &io) ==
         0;
}

static bool regs_set_ret(int child_pid, int ret) {
  struct regs regs;
  return regs_read(&regs, child_pid) && regs_set(child_pid, &regs, ret);
}

static bool regs_break_syscall(int child_pid, const struct regs *orig_regs) {
  // Replacing the syscall number with -1 doesn't work on AArch64 thus we set
  // the first argument to -1, which suffices to break the syscalls that we care
  // about here.
  return regs_set(child_pid, orig_regs, -1);
}

#endif

// SyscallResult is like std::optional<int>.
// TODO: use std::optional when we can use C++17.
class SyscallResult {
 public:
  SyscallResult &operator=(int value) {
    has_value_ = true;
    value_ = value;
    return *this;
  }

  int value() const {
    if (!has_value_) {
      abort();
    }
    return value_;
  }

  bool has_value() const { return has_value_; }

 private:
  bool has_value_ = false;
  int value_ = 0;
};

// memcpy_to_remote copies |n| bytes from |in_src| in the local address space,
// to |dest| in the address space of |child_pid|.
static void memcpy_to_remote(int child_pid, uint64_t dest, const void *in_src,
                             size_t n) {
  const uint8_t *src = reinterpret_cast<const uint8_t *>(in_src);

  // ptrace always works with ill-defined "words", which appear to be 64-bit
  // on 64-bit systems.
#if !defined(OPENSSL_64_BIT)
#error "This code probably doesn't work"
#endif

  while (n) {
    const uintptr_t aligned_addr = dest & ~7;
    const uintptr_t offset = dest - aligned_addr;
    const size_t space = 8 - offset;
    size_t todo = n;
    if (todo > space) {
      todo = space;
    }

    uint64_t word;
    if (offset == 0 && todo == 8) {
      word = CRYPTO_load_u64_le(src);
    } else {
      uint8_t bytes[8];
      CRYPTO_store_u64_le(
          bytes, ptrace(PTRACE_PEEKDATA, child_pid,
                        reinterpret_cast<void *>(aligned_addr), nullptr));
      memcpy(&bytes[offset], src, todo);
      word = CRYPTO_load_u64_le(bytes);
    }

    ASSERT_EQ(0, ptrace(PTRACE_POKEDATA, child_pid,
                        reinterpret_cast<void *>(aligned_addr),
                        reinterpret_cast<void *>(word)));

    src += todo;
    n -= todo;
    dest += todo;
  }
}

// GetTrace runs |thunk| in a forked process and observes the resulting system
// calls using ptrace. It simulates a variety of failures based on the contents
// of |flags| and records the observed events by appending to |out_trace|.
static void GetTrace(std::vector<Event> *out_trace, unsigned flags,
                     std::function<void()> thunk) {
  const int child_pid = fork();
  ASSERT_NE(-1, child_pid);

  if (child_pid == 0) {
    // Child process
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
      perror("PTRACE_TRACEME");
      _exit(1);
    }
    raise(SIGSTOP);
    thunk();
    _exit(0);
  }

  // Parent process
  int status;
  ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
  ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  // Set options so that:
  //   a) the child process is killed once this process dies.
  //   b) System calls result in a WSTOPSIG value of (SIGTRAP | 0x80) rather
  //      than just SIGTRAP. (This doesn't matter here, but it's recommended
  //      practice so that it's distinct from the signal itself.)
  ASSERT_EQ(0, ptrace(PTRACE_SETOPTIONS, child_pid, nullptr,
                      PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD))
      << strerror(errno);

  // urandom_fd tracks the file descriptor number for /dev/urandom in the child
  // process, if it opens it.
  int urandom_fd = -1;

  // sock_fd tracks the file descriptor number for the socket to the entropy
  // daemon, if one is opened.
  int sock_fd = -1;

  for (;;) {
    // Advance the child to the next system call.
    ASSERT_EQ(0, ptrace(PTRACE_SYSCALL, child_pid, 0, 0));
    ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));

    // The child may have aborted rather than made a system call.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGABRT) {
      out_trace->push_back(Event::Abort());
      break;
    }

    // Otherwise the only valid ptrace event is a system call stop.
    ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

    struct regs regs;
    ASSERT_TRUE(regs_read(&regs, child_pid));

    bool is_opening_urandom = false;
    bool is_socket_call = false;
    bool is_urandom_ioctl = false;
    uintptr_t ioctl_output_addr = 0;
    bool is_socket_read = false;
    uint64_t socket_read_bytes = 0;
    // force_result is unset to indicate that the system call should run
    // normally. Otherwise it's, e.g. -EINVAL, to indicate that the system call
    // should not run and that the given value should be injected on return.
    SyscallResult force_result;

    switch (regs.syscall) {
      case __NR_getrandom:
        if (flags & NO_GETRANDOM) {
          force_result = -ENOSYS;
        } else if (flags & GETRANDOM_ERROR) {
          force_result = -EINVAL;
        } else if (flags & GETRANDOM_NOT_READY) {
          if (regs.args[2] & GRND_NONBLOCK) {
            force_result = -EAGAIN;
          }
        }
        out_trace->push_back(
            Event::GetRandom(/*length=*/regs.args[1], /*flags=*/regs.args[2]));
        break;

      case __NR_openat:
#if defined(OPENSSL_X86_64)
      case __NR_open:
#endif
      {
        // It's assumed that any arguments to open(2) are constants in read-only
        // memory and thus the pointer in the child's context will also be a
        // valid pointer in our address space.
        const char *filename = reinterpret_cast<const char *>(
            (regs.syscall == __NR_openat) ? regs.args[1] : regs.args[0]);
        out_trace->push_back(Event::Open(filename));
        is_opening_urandom = strcmp(filename, "/dev/urandom") == 0;
        if (is_opening_urandom && (flags & NO_URANDOM)) {
          force_result = -ENOENT;
        }
        break;
      }

      case __NR_read: {
        const int read_fd = regs.args[0];
        if (urandom_fd >= 0 && urandom_fd == read_fd) {
          out_trace->push_back(Event::UrandomRead(/*length=*/regs.args[2]));
          if (flags & URANDOM_ERROR) {
            force_result = -EINVAL;
          }
        } else if (sock_fd >= 0 && sock_fd == read_fd) {
          uint64_t length = regs.args[2];
          out_trace->push_back(Event::SocketRead(length));
          if (flags & SOCKET_READ_ERROR) {
            force_result = -EINVAL;
          } else {
            is_socket_read = true;
            socket_read_bytes = length;

            if (flags & SOCKET_READ_SHORT) {
              ASSERT_GT(socket_read_bytes, 0u);
              socket_read_bytes--;
              flags &= ~SOCKET_READ_SHORT;
            }
          }
        }
        break;
      }

      case __NR_close: {
        if (sock_fd >= 0 && static_cast<int>(regs.args[0]) == sock_fd) {
          out_trace->push_back(Event::SocketClose());
          sock_fd = -1;
        }
        break;
      }

      case __NR_ioctl: {
        const int ioctl_fd = regs.args[0];
        if (urandom_fd >= 0 && ioctl_fd == urandom_fd &&
            regs.args[1] == RNDGETENTCNT) {
          out_trace->push_back(Event::UrandomIoctl());
          is_urandom_ioctl = true;
          ioctl_output_addr = regs.args[2];
        }
        break;
      }

      case __NR_socket: {
        const int family = regs.args[0];
        const int type = regs.args[1];
        if (family == AF_UNIX && type == SOCK_STREAM) {
          out_trace->push_back(Event::Socket());
          is_socket_call = true;
          if (flags & SOCKET_ERROR) {
            force_result = -EINVAL;
          }
        }
        break;
      }

      case __NR_connect: {
        const int connect_fd = regs.args[0];
        if (sock_fd >= 0 && connect_fd == sock_fd) {
          out_trace->push_back(Event::Connect());
          if (flags & CONNECT_ERROR) {
            force_result = -EINVAL;
          } else {
            // The test system might not have an entropy daemon running so
            // inject a success result.
            force_result = 0;
          }
        }

        break;
      }
    }

    if (force_result.has_value()) {
      ASSERT_TRUE(regs_break_syscall(child_pid, &regs));
    }

    ASSERT_EQ(0, ptrace(PTRACE_SYSCALL, child_pid, 0, 0));
    ASSERT_EQ(child_pid, waitpid(child_pid, &status, 0));
    // If the system call was exit/exit_group, the process may be terminated
    // rather than have exited the system call.
    if (WIFEXITED(status)) {
      ASSERT_EQ(0, WEXITSTATUS(status));
      return;
    }

    // Otherwise the next state must be a system call exit stop. This is
    // indistinguishable from a system call entry, we just have to keep track
    // and know that these events happen in pairs.
    ASSERT_TRUE(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

    if (force_result.has_value()) {
      ASSERT_TRUE(regs_set_ret(child_pid, force_result.value()));
    } else if (is_opening_urandom) {
      ASSERT_TRUE(regs_read(&regs, child_pid));
      urandom_fd = regs.ret;
    } else if (is_socket_call) {
      ASSERT_TRUE(regs_read(&regs, child_pid));
      sock_fd = regs.ret;
    } else if (is_urandom_ioctl) {
      // The result is the number of bits of entropy that the kernel currently
      // believes that it has. urandom.c waits until 256 bits are ready.
      int result = 256;

      // If we are simulating urandom not being ready then we have the ioctl
      // indicate one too few bits of entropy the first time it's queried.
      if (flags & URANDOM_NOT_READY) {
        result--;
        flags &= ~URANDOM_NOT_READY;
      }

      memcpy_to_remote(child_pid, ioctl_output_addr, &result, sizeof(result));
    } else if (is_socket_read) {
      // Simulate a response from the entropy daemon since it might not be
      // running on the current system.
      uint8_t entropy[kDaemonWriteLength];
      ASSERT_LE(socket_read_bytes, sizeof(entropy));

      for (size_t i = 0; i < sizeof(entropy); i++) {
        entropy[i] = i & 0xff;
      }
      memcpy_to_remote(child_pid, regs.args[1], entropy, socket_read_bytes);

      ASSERT_TRUE(regs_set_ret(child_pid, socket_read_bytes));
    }
  }
}

// TestFunction is the function that |GetTrace| is asked to trace.
static void TestFunction() {
  uint8_t byte;
  RAND_bytes(&byte, sizeof(byte));
  RAND_bytes(&byte, sizeof(byte));
}

static bool have_fork_detection() { return CRYPTO_get_fork_generation() != 0; }

static bool AppendDaemonEvents(std::vector<Event> *events, unsigned flags) {
  events->push_back(Event::Socket());
  if (flags & SOCKET_ERROR) {
    return false;
  }

  bool ret = false;
  events->push_back(Event::Connect());
  if (flags & CONNECT_ERROR) {
    goto out;
  }

  events->push_back(Event::SocketRead(kDaemonWriteLength));
  if (flags & SOCKET_READ_ERROR) {
    goto out;
  }

  if (flags & SOCKET_READ_SHORT) {
    events->push_back(Event::SocketRead(1));
  }

  ret = true;

out:
  events->push_back(Event::SocketClose());
  return ret;
}

// TestFunctionPRNGModel is a model of how the urandom.c code will behave when
// |TestFunction| is run. It should return the same trace of events that
// |GetTrace| will observe the real code making.
static std::vector<Event> TestFunctionPRNGModel(unsigned flags) {
  std::vector<Event> ret;
  bool urandom_probed = false;
  bool getrandom_ready = false;

  const bool used_daemon = kUsesDaemon && AppendDaemonEvents(&ret, flags);

  // Probe for getrandom support
  ret.push_back(Event::GetRandom(1, GRND_NONBLOCK));
  std::function<void()> wait_for_entropy;
  std::function<bool(bool, size_t)> sysrand;

  if (flags & NO_GETRANDOM) {
    ret.push_back(Event::Open("/dev/urandom"));
    if (flags & NO_URANDOM) {
      ret.push_back(Event::Abort());
      return ret;
    }

    wait_for_entropy = [&ret, &urandom_probed, flags] {
      if (!kIsFIPS || urandom_probed) {
        return;
      }

      // Probe urandom for entropy.
      ret.push_back(Event::UrandomIoctl());
      if (flags & URANDOM_NOT_READY) {
        // If the first attempt doesn't report enough entropy, probe
        // repeatedly until it does, which will happen with the second attempt.
        ret.push_back(Event::UrandomIoctl());
      }

      urandom_probed = true;
    };

    sysrand = [&ret, &wait_for_entropy, flags](bool block, size_t len) {
      if (block) {
        wait_for_entropy();
      }
      ret.push_back(Event::UrandomRead(len));
      if (flags & URANDOM_ERROR) {
        ret.push_back(Event::Abort());
        return false;
      }
      return true;
    };
  } else {
    if (flags & GETRANDOM_ERROR) {
      ret.push_back(Event::Abort());
      return ret;
    }

    getrandom_ready = (flags & GETRANDOM_NOT_READY) == 0;
    wait_for_entropy = [&ret, &getrandom_ready] {
      if (getrandom_ready) {
        return;
      }

      ret.push_back(Event::GetRandom(1, GRND_NONBLOCK));
      ret.push_back(Event::GetRandom(1, 0));
      getrandom_ready = true;
    };
    sysrand = [&ret, &wait_for_entropy](bool block, size_t len) {
      if (block) {
        wait_for_entropy();
      }
      ret.push_back(Event::GetRandom(len, block ? 0 : GRND_NONBLOCK));
      return true;
    };
  }

  const size_t kSeedLength = CTR_DRBG_ENTROPY_LEN * (kIsFIPS ? 10 : 1);
  const size_t kAdditionalDataLength = 32;

  if (!have_rdrand()) {
    if ((!have_fork_detection() && !sysrand(true, kAdditionalDataLength)) ||
        // Initialise CRNGT.
        (!used_daemon && !sysrand(true, kSeedLength + (kIsFIPS ? 16 : 0))) ||
        // Personalisation draw if the daemon was used.
        (used_daemon && !sysrand(false, CTR_DRBG_ENTROPY_LEN)) ||
        // Second entropy draw.
        (!have_fork_detection() && !sysrand(true, kAdditionalDataLength))) {
      return ret;
    }
  } else if (
      // First additional data. If fast RDRAND isn't available then a
      // non-blocking OS entropy draw will be tried.
      (!have_fast_rdrand() && !have_fork_detection() &&
       !sysrand(false, kAdditionalDataLength)) ||
      // Opportuntistic entropy draw in FIPS mode because RDRAND was used.
      // In non-FIPS mode it's just drawn from |CRYPTO_sysrand| in a blocking
      // way.
      !sysrand(!kIsFIPS, CTR_DRBG_ENTROPY_LEN) ||
      // Second entropy draw's additional data.
      (!have_fast_rdrand() && !have_fork_detection() &&
       !sysrand(false, kAdditionalDataLength))) {
    return ret;
  }

  return ret;
}

static void CheckInvariants(const std::vector<Event> &events) {
  // If RDRAND is available then there should be no blocking syscalls in FIPS
  // mode.
#if defined(BORINGSSL_FIPS)
  if (have_rdrand()) {
    for (const auto &event : events) {
      switch (event.type) {
        case Event::Syscall::kGetRandom:
          if ((event.flags & GRND_NONBLOCK) == 0) {
            ADD_FAILURE() << "Blocking getrandom found with RDRAND: "
                          << ToString(events);
          }
          break;

        case Event::Syscall::kUrandomIoctl:
          ADD_FAILURE() << "Urandom polling found with RDRAND: "
                        << ToString(events);
          break;

        default:
          break;
      }
    }
  }
#endif
}

// Tests that |TestFunctionPRNGModel| is a correct model for the code in
// urandom.c, at least to the limits of the the |Event| type.
TEST(URandomTest, Test) {
  char buf[256];

#define TRACE_FLAG(flag)                                         \
  snprintf(buf, sizeof(buf), #flag ": %d", (flags & flag) != 0); \
  SCOPED_TRACE(buf);

  for (unsigned flags = 0; flags < NEXT_FLAG; flags++) {
    if (!kUsesDaemon && (flags & (SOCKET_ERROR | CONNECT_ERROR |
                                  SOCKET_READ_ERROR | SOCKET_READ_SHORT))) {
      // These cases are meaningless unless the code will try to use the entropy
      // daemon.
      continue;
    }

    TRACE_FLAG(NO_GETRANDOM);
    TRACE_FLAG(NO_URANDOM);
    TRACE_FLAG(GETRANDOM_NOT_READY);
    TRACE_FLAG(URANDOM_NOT_READY);
    TRACE_FLAG(GETRANDOM_ERROR);
    TRACE_FLAG(URANDOM_ERROR);
    TRACE_FLAG(SOCKET_ERROR);
    TRACE_FLAG(CONNECT_ERROR);
    TRACE_FLAG(SOCKET_READ_ERROR);
    TRACE_FLAG(SOCKET_READ_SHORT);

    const std::vector<Event> expected_trace = TestFunctionPRNGModel(flags);
    CheckInvariants(expected_trace);
    std::vector<Event> actual_trace;
    GetTrace(&actual_trace, flags, TestFunction);

    if (expected_trace != actual_trace) {
      ADD_FAILURE() << "Expected: " << ToString(expected_trace)
                    << "\nFound:    " << ToString(actual_trace);
    }
  }
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  if (getenv("BORINGSSL_IGNORE_MADV_WIPEONFORK")) {
    CRYPTO_fork_detect_ignore_madv_wipeonfork_for_testing();
  }

  return RUN_ALL_TESTS();
}

#else

int main(int argc, char **argv) {
  printf("PASS\n");
  return 0;
}

#endif  // (X86_64 || AARCH64) && !SHARED_LIBRARY &&
        // !UNSAFE_DETERMINISTIC_MODE && USE_NR_getrandom
