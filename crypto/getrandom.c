#include <stdlib.h>
#include <GFp/base.h>

extern const long GFp_SYS_GETRANDOM;

int GFp_getrandom(void* buf, size_t buflen, unsigned int flags);

int GFp_getrandom(void* buf, size_t buflen, unsigned int flags) {
    int res = 0;

#if defined(OPENSSL_X86)
    __asm__ volatile (
      "mov %1, %%eax\n"
      "mov %2, %%ebx\n"
      "mov %3, %%ecx\n"
      "mov %4, %%edx\n"
      "int $0x80\n"
      "mov %%eax, %0\n"
      : "=g" (res) // 0
      : "g" (GFp_SYS_GETRANDOM), // 1
        "g" (buf), // 2
        "g" (buflen), // 3
        "g" (flags) // 4
    );
#elif defined(OPENSSL_X86_64)
    __asm__ volatile (
      "mov %1, %%rax\n"
      "mov %2, %%rdi\n"
      "mov %3, %%rsi"
      "mov %4, %%rcx\n"
      "syscall\n"
      "mov %%rax, %0\n"
      : "=g" (res) // 0
      : "g" (GFp_SYS_GETRANDOM), // 1
        "g" (buf), // 2
        "g" (buflen), // 3
        "g" (flags) // 4
    );
#endif
    return res;
}
