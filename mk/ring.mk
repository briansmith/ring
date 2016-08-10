# Copyright 2015 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

RING_PREFIX ?= ring/

RING_CPPFLAGS = -I$(RING_PREFIX)include -D_XOPEN_SOURCE=700

RING_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/aes/aes.c \
  crypto/bn/add.c \
  crypto/bn/bn.c \
  crypto/bn/cmp.c \
  crypto/bn/convert.c \
  crypto/bn/ctx.c \
  crypto/bn/div.c \
  crypto/bn/exponentiation.c \
  crypto/bn/gcd.c \
  crypto/bn/generic.c \
  crypto/bn/montgomery.c \
  crypto/bn/montgomery_inv.c \
  crypto/bn/mul.c \
  crypto/bn/random.c \
  crypto/bn/rsaz_exp.c \
  crypto/bn/shift.c \
  crypto/cipher/e_aes.c \
  crypto/crypto.c \
  crypto/curve25519/curve25519.c \
  crypto/ec/ecp_nistz.c \
  crypto/ec/ecp_nistz256.c \
  crypto/ec/gfp_constant_time.c \
  crypto/ec/gfp_p256.c \
  crypto/ec/gfp_p384.c \
  crypto/ec/wnaf.c \
  crypto/mem.c \
  crypto/modes/gcm.c \
  crypto/poly1305/poly1305.c \
  crypto/rand/sysrand.c \
  crypto/rsa/blinding.c \
  crypto/rsa/rsa.c \
  crypto/rsa/rsa_impl.c \
  $(NULL)) \
  $(RING_$(TARGET_ARCH_NORMAL)_SRCS) \
  $(NULL)

RING_INTEL_SHARED_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/cpu-intel.c \
  $(NULL))

# TODO: make all .a files depend on these too.
RING_x86_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/aes/asm/aes-586.pl \
  crypto/aes/asm/aesni-x86.pl \
  crypto/aes/asm/vpaes-x86.pl \
  crypto/bn/asm/x86-mont.pl \
  crypto/chacha/asm/chacha-x86.pl \
  crypto/ec/asm/ecp_nistz256-x86.pl \
  crypto/modes/asm/ghash-x86.pl \
  crypto/poly1305/asm/poly1305-x86.pl \
  crypto/sha/asm/sha256-586.pl \
  crypto/sha/asm/sha512-586.pl \
  $(NULL)) \
  $(RING_INTEL_SHARED_SRCS) \
  $(NULL)

RING_x86_64_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/aes/asm/aes-x86_64.pl \
  crypto/aes/asm/aesni-x86_64.pl \
  crypto/aes/asm/bsaes-x86_64.pl \
  crypto/aes/asm/vpaes-x86_64.pl \
  crypto/bn/asm/rsaz-avx2.pl \
  crypto/bn/asm/x86_64-mont.pl \
  crypto/bn/asm/x86_64-mont5.pl \
  crypto/chacha/asm/chacha-x86_64.pl \
  crypto/curve25519/asm/x25519-asm-x86_64.S \
  crypto/curve25519/x25519-x86_64.c \
  crypto/ec/asm/ecp_nistz256-x86_64.pl \
  crypto/ec/asm/p256-x86_64-asm.pl \
  crypto/modes/asm/aesni-gcm-x86_64.pl \
  crypto/modes/asm/ghash-x86_64.pl \
  crypto/poly1305/asm/poly1305-x86_64.pl \
  crypto/sha/asm/sha256-x86_64.pl \
  crypto/sha/asm/sha512-x86_64.pl \
  $(NULL)) \
  $(RING_INTEL_SHARED_SRCS) \
  $(NULL)

RING_ARM_SHARED_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/cpu-arm.c \
  crypto/cpu-arm-linux.c \
  \
  crypto/aes/asm/aesv8-armx.pl \
  crypto/modes/asm/ghashv8-armx.pl \
  $(NULL))

RING_arm_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/aes/asm/aes-armv4.pl \
  crypto/aes/asm/bsaes-armv7.pl \
  crypto/bn/asm/armv4-mont.pl \
  crypto/chacha/asm/chacha-armv4.pl \
  crypto/curve25519/asm/x25519-asm-arm.S \
  crypto/ec/asm/ecp_nistz256-armv4.pl \
  crypto/modes/asm/ghash-armv4.pl \
  crypto/poly1305/asm/poly1305-armv4.pl \
  crypto/sha/asm/sha256-armv4.pl \
  crypto/sha/asm/sha512-armv4.pl \
  $(NULL)) \
  $(RING_ARM_SHARED_SRCS) \
  $(NULL)

RING_aarch64_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/cpu-aarch64-linux.c \
  crypto/bn/asm/armv8-mont.pl \
  crypto/chacha/asm/chacha-armv8.pl \
  crypto/ec/asm/ecp_nistz256-armv8.pl \
  crypto/poly1305/asm/poly1305-armv8.pl \
  crypto/sha/asm/sha256-armv8.pl \
  crypto/sha/asm/sha512-armv8.pl \
  $(NULL)) \
  $(RING_ARM_SHARED_SRCS) \
  $(NULL)

RING_TEST_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/aes/aes_test.cc \
  crypto/bn/bn_test.cc \
  crypto/chacha/chacha_test.cc \
  crypto/constant_time_test.c \
  crypto/poly1305/poly1305_test.cc \
  crypto/test/bn_test_convert.c \
  crypto/test/bn_test_lib.c \
  crypto/test/file_test.cc \
  $(NULL))

RING_CORE_OBJS = \
  $(addprefix $(OBJ_PREFIX), \
    $(patsubst %.pl, %.o, \
      $(patsubst %.S, %.o, \
        $(patsubst %.c, %.o, \
          $(RING_SRCS)))))

RING_TEST_OBJS = \
  $(addprefix $(OBJ_PREFIX), \
    $(patsubst %.c, %.o, \
      $(patsubst %.cc, %.o, \
        $(RING_TEST_SRCS))))

RING_CORE_LIB = $(LIB_PREFIX)libring-core.a
RING_TEST_LIB = $(LIB_PREFIX)libring-test.a

RING_LIBS = \
  $(RING_CORE_LIB) \
  $(RING_TEST_LIB) \
  $(NULL)

# Recent versions of Linux have the D flag for deterministic builds, but Darwin
# (at least) doesn't. Accroding to Debian's documentation, binutils is built
# with --enable-determnistic-archives by default and we shouldn't need to
# worry about it.
$(RING_CORE_LIB): ARFLAGS = crs
$(RING_CORE_LIB): $(RING_CORE_OBJS) $(RING_PREFIX)mk/ring.mk
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(filter-out $(RING_PREFIX)mk/ring.mk, $^)
$(RING_TEST_LIB): ARFLAGS = crs
$(RING_TEST_LIB): $(RING_TEST_OBJS) $(RING_PREFIX)mk/ring.mk
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(filter-out $(RING_PREFIX)mk/ring.mk, $^)

RING_OBJS = \
  $(RING_CORE_OBJS) \
  $(RING_TEST_OBJS) \
  $(NULL)

# TODO: Fix the code so -Wno- overrides are not needed.
$(RING_OBJS) \
$(NULL): CPPFLAGS += $(RING_CPPFLAGS) \
                     -DBORINGSSL_IMPLEMENTATION \
                     -fno-strict-aliasing \
                     -fvisibility=hidden \
                     -Wno-cast-align \
                     $(NULL)

PERLASM_LIB_SRCS = $(addprefix $(RING_PREFIX), \
  crypto/perlasm/arm-xlate.pl \
  crypto/perlasm/x86asm.pl \
  crypto/perlasm/x86gas.pl \
  crypto/perlasm/x86masm.pl \
  crypto/perlasm/x86nasm.pl \
  crypto/perlasm/x86_64-xlate.pl \
  $(NULL))

PERL_EXECUTABLE ?= perl

# The British spelling "flavour" is used for consistency with perlasm's code.
ifeq ($(findstring darwin,$(TARGET_SYS)),darwin)
PERLASM_FLAVOUR ?= macosx
else ifeq ($(TARGET_SYS),ios)
ifeq ($(findstring arm,$(TARGET_ARCH_NORMAL)),arm)
PERLASM_FLAVOUR ?= ios32
else ifeq ($(TARGET_ARCH_NORMAL),aarch64)
PERLASM_FLAVOUR ?= ios64
else
PERLASM_FLAVOUR ?= macosx
endif
else ifeq ($(TARGET_ARCH_NORMAL),aarch64)
PERLASM_FLAVOUR ?= linux64
else ifeq ($(TARGET_ARCH_NORMAL),arm)
PERLASM_FLAVOUR ?= linux32
else
PERLASM_FLAVOUR ?= elf
endif

PERLASM_x86_ARGS = -fPIC -DOPENSSL_IA32_SSE2
PERLASM_ARGS = $(PERLASM_FLAVOUR) $(PERLASM_$(TARGET_ARCH_NORMAL)_ARGS)

$(OBJ_PREFIX)%.S: %.pl $(PERLASM_LIB_SRCS)
	${PERL_EXECUTABLE} $< $(PERLASM_ARGS) $@
