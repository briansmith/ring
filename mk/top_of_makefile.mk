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

.DEFAULT_GOAL := all

# $(TARGET) must be of the form <arch>-<vendor>-<sys>-<abi>, except <abi> can
# omitted on Mac OS X (Darwin).
TARGET_WORDS = $(subst -, ,$(TARGET))
TARGET_ARCH_BASE = $(word 1,$(TARGET_WORDS))
TARGET_ARCH_NORMAL = \
  $(strip $(if $(findstring arm, $(TARGET_ARCH_BASE)),arm, \
               $(if $(filter i386 i486 i586 i686, \
                    $(TARGET_ARCH_BASE)),x86,$(TARGET_ARCH_BASE))))

TARGET_VENDOR = $(word 2,$(TARGET_WORDS))
TARGET_SYS = $(word 3,$(TARGET_WORDS))
TARGET_ABI = $(word 4,$(TARGET_WORDS))

# Cargo doesn't pass the ABI as part of TARGET on Mac OS X.
ifeq ($(TARGET_ABI),)
ifeq ($(findstring apple-darwin,$(TARGET_VENDOR)-$(TARGET_SYS)),apple-darwin)
TARGET_ABI = macho
else
define NEWLINE


endef
$(error TARGET must be of the form \
        <arch>[<sub>]-<vendor>-<sys>-<abi>.$(NEWLINE)\
\
\       Exceptions: <abi> defaults to "macho" on Mac OS X.\
\
        Linux x86 example: TARGET=i586-pc-linux-gnu $(NEWLINE)\
        Mac OS X x64 example: TARGET=x86_64-apple-darwin $(NEWLINE)\
\
        NOTE: Use "i586" instead of "x86".)
endif
endif

# XXX: Apple's toolchain fails to link when the |-target| arch is "x86_64",
# so just skip -target on Darwin for now.
ifneq ($(TARGET_ARCH_NORMAL)-$(findstring darwin,$(TARGET_SYS)),x86_64-darwin)
ifeq ($(findstring clang,$(CC)),clang)
DEFAULT_TARGET_ARCH = -target "$(TARGET)"
endif
endif

ifeq ($(TARGET_ARCH_NORMAL),x86)
MARCH = pentium
MINSTR = 32
else ifeq ($(TARGET_ARCH_NORMAL),x86_64)
MARCH = x86-64
MINSTR = 64
else
MARCH = $(subst _,-,$(TARGET_ARCH_BASE))
endif

ifeq ($(TARGET_ABI),eabi)
MABI = aapcs
endif

# Cortex-M0, Cortex-M0+, Cortex-M1: armv6_m
# Cortex-M3: armv7_m
# Cortex-M4, Cortex-M7: armv7e_m
ifeq ($(filter-out armv6_m armv7_m armv7e_m,$(TARGET_ARCH_BASE)),)
MINSTR = thumb
endif

# Although it isn't mentioned in the GNU Make manual, GNU Make passes
# $(TARGET_ARCH) in its implicit rules.
TARGET_ARCH += $(if $(MCPU),-mcpu=$(MCPU)) \
               $(if $(MARCH),-march=$(MARCH)) \
               $(if $(MABI),-mabi=$(MABI)) \
               $(if $(MINSTR),-m$(MINSTR)) \
               $(NULL)

ifeq ($(CC),)
$(error You must specify CC)
endif
ifeq ($(CXX),)
$(error You must specify CXX)
endif

# e.g. "clang-3.6"
COMPILER_NAME ?= $(notdir $(CC))

# Generate output to a directory like build/x86_64-unknown-linux-elf-clang-3.6.
BUILD_PREFIX_PRIMARY ?= build
BUILD_PREFIX_SUB ?= $(TARGET)-$(COMPILER_NAME)
BUILD_PREFIX ?= $(BUILD_PREFIX_PRIMARY)/$(BUILD_PREFIX_SUB)/

EXE_PREFIX ?= $(BUILD_PREFIX)test/ring/
OBJ_PREFIX ?= $(BUILD_PREFIX)obj/
LIB_PREFIX ?= $(BUILD_PREFIX)lib/

CFLAGS_STD ?= -std=c11
CXXFLAGS_STD ?= -std=c++11

CFLAGS += $(CFLAGS_STD)
CXXFLAGS += $(CXXFLAGS_STD)

# Always add full debug info and strip dead code.
CPPFLAGS += -fpic -fdata-sections -ffunction-sections
ifeq ($(findstring darwin,$(TARGET_SYS)),darwin)
# |-gfull| is required for Darwin's |-dead_strip|.
CPPFLAGS += -gfull
LDFLAGS += -fPIC -Wl,-dead_strip
else
CPPFLAGS += -g3
LDFLAGS += -Wl,--gc-sections
endif

# TODO: link-time optimization.

# Warnings

# TODO:
#   -Wconversion \
#   -Weverything -Wpessimizing-move, etc. \
#   -Wsuggest-attribute \
#   -Wstack-usage=n \
#   -Wformat-signedness \
#   -fsanitize=undefined \
#   -Wnormalized \
#   -fsized-deallocation \
#   -Wmisleading-indentation \
#   -Wmissing-declarations \
#   -Wshadow \
#   -Wsized-deallocation \
#   -Wsuggest-final-types \
#   -Wsuggest-final-methods \
#   -Wsuggest-override \
#   -Wzero-as-null-pointer-constant \
#   -Wunsafe-loop-optimizations \
#   -Wsign-conversion\
#   -Wstrict-overflow=5 \
#   -Wundef \

# TODO: clang-specific warnings

# TODO (not in clang):
#   -Wmaybe-uninitialized \
#   -Wtrampolines \
#   -Wlogical-op \

# TODO (GCC 4.9+):
#   -Wconditionally-supported
#   -Wdate-time

CPPFLAGS += \
  -pedantic -pedantic-errors \
  \
  -Wall -Werror \
  -Wextra \
  \
  -Wcast-align \
  -Wcast-qual \
  -Wenum-compare \
  -Wfloat-equal \
  -Wformat=2 \
  -Winvalid-pch \
  -Wmissing-include-dirs \
  -Wredundant-decls \
  -Wsign-compare \
  -Wuninitialized \
  -Wwrite-strings \
  $(NULL)

# XXX: Stack protector causes linking failures for armv7-*-none-eabi and
# it's use seems questionable for that kind of target anyway.
# The launchpad.net arm-none-eabi-gcc toolchain (at least) uses -fshort-enums.
ifneq ($(TARGET_SYS),none)
CPPFLAGS += -fstack-protector
endif


# TODO (not in clang):
#   -Wjump-misses-init
#   -Wold-style-declaration \
#   -Wold-style-definition
CFLAGS += \
  -Wbad-function-cast \
  -Wnested-externs \
  -Wstrict-prototypes \
  $(NULL)

CMAKE_BUILD_TYPE ?= RELWITHDEBINFO

# Although we don't use CMake, we use a variable CMAKE_BUILD_TYPE with similar
# semantics to the CMake variable of that name.
ifeq ($(CMAKE_BUILD_TYPE),MINSIZEREL)
CPPFLAGS += -DNDEBUG -Os
else ifeq ($(CMAKE_BUILD_TYPE),RELEASE)
CPPFLAGS += -DNDEBUG -O3
else ifeq ($(CMAKE_BUILD_TYPE),RELWITHDEBINFO)
CPPFLAGS += -DNDEBUG -O3
else ifeq ($(CMAKE_BUILD_TYPE),DEBUG)
# Do nothing
else
$(error invalid value for CMAKE_BUILD_TYPE: $(CMAKE_BUILD_TYPE))
endif
