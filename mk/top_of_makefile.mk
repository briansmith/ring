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

# $(TARGET) must be of the form <arch>-<vendor>-<sys>-<abi>.
TARGET_WORDS = $(subst -, ,$(TARGET))
ifneq ($(words $(TARGET_WORDS)),4)
define NEWLINE


endef
$(error TARGET must be of the form \
        <arch>[<sub>]-<vendor>-<sys>-<abi>.$(NEWLINE)\
\
        Linux x86 example:    TARGET=x86-pc-linux-gnu $(NEWLINE)\
        Mac OS X x64 example: TARGET=x86_64-apple-darwin-macho) $(NEWLINE)\
\
        NOTE: Use "x86" instead of "i386", "i586", "i686", etc.)
endif

TARGET_ARCH_BASE = $(word 1,$(TARGET_WORDS))
TARGET_VENDOR = $(word 2,$(TARGET_WORDS))
TARGET_SYS = $(word 3,$(TARGET_WORDS))
TARGET_ABI = $(word 4,$(TARGET_WORDS))

# Although it isn't documented, GNU Make passes $(TARGET_ARCH) in its implicit
# rules.
ifeq ($(TARGET_ARCH_BASE),x86)
TARGET_ARCH ?= -m32
else ifeq ($(TARGET_ARCH_BASE),x86_64)
TARGET_ARCH ?= -m64
else
$(error You must specify TARGET_ARCH_BASE as one of {x86,x86_64})
endif

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

EXE_PREFIX ?= $(BUILD_PREFIX)bin/
OBJ_PREFIX ?= $(BUILD_PREFIX)obj/
LIB_PREFIX ?= $(BUILD_PREFIX)lib/

CFLAGS_STD ?= -std=c11
CXXFLAGS_STD ?= -std=c++11

CFLAGS += $(CFLAGS_STD)
CXXFLAGS += $(CXXFLAGS_STD)

# Always add full debug info and strip dead code.
CPPFLAGS += -fdata-sections -ffunction-sections
ifeq ($(findstring darwin,$(TARGET_SYS)),darwin)
# |-gfull| is required for Darwin's |-dead_strip|.
CPPFLAGS += -gfull
LDFLAGS += -Wl,-dead_strip
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
  -fstack-protector \
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
  -Wuninitialized \
  -Wwrite-strings \
  $(NULL)

# TODO (not in clang):
#   -Wjump-misses-init
#   -Wold-style-declaration \
#   -Wold-style-definition
CFLAGS += \
  -Wbad-function-cast \
  -Wnested-externs \
  -Wstrict-prototypes \
  $(NULL)

CMAKE_BUILD_TYPE ?= DEBUG

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
