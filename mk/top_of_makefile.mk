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

ifeq ($(ARCH),x86)
ARCH_FLAGS ?= -m32
else ifeq ($(ARCH),x86_64)
ARCH_FLAGS ?= -m64
else
$(error You must specify ARCH as one of {x86,x86_64})
endif

BUILD_PREFIX ?= build/

EXE_PREFIX ?= $(BUILD_PREFIX)bin/
OBJ_PREFIX ?= $(BUILD_PREFIX)obj/
LIB_PREFIX ?= $(BUILD_PREFIX)lib/

CFLAGS_STD ?= -std=c11
CXXFLAGS_STD ?= -std=c++11

CFLAGS += $(CFLAGS_STD)
CXXFLAGS += $(CXXFLAGS_STD)

# Always add full debug info.
CPPFLAGS += -g3

# Dead code elimination.
CPPFLAGS += -fdata-sections -ffunction-sections
LDFLAGS += -Wl,--gc-sections

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

CPPFLAGS += $(ARCH_FLAGS)
LDFLAGS += $(ARCH_FLAGS)

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
