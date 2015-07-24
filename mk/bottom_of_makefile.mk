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

GENERATED = \
  $(EXES) \
  $(OBJS) \
  $(OTHER_GENERATED) \
  $(NULL)

GENERATED_DIRS = $(sort $(dir $(GENERATED)))

$(GENERATED_DIRS):
	mkdir -p $@

$(GENERATED) : | $(GENERATED_DIRS)

# Variants of the built-in GNU Make rules that support targets in $(OBJ_PREFIX)

%.o: %.S
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(OBJ_PREFIX)%.o: %.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OBJ_PREFIX)%.o: %.cpp
	$(COMPILE.cpp) $(OUTPUT_OPTION) $<
$(OBJ_PREFIX)%.o: %.cc
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

.DEFAULT_GOAL := all
.PHONY: all
all: $(GENERATED)

.PHONY: check
check:
	$(foreach test, \
	  $(patsubst \"%\", %, $(TESTS)), \
	  "$(test)" &&) /bin/true

.PHONY: clean
clean:
	$(RM) $(EXES) $(OBJS) $(OBJS:.o=.d)

# The C/C++ compiler generates dependency info for #includes.

CPPFLAGS += -MMD
-include $(OBJS:.o=.d)
