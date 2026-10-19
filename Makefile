# Standalone production build. Source provenance is recorded in SOURCE.md.
# Copyright (c) 2026 Nenad Micic
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all
CC ?= cc
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra
CPPFLAGS ?=
LDFLAGS ?=
PYTHON ?= python3
MUSL_CC ?= musl-gcc

PLATFORM := $(shell uname -s)
ARCH := $(shell uname -m)
BUILD := .build/$(PLATFORM)-$(ARCH)
INC := -Isrc -Isrc/vendor -Isrc/vendor/mlkem-native/mlkem
DEFS := -DMLK_CONFIG_FILE=\"unmoor_mlkem_config.h\"

# Keep upstream mandatory protection flags even with command-line CFLAGS.
probe-c-flag = $(strip $(shell printf '%s\n' 'int main(void){return 0;}' | \
    $(1) $(2) -x c -c -o /dev/null - >/dev/null 2>&1 && printf '%s' '$(2)'))
override CFLAGS += -Wsign-compare -Wformat=2 -fstack-protector-strong
ifeq ($(PLATFORM),Linux)
  DEFS += -D_FORTIFY_SOURCE=2
  override CFLAGS += -fPIE $(call probe-c-flag,$(CC),-fstack-clash-protection)
  override LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
  override LDLIBS += -lutil
  ifeq ($(ARCH),x86_64)
    override CFLAGS += $(call probe-c-flag,$(CC),-fcf-protection=full)
  endif
else ifneq ($(PLATFORM),Darwin)
  $(error This snapshot supports native 64-bit Linux and macOS builds)
endif

ifneq ($(filter-out 0,$(UNMOOR_CHAOS)),)
  $(error UNMOOR_CHAOS is not a build option here: this Makefile builds the product only)
endif
ifneq ($(strip $(ASAN)),)
  $(error ASAN is not a build option here. To build with sanitizers, add the flags to CFLAGS and LDFLAGS yourself; the confinement policy will need exceptions for the sanitizer runtime)
endif

# mlkem_native.c includes the vendored implementation: do NOT recursively
# compile the vendor's .c files in addition to this one translation unit.
SRCS := $(sort $(wildcard src/*.c)) src/vendor/monocypher.c \
    src/vendor/mlkem-native/mlkem/mlkem_native.c
OBJS := $(addprefix $(BUILD)/,$(SRCS:.c=.o))
# Product objects without the program entry point, for session-level tests.
CORE_OBJS := $(filter-out $(BUILD)/src/main.o,$(OBJS))
FRAME_SRCS := tools/frame_test.c src/frame.c src/reasm.c src/crypto.c \
    src/negotiation.c src/vendor/monocypher.c
PQ_SRCS := tools/pq_crypto_test.c src/pq_crypto.c src/crypto.c \
    src/vendor/monocypher.c src/vendor/mlkem-native/mlkem/mlkem_native.c
FRAME_OBJS := $(addprefix $(BUILD)/,$(FRAME_SRCS:.c=.o))
PQ_OBJS := $(addprefix $(BUILD)/,$(PQ_SRCS:.c=.o))
KEY_GATE_OBJS := $(BUILD)/tools/session_key_gate_test.o
ALL_OBJS := $(sort $(OBJS) $(FRAME_OBJS) $(PQ_OBJS) $(KEY_GATE_OBJS))
TESTS := $(BUILD)/frame_test $(BUILD)/pq_crypto_test \
    $(BUILD)/session_key_gate_test

.PHONY: all check test smoke hygiene shell-syntax clean bundle unmoor-static help
all: unmoor

unmoor: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) $(INC) -MMD -MP -c $< -o $@

$(BUILD)/frame_test: $(FRAME_OBJS)
	$(CC) $(CFLAGS) -o $@ $(FRAME_OBJS) $(LDFLAGS)

$(BUILD)/pq_crypto_test: $(PQ_OBJS)
	$(CC) $(CFLAGS) -o $@ $(PQ_OBJS) $(LDFLAGS)

# Drives the production session through an in-memory transport.
$(BUILD)/session_key_gate_test: $(KEY_GATE_OBJS) $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $(KEY_GATE_OBJS) $(CORE_OBJS) $(LDFLAGS) $(LDLIBS)

test: $(TESTS)
	$(BUILD)/frame_test
	$(BUILD)/pq_crypto_test
	$(BUILD)/session_key_gate_test

hygiene: unmoor
	sh tests/hygiene.sh ./unmoor

shell-syntax:
	@for script in bin/*.sh tests/hygiene.sh; do sh -n "$$script" || exit; done
	@bash -n tools/unmoor-deaddrop-ssh
	@printf '%s\n' 'shell syntax: PASS'

check: all test hygiene shell-syntax
	@printf '%s\n' 'checks: PASS (build, unit tests, symbol hygiene, shell syntax)'

smoke: all
	$(PYTHON) tests/smoke.py

# Optional native Linux musl build, with no fixed-address fallback.
STATIC_FLAGS := -fPIE -fstack-protector-strong
ifeq ($(PLATFORM),Linux)
  STATIC_FLAGS += $(call probe-c-flag,$(MUSL_CC),-fstack-clash-protection)
  ifeq ($(ARCH),x86_64)
    STATIC_FLAGS += $(call probe-c-flag,$(MUSL_CC),-fcf-protection=full)
  endif
endif
unmoor-static:
	@test "$(PLATFORM)" = Linux || { printf '%s\n' 'static build requires Linux' >&2; exit 1; }
	$(MUSL_CC) -O2 -std=c11 -Wall -Wextra -Wsign-compare -Wformat=2 \
	    $(STATIC_FLAGS) $(DEFS) $(INC) -static-pie \
	    -Wl,-z,relro,-z,now -Wl,-z,noexecstack -o $@ $(SRCS)
	sh tests/hygiene.sh ./unmoor-static

bundle:
	sh bin/source-bundle.sh

# Only named generated artifacts; no reports, home directories or /tmp sweeps.
clean:
	rm -f unmoor unmoor-static $(ALL_OBJS) $(ALL_OBJS:.o=.d) $(TESTS)

help:
	@printf '%s\n' 'make                 native production binary' \
	    'make check           focused C, shell and production-symbol checks' \
	    'make smoke           clean local PQ/UDP/PTY smoke (Python 3)' \
	    'make unmoor-static   optional native Linux musl static-PIE binary' \
	    'make bundle          source-only archive of clean committed HEAD (Git)' \
	    'make clean           remove named build products for this platform'

-include $(ALL_OBJS:.o=.d)
