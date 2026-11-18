# SPDX-License-Identifier: BSD-3-Clause
#
# libFuzzer targets for tqftpserv, with AddressSanitizer and
# UndefinedBehaviorSanitizer. Unsigned overflow is checked as well, as the
# Android build traps on it. Not part of the Android or meson builds.
# Build: make -C fuzz    Run: fuzz/run.sh

CC = clang
CFLAGS ?= -O1 -g
CFLAGS += -Wall -Wno-unused-function -Wno-unused-parameter -Wno-sign-compare \
	  -fsanitize=fuzzer,address,undefined,unsigned-integer-overflow \
	  -fno-sanitize-recover=all -fno-omit-frame-pointer
CPPFLAGS += -I. -I../tests -I..

TARGETS = fuzz_request fuzz_session fuzz_transfer fuzz_translate
DEPS = fuzz_common.h ../tests/libqrtr.h ../tqftpserv.c ../translate.c \
       ../translate.h ../list.h

all: $(TARGETS)

fuzz_%: fuzz_%.c $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)

.PHONY: all clean
