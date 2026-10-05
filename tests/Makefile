# SPDX-License-Identifier: BSD-3-Clause
#
# Host tests for tqftpserv's request handling, built with AddressSanitizer.
# Not part of the Android or meson builds. Run: make -C tests check

CFLAGS ?= -O1 -g
CFLAGS += -Wall -Wno-unused-parameter -Wno-unused-function -Wno-format \
	  -Wno-sign-compare -fsanitize=address,undefined \
	  -fno-sanitize-recover=all -fno-omit-frame-pointer
CPPFLAGS += -I. -I..
LDFLAGS += -fsanitize=address,undefined

test_tqftpserv: test_tqftpserv.c libqrtr.h ../tqftpserv.c ../translate.c \
		../translate.h ../list.h ../xz-decompress.h ../zstd-decompress.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ test_tqftpserv.c

check: test_tqftpserv
	./test_tqftpserv

clean:
	rm -f test_tqftpserv
	rm -rf test_tqftpserv.dSYM

.PHONY: check clean
