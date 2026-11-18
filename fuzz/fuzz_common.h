/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Shared part of the fuzz targets. Not built for Android.
 *
 * tqftpserv.c and translate.c are compiled into each target. QRTR sockets
 * are replaced by fake ones backed by /dev/null file descriptors, so the
 * daemon's own open and close calls show in the descriptor count. The clock,
 * calloc() and qrtr_open() are under the control of the input. The firmware
 * folder, the sysfs files and the readwrite folder live in a temporary tree.
 */
#ifndef __FUZZ_COMMON_H__
#define __FUZZ_COMMON_H__

#define _GNU_SOURCE

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sanitizer/allocator_interface.h>

#include "libqrtr.h"

#define FZ_MAX_FD 1024
#define FZ_LOCAL_NODE 1
#define FZ_AF_QIPCRTR 42

/* The tree, set up once per process */
static char fz_base[PATH_MAX];
static char fz_fw_base[PATH_MAX];	/* with a trailing slash */
static char fz_fwsys[PATH_MAX];		/* the firmware_class path parameter */
static char fz_rw_dir[PATH_MAX];
static char fz_rproc_dir[PATH_MAX];
static char fz_fw_param[PATH_MAX];
static char fz_outside[PATH_MAX];

/* Fake sockets, by descriptor */
struct fz_sock {
	bool is_sock;
	bool connected;
	struct sockaddr_qrtr peer;
	unsigned long sends;
	int last_data_block;
};
static struct fz_sock fz_socks[FZ_MAX_FD];

/* The one packet a recvfrom() may return, and who sent it */
static struct {
	int fd;
	const uint8_t *data;
	size_t len;
	struct sockaddr_qrtr from;
} fz_pend = { .fd = -1 };

static int fz_main_fd = -1;
static bool fz_main_eof;

/* While set, a connect() must go to this address: the sender of the request */
static bool fz_sender_set;
static struct sockaddr_qrtr fz_sender;

static long long fz_now_ms = 1000000000LL;
static int fz_fail_calloc;
static int fz_fail_qrtr_open;

/* Called for every packet the daemon sends, after it is checked */
static void (*fz_on_send)(int fd, const uint8_t *buf, size_t len);
static int (*fz_select_hook)(int nfds, fd_set *r, fd_set *w, fd_set *e,
			     struct timeval *tv);

static void fz_fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "INVARIANT: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	abort();
}

#define FZ_CHECK(cond, ...) do { if (!(cond)) fz_fail(__VA_ARGS__); } while (0)

/* Input reader */
static const uint8_t *fz_in;
static size_t fz_in_len;
static size_t fz_in_pos;

static bool fz_more(void)
{
	return fz_in_pos < fz_in_len;
}

static uint8_t fz_u8(void)
{
	return fz_in_pos < fz_in_len ? fz_in[fz_in_pos++] : 0;
}

static uint16_t fz_u16(void)
{
	return fz_u8() | fz_u8() << 8;
}

static uint32_t fz_u32(void)
{
	return fz_u16() | (uint32_t)fz_u16() << 16;
}

/* Up to @len bytes of input, fewer at its end */
static const uint8_t *fz_bytes(size_t *len)
{
	const uint8_t *p = fz_in + fz_in_pos;

	if (*len > fz_in_len - fz_in_pos)
		*len = fz_in_len - fz_in_pos;
	fz_in_pos += *len;
	return p;
}

/* Replacements of what the daemon calls */

int qrtr_open(int rport)
{
	int fd;

	if (fz_fail_qrtr_open && --fz_fail_qrtr_open == 0) {
		errno = ENOMEM;
		return -1;
	}
	fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	FZ_CHECK(fd >= 0 && fd < FZ_MAX_FD, "qrtr_open: descriptor %d", fd);
	fz_socks[fd] = (struct fz_sock){ .is_sock = true, .last_data_block = -1 };
	return fd;
}

int qrtr_publish(int sock, uint32_t service, uint16_t version, uint16_t instance)
{
	FZ_CHECK(sock >= 0 && fz_socks[sock].is_sock, "publish on a non-socket");
	return 0;
}

/* As libqrtr: a control packet is cmd, then node and port, little endian */
int qrtr_decode(struct qrtr_packet *dest, void *buf, size_t len,
		const struct sockaddr_qrtr *sq)
{
	const uint8_t *p = buf;

	if (sq->sq_port == QRTR_PORT_CTRL) {
		if (len < 20)
			return -EMSGSIZE;
		memset(dest, 0, sizeof(*dest));
		dest->type = p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
		switch (dest->type) {
		case QRTR_TYPE_BYE:
			dest->node = p[4] | p[5] << 8 | p[6] << 16 | (uint32_t)p[7] << 24;
			break;
		case QRTR_TYPE_DEL_CLIENT:
			dest->node = p[4] | p[5] << 8 | p[6] << 16 | (uint32_t)p[7] << 24;
			dest->port = p[8] | p[9] << 8 | p[10] << 16 | (uint32_t)p[11] << 24;
			break;
		default:
			dest->type = 0;
		}
	} else {
		dest->type = QRTR_TYPE_DATA;
		dest->node = sq->sq_node;
		dest->port = sq->sq_port;
		dest->data = buf;
		dest->data_len = len;
	}
	return 0;
}

static void fz_check_packet(const uint8_t *buf, size_t len)
{
	int opcode;
	size_t i;
	int strings = 0;

	FZ_CHECK(len >= 2, "packet of %zu bytes", len);
	opcode = buf[0] << 8 | buf[1];
	switch (opcode) {
	case 3:	/* DATA */
		FZ_CHECK(len >= 4 && len <= 65464 + 4, "DATA of %zu bytes", len);
		break;
	case 4:	/* ACK */
		FZ_CHECK(len == 4, "ACK of %zu bytes", len);
		break;
	case 5:	/* ERROR */
		FZ_CHECK(len >= 5 && buf[len - 1] == '\0', "malformed ERROR");
		FZ_CHECK((buf[2] << 8 | buf[3]) <= 9, "ERROR code %d", buf[2] << 8 | buf[3]);
		FZ_CHECK(strlen((const char *)buf + 4) == len - 5, "ERROR text");
		break;
	case 6:	/* OACK: option and value strings */
		FZ_CHECK(len <= 512, "OACK of %zu bytes", len);
		FZ_CHECK(len == 2 || buf[len - 1] == '\0', "OACK not terminated");
		for (i = 2; i < len; i++)
			strings += buf[i] == '\0';
		FZ_CHECK(strings % 2 == 0, "OACK option without value");
		break;
	default:
		fz_fail("sent opcode %d", opcode);
	}
}

static ssize_t fz_send(int fd, const void *buf, size_t len, int flags)
{
	const uint8_t *p = buf;

	FZ_CHECK(fd >= 0 && fd < FZ_MAX_FD && fz_socks[fd].is_sock,
		 "send on descriptor %d, not a socket", fd);
	FZ_CHECK(fz_socks[fd].connected, "send on an unconnected socket");
	fz_check_packet(p, len);
	fz_socks[fd].sends++;
	if (p[1] == 3)
		fz_socks[fd].last_data_block = p[2] << 8 | p[3];
	if (fz_on_send)
		fz_on_send(fd, p, len);
	return len;
}

static int fz_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	const struct sockaddr_qrtr *sq = (const void *)addr;

	FZ_CHECK(fd >= 0 && fd < FZ_MAX_FD && fz_socks[fd].is_sock, "connect on a non-socket");
	FZ_CHECK(!fz_socks[fd].connected, "connect twice");
	FZ_CHECK(len == sizeof(*sq), "connect length");
	FZ_CHECK(fz_sender_set, "connect with no request in hand");
	FZ_CHECK(sq->sq_node == fz_sender.sq_node && sq->sq_port == fz_sender.sq_port,
		 "reply to %u:%u, request came from %u:%u", sq->sq_node, sq->sq_port,
		 fz_sender.sq_node, fz_sender.sq_port);
	fz_socks[fd].peer = *sq;
	fz_socks[fd].connected = true;
	return 0;
}

static int fz_getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	const struct sockaddr_qrtr local = { FZ_AF_QIPCRTR, FZ_LOCAL_NODE, 1 };

	memcpy(addr, &local, sizeof(local));
	*len = sizeof(local);
	return 0;
}

static ssize_t fz_recvfrom(int fd, void *buf, size_t len, int flags,
			   struct sockaddr *addr, socklen_t *addrlen)
{
	size_t n;

	FZ_CHECK(fd >= 0 && fd < FZ_MAX_FD && fz_socks[fd].is_sock, "recvfrom on a non-socket");
	if (fd == fz_main_fd && fz_main_eof) {
		errno = EIO;
		return -1;
	}
	/* A read with nothing queued would block the daemon */
	FZ_CHECK(fd == fz_pend.fd, "recvfrom on descriptor %d with nothing to read", fd);
	n = fz_pend.len < len ? fz_pend.len : len;
	memcpy(buf, fz_pend.data, n);
	if (addr) {
		FZ_CHECK(*addrlen >= sizeof(fz_pend.from), "recvfrom address length");
		memcpy(addr, &fz_pend.from, sizeof(fz_pend.from));
		*addrlen = sizeof(fz_pend.from);
	}
	fz_pend.fd = -1;
	return n;
}

static int fz_close(int fd)
{
	int ret;

	if (fd >= 0 && fd < FZ_MAX_FD)
		fz_socks[fd].is_sock = false;
	ret = close(fd);
	FZ_CHECK(ret == 0 || errno != EBADF, "close of descriptor %d, which is not open", fd);
	return ret;
}

static int fz_clock_gettime(clockid_t id, struct timespec *ts)
{
	FZ_CHECK(id == CLOCK_MONOTONIC, "clock %d", (int)id);
	ts->tv_sec = fz_now_ms / 1000;
	ts->tv_nsec = (fz_now_ms % 1000) * 1000000;
	return 0;
}

static void *fz_calloc(size_t n, size_t size)
{
	if (fz_fail_calloc && --fz_fail_calloc == 0)
		return NULL;
	return calloc(n, size);
}

static int fz_select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
	FZ_CHECK(fz_select_hook, "select outside the main loop target");
	return fz_select_hook(nfds, r, w, e, tv);
}

#define recvfrom fz_recvfrom
#define send fz_send
#define connect fz_connect
#define getsockname fz_getsockname
#define select fz_select
#define close fz_close
#define clock_gettime fz_clock_gettime
#define calloc fz_calloc
#define main tqftpserv_main
#define TQFTPSERV_RW_DIR fz_rw_dir
#define FIRMWARE_BASE fz_fw_base
#define REMOTEPROC_CLASS_DIR fz_rproc_dir
#define FW_PATH_PARAM fz_fw_param
#include "../tqftpserv.c"
#include "../translate.c"
#undef recvfrom
#undef send
#undef connect
#undef getsockname
#undef select
#undef close
#undef clock_gettime
#undef calloc
#undef main

/* The tree */

static void fz_write_file(const char *dir, const char *name, size_t size, uint8_t seed)
{
	char path[PATH_MAX];
	uint8_t buf[4096];
	size_t i, n;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		err(1, "create %s", path);
	for (i = 0; i < size; i += n) {
		size_t j;

		n = size - i < sizeof(buf) ? size - i : sizeof(buf);
		for (j = 0; j < n; j++)
			buf[j] = (uint8_t)((i + j) * 7 + seed);
		if (write(fd, buf, n) != (ssize_t)n)
			err(1, "write %s", path);
	}
	close(fd);
}

static void fz_sparse_file(const char *dir, const char *name, off_t size)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || ftruncate(fd, size) < 0)
		err(1, "sparse %s", path);
	close(fd);
}

static void fz_mkdir(const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (mkdir(path, 0700) < 0 && errno != EEXIST)
		err(1, "mkdir %s", path);
}

static void fz_symlink(const char *target, const char *dir, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (symlink(target, path) < 0)
		err(1, "symlink %s", path);
}

static int fz_rm_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	if (ftw->level == 0)
		return 0;
	if (type == FTW_DP)
		return rmdir(path);
	return unlink(path);
}

/* Empties @dir, keeping it */
static void fz_empty_dir(const char *dir)
{
	if (nftw(dir, fz_rm_one, 16, FTW_DEPTH | FTW_PHYS) < 0)
		err(1, "empty %s", dir);
}

static void fz_cleanup(void)
{
	char cmd[PATH_MAX + 16];

	if (!fz_base[0])
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fz_base);
	if (system(cmd) != 0)
		warnx("could not remove %s", fz_base);
}

enum {
	FZ_TREE_PLAIN,
	FZ_TREE_FILES_NEARLY_FULL,	/* one entry left at the top level */
	FZ_TREE_BYTES_NEARLY_FULL,	/* 1 MiB left at the top level */
	FZ_TREE_VARIANTS,
};

/*
 * The readwrite folder and a folder outside of it. Some names in each lead
 * outside, by symbolic link. "sub" and "ota_firewall" are subfolders as a
 * populated folder has them.
 */
static void fz_reset_rw(int variant)
{
	char name[32];
	int i;

	fz_empty_dir(fz_rw_dir);
	fz_empty_dir(fz_outside);
	fz_write_file(fz_outside, "secret", 6, 1);
	fz_mkdir(fz_outside, "dir");
	fz_write_file(fz_outside, "dir/file", 6, 2);

	fz_write_file(fz_rw_dir, "a", 10, 3);
	fz_write_file(fz_rw_dir, "mcfg.tmp", 1, 4);
	fz_write_file(fz_rw_dir, "big", 20000, 5);
	fz_mkdir(fz_rw_dir, "sub");
	fz_write_file(fz_rw_dir, "sub/b", 100, 6);
	fz_mkdir(fz_rw_dir, "ota_firewall");
	fz_write_file(fz_rw_dir, "ota_firewall/ruleset", 52, 7);
	fz_symlink("../outside/secret", fz_rw_dir, "ln");
	fz_symlink("../outside", fz_rw_dir, "dln");
	fz_symlink("sub", fz_rw_dir, "subln");

	switch (variant) {
	case FZ_TREE_FILES_NEARLY_FULL:
		/* 8 entries at the top level so far */
		for (i = 8; i < TQFTPSERV_MAX_RW_FILES - 1; i++) {
			snprintf(name, sizeof(name), "f%d", i);
			fz_write_file(fz_rw_dir, name, 0, 0);
		}
		break;
	case FZ_TREE_BYTES_NEARLY_FULL:
		/* Sparse, so cheap. With the files above, 1 MiB short */
		for (i = 0; i < 3; i++) {
			snprintf(name, sizeof(name), "full%d", i);
			fz_sparse_file(fz_rw_dir, name, TQFTPSERV_MAX_FILE_BYTES);
		}
		fz_sparse_file(fz_rw_dir, "full3",
			       TQFTPSERV_MAX_RW_BYTES - 3LL * TQFTPSERV_MAX_FILE_BYTES -
			       (1 << 20) - 10 - 1 - 20000);
		break;
	}
}

/*
 * Firmware as the remote processors find it: remoteproc0 names
 * qcom/test/modem.mdt, the sysfs path parameter names a second folder.
 * remoteproc1 has an empty firmware name, remoteproc2 none at all.
 */
static void fz_make_firmware(void)
{
	char path[PATH_MAX];
	char value[PATH_MAX + 2];

	snprintf(path, sizeof(path), "%s/fw", fz_base);
	fz_mkdir(fz_base, "fw");
	fz_mkdir(path, "qcom");
	fz_mkdir(path, "qcom/test");
	fz_mkdir(path, "qcom/test/modem_pr");
	fz_mkdir(path, "qcom/test/modem_pr/so");
	fz_mkdir(path, "qcom/test/sub");
	fz_write_file(path, "qcom/test/modem.mdt", 64, 10);
	fz_write_file(path, "qcom/test/f1.bin", 1500, 11);
	fz_write_file(path, "qcom/test/big.bin", 70000, 12);
	fz_write_file(path, "qcom/test/modem_pr/so/901_0_0.mbn", 100, 13);
	fz_write_file(path, "qcom/test/sub/x.bin", 33, 14);
	fz_write_file(path, "qcom/test/odd name\t!.bin", 5, 15);
	fz_symlink("f1.bin", path, "qcom/test/link.bin");
	fz_write_file(path, "f0.bin", 7, 16);
	fz_mkdir(path, "updates");
	fz_mkdir(path, "updates/qcom");
	fz_mkdir(path, "updates/qcom/test");
	fz_write_file(path, "updates/qcom/test/f1.bin", 700, 17);

	fz_mkdir(fz_base, "fwsys");
	fz_mkdir(fz_fwsys, "qcom");
	fz_mkdir(fz_fwsys, "qcom/test");
	fz_write_file(fz_fwsys, "qcom/test/s.bin", 40, 18);

	fz_mkdir(fz_base, "sys");
	snprintf(path, sizeof(path), "%s/sys", fz_base);
	fz_mkdir(path, "remoteproc");
	fz_mkdir(fz_rproc_dir, "remoteproc0");
	fz_mkdir(fz_rproc_dir, "remoteproc1");
	fz_mkdir(fz_rproc_dir, "remoteproc2");
	snprintf(path, sizeof(path), "%s/remoteproc0/firmware", fz_rproc_dir);
	FILE *f = fopen(path, "w");
	fputs("qcom/test/modem.mdt\n", f);
	fclose(f);
	snprintf(path, sizeof(path), "%s/remoteproc1/firmware", fz_rproc_dir);
	f = fopen(path, "w");
	fclose(f);
	snprintf(value, sizeof(value), "%s\n", fz_fwsys);
	f = fopen(fz_fw_param, "w");
	fputs(value, f);
	fclose(f);
}

/* An order-independent hash of a tree: names, types, sizes, contents, links */
static uint64_t fz_tree_hash_acc;

/* FNV-1a wraps by design */
__attribute__((no_sanitize("unsigned-integer-overflow")))
static int fz_hash_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	uint64_t h = 1469598103934665603ULL;
	char buf[4096];
	ssize_t n;
	const char *p;
	int fd;

	for (p = path; *p; p++)
		h = (h ^ (uint8_t)*p) * 1099511628211ULL;
	h = (h ^ (uint64_t)st->st_mode) * 1099511628211ULL;
	h = (h ^ (uint64_t)st->st_size) * 1099511628211ULL;
	if (type == FTW_SL) {
		n = readlink(path, buf, sizeof(buf));
		for (ssize_t i = 0; i < n; i++)
			h = (h ^ (uint8_t)buf[i]) * 1099511628211ULL;
	} else if (type == FTW_F && S_ISREG(st->st_mode) && st->st_size < (1 << 20)) {
		fd = open(path, O_RDONLY | O_CLOEXEC);
		while (fd >= 0 && (n = read(fd, buf, sizeof(buf))) > 0)
			for (ssize_t i = 0; i < n; i++)
				h = (h ^ (uint8_t)buf[i]) * 1099511628211ULL;
		if (fd >= 0)
			close(fd);
	}
	fz_tree_hash_acc += h;
	return 0;
}

static uint64_t fz_tree_hash(const char *dir)
{
	fz_tree_hash_acc = 0;
	if (nftw(dir, fz_hash_one, 16, FTW_PHYS) < 0)
		err(1, "hash %s", dir);
	return fz_tree_hash_acc;
}

/* Usage of the readwrite folder, all levels */
static long long fz_rw_entries;
static long long fz_rw_bytes;
static long long fz_rw_largest;

static int fz_rw_one(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	if (ftw->level == 0)
		return 0;
	fz_rw_entries++;
	if (S_ISREG(st->st_mode)) {
		fz_rw_bytes += st->st_size;
		if (st->st_size > fz_rw_largest)
			fz_rw_largest = st->st_size;
	}
	return 0;
}

static void fz_rw_usage(long long *entries, long long *bytes, long long *largest)
{
	fz_rw_entries = fz_rw_bytes = fz_rw_largest = 0;
	if (nftw(fz_rw_dir, fz_rw_one, 16, FTW_PHYS) < 0)
		err(1, "usage of %s", fz_rw_dir);
	*entries = fz_rw_entries;
	*bytes = fz_rw_bytes;
	*largest = fz_rw_largest;
}

struct fz_usage {
	long long entries;
	long long bytes;
	long long largest;
};

/* Bytes held outside the folder, by unlinked files still open */
static long long fz_extra_bytes;

/* The daemon must not take the folder over a budget, or further over one */
static void fz_check_budgets(struct fz_usage *before)
{
	struct fz_usage now;

	fz_rw_usage(&now.entries, &now.bytes, &now.largest);
	now.bytes += fz_extra_bytes;
	FZ_CHECK(now.entries <= TQFTPSERV_MAX_RW_FILES || now.entries <= before->entries,
		 "%lld entries under the readwrite folder, %lld before",
		 now.entries, before->entries);
	FZ_CHECK(now.bytes <= TQFTPSERV_MAX_RW_BYTES || now.bytes <= before->bytes,
		 "%lld bytes under the readwrite folder, %lld before",
		 now.bytes, before->bytes);
	FZ_CHECK(now.largest <= TQFTPSERV_MAX_FILE_BYTES || now.largest <= before->largest,
		 "a file of %lld bytes, the largest was %lld",
		 now.largest, before->largest);
	*before = now;
}

static int fz_count_fds(void)
{
	struct dirent *de;
	DIR *d = opendir("/proc/self/fd");
	int n = 0;

	if (!d)
		err(1, "/proc/self/fd");
	while ((de = readdir(d)) != NULL)
		n += de->d_name[0] != '.';
	closedir(d);
	return n;
}

static bool fz_under(const char *path, const char *dir)
{
	size_t n = strlen(dir);

	return !strncmp(path, dir, n) && (path[n] == '/' || path[n] == '\0');
}

/* Where an open file is. False if it is not under @rw_only's folder or a firmware one */
static bool fz_fd_inside(int fd, bool rw_only, char *where, size_t size)
{
	char link[64];
	ssize_t n;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	n = readlink(link, where, size - 1);
	if (n < 0)
		return false;
	where[n] = '\0';
	if (fz_under(where, fz_rw_dir))
		return true;
	if (rw_only)
		return false;
	/* fz_fw_base has a trailing slash */
	return !strncmp(where, fz_fw_base, strlen(fz_fw_base)) || fz_under(where, fz_fwsys);
}

static bool fz_fd_writable(int fd)
{
	return (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY;
}

static off_t fz_fd_size(int fd)
{
	struct stat st;

	FZ_CHECK(fstat(fd, &st) == 0, "fstat");
	return st.st_size;
}

static void fz_init_once(void)
{
	const char *tmp = getenv("FZ_TMPDIR");
	char real[PATH_MAX];

	if (fz_base[0])
		return;
	if (!tmp || !*tmp)
		tmp = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : "/tmp";
	snprintf(fz_base, sizeof(fz_base), "%s/tqftpserv-fuzz.XXXXXX", tmp);
	if (!mkdtemp(fz_base))
		err(1, "mkdtemp");
	if (!realpath(fz_base, real))
		err(1, "realpath");
	snprintf(fz_base, sizeof(fz_base), "%s", real);
	atexit(fz_cleanup);

	snprintf(fz_fw_base, sizeof(fz_fw_base), "%s/fw/", fz_base);
	snprintf(fz_fwsys, sizeof(fz_fwsys), "%s/fwsys", fz_base);
	snprintf(fz_rw_dir, sizeof(fz_rw_dir), "%s/rw", fz_base);
	snprintf(fz_outside, sizeof(fz_outside), "%s/outside", fz_base);
	snprintf(fz_rproc_dir, sizeof(fz_rproc_dir), "%s/sys/remoteproc", fz_base);
	snprintf(fz_fw_param, sizeof(fz_fw_param), "%s/sys/fw_path", fz_base);
	fz_mkdir(fz_base, "rw");
	fz_mkdir(fz_base, "outside");
	fz_make_firmware();

	/* stdout's buffer would otherwise show as memory held after the first log */
	setvbuf(stdout, NULL, _IONBF, 0);
	tftp_debug = getenv("FZ_DEBUG") != NULL;
}

/* Every session, readers first */
static int fz_sessions(struct tftp_client **out, int max)
{
	struct tftp_client *client;
	int n = 0;

	list_for_each_entry(client, &readers, node) {
		if (n < max)
			out[n] = client;
		n++;
	}
	list_for_each_entry(client, &writers, node) {
		if (n < max)
			out[n] = client;
		n++;
	}
	return n;
}

static bool fz_is_writer(struct tftp_client *c)
{
	struct tftp_client *client;

	list_for_each_entry(client, &writers, node)
		if (client == c)
			return true;
	return false;
}

/* Limits that hold for one session at any time */
static void fz_check_session(struct tftp_client *c, bool writer)
{
	char where[PATH_MAX];

	FZ_CHECK(c->sock >= 0 && c->sock < FZ_MAX_FD && fz_socks[c->sock].is_sock,
		 "session socket %d is not an open socket", c->sock);
	FZ_CHECK(fz_socks[c->sock].connected &&
		 fz_socks[c->sock].peer.sq_node == c->sq.sq_node &&
		 fz_socks[c->sock].peer.sq_port == c->sq.sq_port,
		 "session socket not connected to its client");
	FZ_CHECK(c->fd >= 0 && c->fd < FZ_MAX_FD && !fz_socks[c->fd].is_sock &&
		 fcntl(c->fd, F_GETFD) >= 0, "session file %d not open", c->fd);
	/* A write to a firmware path gets the file read-only, and fails */
	FZ_CHECK(fz_fd_inside(c->fd, writer && fz_fd_writable(c->fd), where, sizeof(where)),
		 "%s has %s open", writer ? "a writer" : "a reader", where);
	FZ_CHECK(c->blksize >= MIN_BLKSIZE && c->blksize <= MAX_BLKSIZE, "blksize %zu", c->blksize);
	FZ_CHECK(c->wsize >= MIN_WSIZE && c->wsize <= MAX_WSIZE, "wsize %zu", c->wsize);
	FZ_CHECK(c->rsize <= MAX_RSIZE, "rsize %zu", c->rsize);
	FZ_CHECK(c->blk_buf, "no block buffer");
	if (writer) {
		FZ_CHECK(c->rw_buf && c->rw_buf_size == c->blksize * c->wsize,
			 "window buffer of %zu bytes", c->rw_buf_size);
		FZ_CHECK(c->rw_buf_size <= MAX_WINDOW_BYTES, "window of %zu bytes", c->rw_buf_size);
		FZ_CHECK(c->blk_offset < c->rw_buf_size, "window offset %zu of %zu",
			 c->blk_offset, c->rw_buf_size);
		FZ_CHECK(c->seek <= TQFTPSERV_MAX_FILE_BYTES, "write at %lld", (long long)c->seek);
	} else {
		FZ_CHECK(!c->rw_buf, "a reader with a window buffer");
	}
}

/* The memory sessions may hold: the client, its block buffer and its window */
#define FZ_SESSION_BYTES (sizeof(struct tftp_client) + MAX_BLKSIZE + 4 + MAX_WINDOW_BYTES)
#define FZ_SLACK_BYTES (256 * 1024)

static size_t fz_allocated(void)
{
	return __sanitizer_get_current_allocated_bytes();
}

/* On 32-bit hosts ASan's byte counters wrap after 4 GiB, so no exact count */
static bool fz_alloc_exact(void)
{
	return sizeof(size_t) >= 8;
}

#endif
