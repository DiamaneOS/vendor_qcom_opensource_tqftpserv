// SPDX-License-Identifier: BSD-3-Clause
/*
 * Host tests for tqftpserv's request handling. Not built for Android.
 *
 * tqftpserv.c and translate.c are compiled into this file. QRTR sockets
 * are replaced by local datagram socket pairs, the readwrite directory by
 * a temporary one, so the handlers can be fed packets directly. Each test
 * runs in its own process. Build with AddressSanitizer (see Makefile) so
 * memory errors fail the test.
 */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libqrtr.h"

#define MAX_FDS 1024
#define BUF_SIZE (256 * 1024)

static char test_rw_dir[PATH_MAX];
static char outside_dir[PATH_MAX];

/* Test end of each socket pair, by the server's fd */
static int peer_of[MAX_FDS];
/* Test end of the socket opened last */
static int last_peer = -1;

/* main(): its socket, packets queued on it, and reads left before EIO */
static int ctrl_fd = -1;
static bool next_open_is_ctrl;
static const void *ctrl_pkts[4];
static size_t ctrl_lens[4];
static int ctrl_npkts;
static int ctrl_reads_left;

/* Fail the n-th calloc() from now (0: never) */
static int fail_calloc_at;

/* Fail a seek to the end, as on a directory on tmpfs */
static bool fail_seek_end;

/* What qrtr_decode() reports, and its error if not 0 */
static struct qrtr_packet decoded = { .type = QRTR_TYPE_DATA };
static int decode_error;

/* The next reads on a session socket seem to come from here, when set */
static const struct sockaddr_qrtr *stray_sender;

#define LOCAL_NODE 9

int qrtr_open(int rport)
{
	int size = BUF_SIZE;
	int sv[2];
	int i;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
		return -1;
	for (i = 0; i < 2; i++) {
		setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
		setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	}
	if (sv[0] >= MAX_FDS)
		abort();
	peer_of[sv[0]] = sv[1];
	last_peer = sv[1];

	if (next_open_is_ctrl) {
		next_open_is_ctrl = false;
		ctrl_fd = sv[0];
		for (i = 0; i < ctrl_npkts; i++)
			if (send(sv[1], ctrl_pkts[i], ctrl_lens[i], 0) < 0)
				err(1, "queueing request");
	}

	return sv[0];
}

int qrtr_publish(int sock, uint32_t service, uint16_t version, uint16_t instance)
{
	return 0;
}

int qrtr_decode(struct qrtr_packet *dest, void *buf, size_t len,
		const struct sockaddr_qrtr *sq)
{
	if (decode_error)
		return decode_error;
	*dest = decoded;
	return 0;
}

/* The remote end: node 1, port 100 */
static const struct sockaddr_qrtr remote = { 42, 1, 100 };

static ssize_t test_recvfrom(int fd, void *buf, size_t len, int flags,
			     struct sockaddr *addr, socklen_t *addrlen)
{
	if (fd == ctrl_fd && ctrl_reads_left-- <= 0) {
		errno = EIO;
		return -1;
	}
	if (addr) {
		memcpy(addr, stray_sender ? stray_sender : &remote, sizeof(remote));
		*addrlen = sizeof(remote);
	}
	return recv(fd, buf, len, flags);
}

static int test_getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	const struct sockaddr_qrtr local = { 42, LOCAL_NODE, 200 };

	memcpy(addr, &local, sizeof(local));
	*len = sizeof(local);
	return 0;
}

static int test_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	return 0;
}

static void *test_calloc(size_t n, size_t size)
{
	if (fail_calloc_at && --fail_calloc_at == 0)
		return NULL;
	return calloc(n, size);
}

static off_t test_lseek(int fd, off_t offset, int whence)
{
	if (fail_seek_end && whence == SEEK_END) {
		errno = EINVAL;
		return -1;
	}
	return lseek(fd, offset, whence);
}

#define recvfrom test_recvfrom
#define connect test_connect
#define getsockname test_getsockname
#define calloc test_calloc
#define lseek test_lseek
#define main tqftpserv_main
#define TQFTPSERV_RW_DIR test_rw_dir
#include "../tqftpserv.c"
#include "../translate.c"
#undef recvfrom
#undef connect
#undef getsockname
#undef calloc
#undef lseek
#undef main

/* Helpers */

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
		exit(1); \
	} \
} while (0)

/* Builds a request. The variable arguments are option/value pairs, then NULL */
static size_t request(char *buf, int opcode, const char *path, ...)
{
	const char *s;
	va_list ap;
	char *p = buf;

	*p++ = 0;
	*p++ = opcode;
	p = stpcpy(p, path) + 1;
	p = stpcpy(p, "octet") + 1;
	va_start(ap, path);
	while ((s = va_arg(ap, const char *)) != NULL)
		p = stpcpy(p, s) + 1;
	va_end(ap);

	return p - buf;
}

static ssize_t reply(int peer, void *buf, size_t len)
{
	return recv(peer, buf, len, MSG_DONTWAIT);
}

static int reply_opcode(int peer, char *buf, size_t len)
{
	ssize_t n = reply(peer, buf, len);

	if (n < 2)
		return -1;
	return (uint8_t)buf[0] << 8 | (uint8_t)buf[1];
}

/* Value of an option in an OACK of @len bytes, or NULL */
static const char *oack_option(const char *buf, size_t len, const char *opt)
{
	const char *p = buf + 2;

	while (p < buf + len) {
		const char *value = p + strlen(p) + 1;

		if (!strcmp(p, opt))
			return value;
		p = value + strlen(value) + 1;
	}
	return NULL;
}

static struct tftp_client *newest(struct list_head *list)
{
	if (list_empty(list))
		return NULL;
	return container_of(list->prev, struct tftp_client, node);
}

static void rw_path(char *out, const char *name)
{
	snprintf(out, PATH_MAX, "%s/%s", test_rw_dir, name);
}

static const char *rw_path_of(char *out, const char *name)
{
	rw_path(out, name);
	return out;
}

static void write_file(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	CHECK(fd >= 0);
	CHECK(write(fd, data, strlen(data)) == (ssize_t)strlen(data));
	close(fd);
}

static void read_file(const char *path, char *out, size_t len)
{
	ssize_t n;
	int fd = open(path, O_RDONLY);

	CHECK(fd >= 0);
	n = read(fd, out, len - 1);
	CHECK(n >= 0);
	out[n] = '\0';
	close(fd);
}

static int count_fds(void)
{
	int n = 0;
	int fd;

	for (fd = 0; fd < MAX_FDS; fd++)
		n += fcntl(fd, F_GETFD) >= 0;
	return n;
}

static bool exists(const char *path)
{
	struct stat st;

	return lstat(path, &st) == 0;
}

/* Sends one DATA block to a writer session and runs the handler */
static int send_data(struct tftp_client *client, int block, const char *data, size_t len)
{
	char pkt[600];

	pkt[0] = 0;
	pkt[1] = OP_DATA;
	pkt[2] = block >> 8;
	pkt[3] = block & 0xff;
	memcpy(pkt + 4, data, len);
	CHECK(send(peer_of[client->sock], pkt, len + 4, 0) == (ssize_t)len + 4);
	return handle_writer(client);
}

/* A WRQ with blksize 512 plus @extra options, then one DATA block */
static void write_request(const char *path, const char *data, const char *opt, const char *val)
{
	struct tftp_client *client;
	char buf[1024];
	size_t len;

	len = request(buf, OP_WRQ, path, "blksize", "512", "timeoutms", "5000",
		      opt, val, NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	CHECK(send_data(client, 1, data, strlen(data)) == 0);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_ACK);
	client_close_and_free(client);
}

/* An unlink request. Returns the opcode of the reply */
static int unlink_request(const char *path, char *buf, size_t size, ssize_t *n)
{
	size_t len;

	len = request(buf, OP_WRQ, path, "blksize", "7680", "timeoutms", "5000",
		      "unlink", "0", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	*n = reply(last_peer, buf, size);
	if (*n < 4)
		return -1;
	return (uint8_t)buf[0] << 8 | (uint8_t)buf[1];
}

/* The four memory and path defects of tqftpserv 1.2 */

/* A 128-byte ERROR on a read session filled the buffer, then wrote past it */
static void test_session_error_fills_buffer(void)
{
	struct tftp_client *client;
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	rw_path(path, "r.bin");
	write_file(path, "0123456789");
	len = request(buf, OP_RRQ, "/readwrite/r.bin", "blksize", "512",
		      "tsize", "0", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&readers);
	CHECK(client);

	memset(buf, 'A', 128);
	buf[0] = 0;
	buf[1] = OP_ERROR;
	buf[2] = 0;
	buf[3] = 1;
	CHECK(send(peer_of[client->sock], buf, 128, 0) == 128);
	CHECK(handle_reader(client) == -1);
	client_close_and_free(client);
}

/* A 4096-byte ERROR on the request socket did the same in main() */
static void test_request_error_fills_buffer(void)
{
	static char big[4096];
	static const char short_error[2] = { 0, OP_ERROR };
	static const char other[4] = { 0, 9, 0, 0 };
	char *argv[] = { "tqftpserv", NULL };

	memset(big, 'A', sizeof(big));
	big[0] = 0;
	big[1] = OP_ERROR;
	big[2] = 0;
	big[3] = 1;
	ctrl_pkts[0] = big;
	ctrl_lens[0] = sizeof(big);
	ctrl_pkts[1] = short_error;
	ctrl_lens[1] = sizeof(short_error);
	/* Keeps the socket readable. Its read fails and main() returns */
	ctrl_pkts[2] = other;
	ctrl_lens[2] = sizeof(other);
	ctrl_npkts = 3;
	ctrl_reads_left = 2;
	next_open_is_ctrl = true;
	optind = 1;
	CHECK(tqftpserv_main(1, argv) == -EIO);
}

/* Bytes over 0x7f in a request's opcode or error code were shifted as negative values */
static void test_request_high_bytes(void)
{
	static const char high_opcode[2] = { (char)0x80, 1 };
	static const char high_error[6] = { 0, OP_ERROR, (char)0x80, 1, 'x', 0 };
	static const char other[4] = { 0, 9, 0, 0 };
	char *argv[] = { "tqftpserv", NULL };

	ctrl_pkts[0] = high_opcode;
	ctrl_lens[0] = sizeof(high_opcode);
	ctrl_pkts[1] = high_error;
	ctrl_lens[1] = sizeof(high_error);
	ctrl_pkts[2] = other;
	ctrl_lens[2] = sizeof(other);
	ctrl_npkts = 3;
	ctrl_reads_left = 2;
	next_open_is_ctrl = true;
	optind = 1;
	CHECK(tqftpserv_main(1, argv) == -EIO);
}

/* A DATA packet shorter than its header underflowed the payload size */
static void test_short_data_packet(void)
{
	struct tftp_client *client;
	char buf[1024];
	size_t len;

	len = request(buf, OP_WRQ, "/readwrite/w.bin", "blksize", "512", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);

	/*
	 * The block number of a short packet is read from what the previous
	 * one left in the buffer, so leave the expected block number there.
	 */
	memcpy(buf, "\0\1\0\1", 4);
	CHECK(send(peer_of[client->sock], buf, 4, 0) == 4);
	CHECK(handle_writer(client) == -1);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_ERROR);

	buf[0] = 0;
	buf[1] = OP_DATA;
	CHECK(send(peer_of[client->sock], buf, 2, 0) == 2);
	CHECK(handle_writer(client) == -1);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_ERROR);
	client_close_and_free(client);
}

/* "/readwrite//abs/path" opened /abs/path, outside the readwrite directory */
static void test_absolute_path_escape(void)
{
	char secret[PATH_MAX];
	char req[PATH_MAX + 32];
	char buf[PATH_MAX + 128];
	size_t len;

	snprintf(secret, sizeof(secret), "%s/secret", outside_dir);
	write_file(secret, "secret");

	snprintf(req, sizeof(req), "/readwrite/%s", secret);
	len = request(buf, OP_RRQ, req, "blksize", "512", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);

	snprintf(req, sizeof(req), "/readwrite/%s/new", outside_dir);
	len = request(buf, OP_WRQ, req, "blksize", "512", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	snprintf(req, sizeof(req), "%s/new", outside_dir);
	CHECK(!exists(req));

	len = request(buf, OP_RRQ, "/readwrite/../x", "blksize", "512", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
}

/* The client allocation was used without a NULL check */
static void test_client_calloc_failure(void)
{
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	rw_path(path, "c.bin");
	write_file(path, "0123456789");

	len = request(buf, OP_RRQ, "/readwrite/c.bin", "blksize", "512", NULL);
	fail_calloc_at = 1;
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);

	len = request(buf, OP_WRQ, "/readwrite/c.bin", "blksize", "512", NULL);
	fail_calloc_at = 1;
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
}

/* A read whose file size could not be found left the file open */
static void test_tsize_failure_closes_the_file(void)
{
	char path[PATH_MAX];
	char buf[1024];
	size_t len;
	int before;

	rw_path(path, "z");
	write_file(path, "0123456789");
	before = count_fds();
	len = request(buf, OP_RRQ, "/readwrite/z", "blksize", "512", "tsize", "0", NULL);
	fail_seek_end = true;
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	fail_seek_end = false;
	CHECK(list_empty(&readers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	close(last_peer);
	CHECK(count_fds() == before);
}

/* Deleting files */

static void test_unlink(void)
{
	char path[PATH_MAX];
	char buf[1024];
	const char *value;
	ssize_t n;

	rw_path(path, "mcfg.tmp");
	write_file(path, "x");
	CHECK(unlink_request("/readwrite/mcfg.tmp", buf, sizeof(buf), &n) == OP_OACK);
	CHECK(!exists(path));
	value = oack_option(buf, n, "unlink");
	CHECK(value && !strcmp(value, "0"));
	value = oack_option(buf, n, "blksize");
	CHECK(value && !strcmp(value, "7680"));

	/* Gone already */
	CHECK(unlink_request("/readwrite/mcfg.tmp", buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_ENOENT);
}

static void test_unlink_stays_inside(void)
{
	char secret[PATH_MAX];
	char path[PATH_MAX];
	char req[PATH_MAX + 32];
	char buf[1024];
	ssize_t n;

	snprintf(secret, sizeof(secret), "%s/secret", outside_dir);
	write_file(secret, "secret");

	/* A symbolic link is deleted, not its target */
	rw_path(path, "link");
	CHECK(symlink(secret, path) == 0);
	CHECK(unlink_request("/readwrite/link", buf, sizeof(buf), &n) == OP_OACK);
	CHECK(!exists(path));
	CHECK(exists(secret));

	/* No way through a directory link, "..", an absolute path or another namespace */
	rw_path(path, "dirlink");
	CHECK(symlink(outside_dir, path) == 0);
	CHECK(unlink_request("/readwrite/dirlink/secret", buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(unlink_request("/readwrite/../outside/secret", buf, sizeof(buf), &n) == OP_ERROR);
	snprintf(req, sizeof(req), "/readwrite/%s", secret);
	CHECK(unlink_request(req, buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(unlink_request("/readonly/firmware/image/secret", buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(exists(secret));

	/* Directories are refused */
	rw_path(path, "sub");
	CHECK(mkdir(path, 0700) == 0);
	CHECK(unlink_request("/readwrite/sub", buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(unlink_request("/readwrite/", buf, sizeof(buf), &n) == OP_ERROR);
	CHECK(exists(path));
}

static void test_unlink_in_rrq(void)
{
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	rw_path(path, "keep");
	write_file(path, "x");
	len = request(buf, OP_RRQ, "/readwrite/keep", "blksize", "512",
		      "unlink", "1", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(exists(path));
}

/* Writing files */

static void test_no_symlinks_followed(void)
{
	char secret[PATH_MAX];
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	snprintf(secret, sizeof(secret), "%s/secret", outside_dir);
	write_file(secret, "secret");
	rw_path(path, "wlink");
	CHECK(symlink(secret, path) == 0);

	len = request(buf, OP_WRQ, "/readwrite/wlink", "blksize", "512", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	len = request(buf, OP_RRQ, "/readwrite/wlink", "blksize", "512", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));

	rw_path(path, "dirlink");
	CHECK(symlink(outside_dir, path) == 0);
	len = request(buf, OP_WRQ, "/readwrite/dirlink/secret", "blksize", "512", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));

	read_file(secret, buf, sizeof(buf));
	CHECK(!strcmp(buf, "secret"));
}

static void test_write_truncates_without_seek(void)
{
	char path[PATH_MAX];
	char buf[64];

	rw_path(path, "t.bin");
	write_file(path, "0123456789");
	write_request("/readwrite/t.bin", "x", NULL, NULL);
	read_file(path, buf, sizeof(buf));
	CHECK(!strcmp(buf, "x"));
}

/* A rejected write leaves the file as it was */
static void test_rejected_write_keeps_the_file(void)
{
	char path[PATH_MAX];
	char buf[1024];
	size_t len;
	int n;

	rw_path(path, "k.bin");
	write_file(path, "0123456789");
	/* The client, its block buffer and its window buffer */
	for (n = 1; n <= 3; n++) {
		len = request(buf, OP_WRQ, "/readwrite/k.bin", "blksize", "512", NULL);
		fail_calloc_at = n;
		handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
		CHECK(list_empty(&writers));
		CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
		read_file(path, buf, sizeof(buf));
		CHECK(!strcmp(buf, "0123456789"));
	}
}

/* A WRQ without options: ACK of block 0, then the data replaces the file */
static void test_write_without_options(void)
{
	struct tftp_client *client;
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	rw_path(path, "b.bin");
	write_file(path, "0123456789");
	len = request(buf, OP_WRQ, "/readwrite/b.bin", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply(last_peer, buf, sizeof(buf)) == 4);
	CHECK(buf[1] == OP_ACK && buf[2] == 0 && buf[3] == 0);
	CHECK(send_data(client, 1, "x", 1) == 0);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_ACK);
	client_close_and_free(client);
	read_file(path, buf, sizeof(buf));
	CHECK(!strcmp(buf, "x"));
}

static void test_write_with_seek_keeps_the_rest(void)
{
	char path[PATH_MAX];
	char buf[64];

	rw_path(path, "s.bin");
	write_file(path, "0123456789");
	write_request("/readwrite/s.bin", "ab", "seek", "0");
	read_file(path, buf, sizeof(buf));
	CHECK(!strcmp(buf, "ab23456789"));
	write_request("/readwrite/s.bin", "Z", "seek", "5");
	read_file(path, buf, sizeof(buf));
	CHECK(!strcmp(buf, "ab234Z6789"));
}

/*
 * The modem's check of mcfg.tmp at boot, as logged with Qualcomm's server:
 * stat, create empty, write one byte, stat, delete. A stale longer file
 * must not change the result.
 */
static void test_modem_mcfg_sequence(void)
{
	struct tftp_client *client;
	char path[PATH_MAX];
	char buf[1024];
	const char *value;
	size_t len;
	ssize_t n;

	rw_path(path, "mcfg.tmp");

	len = request(buf, OP_RRQ, "/readwrite/mcfg.tmp", "blksize", "7680",
		      "timeoutms", "5000", "tsize", "0", "wsize", "10", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_ENOENT);

	write_file(path, "stale data");

	len = request(buf, OP_WRQ, "/readwrite/mcfg.tmp", "blksize", "7680",
		      "timeoutms", "5000", "wsize", "10", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	CHECK(send_data(client, 1, "", 0) == 0);
	client_close_and_free(client);

	len = request(buf, OP_WRQ, "/readwrite/mcfg.tmp", "blksize", "7680",
		      "timeoutms", "5000", "seek", "0", "wsize", "10", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	CHECK(send_data(client, 1, "1", 1) == 0);
	client_close_and_free(client);

	len = request(buf, OP_RRQ, "/readwrite/mcfg.tmp", "blksize", "7680",
		      "timeoutms", "5000", "tsize", "0", "wsize", "10", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&readers);
	CHECK(client);
	n = reply(last_peer, buf, sizeof(buf));
	CHECK(n > 2 && buf[1] == OP_OACK);
	value = oack_option(buf, n, "tsize");
	CHECK(value && !strcmp(value, "1"));
	memcpy(buf, "\0\5\0\11End of Transfer", 20);
	CHECK(send(peer_of[client->sock], buf, 20, 0) == 20);
	CHECK(handle_reader(client) == -1);
	client_close_and_free(client);

	CHECK(unlink_request("/readwrite/mcfg.tmp", buf, sizeof(buf), &n) == OP_OACK);
	CHECK(!exists(path));
}

/* Limits */

/* Opens a read of an existing file. True if a session came of it */
static bool open_read(const struct sockaddr_qrtr *sq)
{
	char buf[1024];
	int before = 0;
	int after = 0;
	struct tftp_client *client;
	size_t len;

	list_for_each_entry(client, &readers, node)
		before++;
	len = request(buf, OP_RRQ, "/readwrite/f", "blksize", "512", "tsize", "0", NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)sq);
	list_for_each_entry(client, &readers, node)
		after++;
	return after > before;
}

static void test_window_is_capped(void)
{
	char buf[1024];
	char big[16];
	size_t len;

	/* 64 KiB blocks in 65535 blocks: about 4 GB of buffer per transfer */
	len = request(buf, OP_WRQ, "/readwrite/w", "blksize", "65464", "wsize", "65535", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_EOPTNEG);

	/* Within each limit, over them together */
	len = request(buf, OP_WRQ, "/readwrite/w", "blksize", "65464", "wsize", "17", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);

	snprintf(big, sizeof(big), "%d", MAX_WSIZE + 1);
	len = request(buf, OP_RRQ, "/readwrite/w", "blksize", "512", "wsize", big, NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&readers));
}

/* wsize 65535 once wrapped the loop's 16-bit block and it never ended */
static void test_reader_window_ends(void)
{
	struct tftp_client *client;
	char path[PATH_MAX];
	char wsize[16];
	char buf[1024];
	size_t len;
	int sent = 0;

	rw_path(path, "r");
	write_file(path, "0123456789");
	snprintf(wsize, sizeof(wsize), "%d", MAX_WSIZE);
	len = request(buf, OP_RRQ, "/readwrite/r", "blksize", "8", "rsize", "104857600",
		      "wsize", wsize, NULL);
	handle_rrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&readers);
	CHECK(client);
	CHECK(!client->rw_buf);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_OACK);

	/* An ACK from high in the block range, where the old loop bound passed 65535 */
	memcpy(buf, "\0\4\377\377", 4);
	CHECK(send(peer_of[client->sock], buf, 4, 0) == 4);
	CHECK(handle_reader(client) == 1);
	while (reply(peer_of[client->sock], buf, sizeof(buf)) >= 0)
		sent++;
	CHECK(sent == MAX_WSIZE);
	client_close_and_free(client);
}

static void test_sessions_are_capped(void)
{
	const struct sockaddr_qrtr other = { 42, 5, 100 };
	const struct sockaddr_qrtr third = { 42, 10, 100 };
	struct sockaddr_qrtr sq;
	char path[PATH_MAX];
	char buf[256];
	int i;

	rw_path(path, "f");
	write_file(path, "0123456789");

	sq = remote;
	for (i = 0; i < MAX_NODE_SESSIONS; i++) {
		sq.sq_port = 1000 + i;
		CHECK(open_read(&sq));
	}
	/* One node is full, another still gets its share */
	CHECK(!open_read(&sq));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(open_read(&other));

	sq = other;
	for (i = 1; i < MAX_NODE_SESSIONS; i++) {
		sq.sq_port = 2000 + i;
		CHECK(open_read(&sq));
	}
	/* Every transfer in use */
	CHECK(!open_read(&third));

	/* A write counts too, and an unlink needs no transfer */
	sq = third;
	CHECK(unlink_request("/readwrite/f", buf, sizeof(buf), &(ssize_t){ 0 }) == OP_OACK);
	write_file(path, "0123456789");
	close_sessions(remote.sq_node, 0, true);
	CHECK(open_read(&third));
}

static void test_idle_sessions_end(void)
{
	struct tftp_client *busy;
	struct tftp_client *idle;
	char path[PATH_MAX];
	char buf[1024];
	size_t len;
	long long now = now_ms();

	rw_path(path, "f");
	write_file(path, "0123456789");
	CHECK(open_read(&remote));
	idle = newest(&readers);
	CHECK(open_read(&remote));
	busy = newest(&readers);
	idle->last_active_ms = now - SESSION_IDLE_MS;
	busy->last_active_ms = now - SESSION_IDLE_MS + 1;

	len = request(buf, OP_WRQ, "/readwrite/g", "blksize", "512", "timeoutms", "5000", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(newest(&writers));
	newest(&writers)->last_active_ms = now - SESSION_IDLE_MS;

	reap_idle_sessions(now);
	CHECK(list_empty(&writers));
	CHECK(newest(&readers) == busy);
	CHECK(busy->node.prev == &readers);

	/* A packet from the peer counts as activity, a stray one does not */
	busy->last_active_ms = now - SESSION_IDLE_MS;
	stray_sender = &(struct sockaddr_qrtr){ 42, 5, 100 };
	memcpy(buf, "\0\4\0\0", 4);
	CHECK(send(peer_of[busy->sock], buf, 4, 0) == 4);
	CHECK(handle_reader(busy) == 1);
	CHECK(busy->last_active_ms == now - SESSION_IDLE_MS);
	stray_sender = NULL;
	CHECK(send(peer_of[busy->sock], buf, 4, 0) == 4);
	CHECK(handle_reader(busy) >= 0);
	CHECK(busy->last_active_ms >= now);
}

static void test_stray_packet_keeps_the_session(void)
{
	const struct sockaddr_qrtr stray = { 42, 5, 100 };
	struct tftp_client *client;
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	rw_path(path, "f");
	write_file(path, "0123456789");
	CHECK(open_read(&remote));
	client = newest(&readers);
	stray_sender = &stray;
	memcpy(buf, "\0\5\0\1x", 6);
	CHECK(send(peer_of[client->sock], buf, 6, 0) == 6);
	CHECK(handle_reader(client) == 1);

	stray_sender = NULL;
	len = request(buf, OP_WRQ, "/readwrite/g", "blksize", "512", "timeoutms", "5000", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	stray_sender = &stray;
	CHECK(send_data(client, 1, "bad", 3) == 1);
	stray_sender = NULL;
	CHECK(client->blk_expected == 1);
	CHECK(send_data(client, 1, "good", 4) == 0);
	client_close_and_free(client);
	read_file(rw_path_of(path, "g"), buf, sizeof(buf));
	CHECK(!strcmp(buf, "good"));
}

/* A file and the whole directory have budgets, and so has the number of files */
static void test_write_budgets(void)
{
	struct tftp_client *client;
	char path[PATH_MAX];
	char name[32];
	char seek[32];
	char buf[1024];
	size_t len;
	int i;

	/* Past the file budget at the start */
	snprintf(seek, sizeof(seek), "%d", TQFTPSERV_MAX_FILE_BYTES + 1);
	len = request(buf, OP_WRQ, "/readwrite/big", "blksize", "512", "seek", seek, NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_ENOSPACE);
	rw_path(path, "big");
	CHECK(!exists(path));

	/* Across the file budget by a write */
	snprintf(seek, sizeof(seek), "%d", TQFTPSERV_MAX_FILE_BYTES - 1);
	len = request(buf, OP_WRQ, "/readwrite/big", "blksize", "512", "seek", seek, NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	CHECK(send_data(client, 1, "ab", 2) == -1);
	CHECK(reply_opcode(peer_of[client->sock], buf, sizeof(buf)) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_ENOSPACE);
	client_close_and_free(client);
	unlink(path);

	/* Just under the total, then over it */
	rw_path(path, "fill");
	write_file(path, "");
	CHECK(truncate(path, TQFTPSERV_MAX_RW_BYTES - 3) == 0);
	len = request(buf, OP_WRQ, "/readwrite/t", "blksize", "512", "timeoutms", "5000", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	client = newest(&writers);
	CHECK(client);
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_OACK);
	CHECK(send_data(client, 1, "abcd", 4) == -1);
	client_close_and_free(client);
	/* Overwriting in place costs nothing */
	write_request("/readwrite/t", "abc", "timeoutms", "5000");
	unlink(path);

	/* The number of files. An existing one still opens */
	for (i = 0; i < TQFTPSERV_MAX_RW_FILES; i++) {
		snprintf(name, sizeof(name), "n%d", i);
		rw_path(path, name);
		write_file(path, "");
	}
	len = request(buf, OP_WRQ, "/readwrite/extra", "blksize", "512", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(list_empty(&writers));
	CHECK(reply_opcode(last_peer, buf, sizeof(buf)) == OP_ERROR);
	CHECK(buf[3] == TFTP_ERROR_ENOSPACE);
	rw_path(path, "extra");
	CHECK(!exists(path));
	write_request("/readwrite/n0", "x", "timeoutms", "5000");
}

/* The name service reports a client or a node going away, as on a modem restart */
static void test_control_ends_sessions(void)
{
	const struct sockaddr_qrtr other = { 42, 5, 100 };
	const struct sockaddr_qrtr ns = { 42, LOCAL_NODE, QRTR_PORT_CTRL };
	const struct sockaddr_qrtr forged = { 42, 5, QRTR_PORT_CTRL };
	struct sockaddr_qrtr port2 = remote;
	struct tftp_client *client;
	char path[PATH_MAX];
	char buf[1024];
	size_t len;

	port2.sq_port = 101;
	rw_path(path, "f");
	write_file(path, "0123456789");
	CHECK(open_read(&remote));
	CHECK(open_read(&port2));
	CHECK(open_read(&other));
	len = request(buf, OP_WRQ, "/readwrite/g", "blksize", "512", "timeoutms", "5000", NULL);
	handle_wrq(buf, len, (struct sockaddr_qrtr *)&remote);
	CHECK(newest(&writers));

	/* Only the name service speaks for a node */
	decoded = (struct qrtr_packet){ .type = QRTR_TYPE_BYE, .node = remote.sq_node };
	CHECK(handle_control(buf, 4, &forged, LOCAL_NODE) == 0);
	CHECK(!list_empty(&writers));

	decoded = (struct qrtr_packet){ .type = QRTR_TYPE_DEL_CLIENT, .node = remote.sq_node, .port = 101 };
	CHECK(handle_control(buf, 4, &ns, LOCAL_NODE) == 0);
	list_for_each_entry(client, &readers, node)
		CHECK(!(client->sq.sq_node == remote.sq_node && client->sq.sq_port == 101));
	CHECK(!list_empty(&writers));

	decoded = (struct qrtr_packet){ .type = QRTR_TYPE_BYE, .node = remote.sq_node };
	CHECK(handle_control(buf, 4, &ns, LOCAL_NODE) == 0);
	CHECK(list_empty(&writers));
	client = newest(&readers);
	CHECK(client && client->sq.sq_node == other.sq_node);
	CHECK(client->node.prev == &readers);
}

/* A control packet libqrtr cannot decode, as one under 20 bytes, ended main() */
static void test_bad_control_packet(void)
{
	static const char short_ctrl[4] = { 3, 0, 0, 0 };
	static const char other[4] = { 0, 9, 0, 0 };
	const struct sockaddr_qrtr ns = { 42, LOCAL_NODE, QRTR_PORT_CTRL };
	char *argv[] = { "tqftpserv", NULL };

	ctrl_pkts[0] = short_ctrl;
	ctrl_lens[0] = sizeof(short_ctrl);
	ctrl_pkts[1] = other;
	ctrl_lens[1] = sizeof(other);
	ctrl_npkts = 2;
	ctrl_reads_left = 1;
	next_open_is_ctrl = true;
	stray_sender = &ns;
	decode_error = -EMSGSIZE;
	optind = 1;
	CHECK(tqftpserv_main(1, argv) == -EIO);
}

static const struct {
	const char *name;
	void (*fn)(void);
} tests[] = {
	{ "session_error_fills_buffer", test_session_error_fills_buffer },
	{ "request_error_fills_buffer", test_request_error_fills_buffer },
	{ "request_high_bytes", test_request_high_bytes },
	{ "short_data_packet", test_short_data_packet },
	{ "absolute_path_escape", test_absolute_path_escape },
	{ "client_calloc_failure", test_client_calloc_failure },
	{ "tsize_failure_closes_the_file", test_tsize_failure_closes_the_file },
	{ "unlink", test_unlink },
	{ "unlink_stays_inside", test_unlink_stays_inside },
	{ "unlink_in_rrq", test_unlink_in_rrq },
	{ "no_symlinks_followed", test_no_symlinks_followed },
	{ "write_truncates_without_seek", test_write_truncates_without_seek },
	{ "rejected_write_keeps_the_file", test_rejected_write_keeps_the_file },
	{ "write_without_options", test_write_without_options },
	{ "write_with_seek_keeps_the_rest", test_write_with_seek_keeps_the_rest },
	{ "modem_mcfg_sequence", test_modem_mcfg_sequence },
	{ "window_is_capped", test_window_is_capped },
	{ "reader_window_ends", test_reader_window_ends },
	{ "sessions_are_capped", test_sessions_are_capped },
	{ "idle_sessions_end", test_idle_sessions_end },
	{ "stray_packet_keeps_the_session", test_stray_packet_keeps_the_session },
	{ "write_budgets", test_write_budgets },
	{ "control_ends_sessions", test_control_ends_sessions },
	{ "bad_control_packet", test_bad_control_packet },
};

static void remove_tree(const char *path)
{
	char cmd[PATH_MAX + 16];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
	if (system(cmd) != 0)
		warnx("could not remove %s", path);
}

/* Runs one test in a child with its own directories. True if it passed */
static bool run(int i, const char *tmp)
{
	char base[PATH_MAX];
	char log[PATH_MAX];
	char line[512];
	FILE *f;
	pid_t pid;
	int status;
	int fd;

	snprintf(base, sizeof(base), "%s/tqftpserv-test.XXXXXX", tmp);
	if (!mkdtemp(base))
		err(1, "mkdtemp");
	snprintf(test_rw_dir, sizeof(test_rw_dir), "%s/rw", base);
	snprintf(outside_dir, sizeof(outside_dir), "%s/outside", base);
	snprintf(log, sizeof(log), "%s/log", base);
	if (mkdir(test_rw_dir, 0700) < 0 || mkdir(outside_dir, 0700) < 0)
		err(1, "mkdir");

	fflush(stdout);
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			_exit(2);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		tests[i].fn();
		fflush(NULL);
		_exit(0);
	}
	if (waitpid(pid, &status, 0) < 0)
		err(1, "waitpid");

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("PASS %s\n", tests[i].name);
		remove_tree(base);
		return true;
	}

	printf("FAIL %s\n", tests[i].name);
	f = fopen(log, "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			printf("  | %s", line);
		fclose(f);
	}
	remove_tree(base);
	return false;
}

int main(int argc, char **argv)
{
	const char *tmp = getenv("TMPDIR");
	size_t i;
	int failed = 0;
	int ran = 0;
	int j;

	if (!tmp || !*tmp)
		tmp = "/tmp";

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool selected = argc < 2;

		for (j = 1; j < argc; j++)
			if (!strcmp(argv[j], tests[i].name))
				selected = true;
		if (!selected)
			continue;
		ran++;
		if (!run(i, tmp))
			failed++;
	}

	printf("%d of %d tests passed\n", ran - failed, ran);
	return failed ? 1 : 0;
}
