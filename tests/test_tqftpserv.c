// SPDX-License-Identifier: BSD-3-Clause
/*
 * Host tests for tqftpserv's request handling. Not built for Android.
 *
 * tqftpserv.c and translate.c are compiled into this file. QRTR sockets
 * are replaced by local datagram socket pairs, the readwrite directory by
 * a temporary one, so the handlers can be fed packets directly. Each test
 * runs in its own process; build with AddressSanitizer (see Makefile) so
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
	memset(dest, 0, sizeof(*dest));
	dest->type = QRTR_TYPE_DATA;
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
		memcpy(addr, &remote, sizeof(remote));
		*addrlen = sizeof(remote);
	}
	return recv(fd, buf, len, flags);
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

#define recvfrom test_recvfrom
#define connect test_connect
#define calloc test_calloc
#define main tqftpserv_main
#define TQFTPSERV_RW_DIR test_rw_dir
#include "../tqftpserv.c"
#include "../translate.c"
#undef recvfrom
#undef connect
#undef calloc
#undef main

/* Helpers */

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
		exit(1); \
	} \
} while (0)

/* Builds a request; the variable arguments are option/value pairs, then NULL */
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

/* An unlink request; returns the opcode of the reply */
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
	/* Keeps the socket readable; its read fails and main() returns */
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

static const struct {
	const char *name;
	void (*fn)(void);
} tests[] = {
	{ "session_error_fills_buffer", test_session_error_fills_buffer },
	{ "request_error_fills_buffer", test_request_error_fills_buffer },
	{ "short_data_packet", test_short_data_packet },
	{ "absolute_path_escape", test_absolute_path_escape },
	{ "client_calloc_failure", test_client_calloc_failure },
	{ "unlink", test_unlink },
	{ "unlink_stays_inside", test_unlink_stays_inside },
	{ "unlink_in_rrq", test_unlink_in_rrq },
	{ "no_symlinks_followed", test_no_symlinks_followed },
	{ "write_truncates_without_seek", test_write_truncates_without_seek },
	{ "write_with_seek_keeps_the_rest", test_write_with_seek_keeps_the_rest },
	{ "modem_mcfg_sequence", test_modem_mcfg_sequence },
};

static void remove_tree(const char *path)
{
	char cmd[PATH_MAX + 16];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
	if (system(cmd) != 0)
		warnx("could not remove %s", path);
}

/* Runs one test in a child with its own directories; true if it passed */
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
