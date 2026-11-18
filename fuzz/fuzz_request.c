// SPDX-License-Identifier: BSD-3-Clause
/*
 * Request parsing. The input after its first byte is either the option list
 * alone, given to parse_options(), or a whole RRQ or WRQ after its opcode,
 * given to handle_rrq() or handle_wrq().
 *
 * Input: u8 mode, then bytes.
 *   mode % 4: 0 options of an RRQ, 1 options of a WRQ, 2 an RRQ, 3 a WRQ
 */
#include "fuzz_common.h"

static const struct sockaddr_qrtr requester = { FZ_AF_QIPCRTR, 0, 100 };

static uint8_t reply[600];
static size_t reply_len;
static int replies;

static void on_send(int fd, const uint8_t *buf, size_t len)
{
	replies++;
	reply_len = len < sizeof(reply) ? len : sizeof(reply);
	memcpy(reply, buf, reply_len);
}

/* The value of @opt in the OACK, or NULL */
static const char *oack_value(const char *opt)
{
	const char *p = (const char *)reply + 2;
	const char *end = (const char *)reply + reply_len;

	while (p < end) {
		const char *value = p + strlen(p) + 1;

		if (!strcmp(p, opt))
			return value;
		p = value + strlen(value) + 1;
	}
	return NULL;
}

static void check_echo(const char *opt, long long v)
{
	const char *s = oack_value(opt);

	FZ_CHECK(s && strtoll(s, NULL, 10) == v, "OACK %s is %s, not %lld", opt, s ? s : "missing", v);
}

static void parse_only(const uint8_t *data, size_t size, bool wrq)
{
	static char buf[8192];
	size_t blksize = 512, wsize = 1, rsize = 0;
	ssize_t tsize = -1;
	unsigned int timeoutms = 1000;
	off_t seek = -1;
	bool do_unlink = false;
	int sock;
	int ret;

	memcpy(buf, data, size);
	ret = parse_options(buf, size, &blksize, &tsize, &wsize, &timeoutms, &rsize, &seek,
			    wrq ? &do_unlink : NULL);
	if (ret < 0)
		return;

	/* Whatever was taken is in range */
	FZ_CHECK(size == 0 || buf[size - 1] == '\0', "options not terminated were taken");
	FZ_CHECK(blksize >= MIN_BLKSIZE && blksize <= MAX_BLKSIZE, "blksize %zu", blksize);
	FZ_CHECK(wsize >= MIN_WSIZE && wsize <= MAX_WSIZE, "wsize %zu", wsize);
	FZ_CHECK(rsize <= MAX_RSIZE, "rsize %zu", rsize);
	FZ_CHECK(timeoutms >= MIN_TIMEOUTMS && timeoutms <= MAX_TIMEOUTMS, "timeoutms %u", timeoutms);
	FZ_CHECK(seek >= -1 && tsize >= -1, "seek or tsize below -1");
	FZ_CHECK(wrq || !do_unlink, "unlink taken in an RRQ");

	/* The OACK built from them carries them */
	sock = qrtr_open(0);
	fz_sender_set = true;
	fz_sender = requester;
	fz_connect(sock, (const struct sockaddr *)&requester, sizeof(requester));
	fz_sender_set = false;
	replies = 0;
	tftp_send_oack(sock, &blksize, (size_t *)&tsize, &wsize, &timeoutms,
		       rsize ? &rsize : NULL, seek >= 0 ? &seek : NULL, do_unlink);
	FZ_CHECK(replies == 1 && reply[1] == OP_OACK, "no OACK");
	check_echo("blksize", blksize);
	check_echo("wsize", wsize);
	check_echo("timeoutms", timeoutms);
	if (tsize >= 0)
		check_echo("tsize", tsize);
	if (rsize)
		check_echo("rsize", rsize);
	if (seek >= 0)
		check_echo("seek", seek);
	if (do_unlink)
		check_echo("unlink", 0);
	fz_close(sock);
}

static void whole_request(const uint8_t *data, size_t size, bool wrq)
{
	static char buf[4096];
	struct fz_usage usage;
	uint64_t out_hash;
	size_t base_alloc;
	int base_fds;
	int sessions;

	if (size > sizeof(buf) - 3)
		size = sizeof(buf) - 3;
	buf[0] = 0;
	buf[1] = wrq ? OP_WRQ : OP_RRQ;
	memcpy(buf + 2, data, size);

	if (wrq)
		fz_reset_rw(FZ_TREE_PLAIN);
	out_hash = fz_tree_hash(fz_outside);
	fz_rw_usage(&usage.entries, &usage.bytes, &usage.largest);
	base_fds = fz_count_fds();
	base_alloc = fz_allocated();

	replies = 0;
	fz_sender_set = true;
	fz_sender = requester;
	if (wrq)
		handle_wrq(buf, size + 2, (struct sockaddr_qrtr *)&requester);
	else
		handle_rrq(buf, size + 2, (struct sockaddr_qrtr *)&requester);
	fz_sender_set = false;

	sessions = !list_empty(&readers) + !list_empty(&writers);
	FZ_CHECK(sessions <= 1, "two sessions from one request");
	FZ_CHECK(replies <= 1, "%d replies to one request", replies);
	if (sessions) {
		struct tftp_client *c = container_of((wrq ? &writers : &readers)->next,
						     struct tftp_client, node);

		fz_check_session(c, wrq);
		FZ_CHECK(replies == 1, "a session opened without a reply");
		FZ_CHECK(fz_count_fds() == base_fds + 2, "a session holds %d descriptors",
			 fz_count_fds() - base_fds);
	}
	close_sessions(requester.sq_node, 0, true);

	FZ_CHECK(fz_count_fds() == base_fds, "%d descriptors open, %d at start",
		 fz_count_fds(), base_fds);
	FZ_CHECK(!fz_alloc_exact() || fz_allocated() == base_alloc, "%lld bytes held",
		 (long long)fz_allocated() - (long long)base_alloc);
	FZ_CHECK(fz_tree_hash(fz_outside) == out_hash, "a folder outside changed");
	fz_check_budgets(&usage);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t mode;

	fz_init_once();
	if (!size)
		return 0;
	fz_on_send = on_send;
	mode = data[0] % 4;
	data++;
	size--;
	if (size > 4096)
		size = 4096;
	if (mode < 2)
		parse_only(data, size, mode == 1);
	else
		whole_request(data, size, mode == 3);
	return 0;
}
