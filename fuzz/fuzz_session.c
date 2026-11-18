// SPDX-License-Identifier: BSD-3-Clause
/*
 * The whole daemon: main() runs on fake sockets and a fake clock, and the
 * input decides what each select() returns. Between two turns of the loop
 * the state is checked, and so is what the last event was allowed to change.
 *
 * Input: one byte picks the starting tree, then events, each an opcode byte:
 *   0 TIMER   u16 t: the clock moves t * 8 ms, select() times out
 *   1 MAIN    u8 who, u16 len, bytes: a packet to the service socket.
 *             who & 3 picks the node (0, 3, 5, local 1), (who >> 2) & 3
 *             the port (100, 101, 0x4000, control)
 *   2 RAW     u8 k, u8 who, u16 len, bytes: a packet to session k % n.
 *             who & 1: from someone else, then who >> 1 picks how
 *   3 NEXT    u8 k, u8 who, i8 delta, u16 len: to session k, from its
 *             client unless who & 1. A reader gets an ACK of the last block
 *             it sent plus delta, a writer DATA of the expected block plus
 *             delta with len % (blksize + 1) bytes
 *   4 CTRL    u8 how, u8 cmd, u8 node, u8 port, u8 len: a control packet.
 *             how & 3: from the local name service, from node 0's control
 *             port, from local port 100, or from local port 0x4000.
 *             how & 0x80: len % 20 bytes only
 *   5 FAIL    u8 n: (n >> 1) % 4 + 1 calls from now, calloc() (n even)
 *             or qrtr_open() (n odd) fails
 * At the end of the input every node with a session gets a BYE, then the
 * service socket fails and main() must return.
 *
 * With FZ_COUNT_UNLINKED set, bytes in unlinked files still open for writing
 * count against the readwrite budget as well.
 */
#include "fuzz_common.h"

static const unsigned int nodes[4] = { 0, 3, 5, FZ_LOCAL_NODE };
static const unsigned int ports[4] = { 100, 101, 0x4000, QRTR_PORT_CTRL };

enum ev_kind {
	EV_NONE,
	EV_TIMER,
	EV_REQUEST,	/* a packet on the service socket, not a control one */
	EV_CLIENT,	/* to a session, from its client */
	EV_STRAY,	/* to a session, from anyone else */
	EV_BYE,
	EV_DEL_CLIENT,
	EV_CTRL_NONE,	/* a control packet that ends nothing */
};

struct snap {
	struct tftp_client *c;
	struct tftp_client copy;
	off_t file_off;
	unsigned long sends;
};

static struct snap snap[MAX_SESSIONS + 1];
static int nsnap;
static struct {
	enum ev_kind kind;
	int sock;
	unsigned int node;
	unsigned int port;
} ev;

static uint8_t pkt[4096 + 70000];
static bool count_unlinked;
static struct fz_usage usage;
static int base_fds;
static size_t base_alloc;

static void take_snapshot(void)
{
	struct tftp_client *list[MAX_SESSIONS + 1];
	int n = fz_sessions(list, MAX_SESSIONS + 1);
	int i;

	FZ_CHECK(n <= MAX_SESSIONS, "%d sessions", n);
	for (i = 0; i < n; i++) {
		snap[i].c = list[i];
		snap[i].copy = *list[i];
		snap[i].file_off = lseek(list[i]->fd, 0, SEEK_CUR);
		snap[i].sends = fz_socks[list[i]->sock].sends;
	}
	nsnap = n;
}

static bool may_end(const struct snap *s)
{
	const struct tftp_client *c = &s->copy;

	switch (ev.kind) {
	case EV_TIMER:
		return fz_now_ms - c->last_active_ms >= SESSION_IDLE_MS;
	case EV_CLIENT:
		return c->sock == ev.sock;
	case EV_BYE:
		return c->sq.sq_node == ev.node;
	case EV_DEL_CLIENT:
		return c->sq.sq_node == ev.node && c->sq.sq_port == ev.port;
	default:
		return false;
	}
}

static bool must_end(const struct snap *s)
{
	return may_end(s) && ev.kind != EV_CLIENT;
}

/* What the last event changed, against what it was allowed to */
static void check_event(void)
{
	struct tftp_client *list[MAX_SESSIONS + 1];
	int n = fz_sessions(list, MAX_SESSIONS + 1);
	int kept = 0;
	int i, j;

	for (i = 0; i < nsnap; i++) {
		struct snap *s = &snap[i];
		struct tftp_client *now = NULL;

		for (j = 0; j < n; j++)
			if (list[j] == s->c && list[j]->sock == s->copy.sock &&
			    list[j]->fd == s->copy.fd)
				now = list[j];
		if (!now) {
			FZ_CHECK(may_end(s), "event %d ended the session of %u:%u",
				 ev.kind, s->copy.sq.sq_node, s->copy.sq.sq_port);
			continue;
		}
		kept++;
		FZ_CHECK(!must_end(s), "event %d kept the session of %u:%u",
			 ev.kind, s->copy.sq.sq_node, s->copy.sq.sq_port);
		if (ev.kind == EV_CLIENT && s->copy.sock == ev.sock)
			continue;
		/* Untouched: its state, its file offset, and nothing sent */
		FZ_CHECK(!memcmp(&now->sq, &s->copy.sq, sizeof(now->sq)) &&
			 now->block == s->copy.block &&
			 now->blksize == s->copy.blksize &&
			 now->rsize == s->copy.rsize &&
			 now->wsize == s->copy.wsize &&
			 now->seek == s->copy.seek &&
			 now->blk_buf == s->copy.blk_buf &&
			 now->rw_buf == s->copy.rw_buf &&
			 now->blk_offset == s->copy.blk_offset &&
			 now->blk_expected == s->copy.blk_expected &&
			 now->last_active_ms == s->copy.last_active_ms,
			 "event %d changed the session of %u:%u", ev.kind,
			 s->copy.sq.sq_node, s->copy.sq.sq_port);
		FZ_CHECK(lseek(now->fd, 0, SEEK_CUR) == s->file_off,
			 "event %d moved the file of %u:%u", ev.kind,
			 s->copy.sq.sq_node, s->copy.sq.sq_port);
		FZ_CHECK(fz_socks[now->sock].sends == s->sends,
			 "event %d sent on the session of %u:%u", ev.kind,
			 s->copy.sq.sq_node, s->copy.sq.sq_port);
	}

	/* Only a request opens a session, and only for its sender */
	if (ev.kind != EV_REQUEST) {
		FZ_CHECK(n == kept, "event %d opened a session", ev.kind);
		return;
	}
	for (j = 0; j < n; j++) {
		bool old = false;

		for (i = 0; i < nsnap; i++)
			old |= list[j] == snap[i].c;
		if (!old)
			FZ_CHECK(list[j]->sq.sq_node == ev.node && list[j]->sq.sq_port == ev.port,
				 "a request from %u:%u opened a session for %u:%u", ev.node,
				 ev.port, list[j]->sq.sq_node, list[j]->sq.sq_port);
	}
}

/* What holds between any two turns of the loop */
static void check_state(struct timeval *tv)
{
	struct tftp_client *list[MAX_SESSIONS + 1];
	unsigned int per_node[4] = { 0 };
	int n = fz_sessions(list, MAX_SESSIONS + 1);
	int fds;
	int i, j;

	FZ_CHECK(n <= MAX_SESSIONS, "%d sessions", n);
	fz_extra_bytes = 0;
	for (i = 0; i < n; i++) {
		struct stat st;

		/* Opt-in: count what unlinked files under write still hold */
		if (count_unlinked && fz_is_writer(list[i]) &&
		    fstat(list[i]->fd, &st) == 0 && st.st_nlink == 0)
			fz_extra_bytes += st.st_size;
		fz_check_session(list[i], fz_is_writer(list[i]));
		FZ_CHECK(fz_now_ms - list[i]->last_active_ms < SESSION_IDLE_MS,
			 "a session idle for %lld ms", fz_now_ms - list[i]->last_active_ms);
		for (j = 0; j < 4; j++)
			per_node[j] += list[i]->sq.sq_node == nodes[j];
	}
	for (j = 0; j < 4; j++)
		FZ_CHECK(per_node[j] <= MAX_NODE_SESSIONS, "%u sessions for node %u",
			 per_node[j], nodes[j]);
	/* With a session open the loop must wake up to end it */
	if (n)
		FZ_CHECK(tv && tv->tv_sec <= REAP_INTERVAL_SEC, "select() without a timeout");

	/* The service socket, and a socket and a file per session */
	fds = fz_count_fds();
	FZ_CHECK(fds == base_fds + 1 + 2 * n, "%d descriptors open with %d sessions, %d at start",
		 fds, n, base_fds);
	FZ_CHECK(!fz_alloc_exact() || fz_allocated() <= base_alloc + n * FZ_SESSION_BYTES + FZ_SLACK_BYTES,
		 "%lld bytes allocated with %d sessions", (long long)fz_allocated() - (long long)base_alloc, n);
	fz_check_budgets(&usage);
}

static struct tftp_client *session_at(fd_set *r, int nfds, unsigned int k, int *sock)
{
	struct tftp_client *list[MAX_SESSIONS + 1];
	int n = fz_sessions(list, MAX_SESSIONS + 1);

	if (!n)
		return NULL;
	*sock = list[k % n]->sock;
	FZ_CHECK(*sock < nfds && FD_ISSET(*sock, r), "session socket not watched");
	return list[k % n];
}

/* Someone other than @peer, picked by @who */
static struct sockaddr_qrtr stray_of(const struct sockaddr_qrtr *peer, unsigned int who)
{
	struct sockaddr_qrtr sq = *peer;

	switch (who % 4) {
	case 0:
		sq.sq_node = peer->sq_node == 3 ? 5 : 3;
		break;
	case 1:
		sq.sq_port = peer->sq_port + 1;
		break;
	case 2:
		sq.sq_node = FZ_LOCAL_NODE;
		sq.sq_port = QRTR_PORT_CTRL;
		break;
	default:
		sq.sq_node = peer->sq_node + 1 + (who >> 2);
		break;
	}
	return sq;
}

static void deliver(int fd, const uint8_t *data, size_t len, struct sockaddr_qrtr from,
		    fd_set *r)
{
	fz_pend.fd = fd;
	fz_pend.data = data;
	fz_pend.len = len;
	fz_pend.from = from;
	FD_ZERO(r);
	FD_SET(fd, r);
}

/* A packet on the service socket: a request, or a control message */
static void classify_main(const uint8_t *data, size_t len, struct sockaddr_qrtr from)
{
	uint32_t cmd;

	ev.node = from.sq_node;
	ev.port = from.sq_port;
	if (from.sq_port != QRTR_PORT_CTRL) {
		ev.kind = EV_REQUEST;
		return;
	}
	ev.kind = EV_CTRL_NONE;
	if (from.sq_node != FZ_LOCAL_NODE || len < 20)
		return;
	cmd = data[0] | data[1] << 8 | data[2] << 16 | (uint32_t)data[3] << 24;
	ev.node = data[4] | data[5] << 8 | data[6] << 16 | (uint32_t)data[7] << 24;
	ev.port = data[8] | data[9] << 8 | data[10] << 16 | (uint32_t)data[11] << 24;
	if (cmd == QRTR_TYPE_BYE)
		ev.kind = EV_BYE;
	else if (cmd == QRTR_TYPE_DEL_CLIENT)
		ev.kind = EV_DEL_CLIENT;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static int session_select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
	struct sockaddr_qrtr from;
	struct tftp_client *c;
	size_t len;
	int sock;

	FZ_CHECK(!w && !e && r, "select() sets");
	FZ_CHECK(fz_main_fd < nfds && FD_ISSET(fz_main_fd, r), "service socket not watched");
	FZ_CHECK(fz_pend.fd == -1, "a packet was not read");
	check_event();
	check_state(tv);
	fz_sender_set = false;

	for (;;) {
		if (!fz_more()) {
			struct tftp_client *list[1];

			/* Every node goes away, then the service socket fails */
			if (fz_sessions(list, 1)) {
				memset(pkt, 0, 20);
				put32(pkt, QRTR_TYPE_BYE);
				put32(pkt + 4, list[0]->sq.sq_node);
				from = (struct sockaddr_qrtr){ FZ_AF_QIPCRTR, FZ_LOCAL_NODE, QRTR_PORT_CTRL };
				classify_main(pkt, 20, from);
				take_snapshot();
				deliver(fz_main_fd, pkt, 20, from, r);
				return 1;
			}
			fz_main_eof = true;
			ev.kind = EV_NONE;
			take_snapshot();
			FD_ZERO(r);
			FD_SET(fz_main_fd, r);
			return 1;
		}

		switch (fz_u8() % 6) {
		case 0:
			fz_now_ms += fz_u16() * 8LL;
			if (!tv)
				continue;
			ev.kind = EV_TIMER;
			take_snapshot();
			FD_ZERO(r);
			return 0;
		case 1: {
			uint8_t who = fz_u8();
			const uint8_t *data;

			from = (struct sockaddr_qrtr){ FZ_AF_QIPCRTR, nodes[who & 3], ports[(who >> 2) & 3] };
			len = fz_u16() % 4096;
			data = fz_bytes(&len);
			memcpy(pkt, data, len);
			classify_main(pkt, len, from);
			fz_sender_set = true;
			fz_sender = from;
			take_snapshot();
			deliver(fz_main_fd, pkt, len, from, r);
			return 1;
		}
		case 2: {
			uint8_t k = fz_u8();
			uint8_t who = fz_u8();
			const uint8_t *data;

			len = fz_u16() % (MAX_BLKSIZE + 8);
			data = fz_bytes(&len);
			c = session_at(r, nfds, k, &sock);
			if (!c)
				continue;
			memcpy(pkt, data, len);
			from = who & 1 ? stray_of(&c->sq, who >> 1) : c->sq;
			goto session;
		}
		case 3: {
			uint8_t k = fz_u8();
			uint8_t who = fz_u8();
			int8_t delta = fz_u8();
			uint16_t block;

			len = fz_u16();
			c = session_at(r, nfds, k, &sock);
			if (!c)
				continue;
			from = who & 1 ? stray_of(&c->sq, who >> 1) : c->sq;
			if (fz_is_writer(c)) {
				block = c->blk_expected + delta;
				len %= c->blksize + 1;
				pkt[0] = 0;
				pkt[1] = OP_DATA;
				memset(pkt + 4, block, len);
				len += 4;
			} else {
				block = fz_socks[sock].last_data_block < 0 ? 0 :
					fz_socks[sock].last_data_block;
				block += delta;
				pkt[0] = 0;
				pkt[1] = OP_ACK;
				len = 4;
			}
			pkt[2] = block >> 8;
			pkt[3] = block;
			goto session;
		}
		case 4: {
			uint8_t how = fz_u8();
			uint8_t cmd = fz_u8();
			uint8_t node = fz_u8();
			uint8_t port = fz_u8();
			uint8_t short_len = fz_u8();
			static const struct sockaddr_qrtr senders[4] = {
				{ FZ_AF_QIPCRTR, FZ_LOCAL_NODE, QRTR_PORT_CTRL },
				{ FZ_AF_QIPCRTR, 0, QRTR_PORT_CTRL },
				{ FZ_AF_QIPCRTR, FZ_LOCAL_NODE, 100 },
				{ FZ_AF_QIPCRTR, FZ_LOCAL_NODE, 0x4000 },
			};

			memset(pkt, 0, 20);
			put32(pkt, cmd & 0x80 ? cmd & 0x7f :
			      (const uint32_t[]){ QRTR_TYPE_BYE, QRTR_TYPE_DEL_CLIENT, 4, 5 }[cmd & 3]);
			put32(pkt + 4, node & 0x80 ? node : nodes[node & 3]);
			put32(pkt + 8, port & 0x80 ? port : ports[port & 3]);
			len = how & 0x80 ? short_len % 20 : 20;
			from = senders[how & 3];
			classify_main(pkt, len, from);
			fz_sender_set = true;
			fz_sender = from;
			take_snapshot();
			deliver(fz_main_fd, pkt, len, from, r);
			return 1;
		}
		default: {
			uint8_t n = fz_u8();

			if (n & 1)
				fz_fail_qrtr_open = (n >> 1) % 4 + 1;
			else
				fz_fail_calloc = (n >> 1) % 4 + 1;
			continue;
		}
		}
session:
		ev.kind = from.sq_node == c->sq.sq_node && from.sq_port == c->sq.sq_port ?
			  EV_CLIENT : EV_STRAY;
		ev.sock = sock;
		take_snapshot();
		deliver(sock, pkt, len, from, r);
		return 1;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[] = { "tqftpserv", NULL };
	uint64_t fw_hash, out_hash;
	int ret;

	fz_init_once();
	count_unlinked = getenv("FZ_COUNT_UNLINKED") != NULL;
	fz_in = data;
	fz_in_len = size;
	fz_in_pos = 0;
	fz_reset_rw(fz_u8() % FZ_TREE_VARIANTS);
	fw_hash = fz_tree_hash(fz_fw_base);
	out_hash = fz_tree_hash(fz_outside);
	fz_rw_usage(&usage.entries, &usage.bytes, &usage.largest);

	fz_now_ms = 1000000000LL;
	fz_fail_calloc = 0;
	fz_fail_qrtr_open = 0;
	fz_main_eof = false;
	fz_pend.fd = -1;
	fz_sender_set = false;
	nsnap = 0;
	ev.kind = EV_NONE;
	fz_select_hook = session_select;
	FZ_CHECK(list_empty(&readers) && list_empty(&writers), "sessions left from before");

	base_fds = fz_count_fds();
	base_alloc = fz_allocated();

	/* The service socket is the first one opened */
	fz_main_fd = fcntl(0, F_DUPFD, 0);
	close(fz_main_fd);
	optind = 1;
	ret = tqftpserv_main(1, argv);
	FZ_CHECK(fz_main_eof && ret == -EIO, "the daemon ended (%d) on its input", ret);
	FZ_CHECK(list_empty(&readers) && list_empty(&writers), "sessions left after every node went");
	/* main() returns without closing its socket */
	fz_close(fz_main_fd);

	FZ_CHECK(fz_count_fds() == base_fds, "%d descriptors open at the end, %d at start",
		 fz_count_fds(), base_fds);
	FZ_CHECK(!fz_alloc_exact() || fz_allocated() == base_alloc, "%lld bytes held at the end",
		 (long long)fz_allocated() - (long long)base_alloc);
	FZ_CHECK(fz_tree_hash(fz_fw_base) == fw_hash, "the firmware folder changed");
	FZ_CHECK(fz_tree_hash(fz_outside) == out_hash, "a folder outside changed");
	return 0;
}
