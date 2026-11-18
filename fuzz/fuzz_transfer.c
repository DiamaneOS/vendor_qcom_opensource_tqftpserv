// SPDX-License-Identifier: BSD-3-Clause
/*
 * One read or one write, then ACK and DATA packets straight to its handler.
 * Every DATA sent must carry the file's bytes at its offset, and a write must
 * leave the file holding exactly the blocks the server acknowledged.
 *
 * Input:
 *   u8 kind: bit 0 write, bits 1-2 the file, bits 3-4 the starting tree
 *   u8 opts: which of blksize, wsize, rsize, seek, tsize, timeoutms follow
 *   u16 blksize, u8 wsize, u32 rsize, u32 seek, u8 tsize, u16 timeoutms
 *            (each only if its bit is set)
 *   then events: u8 how, then
 *     how & 3 == 0: i8 delta, u16 len: the next ACK or DATA, as the
 *                   main loop target builds it
 *     how & 3 == 1: u16 len, bytes: a raw packet
 *     how & 3 == 2: as 0, from another node or port
 *     how & 3 == 3: u8 len: a packet of len % 4 bytes
 */
#include "fuzz_common.h"

static const struct sockaddr_qrtr peer = { FZ_AF_QIPCRTR, 0, 100 };
static const struct sockaddr_qrtr other = { FZ_AF_QIPCRTR, 3, 100 };

static const char *const read_files[4] = {
	"/readwrite/big", "/readonly/firmware/image/big.bin",
	"/readwrite/sub/b", "/readonly/firmware/image/f1.bin",
};
static const char *const write_files[4] = {
	"/readwrite/w", "/readwrite/a", "/readwrite/sub/b", "/readwrite/big",
};

static uint8_t pkt[70000];

/* What the current event sent on the session socket */
static int session_sock = -1;
static struct {
	uint8_t data[300][4 + 65464];
	size_t len[300];
	int n;
	int others;
} sent;

static void on_send(int fd, const uint8_t *buf, size_t len)
{
	if (fd != session_sock) {
		sent.others++;
		return;
	}
	FZ_CHECK(sent.n < 300, "more than 300 packets for one event");
	memcpy(sent.data[sent.n], buf, len);
	sent.len[sent.n++] = len;
}

static size_t put_opt(char *p, const char *name, unsigned long long v)
{
	return sprintf(p, "%s", name) + 1 + sprintf(p + strlen(name) + 1, "%llu", v) + 1;
}

/* The whole file */
static uint8_t *read_all(int fd, size_t *size)
{
	off_t end = fz_fd_size(fd);
	uint8_t *buf;

	buf = malloc(end + 1);
	FZ_CHECK(pread(fd, buf, end, 0) == end, "file read");
	*size = end;
	return buf;
}

/* A reader sent what it holds, in order, and no more than a window */
static void check_reader_sends(struct tftp_client *c, uint16_t acked, const uint8_t *file,
			       size_t fsize)
{
	int i;

	FZ_CHECK(sent.n <= (int)c->wsize, "%d DATA for a window of %zu", sent.n, c->wsize);
	for (i = 0; i < sent.n; i++) {
		const uint8_t *p = sent.data[i];
		unsigned int block = (unsigned int)acked + i;
		unsigned long long off = (unsigned long long)c->seek +
					 (unsigned long long)block * c->blksize;
		size_t len = sent.len[i] - 4;
		size_t full;

		if (p[1] == OP_ERROR)
			continue;
		FZ_CHECK(p[1] == OP_DATA, "reader sent opcode %d", p[1]);
		FZ_CHECK((p[2] << 8 | p[3]) == ((block + 1) & 0xffff), "DATA block %d after ACK %u",
			 p[2] << 8 | p[3], acked);
		full = off >= fsize ? 0 : fsize - off < c->blksize ? fsize - off : c->blksize;
		if ((unsigned long long)(block + 1) * c->blksize > c->rsize && c->rsize % c->blksize)
			FZ_CHECK(len == c->rsize % c->blksize && len <= full,
				 "DATA of %zu bytes, rsize leaves %zu", len, c->rsize % c->blksize);
		else
			FZ_CHECK(len == full, "DATA of %zu bytes at %llu, the file has %zu there",
				 len, off, full);
		FZ_CHECK(!len || !memcmp(p + 4, file + off, len), "DATA %u differs from the file",
			 block + 1);
	}
}

static int run_events(struct tftp_client *c, bool writer, uint8_t **model, size_t *model_len)
{
	uint8_t *file = NULL;
	size_t fsize = 0;
	uint8_t pending[MAX_WINDOW_BYTES];
	size_t npending = 0;
	off_t pos = c->seek;
	int ret = 1;

	if (!writer)
		file = read_all(c->fd, &fsize);

	while (ret > 0 && fz_more()) {
		uint8_t how = fz_u8();
		struct sockaddr_qrtr from = peer;
		uint16_t block = 0;
		size_t len;
		size_t before_offset = c->blk_offset;
		struct tftp_client copy = *c;
		off_t file_before = writer ? fz_fd_size(c->fd) : 0;

		switch (how & 3) {
		case 2:
			from = how & 4 ? other : (struct sockaddr_qrtr){ FZ_AF_QIPCRTR, 0, 101 };
			/* fall through */
		case 0: {
			int8_t delta = fz_u8();

			len = fz_u16();
			if (writer) {
				block = c->blk_expected + delta;
				len %= c->blksize + 1;
				pkt[1] = OP_DATA;
				memset(pkt + 4, (uint8_t)(block * 31 + len), len);
				len += 4;
			} else {
				block = (fz_socks[c->sock].last_data_block < 0 ? 0 :
					 fz_socks[c->sock].last_data_block) + delta;
				pkt[1] = OP_ACK;
				len = 4;
			}
			pkt[0] = 0;
			pkt[2] = block >> 8;
			pkt[3] = block;
			break;
		}
		case 1: {
			const uint8_t *data;

			len = fz_u16() % (MAX_BLKSIZE + 8);
			data = fz_bytes(&len);
			memcpy(pkt, data, len);
			break;
		}
		default:
			len = fz_u8() % 4;
			memset(pkt, 0, len);
			break;
		}

		sent.n = sent.others = 0;
		fz_pend = (typeof(fz_pend)){ c->sock, pkt, len, from };
		ret = writer ? handle_writer(c) : handle_reader(c);
		FZ_CHECK(fz_pend.fd == -1, "packet not read");
		FZ_CHECK(sent.others == 0, "a reply to someone else");

		if (from.sq_node != peer.sq_node || from.sq_port != peer.sq_port) {
			FZ_CHECK(ret == 1 && sent.n == 0, "a stray packet got %d and %d replies",
				 ret, sent.n);
			FZ_CHECK(c->blk_offset == copy.blk_offset &&
				 c->blk_expected == copy.blk_expected &&
				 c->last_active_ms == copy.last_active_ms,
				 "a stray packet changed the transfer");
			if (writer)
				FZ_CHECK(fz_fd_size(c->fd) == file_before,
					 "a stray packet changed the file");
			continue;
		}

		if (!writer) {
			if (len >= 4 && pkt[1] == OP_ACK && pkt[0] == 0)
				check_reader_sends(c, pkt[2] << 8 | pkt[3], file, fsize);
			continue;
		}

		/* The writer took the block into its window, or wrote the window out */
		if (ret >= 0 && sent.n == 0) {
			FZ_CHECK(c->blk_offset == before_offset + len - 4, "window offset");
			memcpy(pending + npending, pkt + 4, len - 4);
			npending += len - 4;
		} else if (ret >= 0) {
			FZ_CHECK(sent.n == 1 && sent.data[0][1] == OP_ACK &&
				 !memcmp(sent.data[0] + 2, pkt + 2, 2), "writer reply to a block");
			FZ_CHECK(c->blk_offset == 0, "window not emptied");
			memcpy(pending + npending, pkt + 4, len - 4);
			npending += len - 4;
			/* Writing nothing past the end does not grow the file */
			if (npending && (size_t)pos + npending > *model_len) {
				*model = realloc(*model, pos + npending);
				memset(*model + *model_len, 0, pos + npending - *model_len);
				*model_len = pos + npending;
			}
			if (npending)
				memcpy(*model + pos, pending, npending);
			pos += npending;
			npending = 0;
		}
		FZ_CHECK(npending <= c->rw_buf_size, "window of %zu bytes", npending);
	}
	free(file);
	return ret;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char req[512];
	char *p = req;
	uint8_t kind, opts;
	bool writer;
	const char *path;
	struct tftp_client *c;
	struct fz_usage usage;
	uint8_t *model = NULL;
	size_t model_len = 0;
	long long seek = -1;
	int base_fds;
	size_t base_alloc;
	int ret;

	fz_init_once();
	fz_in = data;
	fz_in_len = size;
	fz_in_pos = 0;
	kind = fz_u8();
	opts = fz_u8();
	writer = kind & 1;
	path = (writer ? write_files : read_files)[(kind >> 1) & 3];
	fz_reset_rw(((kind >> 3) & 3) % FZ_TREE_VARIANTS);
	fz_rw_usage(&usage.entries, &usage.bytes, &usage.largest);
	fz_on_send = on_send;
	fz_fail_calloc = fz_fail_qrtr_open = 0;

	*p++ = 0;
	*p++ = writer ? OP_WRQ : OP_RRQ;
	p = stpcpy(p, path) + 1;
	p = stpcpy(p, "octet") + 1;
	if (opts & 1)
		p += put_opt(p, "blksize", fz_u16() % (MAX_BLKSIZE + 16));
	if (opts & 2)
		p += put_opt(p, "wsize", fz_u8() + 1);
	if (opts & 4)
		p += put_opt(p, "rsize", fz_u32() % (MAX_RSIZE + 16));
	if (opts & 8)
		p += put_opt(p, "seek", seek = fz_u32() % (TQFTPSERV_MAX_FILE_BYTES + 16));
	if (opts & 16)
		p += put_opt(p, "tsize", fz_u8());
	if (opts & 32)
		p += put_opt(p, "timeoutms", fz_u16() % 300000);

	base_fds = fz_count_fds();
	base_alloc = fz_allocated();

	/* The model of the file a write leaves */
	if (writer) {
		char full[PATH_MAX];
		int fd;

		snprintf(full, sizeof(full), "%s/%s", fz_rw_dir, path + strlen("/readwrite/"));
		fd = open(full, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			model = read_all(fd, &model_len);
			close(fd);
		}
	}

	fz_sender_set = true;
	fz_sender = peer;
	session_sock = -1;
	sent.n = sent.others = 0;
	if (writer)
		handle_wrq(req, p - req, (struct sockaddr_qrtr *)&peer);
	else
		handle_rrq(req, p - req, (struct sockaddr_qrtr *)&peer);
	fz_sender_set = false;

	c = list_empty(writer ? &writers : &readers) ? NULL :
	    container_of((writer ? &writers : &readers)->next, struct tftp_client, node);
	if (c) {
		fz_check_session(c, writer);
		session_sock = c->sock;
		FZ_CHECK(fz_count_fds() == base_fds + 2, "a new session holds %d descriptors",
			 fz_count_fds() - base_fds);
		if (writer && seek < 0)
			FZ_CHECK(fz_fd_size(c->fd) == 0, "a write without seek kept the file");
		if (writer && seek < 0)
			model_len = 0;
		ret = run_events(c, writer, &model, &model_len);
		if (ret > 0)
			fz_check_session(c, writer);
		client_close_and_free(c);
	}
	FZ_CHECK(list_empty(&readers) && list_empty(&writers), "two sessions");
	fz_check_budgets(&usage);

	/* A refused write leaves the file as it was */
	if (writer) {
		char full[PATH_MAX];
		size_t len;
		uint8_t *now;
		int fd;

		snprintf(full, sizeof(full), "%s/%s", fz_rw_dir, path + strlen("/readwrite/"));
		fd = open(full, O_RDONLY | O_CLOEXEC);
		FZ_CHECK(fd >= 0 || (!c && !model), "the file is gone");
		now = fd >= 0 ? read_all(fd, &len) : NULL;
		if (fd >= 0)
			close(fd);
		if (!c && !model)
			FZ_CHECK(fd < 0 || len == 0, "a refused write left a file");
		FZ_CHECK(!now || len == model_len, "file of %zu bytes, %zu expected", len, model_len);
		FZ_CHECK(!model_len || !memcmp(now, model, model_len),
			 "file differs from what was acknowledged");
		free(now);
	}
	free(model);

	FZ_CHECK(fz_count_fds() == base_fds, "%d descriptors open at the end, %d at start",
		 fz_count_fds(), base_fds);
	FZ_CHECK(!fz_alloc_exact() || fz_allocated() == base_alloc, "%lld bytes held at the end",
		 (long long)fz_allocated() - (long long)base_alloc);
	return 0;
}
