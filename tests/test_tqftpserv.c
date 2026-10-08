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

	{ "rejected_write_keeps_the_file", test_rejected_write_keeps_the_file },
	{ "write_without_options", test_write_without_options },
