/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Just enough of libqrtr for the host tests (test_tqftpserv.c), which
 * replace QRTR sockets with local datagram socket pairs.
 */
#ifndef __TEST_LIBQRTR_H__
#define __TEST_LIBQRTR_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

struct sockaddr_qrtr {
	unsigned short sq_family;
	uint32_t sq_node;
	uint32_t sq_port;
};

#define QRTR_PORT_CTRL	0xfffffffeu

/* As enum qrtr_pkt_type in the kernel's include/uapi/linux/qrtr.h */
enum {
	QRTR_TYPE_DATA = 1,
	QRTR_TYPE_BYE = 3,
	QRTR_TYPE_DEL_CLIENT = 6,
};

struct qrtr_packet {
	int type;
	unsigned int node;
	unsigned int port;
	void *data;
	size_t data_len;
};

int qrtr_open(int rport);
int qrtr_publish(int sock, uint32_t service, uint16_t version, uint16_t instance);
int qrtr_decode(struct qrtr_packet *dest, void *buf, size_t len,
		const struct sockaddr_qrtr *sq);

#endif
