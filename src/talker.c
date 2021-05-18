/*
 *  talker.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "octopi.h"
#include "setproctitle.h"
#include "rule.h"
#include "addrutil.h"
#include "ioutil.h"
#include "io_sync.h"
#include "logging.h"
#include "lpm.h"
#include "que.h"

static int
connect_peer(OD *od, ADDR *address, char *peer)
{
	int sock;
	int ret;
	struct timeval start;
        union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr ad;
	} sa;
	socklen_t len;
	int e;

	/*
	 *  get start time
	 */
	gettimeofday(&start, NULL);

	/*
	 *  create socket
	 */
	sock = socket(address->af, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (sock < 0) {
		error("sync to %s: socket failed: %s", peer, strerror(errno));
		return -1;
	}

	/*
	 *  connect
	 */
	memset(&sa, 0, sizeof(sa));
	if (address->af == AF_INET) {
		sa.in.sin_family = AF_INET;
		sa.in.sin_port = htons(od->sync_port);
		sa.in.sin_addr.s_addr = htonl(address->ipv4_addr);
		len = sizeof(struct sockaddr_in);
	} else {
		sa.in6.sin6_family = AF_INET6;
		sa.in6.sin6_port = htons(od->sync_port);
		sa.in6.sin6_addr.s6_addr32[0]= htonl(address->addr32[3]);
		sa.in6.sin6_addr.s6_addr32[1]= htonl(address->addr32[2]);
		sa.in6.sin6_addr.s6_addr32[2]= htonl(address->addr32[1]);
		sa.in6.sin6_addr.s6_addr32[3]= htonl(address->addr32[0]);
		len = sizeof(struct sockaddr_in6);
	}
	ret = connect(sock, &sa.ad, len);
	if (ret < 0 && errno != EINPROGRESS) {
		error("sync to %s: conect failed: %s", peer, strerror(errno));
		return -1;
	}

	/*
	 *  wait connection
	 */
	do {
		if (od->terminate)
			break;
		ret = wait_writable(sock, od->sync_timeout);
		if (ret == IO_FAIL) {
			error("sync to %s: conection timeout:", peer);
			return -1;
		}
	} while (ret == IO_IRUPT);

	/*
	 *  check error
	 */
	len = sizeof e;
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
		       (void *)&e, (socklen_t *)&len) < 0) {
		error("sync to %s: getsockopt failed: %s",
		      peer, strerror(errno));
		return -1;
	}
	if (e != 0) {
		error("sync to %s: connect failed (after delay): %s",
		      peer, strerror(e));
		return -1;
	}

	debug("sync to %s: connected", peer);
	return sock;
}

static int
send_rule(OD *od, IOBUF *buf)
{
	int ret = IO_IRUPT;
	int state = FALSE;

	while (ret == IO_IRUPT) {
		if (od->terminate)
			return FALSE;

		ret = flush_iobuf(buf, od->sync_timeout);
		if (ret == IO_OK)
			state = TRUE;
		else if (ret != IO_IRUPT)
			error("write failed: %s", strerror(errno));
	}

	return state;
}

void
talker(OD *od, qpos_t mem)
{
	ADDR addr;
	char peer[IP_STR_LEN];
	IOBUF *buf;
	int all = 0;
	int count = 0;
	uint32_t update;
	int sock;
	int state = TRUE;

	/* initalize */
	setproctitle("octopi-talker");
	logging_init("octopi-talker", od->log_facility);
	debug("talker %d is luanched", getpid());

	/* open rule and queue */
	open_rule_file(od, O_RDONLY);
	open_queue_file(od, O_RDWR);

	/* get target address */
	QUE_member_addr(mem, &addr);

	/* make data */
	buf = init_iobuf(od->sync_buffer, SYNC_IO_SIZE);
	update = QUE_make_data(buf, mem, &all, &count);

	/* sync start */
	QUE_sync_start(mem);
	
	/*  once, close queue and rule */
	close_queue_file(od);
	close_rule_file(od);

	/*  check no need to update */
	if (update == 0) {
		free_iobuf(buf);
		exit(EXIT_SUCCESS);
	}

	/* debug logging start */
	addr_to_str(&addr, peer);
	debug("sync to %s: started", peer);

	/* connect to peer */
	sock = connect_peer(od, &addr, peer);
	if (sock < 0)
		state = FALSE;

	/* get greeting */
	if (state)
		state = get_greeting(od, sock, peer);

	/* put command */
	if (state)
		state = put_command(od, sock, all, peer);

	/* get waiting */
	if (state)
		state = get_waiting(od, sock, peer);	

	/* flush  */
	set_fd_iobuf(buf, sock);
	if (state)
		state = send_rule(od, buf);
	free_iobuf(buf);

	/*  get result */
	if (state)
		state = get_result(od, sock, peer);
	close(sock);

	/* re-open queue and finish */
	open_queue_file(od, O_RDWR);
	if (state) {
		QUE_sync_finish(mem, update);
		info("sync to %s: Succeeded", peer);
	} else {
		QUE_sync_abort(mem);
	}
	close_queue_file(od);

	exit(EXIT_SUCCESS);
}
