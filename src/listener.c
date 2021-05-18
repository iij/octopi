/*
 *  listener.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "octopi.h"
#include "lpm.h"
#include "rule.h"
#include "io_sync.h"
#include "logging.h"
#include "addrutil.h"
#include "setproctitle.h"

static int
check_acl(OD *od, ADDR *p)
{
	ADDR relay;
	npos_t n;
	static ADDR v4mapedv6 = {
		.af = AF_INET6, 
		.mask = 96,
		.next = NULL,
		.ipv6_addr = 0xffff00000000,
	};

	if (p->af == AF_INET) {
		n = LPM_find_urelay_ip4(VNI_ACL, p->ipv4_addr);
	} else if (p->af == AF_INET6) {
		if (check_cidr_ipv6(p->ipv6_addr, &v4mapedv6)) {
			n = LPM_find_urelay_ip4(VNI_ACL,
						p->ipv6_addr & 0xffffffff);
		} else {
			n = LPM_find_urelay_ip6(VNI_ACL, p->ipv6_addr);
		}
	} else {
		return FALSE;
	}

	if (n == 0)
		return FALSE;

	if (LPM_get_next_relay(&n, &relay) == LPM_FAIL)
		return FALSE;

	if (relay.af != AF_INET
	    || relay.ipv4_addr != LPM_RELAY_Broadcast)
		return FALSE;

	return TRUE;
}

static void
listen_socket(OD *od)
{
	if (listen(od->sync_in, 1) < 0)
		error_exit("listen(sync) failed: %s", strerror(errno));
}

static int
accept_socket(OD *od, char **peer)
{
	int sock;

	/*
	 *  wait connecttion
	 */
	while (od->terminate == 0) {
		struct sockaddr_storage s;
		socklen_t len;
		ADDR ad;
		char buf[IP_STR_LEN];

		/*
		 *  accept
		 */
		len = sizeof(s);
		sock = accept(od->sync_in, (struct sockaddr *)&s, &len);
		if (sock < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			error_exit("sync accept failed: %s", strerror(errno));
		}

		/*
		 *  get peer address
		 */
		ad.af = s.ss_family;
		if (ad.af == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *) &s;
			ad.ipv4_addr = ntohl(sin->sin_addr.s_addr);
		} else if (ad.af == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &s;
			ad.ipv6_addr = ntohq(*(ip6_t*)(&sin6->sin6_addr));
		} else {
			error("connected from unknown address family %d",
			      ad.af);
			close(sock);
			continue;
		}
		addr_to_str(&ad, buf);
		*peer = strdup(buf);
		if (*peer == NULL)
			crit_exit("out of memory ... aborted");

		/*
		 *  check acl
		 */
		if (check_acl(od, &ad) != TRUE) {
			info("sync from %s: denied by ACL", *peer);
			close(sock);
			continue;
		}

		info("sync from %s: accepted", *peer);
		return sock;
	}

	exit(EXIT_SUCCESS);

	/* NOT REACHED */
	return -1;
}

void
listener(OD *od)
{
	int sock;
	int replace;
	char *peer = NULL;
	
	setproctitle("octopi-listener");
	logging_init("octopi-listener", od->log_facility);

	/*
	 *  waiting connection
	 */
	listen_socket(od);
	sock = accept_socket(od, &peer);

	/*
	 *  close rule for reopen read/write mode
	 */
	close_rule_file(od);

	/*
	 *  put greeting
	 */
	put_greeting(od, sock, peer);

	/*
	 *  get command
	 */
	replace = get_command(od, sock, peer);

	/*
	 *  put waiting
	 */
	put_waiting(od, sock, peer);

	/*
	 *  process SYNC rules
	 */
	if (update_rules(od, sock, PROTO_ALL, replace, peer) == TRUE) {
		put_success_result(od, sock, peer);
	} else {
		put_failure_result(od, sock, peer);
	}

	exit(EXIT_SUCCESS);
}
