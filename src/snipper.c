/*
 *  snipper.c
 *
 *  copyright (c) 2019 HANATAKA Shinya
 *  copyright (c) 2019 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <netinet/if_ether.h>

#include "octopi.h"
#include "logging.h"
#include "setproctitle.h"

void
snipper_loop(uint8_t *user, const struct pcap_pkthdr *head, const uint8_t *buf)
{
	OD *od = (OD *)user;
	uint16_t ether_type;

	/*
	 *  received
	 */
	if (head->len == 0) {
		inc_drop(od);
		return;
	}
	inc_recv(od);
	debug_packet("snipper receive", buf, head->caplen);

	/*
	 *  error: truncate packet
	 */
	if (head->len != head->caplen) {
		inc_error(od);
		return;
	}

	/*
	 *  drop: non-multicast packet
	 */
	if ((buf[0] & 1) == 0) {
		inc_drop(od);
		return;
	}

	/*
	 *  drop: non IPv4/IPv6 packet
	 */
	ether_type = buf[12] << 8 | buf[13];
	if (ether_type != ETH_P_IP && ether_type != ETH_P_IPV6) {
		inc_drop(od);
		return;
	}

	/*
	 *  site tagging
	 */
        *(uint32_t *)(buf + sizeof(uint32_t) * 0) = 0x00000000UL;
	*(uint32_t *)(buf + sizeof(uint32_t) * 1) = 0x00000000UL;
	*(uint32_t *)(buf + sizeof(uint32_t) * 2) = 0x00000000UL;

	/*
	 *  send packet to dispatcher
	 */
	while (od->terminate == 0) {
		if (send(od->unix_out, buf, head->len, 0) > 0) {
			inc_sent(od);
			break;
		}
		if (errno == EINTR || errno == EAGAIN)
			continue;

		inc_error(od);
		break;
	}
}

void
snipper(OD *od)
{
	struct bpf_program prog;

	setproctitle("octopi-snipper");
	logging_init("octopi-snipper", od->log_facility);

	/*
	 *  activate packet capture
	 */
	if (pcap_activate(od->pcap)) {
		sleep(1);
		error_exit("pcap_activate failed: %s", pcap_geterr(od->pcap));
	}

	/*
	 *  setup filter
	 */
	if (pcap_compile(od->pcap, &prog, od->pcap_filter, 1,
			 PCAP_NETMASK_UNKNOWN)) {
		sleep(1);
		error_exit("pcap_compile failed: %s", pcap_geterr(od->pcap));
	}
	if (pcap_setfilter(od->pcap, &prog)) {
		sleep(1);
		error_exit("pcap_setfilter failed: %s", pcap_geterr(od->pcap));
	}

	/*
	 *  capture loop
	 */
	while (od->terminate == 0)
		pcap_loop(od->pcap, -1, snipper_loop, (uint8_t *)od);

	exit(EXIT_SUCCESS);
}
