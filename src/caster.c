/*
 *  caster.c
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
#include <sys/socket.h>
#include <netinet/if_ether.h>

#include "octopi.h"
#include "addrutil.h"
#include "packet.h"
#include "logging.h"
#include "setproctitle.h"
#include "md5.h"

static int
check_timeout_packet(OD *od, uint8_t *buf, int len)
{
	PACKET *h = (PACKET *)buf;
	uint64_t packet_time;
	uint64_t now_time;
	struct timeval tv;

	if (od->timeout == 0)
		return TRUE;

	packet_time = ntohl(h->time_sec);
	packet_time = packet_time * 1000 + ntohs(h->time_msec);

	gettimeofday(&tv, NULL);
	now_time = tv.tv_sec;
	now_time = now_time * 1000 + (tv.tv_usec / 1000);

	if (packet_time > now_time + od->timeout)
		return FALSE;
	if (packet_time + od->timeout < now_time)
		return FALSE;

	return TRUE;
}


int
check_secret(OD *od, uint8_t *buf, int len)
{
	PACKET *h = (PACKET *)buf;
	uint8_t packet_digest[SECRET_LEN];
	uint8_t digest[SECRET_LEN];

	if (od->secret == NULL)
		return TRUE;

	/*
	 *  md5 digest
	 */
	memcpy(packet_digest, h->secret, SECRET_LEN);
	memset(h->secret, 0, SECRET_LEN);
	strncpy((char*)h->secret, od->secret, SECRET_LEN);
	md5_sum(buf, len, digest);

	/*
	 *  compare secret
	 */
	if (memcmp(packet_digest, digest, SECRET_LEN) != 0)
		return FALSE;

	return TRUE;
}

uint16_t
calc_checksum(uint8_t *data, int len)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < len; ++ i) {
		if (i % 2 == 0)
			sum += data[i] << 8;
		else
			sum += data[i];
		while (sum >> 16)
			sum = (sum >> 16) + (sum & 0xffff);
	}

	return htons(~sum & 0xffff);
}

static void
make_ipv4_mcast_mac(uint8_t *mac, uint32_t ip4)
{
	ip4_t n = ntohl(ip4);

	memset(mac, 0, ETHER_ADDR_LEN);
	mac[0] = 0x01;
	mac[1] = 0x00;
	mac[2] = 0x5e;
	mac[3] = (n >> 16) & 0x7f;
	mac[4] = (n >> 8)  & 0xff;
	mac[5] = n & 0xff;
}

static void
cast_ip4(OD* od, uint8_t *buf, int len)
{
	struct ip_packet *ip;
	struct ether_packet *e;
	PACKET packet;
	ADDRESS4 addr;

	debug("cast_ip4");

	/*
	 *  copy relay header
	 */
	memcpy(&packet, buf, sizeof(PACKET));
	buf += sizeof(PACKET);
	len -= sizeof(PACKET);

	/*
	 *  copy address header
	 */
	memcpy(&addr, buf, sizeof(ADDRESS4));
	buf += sizeof(ADDRESS4);
	len -= sizeof(ADDRESS4);

	/*
	 *  make ip header
	 */
	buf -= sizeof(struct ip_packet);
	len += sizeof(struct ip_packet);
	ip = (struct ip_packet *)buf;
	memset(ip, 0, sizeof(struct ip_packet));
	ip->version  = 0x45;
	ip->len      = htons(len);
	ip->id       = packet.random;
	ip->ttl      = od->caster_ttl;
	ip->proto    = IPPROTO_UDP;
	ip->src_ip4  = addr.src_ip4;
	ip->dst_ip4  = addr.dst_ip4;
	ip->checksum = calc_checksum((uint8_t *)ip, sizeof(struct ip_packet));

	/*
	 *  make ether header
	 */
	buf -= sizeof(struct ether_packet);
	len += sizeof(struct ether_packet);
	e = (struct ether_packet *)buf;
	memcpy(e->src_mac, od->mac, ETHER_ADDR_LEN);
	make_ipv4_mcast_mac(e->dst_mac, ip->dst_ip4);
	e->ether_type = htons(ETH_P_IP);

	/*
	 *  send raw packet
	 */
	debug_packet("caster IPv4 send", buf, len);
	while (od->terminate == 0) {
		if (send(od->raw_out, buf, len, 0) > 0) {
			inc_sent(od);
			break;
		}
		if (errno == EINTR || errno == EAGAIN)
			continue;

		inc_error(od);
		break;
	}
}

static void
make_ipv6_mcast_mac(uint8_t *mac, uint128_t ip6)
{
	ip6_t n = ntohq(ip6);

	memset(mac, 0, ETHER_ADDR_LEN);
	mac[0] = 0x33;
	mac[1] = 0x33;
	mac[2] = (n >> 24) & 0xff;
	mac[3] = (n >> 16) & 0xff;
	mac[4] = (n >> 8)  & 0xff;
	mac[5] = n & 0xff;
}

static void
cast_ip6(OD* od, uint8_t *buf, int len)
{
	struct ip6_packet *ip6;
	struct ether_packet *e;
	PACKET packet;
	ADDRESS6 addr;

	debug("cast_ip6");

	/*
	 *  copy relay header
	 */
	memcpy(&packet, buf, sizeof(PACKET));
	buf += sizeof(PACKET);
	len -= sizeof(PACKET);

	/*
	 *  copy address header
	 */
	memcpy(&addr, buf, sizeof(ADDRESS6));
	buf += sizeof(ADDRESS6);
	len -= sizeof(ADDRESS6);

	/*
	 *  make ip header
	 */
	buf -= sizeof(struct ip6_packet);
	len += sizeof(struct ip6_packet);
	ip6 = (struct ip6_packet *)buf;
	memset(ip6, 0, sizeof(struct ip6_packet));
	ip6->version  = 0x60;
	ip6->len      = htons(len - sizeof(struct ip6_packet));
	ip6->proto    = IPPROTO_UDP;
	ip6->ttl      = od->caster_ttl;
	ip6->src_ip6  = addr.src_ip6;
	ip6->dst_ip6  = addr.dst_ip6;

	/*
	 *  make ether header
	 */
	buf -= sizeof(struct ether_packet);
	len += sizeof(struct ether_packet);
	e = (struct ether_packet *)buf;
	memcpy(e->src_mac, od->mac, ETHER_ADDR_LEN);
	make_ipv6_mcast_mac(e->dst_mac, ip6->dst_ip6);
	e->ether_type = htons(ETH_P_IPV6);

	/*
	 *  send raw packet
	 */
	debug_packet("caster IPv6 send", buf, len);
	while (od->terminate == 0) {
		if (send(od->raw_out, buf, len, 0) > 0) {
			inc_sent(od);
			break;
		}
		if (errno == EINTR || errno == EAGAIN)
			continue;

		debug("send raw packet failed: %s", strerror(errno));
		inc_error(od);
		break;
	}
}

void
caster(OD *od)
{
	uint8_t packet[MAX_PACKET_SIZE];
	int offset = sizeof(struct ether_packet) + sizeof(struct ip6_packet);

	setproctitle("octopi-caster");
	logging_init("octopi-caster", od->log_facility);

	while (od->terminate == 0) {
		uint8_t *buf = packet + offset;
		int bufsize  = MAX_PACKET_SIZE - offset;
		int len;

		/*
		 *  receive packet
		 */
		len = recv(od->udp_in, buf, bufsize, 0);
		if (len <= 0)
			continue;
		inc_recv(od);
		debug_packet("caster receive", buf, len);

		/*
		 *  error: truncated packet
		 */
		if (len > bufsize) {
			inc_error(od);
			continue;
		}

		/*
		 *  drop: non-octopi packet
		 */
		if (buf[0] != OCTOPI_MAGIC) {
			inc_drop(od);
			continue;
		}

		/*
		 *  drop: timeouted packet
		 */
		if (check_timeout_packet(od, buf, len) == FALSE) {
			inc_drop(od);
			continue;
		}

		/*
		 *  drop: invalid secret packet
		 */
		if (check_secret(od, buf, len) == FALSE) {
			inc_drop(od);
			continue;
		}

		/*
		 *  broadcast packet
		 */
		switch (buf[1]) {
		case OCTOPI_PROTO_IP4:
			cast_ip4(od, buf, len);
			break;
		case OCTOPI_PROTO_IP6:
			cast_ip6(od, buf, len);
			break;
		}
	}

	exit(EXIT_SUCCESS);
}
