/*
 *  dispatcher.c
 *
 *  copyright (c) 2019-2021 HANATAKA Shinya
 *  copyright (c) 2019-2021 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>

#include "octopi.h"
#include "packet.h"
#include "logging.h"
#include "addrutil.h"
#include "lpm.h"
#include "setproctitle.h"
#include "md5.h"

enum {
	ACT_DROP   = 0,
	ACT_SWITCH = 1,
	ACT_FLOOD  = 2,
	ACT_NEXT   = 3,
};

static void
init_random()
{
	struct timeval tv;
	pid_t pid;

	pid = getpid();
	gettimeofday(&tv, NULL);
	srandom((pid << 3 | tv.tv_sec | tv.tv_usec));
}

static int
analyze_inner_arp(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct arp_packet *h = (struct arp_packet *) buf;
	int op;

	debug("analyze_inner_arp");

	/*
	 *  store packet protocol
	 */
	p->inner_af = AF_INET;

	/*
	 *  check packet length
	 */
	if (len < sizeof (struct arp_packet))
		return ACT_DROP;

	/*
	 *  check packet header
	 */
	if (ntohs(h->ha_type) != ARPHRD_ETHER)
		return ACT_DROP;
	if (ntohs(h->pa_type) != ETH_P_IP)
		return ACT_DROP;
	if (h->ha_len != ETHER_ADDR_LEN)
		return ACT_DROP;
	if (h->pa_len != IP4_ADDR_LEN)
		return ACT_DROP;

	/*
	 *  check operation
	 */
	op = ntohs(h->operation);
	if (op != ARPOP_REQUEST && op != ARPOP_REPLY)
		return ACT_FLOOD;

	/*
	 *  check Duplicate Address Detection
	 */
	if (op == ARPOP_REQUEST && h->sender_pa == 0)
		return ACT_FLOOD;

	/*
	 *  check Gratuitous ARP
	 */
	if (h->sender_pa == h->target_pa)
		return ACT_FLOOD;

	/*
	 *  check operation
	 */
	if (op != ARPOP_REQUEST)
		return ACT_DROP;

	/*
	 *  store relay address
	 */
	p->relay_ip4 = h->target_pa;

	return ACT_SWITCH;
}

static int
analyze_inner_icmp6(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ip6_packet *ip6h = (struct ip6_packet *) buf;
	struct icmp6_packet *h;
	uint128_t src = ip6h->src_ip6;
	uint128_t dst = ip6h->dst_ip6;
	ADDR mcast;

	debug("analyze_inner_icmp6");

	/*
	 *  check packet length
	 */
	buf += sizeof(struct ip6_packet);
	len -= sizeof(struct ip6_packet);
	if (len < sizeof(struct icmp6_packet))
		return ACT_NEXT;
	h = (struct icmp6_packet *) buf;

	/*
	 *  check ICMPv6 header
	 */
	if (h->type != ND_NEIGHBOR_SOLICIT && h->type != ND_NEIGHBOR_ADVERT)
		return ACT_NEXT;
	if (h->code != 0)
		return ACT_NEXT;

	/*
	 *  check Unsolicited Advertisement
	 */
	memset(&mcast, 0, sizeof(ADDR));
	mcast.af   = AF_INET6;
	mcast.mask = 8;
	mcast.addr32[0] = 0xff000000;
	if (h->type == ND_NEIGHBOR_ADVERT
	    && (h->flags & ICMP6_NA_SOLICITED) == 0
	    && (dst == 0 || check_cidr_ipv6(ntohq(dst), &mcast) == TRUE))
		return ACT_FLOOD;

	/*
	 *  check Duplicate Address Detection
	 */
	if (h->type == ND_NEIGHBOR_SOLICIT && src == 0)
		return ACT_FLOOD;

	/*
	 *  check Solicitation
	 */
	if (h->type != ND_NEIGHBOR_SOLICIT)
		return ACT_NEXT;

	/*
	 *  store relay address
	 */
	p->relay_ip6 = h->target;

	return ACT_SWITCH;
}

static int
analyze_inner_ip4(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ip_packet *h = (struct ip_packet *) buf;

	debug("analyze_inner_ip4");

	/*
	 *  store packet protocol
	 */
	p->inner_af = AF_INET;

	/*
	 *  check packet length
	 */
	if (len < sizeof (struct ip_packet))
		return ACT_DROP;

	/*
	 *  check IP version
	 */
	if ((h->version >> 4) != 4)
		return ACT_DROP;

	/*
	 *  store relay address
	 */
	p->relay_ip4 = h->dst_ip4;

	return ACT_SWITCH;
}

static int
analyze_inner_ip6(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ip6_packet *h = (struct ip6_packet *) buf;

	debug("analyze_inner_ip6");

	/*
	 *  store pakcet protocol
	 */
	p->inner_af = AF_INET6;

	/*
	 *  check packet length
	 */
	if (len < sizeof (struct ip6_packet))
		return ACT_DROP;

	/*
	 *  check IP version
	 */
	if ((h->version >> 4) != 6)
		return ACT_DROP;

	/*
	 *  check ICMPv6
	 */
	if (h->proto == IPPROTO_ICMPV6) {
		int act = analyze_inner_icmp6(od, buf, len, p);
		if (act != ACT_NEXT)
			return act;
	}

	/*
	 *  store relay address
	 */
	p->relay_ip6 = h->dst_ip6;

	return ACT_SWITCH;
}

static int
analyze_inner_ether(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ether_packet *h = (struct ether_packet *) buf;

	debug("analyze_inner_ether");

	/*
	 *  check packet length
	 */
	if (len < sizeof(struct ether_packet))
		return ACT_DROP;

	/*
	 *  check inner ether type
	 */
	buf += sizeof(struct ether_packet);
	len -= sizeof(struct ether_packet);
	if (ntohs(h->ether_type) == ETH_P_ARP)
		return analyze_inner_arp(od, buf, len, p);
	else if (ntohs(h->ether_type) == ETH_P_IP)
		return analyze_inner_ip4(od, buf, len, p);
	else if (ntohs(h->ether_type) == ETH_P_IPV6)
		return analyze_inner_ip6(od, buf, len, p);

	return ACT_DROP;
}

static int
analyze_vxlan(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct udp_vxlan *h = (struct udp_vxlan *) buf;

	debug("analyze_vxlan");

	/*
	 *  check packet length
	 */
	if (len < sizeof(struct udp_vxlan))
		return ACT_DROP;

	/*
	 *  check destination port
	 */
	if (ntohs(h->dst_port) != od->vxlan_port)
		return ACT_DROP;

	/*
	 *  check vxlan flag
	 */
	if ((h->vxlan_flags & VXLAN_FLAG) != VXLAN_FLAG)
		return ACT_DROP;

	/*
	 *  store VxLAN ID
	 */
	p->vni = ntohl(h->vni) >> 8;

	/*
	 *  store payload data
	 */
	p->data     = buf;
	p->data_len = len;

	/*
	 *  check inner ether packet
	 */
	buf += sizeof(struct udp_vxlan);
	len -= sizeof(struct udp_vxlan);
	return analyze_inner_ether(od, buf, len, p);
}

static int
analyze_outer_ip4(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ip_packet *h = (struct ip_packet*) buf;

	debug("analyze_outer_ip4");

	/*
	 *  store encapsule protocol
	 */
	p->outer_af = AF_INET;

	/*
	 *  check packet length
	 */
	if (len < sizeof(struct ip_packet))
		return ACT_DROP;

	/*
	 *  check IP version
	 */
	if ((h->version >> 4) != 4)
		return ACT_DROP;

	/*
	 *  check TTL
	 */
	if (h->ttl <= od->caster_ttl)
		return ACT_DROP;

	/*
	 *  check protocol
	 */
	if (h->proto != IPPROTO_UDP)
		return ACT_DROP;

	/*
	 *  check destination IP address
	 */
	if (check_cidr_ipv4(ntohl(h->dst_ip4), od->multicast) == FALSE)
		return ACT_DROP;

	/*
	 *  store src/dst IP address
	 */
	p->src_ip4 = h->src_ip4;
	p->dst_ip4 = h->dst_ip4;

	/*
	 *  check UDP and VxLAN header
	 */
	buf += (h->version & 0xf) * 4;
	len -= (h->version & 0xf) * 4;

	return analyze_vxlan(od, buf, len, p);
}

static int
analyze_outer_ip6(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ip6_packet *h = (struct ip6_packet*) buf;

	debug("analyze_outer_ip6");

	/*
	 *  store encapsule protocol
	 */
	p->outer_af = AF_INET6;

	/*
	 *  check packet length
	 */
	if (len < sizeof(struct ip6_packet))
		return ACT_DROP;

	/*
	 *  check IP version
	 */
	if ((h->version >> 4) != 6)
		return ACT_DROP;

	/*
	 *  check TTL
	 */
	if (h->ttl <= od->caster_ttl)
		return ACT_DROP;

	/*
	 *  check protocol
	 */
	if (h->proto != IPPROTO_UDP)
		return ACT_DROP;

	/*
	 *  check destination IPv6 address
	 */
	if (check_cidr_ipv6(ntohq(h->dst_ip6), od->multicast) == FALSE)
		return ACT_DROP;

	/*
	 *  store src/dst IPv6 address
	 */
	p->src_ip6 = h->src_ip6;
	p->dst_ip6 = h->dst_ip6;

	/*
	 *  check UDP and VxLAN header
	 */
	buf += sizeof(struct ip6_packet);
	len -= sizeof(struct ip6_packet);

	return analyze_vxlan(od, buf, len, p);
}

static int
analyze_packet(OD *od, uint8_t *buf, int len, PAYLOAD *p)
{
	struct ether_packet *h = (struct ether_packet *)buf;

	debug("analyze_packet");

	/*
	 *  check pakcet size
	 */
	if (len < sizeof(struct ether_packet))
		return ACT_DROP;

	/*
	 *  store site config
	 */
	p->site_begin = h->site_begin;
	p->site_end   = h->site_end;

	/*
	 *  check Outer Ether Type
	 */
	buf += sizeof(struct ether_packet);
	len -= sizeof(struct ether_packet);
	if (ntohs(h->ether_type) == ETH_P_IP) {
		return analyze_outer_ip4(od, buf, len, p);
	} else if (ntohs(h->ether_type) == ETH_P_IPV6) {
		return analyze_outer_ip6(od, buf, len, p);
	}

	/*
	 *  drop: outer protocol is not IPv4/IPv6
	 */
	return ACT_DROP;
}

static void
construct_packet(OD *od, PAYLOAD *p)
{
        struct timeval tv;
	PACKET *h;
	uint8_t proto;

	/*
	 *  set address
	 */
	if (p->outer_af == AF_INET) {
		ADDRESS4 *a;

		p->buf = p->data - sizeof(ADDRESS4);
		p->buf_len = p->data_len + sizeof(ADDRESS4);
		proto = OCTOPI_PROTO_IP4;

		a = (ADDRESS4 *) p->buf;
		a->src_ip4 = p->src_ip4;
		a->dst_ip4 = p->dst_ip4;
	} else {
		ADDRESS6 *a;

		p->buf = p->data - sizeof(ADDRESS6);
		p->buf_len = p->data_len + sizeof(ADDRESS6);
		proto = OCTOPI_PROTO_IP6;

		a = (ADDRESS6 *) p->buf;
		a->src_ip6 = p->src_ip6;
		a->dst_ip6 = p->dst_ip6;
	}

	/*
	 *  setup buffer
	 */
	p->buf     -= sizeof(PACKET);
	p->buf_len += sizeof(PACKET);
	memset(p->buf, 0, sizeof(PACKET));

	/*
	 *  set header
	 */
	h = (PACKET *) p->buf;
	h->octopi_magic = OCTOPI_MAGIC;
	h->octopi_proto = proto;
	h->random = (random() >> 5) & 0xffff;

	/*
	 *  set site config
	 */
	h->site_end   = p->site_end;
	h->site_begin = p->site_begin;

	/*
	 *  set timestamp
	 */
	if (od->timeout) {
		gettimeofday(&tv, NULL);
		h->time_sec = htonl(tv.tv_sec);
		h->time_msec = htons(tv.tv_usec / 1000);
	}

	 /*
	 *  set secret
	 */
	if (od->secret) {
		uint8_t digest[SECRET_LEN];
		strncpy((char*)h->secret, od->secret, SECRET_LEN);
		md5_sum(p->buf, p->buf_len, digest);
		memcpy(h->secret, digest, SECRET_LEN);
	}
}

static int
ipv4_destination(OD *od, ADDR *r, struct sockaddr_in *s)
{
	if (r->af != AF_INET)
		return 0;

	if (r->ipv4_addr == od->address->ipv4_addr)
		return 0;

	memset(s, 0, sizeof(struct sockaddr_in));
	s->sin_family = AF_INET;
	s->sin_port = htons(od->relay_port);
	s->sin_addr.s_addr = htonl(r->ipv4_addr);

	return sizeof(struct sockaddr_in);
}

static int
ipv6_destination(OD *od, ADDR *r, struct sockaddr_in6 *s)
{
	if (r->af != AF_INET6)
		return 0;

	if (r->ipv6_addr == od->address->ipv6_addr)
		return 0;

	memset(s, 0, sizeof(struct sockaddr_in6));
	s->sin6_family = AF_INET6;
	s->sin6_port = htons(od->relay_port);
	s->sin6_addr.s6_addr32[0]= htonl(r->addr32[3]);
	s->sin6_addr.s6_addr32[1]= htonl(r->addr32[2]);
	s->sin6_addr.s6_addr32[2]= htonl(r->addr32[1]);
	s->sin6_addr.s6_addr32[3]= htonl(r->addr32[0]);

	return sizeof(struct sockaddr_in6);
}

static void
relay_packet(OD *od, PAYLOAD *p, npos_t n)
{
	int packet_constructed = 0;
	ADDR relay;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *dest;
	socklen_t dest_len;

	while (n) {
		/*
		 *  get next relay target
		 */
		if (LPM_get_next_relay(&n, &relay) == LPM_FAIL)
			break;

		/*
		 *  make socket address
		 */
		if (od->address->af == AF_INET) {
			dest = (struct sockaddr*)&sin;
			dest_len = ipv4_destination(od, &relay, &sin);
			if (dest_len == 0)
				continue;
		} else if (od->address->af == AF_INET6) {
			dest = (struct sockaddr*)&sin6;
			dest_len = ipv6_destination(od, &relay, &sin6);
			if (dest_len == 0)
				continue;
		} else {
			continue;
		}

		/*
		 *  construct packet
		 */
		if (packet_constructed == 0) {
			construct_packet(od, p);
			packet_constructed = 1;
			debug_packet("dispatcher send", p->buf, p->buf_len);
		}

		/*
		 *  send packet
		 */
		if (logging_debug) {
			char str[IP_STR_LEN];
			if (addr_to_str(&relay, str) == TRUE)
				debug("relay to: %s", str);
		}
		while (od->terminate == 0) {
			if (sendto(od->udp_out, p->buf, p->buf_len,
				   0, dest, dest_len) > 0) {
				inc_sent(od);
				break;
			}
			if (errno == EINTR || errno == EAGAIN)
				continue;

			inc_error(od);
			break;
		}
	}
}

static void
switch_packet(OD *od, PAYLOAD *p)
{
	npos_t n = 0;

	if (p->inner_af == AF_INET) {
		n = LPM_find_urelay_ip4(p->vni, ntohl(p->relay_ip4));
	} else if (p->inner_af == AF_INET6) {
		n = LPM_find_urelay_ip6(p->vni, ntohq(p->relay_ip6));
	}

	if (n == 0) {
		inc_drop(od);
		return;
	}

	relay_packet(od, p, n);
}

static void
flood_packet(OD *od, PAYLOAD *p)
{
	npos_t n = 0;

	if (p->inner_af == AF_INET)
		n = LPM_find_mrelay_ip4(p->vni);
	else if (p->inner_af == AF_INET6)
		n = LPM_find_mrelay_ip6(p->vni);

	if (n == 0) {
		inc_drop(od);
		return;
	}

	relay_packet(od, p, n);
}

void
dispatcher(OD *od)
{
	uint8_t packet[MAX_PACKET_SIZE];
	PAYLOAD payload;
	int offset = sizeof(PACKET) + sizeof(ADDRESS6);

	setproctitle("octopi-dispatcher");
	logging_init("octopi-dispatcher", od->log_facility);

	init_random();

	while (od->terminate == 0) {
		uint8_t *buf = packet + offset;
		int bufsize  = MAX_PACKET_SIZE - offset;
		int len;
		int act;

		/*
		 *  receive packet
		 */
		len = recv(od->unix_in, buf, bufsize, 0);
		if (len <= 0)
			continue;
		inc_recv(od);
		debug_packet("dispatcher receive", buf, len);

		/*
		 *  error: truncated packet
		 */
		if (len > bufsize) {
			inc_error(od);
			continue;
		}

		/*
		 *  check rule pause
		 */
		if (LPM_check_pause() != LPM_OK)
			continue;

		/*
		 *  find destination
		 */
		memset(&payload, 0, sizeof(PAYLOAD));
		act = analyze_packet(od, buf, len, &payload);
		debug("dispatch action %d", act);

		/*
		 *  dispacth
		 */
		if (act == ACT_SWITCH)
			switch_packet(od, &payload);
		else if (act == ACT_FLOOD)
			flood_packet(od, &payload);
		else if (act == ACT_DROP)
			inc_drop(od);
	}

	exit(EXIT_SUCCESS);
}
