/*
 *  lpm_dump.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "addrutil.h"
#include "lpm.h"
#include "lpm_internal.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

void
LPM_dump_header(IOBUF *buf)
{
	zprintf(buf, "magic:\t\t%016lx\n",  header->magic);
	zprintf(buf, "version:\t%016lx\n",  header->version);
	zprintf(buf, "node_size:\t%u\n",    header->node_size);
	zprintf(buf, "npos_size:\t%u\n",    header->npos_size);
	zprintf(buf, "header_size:\t%u\n",  header->header_size);
	zprintf(buf, "pool_size:\t%u\n",    header->pool_size);
	zprintf(buf, "hash_size:\t%u\n",    header->hash_size);
	zprintf(buf, "file_size:\t%u\n",    header->file_size);
	zprintf(buf, "pool_head:\t%u\n",    header->pool_head);
	zprintf(buf, "pool_tail:\t%u\n",    header->pool_tail);
	zprintf(buf, "pause:\t\t%u\n",      header->pause);
	zprintf(buf, "queue_sync:\t%u\n",   header->queue_sync);
}

static uint32_t
LPM_count_tree(npos_t n, uint32_t *relay)
{
	uint32_t node = 1;
	npos_t r;

	for (r = RELAY(n); r; r = RELAY(r))
		(*relay) ++;

	if (CHILD(n, 0))
		node += LPM_count_tree(CHILD(n, 0), relay);
	if (CHILD(n, 1))
		node += LPM_count_tree(CHILD(n, 1), relay);

	return node;
}

void
LPM_count_node(IOBUF *buf)
{
	uint32_t base  = 1;
	uint32_t root  = 0;
	uint32_t node  = 0;
	uint32_t relay = 0;
	uint32_t free  = 0;
	uint32_t i;
	npos_t h;
	npos_t n;
	npos_t r;

	for (i = 0; i < header->hash_size; ++ i) {
		for (h = hash[i]; h; h = CHILD(h, 1)) {
			root ++;
			for (r = RELAY(h); r; r = RELAY(r))
				relay ++;
			node  += LPM_count_tree(CHILD(h, 0), &relay);
		}
	}

	for (n = header->pool_head; n; n = NEXT(n))
		free ++;

	zprintf(buf, "\n");
	zprintf(buf, "base:\t\t%u\n",    base);
	zprintf(buf, "root:\t\t%u\n",    root);
	zprintf(buf, "node:\t\t%u\n",    node);
	zprintf(buf, "relay:\t\t%u\n",   relay);
	zprintf(buf, "free:\t\t%u\n",    free);
	zprintf(buf, "total:\t\t%u\n",   base + root + node + relay + free);
}

static void
show_mark(IOBUF *buf, npos_t n)
{
	if (MARK(n))
		zprintf(buf, " mark=%02x", MARK(n));
}

static void
show_proto(IOBUF *buf, npos_t n)
{
	switch (PROTO(n)) {
	case PROTO_NONE:
		zprintf(buf, " none");
		break;
	case PROTO_IP4:
		zprintf(buf, " ipv4");
		break;
	case PROTO_IP6:
		zprintf(buf, " ipv6");
		break;
	case PROTO_ALL:
		zprintf(buf, " all");
		break;
	default:
		zprintf(buf, " unknown");
	}
}

static void
show_addr(IOBUF *buf, npos_t n)
{
	ADDR addr;
	char addrbuf[IP_STR_LEN];

	switch (PROTO(n)) {
	case PROTO_IP4:
		addr.af = AF_INET;
		addr.ipv4_addr = V4ADDR(n);
		if (addr_to_str(&addr, addrbuf) == TRUE) {
			zprintf(buf, " addr=%s", addrbuf);
		} else {
			zprintf(buf, " addr=unknown");
		}
		break;
	case PROTO_IP6:
		addr.af = AF_INET6;
		addr.ipv6_addr = V6ADDR(n);
		if (addr_to_str(&addr, addrbuf) == TRUE) {
			zprintf(buf, " addr=%s", addrbuf);
		} else {
			zprintf(buf, " addr=unknown");
		}
		break;
	}
}

static void
show_mask(IOBUF *buf, npos_t n)
{
	zprintf(buf, "/%d", MASK(n));
}

static void
show_forkbit(IOBUF *buf, npos_t n)
{
	zprintf(buf, " fork=%d", FORKBIT(n));
}

static void
show_vni(IOBUF *buf, npos_t n)
{
	LPM_disp_vni(buf, " vni=%s", VNI(n));
}

static void
show_relay(IOBUF *buf, npos_t n)
{
	if (RELAY(n))
		zprintf(buf, " relay=%d", RELAY(n));
}

static void
show_child(IOBUF *buf, npos_t n)
{
	zprintf(buf, " child=%d,%d", CHILD(n,0), CHILD(n,1));
}

static void
show_next(IOBUF *buf, npos_t n)
{
	if (NEXT(n))
		zprintf(buf, " next=%d", NEXT(n));
	if (n == header->pool_head)
		zprintf(buf, " pool_head");
	if (n == header->pool_tail)
		zprintf(buf, " next=0 pool_tail");
}

void
LPM_dump_all(IOBUF *buf)
{
	uint32_t i;

	zprintf(buf, "\n");
	for (i = 0; i < header->pool_size; ++ i) {
		printf("%d", i);

		switch (TYPE(i)) {
		case LPM_TYPE_BASE:
			zprintf(buf, " base");
			show_mark(buf, i);
			show_child(buf, i);
			show_next(buf, i);
			break;
		case LPM_TYPE_NONE:
			zprintf(buf, " none");
			show_mark(buf, i);
			show_next(buf, i);
			break;
		case LPM_TYPE_ROOT:
			zprintf(buf, " root");
			show_vni(buf, VNI(i));
			show_mark(buf, i);
			show_proto(buf, i);
			show_relay(buf, i);
			show_child(buf, i);
			show_next(buf, i);
			break;
		case LPM_TYPE_NODE:
			zprintf(buf, " node");
			show_mark(buf, i);
			show_proto(buf, i);
			show_addr(buf, i);
			show_mask(buf, i);
			show_forkbit(buf, i);
			show_relay(buf, i);
			show_child(buf, i);
			show_next(buf, i);
			break;
		case LPM_TYPE_RELAY:
			zprintf(buf, " relay");
			show_mark(buf, i);
			show_proto(buf, i);
			show_addr(buf, i);
			show_relay(buf, i);
			show_next(buf, i);
			break;
		default:
			zprintf(buf, " unknown");
			show_mark(buf, i);
			show_next(buf, i);
		}
		zprintf(buf, "\n");
	}
}
