/*
 *  que_dump.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "lpm.h"
#include "que.h"
#include "que_internal.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

void
QUE_dump_header(IOBUF *buf)
{
	zprintf(buf, "magic:\t\t%016lx\n",  q_header->magic);
	zprintf(buf, "version:\t%016lx\n",  q_header->version);
	zprintf(buf, "node_size:\t%u\n",    q_header->node_size);
	zprintf(buf, "qpos_size:\t%u\n",    q_header->qpos_size);
	zprintf(buf, "header_size:\t%u\n",  q_header->header_size);
	zprintf(buf, "pool_size:\t%u\n",    q_header->pool_size);
	zprintf(buf, "hash_size:\t%u\n",    q_header->hash_size);
	zprintf(buf, "file_size:\t%u\n",    q_header->file_size);
	zprintf(buf, "pool_head:\t%u\n",    q_header->pool_head);
	zprintf(buf, "pool_tail:\t%u\n",    q_header->pool_tail);
}

void
QUE_count_node(IOBUF *buf)
{
	uint32_t backup = 1;
	uint32_t relay  = 0;
	uint32_t member = 0;
	uint32_t queue  = 0;
	uint32_t free   = 0;
	uint32_t i;
	qpos_t h;
	qpos_t q;
	qpos_t n;

	for (i = 0; i < q_header->hash_size; ++ i) {
		for (h = q_hash[i]; h; h = LINK(h)) {
			if (TYPE(h) == QUE_TYPE_RELAY) {
				relay ++;
			} else if (TYPE(h) == QUE_TYPE_MEMBER) {
				member ++;
				for (q = QUEUE(h); q; q = QUEUE(q))
					queue ++;
			}
		}
	}

	for (n = q_header->pool_head; n; n = NEXT(n))
		free ++;

	zprintf(buf, "\n");
	zprintf(buf, "backup:\t\t%u\n",  backup);
	zprintf(buf, "relay:\t\t%u\n",   relay);
	zprintf(buf, "member:\t\t%u\n",  member);
	zprintf(buf, "queue:\t\t%u\n",   queue);
	zprintf(buf, "free:\t\t%u\n",    free);
	zprintf(buf, "total:\t\t%u\n",
		backup + relay + member + queue + free);
}

static void
show_mark(IOBUF *buf, qpos_t n)
{
	if (MARK(n))
		zprintf(buf, " mark=%02x", MARK(n));
}

static void
show_proto(IOBUF *buf, qpos_t n)
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
show_addr(IOBUF *buf, qpos_t n)
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
show_vni(IOBUF *buf, qpos_t n)
{
	LPM_disp_vni(buf, " vni=%s", VNI(n));
}

static void
show_link(IOBUF *buf, qpos_t n)
{
	if (LINK(n))
		zprintf(buf, " link=%d", LINK(n));
}

static void
show_relay(IOBUF *buf, qpos_t n)
{
	zprintf(buf, " relay=%d", RELAY(n));
}

static void
show_member(IOBUF *buf, qpos_t n)
{
	if (MEMBER(n))
		zprintf(buf, " member=%d", MEMBER(n));
}

static void
show_queue(IOBUF *buf, qpos_t n)
{
	if (QUEUE(n))
		zprintf(buf, " queue=%d", QUEUE(n));
}

static void
show_next(IOBUF *buf, qpos_t n)
{
	if (NEXT(n))
		zprintf(buf, " next=%d", NEXT(n));
	if (n == q_header->pool_head)
		zprintf(buf, " pool_head");
	if (n == q_header->pool_tail)
		zprintf(buf, " next=%d pool_tail", NEXT(n));
}

static void
show_date(IOBUF *buf, char* fmt, uint64_t t)
{
	char timebuf[32];
	struct tm *tm = localtime((time_t *) &t);

	strftime(timebuf, 32, "%Y%m%d%H%M%S", tm);
	zprintf(buf, fmt, timebuf);
}

static void
show_update(IOBUF *buf, qpos_t n)
{
	zprintf(buf, " update=%u", UPDATE(n));
}

static void
show_sync(IOBUF *buf, qpos_t n)
{
	zprintf(buf, " sync=%u", SYNC(n));
}

static void
show_update_date(IOBUF *buf, qpos_t n)
{
	show_date(buf, " update:%s", UPDATE_TIME(n));
}

static void
show_insert_date(IOBUF *buf, qpos_t n)
{
	show_date(buf, " insert:%s", INSERT_TIME(n));
}

static void
show_action(IOBUF *buf, qpos_t n)
{
	if (ACTION(n))
		zprintf(buf, " action=%u", ACTION(n));
}

void
QUE_dump_all(IOBUF *buf)
{
	uint32_t i;

	zprintf(buf, "\n");
	for (i = 0; i < q_header->pool_size; ++ i) {
		zprintf(buf, "%d", i);

		switch (TYPE(i)) {
		case QUE_TYPE_NONE:
			zprintf(buf, " none");
			show_mark(buf, i);
			show_next(buf, i);
			break;
		case QUE_TYPE_BACKUP:
			zprintf(buf, " backup");
			show_mark(buf, i);
			show_member(buf, i);
			show_next(buf, i);
			show_insert_date(buf, i);
			show_update_date(buf, i);
			break;
		case QUE_TYPE_RELAY:
			zprintf(buf, " relay");
			show_mark(buf, i);
			show_proto(buf, i);
			show_addr(buf, i);
			show_link(buf, i);
			show_member(buf, i);
			show_next(buf, i);
			show_insert_date(buf, i);
			show_update_date(buf, i);
			break;
		case QUE_TYPE_MEMBER:
			zprintf(buf, " member");
			show_mark(buf, i);
			show_proto(buf, i);
			show_addr(buf, i);
			show_update(buf, i);
			show_sync(buf, i);
			show_link(buf, i);
			show_relay(buf, i);
			show_member(buf, i);
			show_queue(buf, i);
			show_action(buf, i);
			show_next(buf, i);
			show_insert_date(buf, i);
			show_update_date(buf, i);
			break;
		case QUE_TYPE_QUEUE:
			zprintf(buf, " queue");
			show_mark(buf, i);
			show_vni(buf, i);
			show_proto(buf, i);
			show_update(buf, i);
			show_queue(buf, i);
			show_next(buf, i);
			show_insert_date(buf, i);
			show_update_date(buf, i);
			break;
		default:
			zprintf(buf, " unknown");
			show_mark(buf, i);
			show_next(buf, i);
		}
		zprintf(buf, "\n");
	}
}
