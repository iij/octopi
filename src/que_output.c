/*
 *  que_output.c
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "lpm.h"
#include "que.h"
#include "que_internal.h"

enum {
	FALSE = 0,
	TRUE  = 1,
};

static void
QUE_disp_date(IOBUF *buf, char *fmt, uint64_t t)
{
	char date[32];

	struct tm *tm = localtime((time_t *) &t);
	strftime(date, 32, "%Y-%m-%d %H:%M:%S", tm);
	zprintf(buf, fmt, date);
}

static void
QUE_disp_address(IOBUF *buf, char *fmt, qpos_t n)
{
	char addrbuf[IP_STR_LEN];
	char *addr = addrbuf;

	if (PROTO(n) == PROTO_IP4) {
		if (ip4_to_str(&V4ADDR(n), addrbuf) == FALSE)
			addr = "unknown";
	} else if (PROTO(n) == PROTO_IP6) {
		if (ip6_to_str(&V6ADDR(n), addrbuf) == FALSE)
			addr = "unknown6";
	} else {
		addr =  "unknown";
	}

	zprintf(buf, fmt, addr);
}

static void
QUE_member_list(IOBUF *buf, char *name, qpos_t relay)
{
	qpos_t mem;

	if (relay == BACKUP_NODE) {
		zprintf(buf, "%s backup add", name);
	} else  {
		zprintf(buf, "%s node add ", name);
		QUE_disp_address(buf, "%s", relay);
	}
	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		QUE_disp_address(buf, " %s", mem);
	}
	zprintf(buf, "\n");
}

static void
QUE_member_list_all(IOBUF *buf, char *name)
{
	uint32_t i;
	qpos_t relay;

	for (i = 0; i < q_header->hash_size; ++ i) {
		for (relay = q_hash[i]; relay; relay = LINK(relay)) {
			if (TYPE(relay) == QUE_TYPE_RELAY)
				QUE_member_list(buf, name, relay);
		}
	}
}

void
QUE_node_list(IOBUF *buf, char *name, ADDR *r)
{
	qpos_t relay;

	if (r == NULL) {
		QUE_member_list_all(buf, name);
		return;
	}

	relay = QUE_find_relay(r);
	if (relay == 0)
		return;

	QUE_member_list(buf, name, relay);
}

void
QUE_backup_list(IOBUF *buf, char *name)
{
	if (MEMBER(BACKUP_NODE))
		QUE_member_list(buf, name, BACKUP_NODE);
}

static void
QUE_disp_update(IOBUF *buf, qpos_t n)
{
	zprintf(buf, "update=%u", UPDATE(n));
}

static void
QUE_disp_sync(IOBUF *buf, qpos_t n)
{
	zprintf(buf, "sync=%u", SYNC(n));
}

static void
QUE_disp_queue(IOBUF *buf, qpos_t mem)
{
	int show_addr = 0;
	qpos_t q;
	uint32_t sync = SYNC(mem);
	uint32_t action = ACTION(mem);

	for (q = QUEUE(mem); q; q = QUEUE(q)) {
		if (UPDATE(q) > sync) {
			if (show_addr == 0) {
				QUE_disp_date(buf, "%s\t", INSERT_TIME(mem));
				QUE_disp_address(buf, "%-16s\t", mem);
				show_addr = 1;
			}
			if (UPDATE(q) > action) {
				LPM_disp_vni(buf, " %s", VNI(q));
			} else {
				LPM_disp_vni(buf, " %s*", VNI(q));
			}
		}
	}
	if (show_addr) {
		zprintf(buf, "\n");
	}
}

static void
QUE_disp_member_queue(IOBUF *buf, ADDR *m)
{
	qpos_t h = QUE_calc_addr_hash(m);
	qpos_t mem;

	for (mem = q_hash[h]; mem; mem = LINK(mem)) {
		if (TYPE(mem) == QUE_TYPE_MEMBER && match_qaddr(mem, m)) {
			QUE_disp_queue(buf, mem);
		}
	}
}

static void
QUE_disp_relay_queue(IOBUF *buf, qpos_t relay)
{
	qpos_t mem;

	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		QUE_disp_queue(buf, mem);
	}
}

void
QUE_queue_list(IOBUF *buf, ADDR *r)
{
	qpos_t relay;

	if (r == NULL) {
		relay = BACKUP_NODE;
	} else {
		relay = QUE_find_relay(r);
		if (relay == 0) {
			QUE_disp_member_queue(buf, r);
			return;
		}
	}
	QUE_disp_relay_queue(buf, relay);
}

void
QUE_queue_list_all(IOBUF *buf)
{
	uint32_t i;

	QUE_disp_relay_queue(buf, BACKUP_NODE);
	for (i = 0; i < q_header->hash_size; ++ i) {
		qpos_t relay;
		for (relay = q_hash[i]; relay; relay = LINK(relay)) {
			if (TYPE(relay) == QUE_TYPE_RELAY)
				QUE_disp_relay_queue(buf, relay);
		}
	}
}

static void
QUE_show_queue(IOBUF *buf, int indent, qpos_t que)
{
	int i;

	/*
	 *  indent
	 */
	for (i = 0; i < indent; ++ i)
		zprintf(buf, " ");

	/*
	 *  show queue
	 */
	LPM_disp_vni(buf, "queue: %s  ", VNI(que));
	QUE_disp_update(buf, que);
	zprintf(buf, "\n");
}

static void
QUE_show_member(IOBUF *buf, int indent, qpos_t mem)
{
	qpos_t q;
	int i;

	/*
	 *  indent
	 */
	for (i = 0; i < indent; ++ i)
		zprintf(buf, " ");

	/*
	 *  show member
	 */
	QUE_disp_address(buf, "member: %s  ", mem);
	QUE_disp_update(buf, mem);
	zprintf(buf, "  ");
	QUE_disp_sync(buf, mem);
	if (ACTION(mem)) {
		zprintf(buf, "  in_action\n");
	} else {
		zprintf(buf, "\n");
	}

	/*
	 *  show queue
	 */
	for (q = QUEUE(mem); q; q = QUEUE(q))
		QUE_show_queue(buf, i + 2, q);
}

static void
QUE_show_relay(IOBUF *buf, qpos_t relay)
{
	qpos_t mem;

	/*
	 *  show relay
	 */
	if (relay == 0) {
		zprintf(buf, "backup:\n");
	} else {
		QUE_disp_address(buf, "relay: %s  ", relay);
		zprintf(buf, "\n");
	}

	/*
	 *  show member
	 */
	for (mem = MEMBER(relay); mem; mem = MEMBER(mem)) {
		QUE_show_member(buf, 2, mem);
	}
}

void
QUE_queue_show_member(IOBUF *buf, ADDR *m)
{
	qpos_t h = QUE_calc_addr_hash(m);
	qpos_t mem;

	for (mem = q_hash[h]; mem; mem = LINK(mem)) {
		if (TYPE(mem) == QUE_TYPE_MEMBER && match_qaddr(mem, m)) {
			QUE_show_member(buf, 0, mem);
		}
	}
}

void
QUE_queue_show(IOBUF *buf, ADDR *r)
{
	qpos_t relay;

	if (r == NULL) {
		relay = BACKUP_NODE;
	} else {
		relay = QUE_find_relay(r);
		if (relay == 0) {
			QUE_queue_show_member(buf, r);
			return;
		}
	}
	QUE_show_relay(buf, relay);
}

void
QUE_queue_show_all(IOBUF *buf)
{
	uint32_t i;

	QUE_show_relay(buf, BACKUP_NODE);
	for (i = 0; i < q_header->hash_size; ++ i) {
		qpos_t relay;
		for (relay = q_hash[i]; relay; relay = LINK(relay)) {
			if (TYPE(relay) == QUE_TYPE_RELAY)
				QUE_show_relay(buf, relay);
		}
	}
}

static void
QUE_make_data_vni(IOBUF *buf, vxid_t vni)
{
	LPM_disp_vni(buf, "rule %s\n", vni);
	LPM_save_root(buf, 0, vni, PROTO_IP4);
	LPM_save_root(buf, 0, vni, PROTO_IP6);
	zprintf(buf, "commit\n");
}

static void
QUE_make_data_all(IOBUF *buf, qpos_t mem)
{
        uint32_t count;
	uint64_t *list;
	uint32_t prev_vni = VNI_INVALID;
	uint32_t n;
	qpos_t relay = RELAY(mem);

	if (relay == 0) {
		count = LPM_listup_roots(PROTO_ALL, &list, NULL);
	} else {
		ADDR addr;
		if (PROTO(relay) == PROTO_IP4) {
			addr.af = AF_INET;
			addr.ipv4_addr = V4ADDR(relay);
		} else {
			addr.af = AF_INET6;
			addr.ipv6_addr = V6ADDR(relay);
		}
		count = LPM_listup_roots(PROTO_ALL, &list, &addr);
	}

	for (n = 0; n < count; ++ n) {
		uint32_t vni = list[n] >> 8;
		if (vni != prev_vni) {
			QUE_make_data_vni(buf, vni);
			prev_vni = vni;
		}
	}
	LPM_free_roots(list);
}

uint32_t
QUE_make_data(IOBUF *buf, qpos_t mem, int *all, int *count)
{
	uint32_t update;
	uint32_t sync;
	qpos_t q;

	/*
	 *  check type
	 */
	if (TYPE(mem) != QUE_TYPE_MEMBER)
		return 0;

	/*
	 *  check actiion
	 */
	if (ACTION(mem) != 0)
		return 0;

	/*
	 *  check update
	 */
	update = UPDATE(mem);
	sync   = SYNC(mem);
	if (SYNC(mem) >= update) {
		QUE_delete_all_queue(mem);
		return 0;
	}

	/*
	 *  check all
	 */
	*all = 0;
	*count = 0;
	for (q = QUEUE(mem); q; q = QUEUE(q)) {
		if (TYPE(q) != QUE_TYPE_QUEUE)
			continue;
		if (UPDATE(q) <= sync)
			continue;
		if (VNI(q) == VNI_ALL) {
			*all = 1;
		} else {
			(*count) ++;
		}
	}

	/*
	 *  check queue empty
	 */
	if (*all == 0 && *count == 0) {
		QUE_delete_all_queue(mem);
		return 0;
	}

	if (*all) {
		/*
		 *  sync all
		 */
		QUE_make_data_all(buf, mem);
	} else {
		/*
		 *  sync count
		 */
		for (q = QUEUE(mem); q; q = QUEUE(q)) {
			if (TYPE(q) != QUE_TYPE_QUEUE)
				continue;
			if (UPDATE(q) <= sync)
				continue;
			QUE_make_data_vni(buf, VNI(q));
		}
	}
	zprintf(buf, "end\n");

	return update;
}

void
QUE_sync_start(qpos_t mem)
{
	UPDATE_TIME(mem) = QUE_now();
	ACTION(mem) = 1;
}

void
QUE_sync_finish(qpos_t mem, uint32_t update)
{
	qpos_t q;
	qpos_t *prev;

	if (TYPE(mem) != QUE_TYPE_MEMBER)
		return;

	prev = &QUEUE(mem);
	while (*prev) {
		q = *prev;
		if (UPDATE(q) <= update) {
			mark_update(q);
			*prev = QUEUE(q);
			put_node(q);
		} else {
			prev = &QUEUE(q);
		}
	}
	if (SYNC(mem) < update) {
		SYNC(mem) = update;
		UPDATE_TIME(mem) = QUE_now();
	}

	UPDATE_TIME(mem) = QUE_now();
	ACTION(mem) = 0;
}

void
QUE_sync_abort(qpos_t mem)
{
	if (TYPE(mem) != QUE_TYPE_MEMBER)
		return;

	UPDATE_TIME(mem) = QUE_now();
	ACTION(mem) = 0;
}
